//! Staged uploads: get a file's bytes to Docmost without passing them through the model.
//!
//! A tool that took the file in its arguments would need it as base64, because over
//! the HTTP transport this server cannot read the client's filesystem. But an agent can only
//! fill a tool argument by generating it, so base64 makes the agent reproduce every byte as
//! output: slow, capped by the transport's request limit, and a single wrong character
//! silently corrupts the file.
//!
//! Instead, `docmost_begin_upload` (a write tool, so default-deny, `confirm`-gated and
//! audited) registers one pending upload here and returns a URL on this server. The client
//! sends the raw file to it with an ordinary HTTP `PUT`, for example `curl -T file <url>`,
//! and the bytes travel as bytes.
//!
//! The URL is the credential. Its token is 256 random bits, kept only as a hash. It is bound
//! to one page, file name, MIME type, size and SHA-256, works once, and expires after
//! [`UPLOAD_TTL`]. It carries the Docmost session that began the upload, so it never grants
//! more than that session already had.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::put,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};

use crate::{
    docmost_client::{DocmostClient, is_outcome_unknown},
    oauth::{random_token, token_hash},
    server::{attachment_markdown, attachment_path},
};

/// How long an upload URL stays valid after `docmost_begin_upload` returns it.
pub const UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

/// Default ceiling for a staged upload, in bytes (50 MiB, Docmost's own default limit).
/// The body streams to this server rather than through the JSON-RPC transport, so it is not
/// bound by the transport's 4 MiB request limit. Docmost's `FILE_UPLOAD_SIZE_LIMIT` still
/// applies on top.
pub const DEFAULT_MAX_STAGED_BYTES: usize = 50 * 1024 * 1024;

/// Most uploads that may be pending at once, so abandoned URLs cannot grow memory without
/// bound before they expire.
const MAX_PENDING: usize = 256;

/// Most bodies being received or forwarded at once. Each holds up to `max_bytes` in memory
/// (twice, while the multipart request to Docmost is built), so this, not `MAX_PENDING`,
/// is what bounds upload memory.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 4;

/// How long one upload may hold its in-flight slot, from the first byte of the body to
/// Docmost's reply. It is a single deadline rather than one per stage, so no stage (the
/// client sending, Docmost receiving, or Docmost answering) can hold a slot unbounded.
/// Fifteen minutes covers 50 MiB at about 0.5 Mbit/s with time left for Docmost.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// One upload that has been approved but not yet received.
struct Pending {
    client: DocmostClient,
    page_id: String,
    file_name: String,
    mime_type: String,
    size: usize,
    sha256: [u8; 32],
    expires_at: Instant,
}

/// What `docmost_begin_upload` reports back.
#[derive(Debug, Clone)]
pub struct BegunUpload {
    pub url: String,
    pub expires_in: Duration,
}

/// Pending uploads, shared between the MCP services that create them and the HTTP route
/// that completes them.
#[derive(Clone)]
pub struct UploadStager {
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    in_flight: Arc<Semaphore>,
    public_url: String,
    max_bytes: usize,
    ttl: Duration,
    deadline: Duration,
}

impl std::fmt::Debug for UploadStager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadStager")
            .field("public_url", &self.public_url)
            .field("max_bytes", &self.max_bytes)
            .field("ttl", &self.ttl)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl UploadStager {
    /// `public_url` is this server's externally reachable base (`DOCMOST_MCP_PUBLIC_URL`);
    /// upload URLs are built under it.
    pub fn new(public_url: &str, max_bytes: usize) -> Self {
        Self::with_ttl(public_url, max_bytes, UPLOAD_TTL)
    }

    pub fn with_ttl(public_url: &str, max_bytes: usize, ttl: Duration) -> Self {
        Self {
            pending: Arc::default(),
            in_flight: Arc::new(Semaphore::new(DEFAULT_MAX_IN_FLIGHT)),
            public_url: public_url.trim_end_matches('/').to_string(),
            max_bytes,
            ttl,
            deadline: DEFAULT_DEADLINE,
        }
    }

    /// Override how many bodies may be received or forwarded at once.
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.in_flight = Arc::new(Semaphore::new(max_in_flight));
        self
    }

    /// Override how long one upload may hold its in-flight slot.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Register an approved upload and return the single-use URL for its bytes. Callers
    /// validate the name, MIME type, size and hash first; this only enforces capacity.
    pub async fn begin(
        &self,
        client: DocmostClient,
        page_id: &str,
        file_name: &str,
        mime_type: &str,
        size: usize,
        sha256: [u8; 32],
    ) -> Result<BegunUpload> {
        let token = random_token(32);
        let now = Instant::now();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, upload| upload.expires_at > now);
        if pending.len() >= MAX_PENDING {
            bail!(
                "Too many uploads are waiting for their files ({MAX_PENDING}). Finish or abandon \
                 some, or wait up to {} minutes for unused URLs to expire.",
                self.ttl.as_secs().div_ceil(60)
            );
        }
        pending.insert(
            token_hash(&token),
            Pending {
                client,
                page_id: page_id.to_string(),
                file_name: file_name.to_string(),
                mime_type: mime_type.to_string(),
                size,
                sha256,
                expires_at: now + self.ttl,
            },
        );
        Ok(BegunUpload {
            url: format!("{}/uploads/{token}", self.public_url),
            expires_in: self.ttl,
        })
    }

    /// Remove and return a pending upload. Taking it is what makes the URL single-use: a
    /// second request, or one after a rejected body, finds nothing.
    async fn take(&self, token: &str) -> Option<Pending> {
        let now = Instant::now();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, upload| upload.expires_at > now);
        pending.remove(&token_hash(token))
    }

    /// How many uploads are waiting for their bytes (unexpired).
    pub async fn pending_count(&self) -> usize {
        let now = Instant::now();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, upload| upload.expires_at > now);
        pending.len()
    }
}

/// The `PUT /uploads/{token}` route.
///
/// The handler takes the raw [`Body`], which axum's `DefaultBodyLimit` does not apply to.
/// The read is bounded instead by the upload's declared size, itself capped at the
/// stager's maximum when the upload began: at most one byte past it is read, enough to
/// refuse an over-long body rather than truncate it.
pub fn routes(stager: UploadStager) -> Router {
    Router::new()
        .route("/uploads/{token}", put(receive_upload))
        .with_state(stager)
}

fn reply(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn rejected(status: StatusCode, message: String) -> Response {
    reply(
        status,
        json!({
            "error": message,
            "uploaded": false,
            "hint": "This upload URL has been used up. Call docmost_begin_upload again to get a new one.",
        }),
    )
}

async fn receive_upload(
    State(stager): State<UploadStager>,
    Path(token): Path<String>,
    body: Body,
) -> Response {
    // Claim an in-flight slot before the URL: a busy server refuses without using the URL
    // up, so the client can simply retry. The slot is held until the upload finishes or
    // its deadline passes.
    let Ok(_slot) = stager.in_flight.clone().try_acquire_owned() else {
        return reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "Too many uploads are in progress. The URL is still valid: retry shortly.",
                "uploaded": false,
            }),
        );
    };
    let Some(upload) = stager.take(&token).await else {
        return reply(
            StatusCode::NOT_FOUND,
            json!({
                "error": "Unknown, already used or expired upload URL. Call docmost_begin_upload to get a new one.",
                "uploaded": false,
            }),
        );
    };

    let page_id = upload.page_id.clone();
    let forwarding = Arc::new(AtomicBool::new(false));
    let processed = tokio::time::timeout(
        stager.deadline,
        process_upload(upload, body, forwarding.clone()),
    )
    .await;
    match processed {
        Ok(response) => response,
        // Dropping the future cancels the request to Docmost, but it may already have
        // stored the file, so say so and audit it as neither success nor failure.
        Err(_) if forwarding.load(Ordering::SeqCst) => {
            if let Err(error) =
                crate::audit::record_mutation("upload_attachment", &page_id, "timed_out").await
            {
                tracing::error!(target = %page_id, %error, "Failed to append upload timeout to audit log");
            }
            reply(
                StatusCode::GATEWAY_TIMEOUT,
                json!({
                    "error": format!(
                        "Docmost didn't finish the upload within {} seconds. It may already have \
                         stored the file: check the page's attachments before uploading again.",
                        stager.deadline.as_secs()
                    ),
                    "uploaded": Value::Null,
                }),
            )
        }
        Err(_) => rejected(
            StatusCode::REQUEST_TIMEOUT,
            format!(
                "The body did not arrive within {} seconds. Nothing was uploaded.",
                stager.deadline.as_secs()
            ),
        ),
    }
}

/// Read, check and forward one upload. Runs under the caller's deadline; `forwarding` is
/// set just before Docmost is contacted, so a timeout can tell "nothing was sent" from
/// "Docmost may have it".
async fn process_upload(upload: Pending, body: Body, forwarding: Arc<AtomicBool>) -> Response {
    // Read at most one byte past the declared size: enough to tell "too long" from "exact".
    let bytes = match to_bytes(body, upload.size.saturating_add(1)).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return rejected(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "The body is larger than the declared {} bytes, or could not be read. \
                     Nothing was uploaded.",
                    upload.size
                ),
            );
        }
    };
    if bytes.len() != upload.size {
        return rejected(
            StatusCode::BAD_REQUEST,
            format!(
                "The body is {} bytes but {} were declared. Nothing was uploaded.",
                bytes.len(),
                upload.size
            ),
        );
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != upload.sha256 {
        return rejected(
            StatusCode::BAD_REQUEST,
            format!(
                "The body's SHA-256 is {} but {} was declared. Nothing was uploaded.",
                to_hex(&digest),
                to_hex(&upload.sha256)
            ),
        );
    }

    if let Err(error) =
        crate::audit::record_mutation("upload_attachment", &upload.page_id, "authorized").await
    {
        return reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": format!("Could not write the audit log, so nothing was uploaded: {error}"), "uploaded": false }),
        );
    }
    forwarding.store(true, Ordering::SeqCst);
    let result = upload
        .client
        .upload_attachment(
            &upload.page_id,
            &upload.file_name,
            &upload.mime_type,
            &bytes,
        )
        .await;
    let uncertain = matches!(&result, Err(error) if is_outcome_unknown(error));
    let status = match &result {
        Ok(_) => "succeeded",
        Err(_) if uncertain => "uncertain",
        Err(_) => "failed",
    };
    if let Err(error) =
        crate::audit::record_mutation("upload_attachment", &upload.page_id, status).await
    {
        tracing::error!(target = %upload.page_id, %status, %error, "Failed to append upload outcome to audit log");
    }

    match result {
        Ok(attachment) => {
            let name = attachment
                .file_name
                .clone()
                .unwrap_or_else(|| upload.file_name.clone());
            let path = attachment_path(&attachment.id, &name);
            let is_image = attachment
                .mime_type
                .as_deref()
                .unwrap_or(&upload.mime_type)
                .starts_with("image/");
            let markdown = attachment_markdown(&name, &path, is_image);
            reply(
                StatusCode::OK,
                json!({
                    "uploaded": true,
                    "attachmentId": attachment.id,
                    "fileName": name,
                    "size": attachment.file_size.unwrap_or(upload.size as u64),
                    "mimeType": attachment.mime_type.unwrap_or(upload.mime_type),
                    "pageId": attachment.page_id,
                    "path": path,
                    "url": attachment.url,
                    "markdown": markdown,
                }),
            )
        }
        // The message already says to check the page before retrying.
        Err(error) if uncertain => reply(
            StatusCode::BAD_GATEWAY,
            json!({ "error": format!("The upload's outcome is unknown: {error}"), "uploaded": Value::Null }),
        ),
        Err(error) => reply(
            StatusCode::BAD_GATEWAY,
            json!({ "error": format!("Docmost rejected the upload: {error}"), "uploaded": false }),
        ),
    }
}

/// Parse a 64-character hex SHA-256 (either case).
pub fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, pair) in value.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha256_hex_in_either_case() {
        let lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let parsed = parse_sha256(lower).expect("valid");
        assert_eq!(to_hex(&parsed), lower);
        assert_eq!(parse_sha256(&lower.to_uppercase()), Some(parsed));
        assert_eq!(parse_sha256(&format!("  {lower}\n")), Some(parsed));
    }

    #[test]
    fn rejects_malformed_sha256() {
        for bad in [
            "",
            "abc",
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
            "é3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
        ] {
            assert!(parse_sha256(bad).is_none(), "{bad:?} should be rejected");
        }
    }
}
