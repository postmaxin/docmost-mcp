use anyhow::{Context, Result, anyhow};
use serde_json::Value;

use crate::{auth::manager::safe_read_response_text, debug::debug_log, types::DocmostAttachment};

/// An upload error whose outcome is unknown: Docmost may already have stored the file.
///
/// Once the request may have left this server, every error is unknown unless it proves
/// nothing was stored. Only two things prove that: the request never left (a connect or
/// request-building failure, or an error before sending) or the reply is a `4xx`, a
/// refusal of the request itself. Anything else, such as a connection reset, a `5xx`
/// from Docmost or from a proxy in front of it, or a success reply that can't be read,
/// may come after the file was stored.
#[derive(Debug)]
pub struct UploadOutcomeUnknown(pub anyhow::Error);

impl std::fmt::Display for UploadOutcomeUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#}. Docmost may already have stored the file: check the page's attachments \
             before uploading again",
            self.0
        )
    }
}

impl std::error::Error for UploadOutcomeUnknown {}

fn outcome_unknown(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(UploadOutcomeUnknown(error))
}

/// True when `error` is an [`UploadOutcomeUnknown`].
pub fn is_outcome_unknown(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UploadOutcomeUnknown>().is_some()
}

impl super::DocmostClient {
    /// Upload a file to a page through Docmost's own attachment endpoint
    /// (`POST /api/files/upload`), the same call the editor makes, so the result is an
    /// ordinary Docmost attachment owned by that page.
    ///
    /// The form carries a `pageId` text field and a single `file` part. Docmost reads the
    /// fields that precede the file part only, so `pageId` MUST be appended first. Docmost
    /// requires edit access to the page and enforces its own `FILE_UPLOAD_SIZE_LIMIT`.
    ///
    /// `page_id` may be a slug ID: it is resolved to the page UUID first, because Docmost
    /// 0.96 accepts a slug for its permission check but then stores it in the attachment's
    /// UUID `pageId` column, failing the upload with a bare 400.
    pub async fn upload_attachment(
        &self,
        page_id: &str,
        file_name: &str,
        mime_type: &str,
        bytes: &[u8],
    ) -> Result<DocmostAttachment> {
        let page_uuid = if is_uuid(page_id) {
            page_id.to_string()
        } else {
            self.get_page(page_id)
                .await?
                .and_then(|page| page.id)
                .ok_or_else(|| anyhow!("Page not found: {page_id}"))?
        };
        let page_id = page_uuid.as_str();

        debug_log(
            "api",
            "Uploading Docmost attachment",
            Some(&serde_json::json!({ "pageId": page_id, "size": bytes.len() })),
        );
        let response = self
            .send_multipart("/api/files/upload", || {
                Ok(reqwest::multipart::Form::new()
                    .text("pageId", page_id.to_string())
                    .part(
                        "file",
                        reqwest::multipart::Part::bytes(bytes.to_vec())
                            .file_name(file_name.to_string())
                            .mime_str(mime_type)?,
                    ))
            })
            .await
            .map_err(|error| match error.downcast_ref::<reqwest::Error>() {
                // A connect or request-building failure means nothing was sent. Any other
                // transport error (a reset or timeout) may come after Docmost read the file.
                Some(transport) if !transport.is_connect() && !transport.is_builder() => {
                    outcome_unknown(error)
                }
                _ => error,
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let details = safe_read_response_text(response).await;
            let error = anyhow!(
                format!("Docmost file upload failed ({status}). {details}")
                    .trim()
                    .to_string()
            );
            // A 4xx refuses the request, so nothing was stored. Anything else (a 5xx from
            // Docmost or from a proxy in front of it) may come after the file was stored.
            return Err(if status.is_client_error() {
                error
            } else {
                outcome_unknown(error)
            });
        }

        // Unlike most endpoints, the upload handler writes its reply directly instead of
        // returning it, so Docmost's `{ data }` envelope is skipped. Accept both shapes.
        // From here on Docmost has said it succeeded, so an unreadable reply is uncertain.
        let mut body: Value = response
            .json()
            .await
            .context("Failed to parse Docmost upload response body")
            .map_err(outcome_unknown)?;
        if body.get("id").is_none()
            && let Some(data) = body.get_mut("data")
        {
            body = data.take();
        }
        serde_json::from_value(body)
            .context("Docmost upload response was not an attachment")
            .map_err(outcome_unknown)
    }
}

/// True for the canonical 8-4-4-4-12 hex UUID form (any version).
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}
