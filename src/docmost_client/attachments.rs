use anyhow::{Context, Result, anyhow};
use serde_json::Value;

use crate::{auth::manager::safe_read_response_text, debug::debug_log, types::DocmostAttachment};

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
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let details = safe_read_response_text(response).await;
            return Err(anyhow!(
                format!("Docmost file upload failed ({status}). {details}")
                    .trim()
                    .to_string()
            ));
        }

        // Unlike most endpoints, the upload handler writes its reply directly instead of
        // returning it, so Docmost's `{ data }` envelope is skipped. Accept both shapes.
        let mut body: Value = response
            .json()
            .await
            .context("Failed to parse Docmost upload response body")?;
        if body.get("id").is_none()
            && let Some(data) = body.get_mut("data")
        {
            body = data.take();
        }
        serde_json::from_value(body).context("Docmost upload response was not an attachment")
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
