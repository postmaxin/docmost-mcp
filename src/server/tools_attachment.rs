//! Attachment write tool: `docmost_upload_attachment`.
//!
//! The file travels inside the tool arguments as base64 rather than as a local path:
//! over the HTTP transport this server usually runs on a different machine from the
//! client, so it cannot read the caller's filesystem.
//!
//! In its own `#[tool_router]` impl (a named `attachment_tool_router`, merged into the
//! server's router in `new()`) to keep each tools file within the size limit.

use base64::{Engine, engine::general_purpose::STANDARD};
use rmcp::{handler::server::wrapper::Parameters, model::ErrorData, tool, tool_router};

use crate::{
    server::{DocmostMcpServer, render::format_optional_id},
    types::{DocmostAttachment, UploadAttachmentInput},
};

/// Largest file accepted, in decoded bytes (2 MiB).
///
/// Bounded by the transport, not by Docmost (whose own default limit is 50 MB): base64
/// grows the payload by a third, and the Streamable HTTP transport rejects request bodies
/// over 4 MiB, so 2 MiB leaves room for the JSON-RPC envelope. Files this size are also
/// already far more than an agent can sensibly emit as tool-call text.
pub const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Longest file name accepted; Docmost truncates stored names at 255 characters.
const MAX_FILE_NAME_CHARS: usize = 255;

const DEFAULT_MIME_TYPE: &str = "application/octet-stream";

#[tool_router(router = attachment_tool_router, vis = "pub(crate)")]
impl DocmostMcpServer {
    #[tool(
        name = "docmost_upload_attachment",
        description = "Upload a file (base64, at most 2 MiB) to a Docmost page as a normal \
                       Docmost attachment. Returns the attachment ID and its path, \
                       `/api/files/{attachment_id}/{file_name}`. Uploading does not change the \
                       page body; to show the file, reference that path in page Markdown via \
                       docmost_update_page: `![alt](/api/files/...)` embeds an image, \
                       `[name](/api/files/...)` links any file. Keep the path relative so it \
                       resolves on the Docmost origin for signed-in readers.",
        annotations(
            title = "Upload Docmost Attachment",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn upload_attachment(
        &self,
        Parameters(input): Parameters<UploadAttachmentInput>,
    ) -> Result<String, ErrorData> {
        // Validate before the write gate so malformed calls fail the same way whether or
        // not writes are enabled, and nothing is audited for a call that cannot proceed.
        validate_file_name(&input.file_name)?;
        let mime_type = validate_mime_type(input.mime_type.as_deref())?;
        let bytes = decode_content(&input.content_base64)?;

        let attachment = self
            .run_write(
                input.confirm,
                "upload_attachment",
                &input.page_id,
                self.client
                    .upload_attachment(&input.page_id, &input.file_name, mime_type, &bytes),
            )
            .await?;
        Ok(format_attachment(
            &attachment,
            &input.file_name,
            bytes.len(),
        ))
    }
}

/// Reject names that are empty, overlong, or could be read as a path. Docmost sanitizes
/// what remains itself (e.g. spaces become `_`), so callers must use the returned name.
pub(crate) fn validate_file_name(name: &str) -> Result<(), ErrorData> {
    let invalid = |reason: &str| {
        Err(ErrorData::invalid_params(
            format!("Invalid file_name: {reason}."),
            None,
        ))
    };
    if name.trim().is_empty() {
        return invalid("it must not be empty");
    }
    if name.chars().count() > MAX_FILE_NAME_CHARS {
        return invalid("it must be at most 255 characters");
    }
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return invalid("it must be a bare file name, not a path");
    }
    if name.chars().any(char::is_control) {
        return invalid("it must not contain control characters");
    }
    Ok(())
}

/// Default and sanity-check the MIME type (`type/subtype`, no parameters or whitespace).
pub(crate) fn validate_mime_type(mime: Option<&str>) -> Result<&str, ErrorData> {
    let Some(mime) = mime.map(str::trim).filter(|m| !m.is_empty()) else {
        return Ok(DEFAULT_MIME_TYPE);
    };
    let well_formed = mime.split_once('/').is_some_and(|(kind, sub)| {
        let token = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "!#$&^_.+-".contains(c))
        };
        token(kind) && token(sub)
    });
    if !well_formed {
        return Err(ErrorData::invalid_params(
            format!("Invalid mime_type {mime:?}: expected `type/subtype`, e.g. `image/png`."),
            None,
        ));
    }
    Ok(mime)
}

/// Decode standard base64, ignoring ASCII whitespace (wrapped output is common). The
/// encoded length is checked first so an oversized payload is refused before any
/// allocation proportional to it.
pub(crate) fn decode_content(encoded: &str) -> Result<Vec<u8>, ErrorData> {
    let too_large = || {
        ErrorData::invalid_params(
            format!(
                "File is too large: the limit is {MAX_UPLOAD_BYTES} bytes (2 MiB) after decoding."
            ),
            None,
        )
    };
    let max_encoded = MAX_UPLOAD_BYTES.div_ceil(3) * 4;
    let compact: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .take(max_encoded + 1)
        .collect();
    if compact.len() > max_encoded {
        return Err(too_large());
    }
    if compact.starts_with("data:") {
        return Err(ErrorData::invalid_params(
            "content_base64 must be bare base64; remove the `data:...;base64,` prefix and pass \
             the type as mime_type."
                .to_string(),
            None,
        ));
    }
    let bytes = STANDARD.decode(compact.as_bytes()).map_err(|error| {
        ErrorData::invalid_params(
            format!("content_base64 is not valid standard base64: {error}."),
            None,
        )
    })?;
    if bytes.is_empty() {
        return Err(ErrorData::invalid_params(
            "The file is empty: content_base64 decoded to zero bytes.".to_string(),
            None,
        ));
    }
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

/// The relative path the Docmost editor itself stores for an uploaded file. The name is
/// percent-encoded so the path survives as a Markdown link destination; Docmost resolves
/// the file by ID and ignores the name segment.
pub(crate) fn attachment_path(id: &str, file_name: &str) -> String {
    format!("/api/files/{id}/{}", urlencoding::encode(file_name))
}

fn format_attachment(attachment: &DocmostAttachment, sent_name: &str, sent_size: usize) -> String {
    let name = attachment.file_name.as_deref().unwrap_or(sent_name);
    let size = attachment.file_size.unwrap_or(sent_size as u64);
    let path = attachment_path(&attachment.id, name);
    let is_image = attachment
        .mime_type
        .as_deref()
        .is_some_and(|mime| mime.starts_with("image/"));
    let mut lines = vec![
        format!("Uploaded \"{name}\" to Docmost."),
        String::new(),
        format!(
            "Attachment ID: {}",
            format_optional_id(Some(&attachment.id))
        ),
        format!("File name: {name}"),
        format!("Size: {size} bytes"),
        format!(
            "MIME type: {}",
            attachment.mime_type.as_deref().unwrap_or("(unknown)")
        ),
        format!(
            "Page ID: {}",
            format_optional_id(attachment.page_id.as_deref())
        ),
        format!("Path: `{path}`"),
    ];
    if let Some(url) = attachment.url.as_deref() {
        lines.push(format!("URL: {url}"));
    }
    lines.push(String::new());
    lines.push(if is_image {
        format!("Embed in page Markdown: `![{name}]({path})`")
    } else {
        format!("Link from page Markdown: `[{name}]({path})`")
    });
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_base64_and_ignores_line_breaks() {
        assert_eq!(decode_content("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_content("aGVs\nbG8=\n").unwrap(), b"hello");
    }

    #[test]
    fn rejects_invalid_empty_and_data_url_content() {
        assert!(decode_content("not base64!").is_err());
        assert!(decode_content("").is_err());
        assert!(decode_content("  \n").is_err());
        let err = decode_content("data:image/png;base64,aGVsbG8=").unwrap_err();
        assert!(err.message.contains("prefix"), "{}", err.message);
    }

    #[test]
    fn accepts_exactly_the_size_limit() {
        let encoded = STANDARD.encode(vec![7u8; MAX_UPLOAD_BYTES]);
        assert_eq!(decode_content(&encoded).unwrap().len(), MAX_UPLOAD_BYTES);
    }

    #[test]
    fn rejects_one_byte_over_the_size_limit() {
        let encoded = STANDARD.encode(vec![7u8; MAX_UPLOAD_BYTES + 1]);
        let err = decode_content(&encoded).unwrap_err();
        assert!(err.message.contains("too large"), "{}", err.message);
    }

    #[test]
    fn rejects_oversized_input_before_decoding() {
        // Not valid base64 at all: the length check must fire first.
        let err = decode_content(&"!".repeat(4 * MAX_UPLOAD_BYTES)).unwrap_err();
        assert!(err.message.contains("too large"), "{}", err.message);
    }

    #[test]
    fn file_name_validation() {
        assert!(validate_file_name("diagram.png").is_ok());
        assert!(validate_file_name("Q3 report (final).pdf").is_ok());
        assert!(validate_file_name(&"a".repeat(255)).is_ok());
        for bad in [
            "",
            "   ",
            "../etc/passwd",
            "dir/file.txt",
            "dir\\file.txt",
            "..",
            "a\nb.txt",
        ] {
            assert!(
                validate_file_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(validate_file_name(&"a".repeat(256)).is_err());
    }

    #[test]
    fn mime_type_validation_and_default() {
        assert_eq!(validate_mime_type(None).unwrap(), DEFAULT_MIME_TYPE);
        assert_eq!(validate_mime_type(Some("  ")).unwrap(), DEFAULT_MIME_TYPE);
        assert_eq!(validate_mime_type(Some("image/png")).unwrap(), "image/png");
        assert_eq!(
            validate_mime_type(Some("application/vnd.ms-excel")).unwrap(),
            "application/vnd.ms-excel"
        );
        for bad in [
            "png",
            "image/",
            "/png",
            "text/plain; charset=utf-8",
            "a/b/c",
        ] {
            assert!(validate_mime_type(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn path_matches_the_editor_form_and_encodes_the_name() {
        assert_eq!(
            attachment_path("0199-id", "diagram.png"),
            "/api/files/0199-id/diagram.png"
        );
        assert_eq!(
            attachment_path("0199-id", "Q3 report (final).pdf"),
            "/api/files/0199-id/Q3%20report%20%28final%29.pdf"
        );
    }
}
