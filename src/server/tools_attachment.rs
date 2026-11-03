//! The attachment write tool, `docmost_begin_upload`.
//!
//! Over the HTTP transport this server usually runs on a different machine from the
//! client, so it cannot read the caller's filesystem. Passing the file in the tool
//! arguments would make an agent generate every byte as output, so instead the tool
//! returns a single-use URL that the client `PUT`s the raw file to (see
//! [`crate::staged_upload`]).
//!
//! In its own `#[tool_router]` impl (a named `attachment_tool_router`, merged into the
//! server's router in `new()`) to keep each tools file within the size limit.

use rmcp::{handler::server::wrapper::Parameters, model::ErrorData, tool, tool_router};

use crate::{
    server::DocmostMcpServer,
    staged_upload::{parse_sha256, to_hex},
    types::BeginUploadInput,
};

/// Longest file name accepted; Docmost truncates stored names at 255 characters.
const MAX_FILE_NAME_CHARS: usize = 255;

const DEFAULT_MIME_TYPE: &str = "application/octet-stream";

#[tool_router(router = attachment_tool_router, vis = "pub(crate)")]
impl DocmostMcpServer {
    #[tool(
        name = "docmost_begin_upload",
        description = "Start uploading a file to a Docmost page without sending its bytes \
                       through the conversation. Give the file's exact size and SHA-256 (for \
                       example from `sha256sum`). Returns a single-use URL; send the raw file \
                       to it with one HTTP PUT, such as `curl -sS --fail-with-body -T <file> '<url>'`. The \
                       server uploads it only if the size and hash match, and the PUT \
                       response gives the attachment ID, its `/api/files/...` path and a \
                       Markdown snippet. Uploading does not change the page body; to show \
                       the file, reference that path in page Markdown via \
                       docmost_update_page (`![alt](/api/files/...)` embeds an image, \
                       `[name](/api/files/...)` links any file), keeping it relative so it \
                       resolves on the Docmost origin for signed-in readers. The URL expires \
                       after 10 minutes.",
        annotations(
            title = "Begin Docmost Upload",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn begin_upload(
        &self,
        Parameters(input): Parameters<BeginUploadInput>,
    ) -> Result<String, ErrorData> {
        validate_file_name(&input.file_name)?;
        let mime_type = validate_mime_type(input.mime_type.as_deref())?.to_string();
        let Some(stager) = self.stager.clone() else {
            return Err(ErrorData::invalid_params(
                "Staged uploads aren't available on this server: they need the HTTP transport \
                 with DOCMOST_MCP_PUBLIC_URL set."
                    .to_string(),
                None,
            ));
        };
        let size = usize::try_from(input.size).unwrap_or(usize::MAX);
        if size == 0 {
            return Err(ErrorData::invalid_params(
                "Invalid size: the file must not be empty.".to_string(),
                None,
            ));
        }
        if size > stager.max_bytes() {
            return Err(ErrorData::invalid_params(
                format!(
                    "File is too large: the limit for staged uploads is {} bytes.",
                    stager.max_bytes()
                ),
                None,
            ));
        }
        let sha256 = parse_sha256(&input.sha256).ok_or_else(|| {
            ErrorData::invalid_params(
                "Invalid sha256: expected 64 hex characters.".to_string(),
                None,
            )
        })?;

        // Pin the session inside the gated step: the upload must run as the account that
        // was approved now, not whichever account the server holds when the PUT arrives.
        let begun = self
            .run_write(input.confirm, "begin_upload", &input.page_id, async {
                let client = self.client.pinned().await?;
                stager
                    .begin(
                        client,
                        &input.page_id,
                        &input.file_name,
                        &mime_type,
                        size,
                        sha256,
                    )
                    .await
            })
            .await?;
        Ok(format!(
            "Ready for \"{name}\" ({size} bytes, {mime_type}). Send the file with one HTTP PUT \
             within {minutes} minutes; the URL works once:\n\n\
             curl -sS --fail-with-body -T <file> '{url}'\n\n\
             Nothing is uploaded unless the body is exactly {size} bytes with SHA-256 {hash}. \
             The PUT response is JSON with the attachment ID, its `path` and a ready-made \
             `markdown` snippet for docmost_update_page. On failure, read the JSON: \
             `\"uploaded\": false` means nothing was stored and the URL is used up, so call \
             docmost_begin_upload again; `\"uploaded\": null` means Docmost may have stored \
             the file, so check the page's attachments before uploading again. If the PUT \
             gets no response at all, check the page's attachments before starting again.",
            name = input.file_name,
            minutes = begun.expires_in.as_secs().div_ceil(60),
            url = begun.url,
            hash = to_hex(&sha256),
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

/// The relative path the Docmost editor itself stores for an uploaded file. The name is
/// percent-encoded so the path survives as a Markdown link destination; Docmost resolves
/// the file by ID and ignores the name segment.
pub(crate) fn attachment_path(id: &str, file_name: &str) -> String {
    format!("/api/files/{id}/{}", urlencoding::encode(file_name))
}

/// The Markdown that embeds (images) or links (anything else) an attachment. The file
/// name is escaped for use as link text: `validate_file_name` allows brackets, and an
/// unmatched one, as in `draft[1.png`, would otherwise break the snippet.
pub(crate) fn attachment_markdown(file_name: &str, path: &str, is_image: bool) -> String {
    let mut label = String::with_capacity(file_name.len());
    for c in file_name.chars() {
        if matches!(c, '\\' | '[' | ']') {
            label.push('\\');
        }
        label.push(c);
    }
    if is_image {
        format!("![{label}]({path})")
    } else {
        format!("[{label}]({path})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn markdown_snippet_escapes_brackets_in_the_name() {
        assert_eq!(
            attachment_markdown("diagram.png", "/api/files/i/diagram.png", true),
            "![diagram.png](/api/files/i/diagram.png)"
        );
        assert_eq!(
            attachment_markdown("draft[1.png", "/p", true),
            "![draft\\[1.png](/p)"
        );
        assert_eq!(
            attachment_markdown("a]b\\c.pdf", "/p", false),
            "[a\\]b\\\\c.pdf](/p)"
        );
    }
}
