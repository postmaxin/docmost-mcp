//! Tool input schemas (`schemars::JsonSchema`) passed to `#[tool]` handlers as
//! `Parameters<T>`. Split from the domain models to keep each file within the size limit.

use schemars::JsonSchema;
use serde::Deserialize;

/// Output format for tools that return data.
///
/// Markdown is the default because it is what an agent reads back to a human and
/// it costs far fewer tokens than the full record. `json` returns every field the
/// API gave us — plus explicit pagination metadata — for callers that post-process
/// the result rather than summarise it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResponseFormat {
    /// Condensed, human-readable Markdown.
    #[default]
    Markdown,
    /// Complete records as JSON, with a `pagination` block on list results.
    Json,
}

impl ResponseFormat {
    pub fn is_json(self) -> bool {
        matches!(self, ResponseFormat::Json)
    }
}

/// Shared `response_format` description, so every tool documents it identically.
pub const RESPONSE_FORMAT_DESC: &str = "Output format: `markdown` (default, condensed and human-readable) or `json` \
     (complete untruncated records, including fields not explicitly modelled, plus pagination metadata).";

/// Input for tools that take no arguments beyond the output format.
#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
pub struct EmptyInput {
    #[serde(default)]
    #[schemars(description = "Output format: `markdown` (default) or `json`.")]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SearchDocsInput {
    #[schemars(description = "Full-text query to search for.")]
    pub query: String,
    #[serde(default)]
    #[schemars(description = "Optional Docmost space ID to scope the search.")]
    pub space_id: Option<String>,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetSpaceInput {
    #[schemars(description = "The Docmost space ID.")]
    pub space_id: String,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetPageInput {
    #[schemars(
        description = "The page slug ID returned from docmost_search_docs or docmost_search_pages."
    )]
    pub slug_id: String,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListPagesInput {
    #[schemars(description = "The Docmost space ID to list pages from.")]
    pub space_id: String,
    #[serde(default)]
    #[schemars(description = "Optional number of pages to return.")]
    pub limit: Option<u32>,
    #[serde(default)]
    #[schemars(description = "Optional cursor returned by a previous list call.")]
    pub cursor: Option<String>,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListChildPagesInput {
    #[schemars(description = "The parent Docmost page ID.")]
    pub page_id: String,
    #[serde(default)]
    #[schemars(description = "Optional number of child pages to return.")]
    pub limit: Option<u32>,
    #[serde(default)]
    #[schemars(description = "Optional cursor returned by a previous list call.")]
    pub cursor: Option<String>,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetCommentsInput {
    #[schemars(description = "The Docmost page ID to list comments for.")]
    pub page_id: String,
    #[serde(default)]
    #[schemars(description = "Optional number of comments to return.")]
    pub limit: Option<u32>,
    #[serde(default)]
    #[schemars(description = "Optional cursor returned by a previous list call.")]
    pub cursor: Option<String>,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreatePageInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost space ID (UUID) to create the page in.")]
    pub space_id: String,
    #[schemars(description = "Page title.")]
    pub title: String,
    #[serde(default)]
    #[schemars(
        description = "Page body as Markdown; converted to ProseMirror JSON before sending."
    )]
    pub markdown: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional parent page ID to nest this page under (must be in the same space)."
    )]
    pub parent_page_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct UpdatePageInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID or slug ID to update.")]
    pub page_id: String,
    #[serde(default)]
    #[schemars(description = "Optional new page title. Omit to leave the title unchanged.")]
    pub title: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional new page body as Markdown; replaces the existing content. Omit to leave content unchanged."
    )]
    pub markdown: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DuplicatePageInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID or slug ID to duplicate within its space.")]
    pub page_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CopyPageToSpaceInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID or slug ID to copy.")]
    pub page_id: String,
    #[schemars(description = "The target space ID (UUID) to copy the page into.")]
    pub space_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MovePageInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID or slug ID to move.")]
    pub page_id: String,
    #[serde(default)]
    #[schemars(
        description = "Optional new parent page ID within the same space. Omit to move the page to the space root. The page is appended after the parent's existing children."
    )]
    pub parent_page_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MovePageToSpaceInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID or slug ID to move.")]
    pub page_id: String,
    #[schemars(
        description = "The target space ID (UUID) to move the page (and its sub-pages) into."
    )]
    pub space_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListWorkspaceMembersInput {
    #[serde(default)]
    #[schemars(description = "Optional number of members to return.")]
    pub limit: Option<u32>,
    #[serde(default)]
    #[schemars(description = "Optional cursor returned by a previous list call.")]
    pub cursor: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional text filter for member names or emails.")]
    pub query: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional admin view flag, when supported by the workspace.")]
    pub admin_view: Option<bool>,
    #[serde(default)]
    #[schemars(description = RESPONSE_FORMAT_DESC)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreateSpaceInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "Space name (2-100 characters).")]
    pub name: String,
    #[schemars(
        description = "URL slug: letters and numbers only (2-100 characters). Some Docmost versions also allow hyphens and underscores, but letters/numbers work everywhere."
    )]
    pub slug: String,
    #[serde(default)]
    #[schemars(description = "Optional space description.")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct UpdateSpaceInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The space ID (UUID) to update.")]
    pub space_id: String,
    #[serde(default)]
    #[schemars(description = "Optional new name (2-100 characters). Omit to leave unchanged.")]
    pub name: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional new URL slug. Omit to leave unchanged.")]
    pub slug: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional new description. Omit to leave unchanged.")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreateCommentInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The Docmost page ID (UUID) to comment on.")]
    pub page_id: String,
    #[schemars(
        description = "Comment body as Markdown. Creates a page-level comment (not anchored to a text selection). To tag a user, write a link with a `user:` URL: `[Display Name](user:USER_UUID)` (get USER_UUID from docmost_list_workspace_members); `[Title](page:PAGE_UUID)` mentions a page. Tables, images, and task lists are not supported inside comments."
    )]
    pub markdown: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct UpdateCommentInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(description = "The comment ID (UUID) to update.")]
    pub comment_id: String,
    #[schemars(
        description = "New comment body as Markdown; replaces the existing content. Tag users with `[Display Name](user:USER_UUID)` (see list_workspace_members)."
    )]
    pub markdown: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct UploadAttachmentInput {
    #[schemars(description = "Must be true after the user reviews and approves this mutation.")]
    pub confirm: bool,
    #[schemars(
        description = "The Docmost page ID or slug ID to attach the file to. Requires edit access to the page."
    )]
    pub page_id: String,
    #[schemars(
        description = "File name including its extension, e.g. `diagram.png`. No path separators. Docmost derives the stored MIME type from the extension and may normalise the name (spaces become underscores); use the name returned."
    )]
    pub file_name: String,
    #[schemars(
        description = "The file's bytes, standard base64-encoded (no `data:` prefix; line breaks are ignored). At most 2 MiB once decoded."
    )]
    pub content_base64: String,
    #[serde(default)]
    #[schemars(
        description = "Optional MIME type sent with the upload, e.g. `image/png`. Defaults to `application/octet-stream`."
    )]
    pub mime_type: Option<String>,
}
