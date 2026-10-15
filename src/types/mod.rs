use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod inputs;
pub use inputs::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredConfig {
    pub base_url: String,
    pub email: String,
    pub last_authenticated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    pub token: String,
    pub expires_at: Option<String>,
    pub saved_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredCredentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSession {
    pub base_url: String,
    pub email: String,
    pub token: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupConfig {
    pub base_url: Option<String>,
    pub interactive_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    pub base_url: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthWindowSession {
    pub login_url: String,
    pub success_url: String,
    pub fallback_url: String,
    pub window_title: String,
    pub window_width: u32,
    pub window_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostSpace {
    pub id: String,
    pub name: Option<String>,
    pub slug: String,
    pub description: Option<String>,
    pub member_count: Option<i64>,
    pub visibility: Option<String>,
    pub default_role: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostSpaceWithMembership {
    pub id: String,
    pub name: Option<String>,
    pub slug: String,
    pub description: Option<String>,
    pub member_count: Option<i64>,
    pub visibility: Option<String>,
    pub default_role: Option<String>,
    pub membership: Option<DocmostSpaceMembership>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostSpaceMembership {
    pub user_id: Option<String>,
    pub role: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostSearchResult {
    pub id: Option<String>,
    pub slug_id: String,
    pub title: Option<String>,
    pub highlight: Option<String>,
    pub icon: Option<String>,
    pub parent_page_id: Option<String>,
    pub creator_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub space: Option<DocmostSearchSpace>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostSearchSpace {
    pub id: Option<String>,
    pub name: Option<String>,
    pub slug: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostPage {
    pub id: Option<String>,
    pub slug_id: Option<String>,
    pub title: Option<String>,
    pub icon: Option<String>,
    pub updated_at: Option<String>,
    pub parent_page_id: Option<String>,
    pub space_id: Option<String>,
    pub space: Option<DocmostPageSpace>,
    pub creator: Option<DocmostPageCreator>,
    pub content: Option<Value>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostPageSpace {
    pub id: Option<String>,
    pub name: Option<String>,
    pub slug: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostPageCreator {
    pub id: Option<String>,
    pub name: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostPageListItem {
    pub id: String,
    pub slug_id: String,
    pub title: Option<String>,
    pub icon: Option<String>,
    pub parent_page_id: Option<String>,
    pub has_children: Option<bool>,
    pub space_id: Option<String>,
    pub updated_at: Option<String>,
    pub space: Option<DocmostSearchSpace>,
    pub position: Option<String>, // fractional-index sibling ordering key; see crate::position
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostComment {
    pub id: String,
    pub page_id: Option<String>,
    pub content: Option<Value>,
    pub selection: Option<String>,
    pub parent_comment_id: Option<String>,
    pub creator: Option<DocmostUserSummary>,
    pub resolved_by: Option<DocmostUserSummary>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub resolved_at: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostUserSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostUser {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub role: Option<String>,
    pub deactivated_at: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostWorkspace {
    pub id: String,
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub default_space_id: Option<String>,
    pub member_count: Option<i64>,
    pub has_license_key: Option<bool>,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DocmostCurrentUserResponse {
    pub user: DocmostUser,
    pub workspace: DocmostWorkspace,
    /// Every field Docmost returned that this struct does not model.
    ///
    /// Without this, serde silently drops unknown keys, so `response_format: "json"`
    /// promised "complete records" while quietly discarding whatever the server
    /// added since these structs were written. Capturing them here means the JSON
    /// response really is everything the API sent, and new Docmost fields appear
    /// automatically instead of requiring a code change.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A file attachment as returned by Docmost's `POST /api/files/upload`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocmostAttachment {
    pub id: String,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub file_ext: Option<String>,
    pub mime_type: Option<String>,
    pub page_id: Option<String>,
    pub space_id: Option<String>,
    /// Absolute download URL built from Docmost's `APP_URL`; optional so a server that
    /// omits it still parses.
    pub url: Option<String>,
    /// Every field Docmost returned that this struct does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
