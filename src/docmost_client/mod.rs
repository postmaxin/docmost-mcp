use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::{
    auth::manager::{AuthManager, safe_read_response_text},
    debug::debug_log,
    types::{
        DocmostComment, DocmostCurrentUserResponse, DocmostPage, DocmostPageListItem,
        DocmostSearchResult, DocmostSpace, DocmostSpaceWithMembership, DocmostUser,
    },
    version::{Capabilities, ServerVersion, VersionResponse},
};

#[derive(Debug, Clone)]
pub struct DocmostClient {
    auth_manager: AuthManager,
    http: Client,
    /// Detected server version, fetched once (on success) and shared across clones.
    version: Arc<OnceCell<ServerVersion>>,
}

#[derive(Debug, serde::Deserialize)]
struct ApiEnvelope<T> {
    data: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum ListResult<T> {
    List(Vec<T>),
    Wrapped { items: Option<Vec<T>> },
}

/// Pagination metadata returned alongside a list.
///
/// Every field is optional and defaulted on purpose. Docmost has shipped this
/// envelope in more than one shape (nested under `meta`, and flat alongside
/// `items`), and a CE instance may omit it entirely — so a missing field must
/// degrade to "unknown", never to a deserialization failure that breaks an
/// otherwise good response.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PaginationMeta {
    pub limit: Option<u32>,
    pub page: Option<u32>,
    pub total: Option<u64>,
    pub count: Option<u64>,
    pub has_next_page: Option<bool>,
    pub has_prev_page: Option<bool>,
    pub next_cursor: Option<String>,
    pub prev_cursor: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CursorListResult<T> {
    pub items: Option<Vec<T>>,
    /// Nested form: `{ items: [...], meta: { nextCursor, hasNextPage, ... } }`
    #[serde(default)]
    pub meta: Option<PaginationMeta>,
    /// Flat form: `{ items: [...], nextCursor: "..." }`
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_next_page: Option<bool>,
    #[serde(default)]
    pub total: Option<u64>,
}

/// A page of results plus the metadata an agent needs to fetch the next one.
///
/// Returning a bare `Vec` (as this client previously did) silently discards the
/// cursor, which makes the `cursor` tool parameter unusable: the caller can only
/// paginate if it somehow already knows the next cursor. Carrying it here is what
/// makes paging actually work.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub total: Option<u64>,
    /// `None` when the server told us nothing either way — reported as unknown
    /// rather than guessed, so an agent never wrongly concludes it has everything.
    pub has_more: Option<bool>,
}

impl<T> Page<T> {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

mod attachments;
mod writes;

impl DocmostClient {
    pub fn new(auth_manager: AuthManager) -> Self {
        Self {
            auth_manager,
            http: Client::new(),
            version: Arc::new(OnceCell::new()),
        }
    }

    /// The detected Docmost server version (from `POST /api/version`). Fetched once and
    /// cached **only on success**, so a transient probe failure doesn't poison the session
    /// (a later call re-probes). `None` if the endpoint is unavailable (e.g. Docmost Cloud)
    /// or the version is unparseable.
    pub async fn server_version(&self) -> Option<ServerVersion> {
        self.version
            .get_or_try_init(|| async {
                let response = self
                    .request::<VersionResponse>("/api/version", serde_json::json!({}), true)
                    .await
                    .map_err(|error| {
                        let detail = serde_json::json!({ "error": error.to_string() });
                        debug_log(
                            "version",
                            "Could not determine Docmost version",
                            Some(&detail),
                        );
                    })?;
                response.version().ok_or(())
            })
            .await
            .ok()
            .copied()
    }

    /// Version-gated server capabilities (see [`crate::version::Capabilities`]).
    pub async fn capabilities(&self) -> Capabilities {
        Capabilities::for_version(self.server_version().await)
    }

    pub async fn list_spaces(&self) -> Result<Vec<DocmostSpace>> {
        let result = self
            .request::<ListResult<DocmostSpace>>(
                "/api/spaces",
                serde_json::json!({ "page": 1, "limit": 100 }),
                true,
            )
            .await?;
        Ok(normalize_list_result(Some(result)))
    }

    pub async fn search_docs(
        &self,
        query: &str,
        space_id: Option<&str>,
    ) -> Result<Vec<DocmostSearchResult>> {
        let mut payload = serde_json::json!({ "query": query });
        if let Some(space_id) = space_id {
            payload["spaceId"] = Value::String(space_id.to_string());
        }

        let result = self
            .request::<ListResult<DocmostSearchResult>>("/api/search", payload, true)
            .await?;
        Ok(normalize_list_result(Some(result)))
    }

    pub async fn get_space(&self, space_id: &str) -> Result<DocmostSpaceWithMembership> {
        self.request(
            "/api/spaces/info",
            serde_json::json!({ "spaceId": space_id }),
            true,
        )
        .await
    }

    pub async fn get_page(&self, slug_id: &str) -> Result<Option<DocmostPage>> {
        self.request(
            "/api/pages/info",
            serde_json::json!({ "pageId": slug_id }),
            true,
        )
        .await
    }

    pub async fn list_pages(
        &self,
        space_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Page<DocmostPageListItem>> {
        let mut payload = serde_json::json!({ "spaceId": space_id });
        if let Some(limit) = limit {
            payload["limit"] = Value::from(limit);
        }
        if let Some(cursor) = cursor {
            payload["cursor"] = Value::String(cursor.to_string());
        }

        let result = self
            .request::<CursorListResult<DocmostPageListItem>>("/api/pages/recent", payload, true)
            .await?;
        Ok(into_page(result))
    }

    pub async fn list_child_pages(
        &self,
        page_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Page<DocmostPageListItem>> {
        let mut payload = serde_json::json!({ "pageId": page_id });
        if let Some(limit) = limit {
            payload["limit"] = Value::from(limit);
        }
        if let Some(cursor) = cursor {
            payload["cursor"] = Value::String(cursor.to_string());
        }

        let result = self
            .request::<CursorListResult<DocmostPageListItem>>(
                "/api/pages/sidebar-pages",
                payload,
                true,
            )
            .await?;
        Ok(into_page(result))
    }

    pub async fn get_comments(
        &self,
        page_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Page<DocmostComment>> {
        let mut payload = serde_json::json!({ "pageId": page_id });
        if let Some(limit) = limit {
            payload["limit"] = Value::from(limit);
        }
        if let Some(cursor) = cursor {
            payload["cursor"] = Value::String(cursor.to_string());
        }

        let result = self
            .request::<CursorListResult<DocmostComment>>("/api/comments", payload, true)
            .await?;
        Ok(into_page(result))
    }

    pub async fn list_workspace_members(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
        query: Option<&str>,
        admin_view: Option<bool>,
    ) -> Result<Page<DocmostUser>> {
        let mut payload = serde_json::json!({});
        if let Some(limit) = limit {
            payload["limit"] = Value::from(limit);
        }
        if let Some(cursor) = cursor {
            payload["cursor"] = Value::String(cursor.to_string());
        }
        if let Some(query) = query {
            payload["query"] = Value::String(query.to_string());
        }
        if let Some(admin_view) = admin_view {
            payload["adminView"] = Value::Bool(admin_view);
        }

        let result = self
            .request::<CursorListResult<DocmostUser>>("/api/workspace/members", payload, true)
            .await?;
        Ok(into_page(result))
    }

    pub async fn get_current_user(&self) -> Result<DocmostCurrentUserResponse> {
        self.request("/api/users/me", serde_json::json!({}), true)
            .await
    }

    /// POST with bearer auth and a single 401-retry, returning the raw response.
    async fn send_json(
        &self,
        endpoint: &str,
        payload: Value,
        retry_on_unauthorized: bool,
    ) -> Result<Response> {
        let mut session = self.auth_manager.get_authenticated_session().await?;
        let mut retry_on_unauthorized = retry_on_unauthorized;

        loop {
            debug_log(
                "api",
                "Calling Docmost API",
                Some(&serde_json::json!({
                    "endpoint": endpoint,
                    "baseUrl": session.base_url,
                    "retryOnUnauthorized": retry_on_unauthorized
                })),
            );

            let response = self
                .http
                .post(format!("{}{}", session.base_url, endpoint))
                .bearer_auth(&session.token)
                .json(&payload)
                .send()
                .await
                .with_context(|| format!("Failed to call {endpoint}"))?;

            debug_log(
                "api",
                "Docmost API response received",
                Some(&serde_json::json!({
                    "endpoint": endpoint,
                    "status": response.status().as_u16(),
                    "ok": response.status().is_success()
                })),
            );

            if response.status() == reqwest::StatusCode::UNAUTHORIZED && retry_on_unauthorized {
                debug_log(
                    "api",
                    "Received 401 from Docmost API; retrying after reauthentication",
                    Some(&serde_json::json!({ "endpoint": endpoint })),
                );
                session = self.auth_manager.reauthenticate().await?;
                retry_on_unauthorized = false;
                continue;
            }

            return Ok(response);
        }
    }

    /// POST a multipart form with bearer auth and a single 401-retry, returning the raw
    /// response. A multipart `Form` cannot be cloned, so `build_form` is called again for
    /// each attempt.
    async fn send_multipart<F>(&self, endpoint: &str, build_form: F) -> Result<Response>
    where
        F: Fn() -> Result<reqwest::multipart::Form>,
    {
        let mut session = self.auth_manager.get_authenticated_session().await?;
        let mut retry_on_unauthorized = true;

        loop {
            debug_log(
                "api",
                "Calling Docmost API (multipart)",
                Some(&serde_json::json!({
                    "endpoint": endpoint,
                    "baseUrl": session.base_url,
                    "retryOnUnauthorized": retry_on_unauthorized
                })),
            );

            let response = self
                .http
                .post(format!("{}{}", session.base_url, endpoint))
                .bearer_auth(&session.token)
                .multipart(build_form()?)
                .send()
                .await
                .with_context(|| format!("Failed to call {endpoint}"))?;

            if response.status() == reqwest::StatusCode::UNAUTHORIZED && retry_on_unauthorized {
                session = self.auth_manager.reauthenticate().await?;
                retry_on_unauthorized = false;
                continue;
            }

            return Ok(response);
        }
    }

    /// POST and deserialize the `{ data }` envelope, erroring if no data is returned.
    async fn request<T>(&self, endpoint: &str, payload: Value, retry: bool) -> Result<T>
    where
        T: DeserializeOwned,
    {
        parse_response(self.send_json(endpoint, payload, retry).await?).await
    }

    /// POST a write that returns no meaningful body (e.g. move-to-space); succeeds on 2xx.
    async fn request_discard(&self, endpoint: &str, payload: Value) -> Result<()> {
        let response = self.send_json(endpoint, payload, true).await?;
        if !response.status().is_success() {
            let status = response.status();
            let details = safe_read_response_text(response).await;
            return Err(anyhow!(
                format!("Docmost API request failed ({status}). {details}")
                    .trim()
                    .to_string()
            ));
        }
        Ok(())
    }
}

pub fn normalize_list_result<T>(result: Option<ListResult<T>>) -> Vec<T> {
    match result {
        Some(ListResult::List(items)) => items,
        Some(ListResult::Wrapped { items }) => items.unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Fold a cursor list response into a [`Page`], accepting either envelope shape.
///
/// Nested `meta` wins when present; the flat fields are the fallback. `has_more`
/// is only inferred when the server actually said something — an explicit
/// `hasNextPage`, or a `nextCursor` (whose presence implies more). It is never
/// guessed from `items.len() == limit`, which is a classic off-by-one source when
/// the last page happens to be exactly full.
pub fn into_page<T>(result: CursorListResult<T>) -> Page<T> {
    let meta = result.meta.unwrap_or_default();
    let next_cursor = meta.next_cursor.or(result.next_cursor);
    let has_more = meta
        .has_next_page
        .or(result.has_next_page)
        .or_else(|| next_cursor.as_ref().map(|_| true));

    Page {
        items: result.items.unwrap_or_default(),
        next_cursor,
        total: meta.total.or(result.total),
        has_more,
    }
}

async fn parse_response<T>(response: Response) -> Result<T>
where
    T: DeserializeOwned,
{
    if !response.status().is_success() {
        let status = response.status();
        let details = safe_read_response_text(response).await;
        return Err(anyhow!(
            format!("Docmost API request failed ({status}). {details}")
                .trim()
                .to_string()
        ));
    }

    let json = response
        .json::<ApiEnvelope<T>>()
        .await
        .context("Failed to parse Docmost API response body")?;
    json.data
        .ok_or_else(|| anyhow!("Docmost API response was missing a data payload"))
}
