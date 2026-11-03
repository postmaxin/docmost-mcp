use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
};

use anyhow::Result;
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header::SET_COOKIE},
    routing::post,
};
use docmost_mcp::{
    docmost_client::DocmostClient,
    prosemirror::markdown_to_prosemirror,
    staged_upload::{UploadStager, routes as staged_upload_routes},
    startup_config::normalize_base_url,
    storage::state_store::StateStore,
    types::{AuthenticatedSession, StartupConfig, StoredConfig, StoredCredentials, StoredSession},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct CapturedState {
    json_bodies: Arc<Mutex<Vec<(String, Value)>>>,
    /// (route, raw multipart body as UTF-8) for the import endpoint.
    multipart_bodies: Arc<Mutex<Vec<(String, String)>>>,
    /// When true, the first hit of each write route returns 401 once (retry testing).
    fail_first_401: Arc<AtomicBool>,
    /// When non-zero, the next write route returns this HTTP status once (error testing).
    force_status: Arc<AtomicU16>,
    create_attempts: Arc<AtomicUsize>,
    update_attempts: Arc<AtomicUsize>,
    import_attempts: Arc<AtomicUsize>,
    upload_attempts: Arc<AtomicUsize>,
    /// Raw multipart bodies sent to the attachment upload endpoint (may be binary).
    upload_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    /// The `Authorization` header of each upload, to show which session sent it.
    upload_auth: Arc<Mutex<Vec<String>>>,
    /// When true, the upload route wraps its reply in a `{ data }` envelope.
    envelope_upload: Arc<AtomicBool>,
    /// When true, the upload route hangs instead of answering, like a stuck Docmost.
    stall_upload: Arc<AtomicBool>,
    /// When true, the upload route stores the file but replies with something that isn't
    /// an attachment, like a proxy page or a truncated response.
    garble_upload: Arc<AtomicBool>,
    /// How many times the mock `/api/auth/login` endpoint was called.
    login_hits: Arc<AtomicUsize>,
}

/// Returns an injected failure status for this attempt, if one is configured. Consumes a
/// single forced status (once) and, when armed, fails the first attempt of a route with 401.
fn injected_status(state: &CapturedState, attempts: &Arc<AtomicUsize>) -> Option<StatusCode> {
    let forced = state.force_status.swap(0, Ordering::SeqCst);
    if forced != 0 {
        return Some(StatusCode::from_u16(forced).expect("valid status"));
    }
    if state.fail_first_401.load(Ordering::SeqCst) && attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        return Some(StatusCode::UNAUTHORIZED);
    }
    None
}

/// Spin up a mock Docmost that records request bodies and returns a page envelope.
/// The auth manager is pre-seeded with a far-future session so no login occurs, plus
/// saved credentials so a forced 401 can be recovered via the mock login endpoint.
async fn spawn(temp: &TempDir) -> Result<(DocmostClient, CapturedState, String)> {
    unsafe {
        std::env::set_var("DOCMOST_DISABLE_KEYRING", "1");
    }

    let state = CapturedState::default();
    let app = Router::new()
        .route("/api/pages/create", post(create_route))
        .route("/api/pages/update", post(update_route))
        .route("/api/pages/import", post(import_route))
        .route("/api/files/upload", post(upload_route))
        .route("/api/pages/info", post(page_info_route))
        .route("/api/auth/login", post(login_route))
        .with_state(state.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base_url = normalize_base_url(&format!("http://{address}"));

    // Pre-seed a valid (non-expiring) session so the client skips interactive auth.
    let store = StateStore::new(Some(temp.path().to_path_buf()))?;
    store
        .write_config(&StoredConfig {
            base_url: base_url.clone(),
            email: "jane@example.com".to_string(),
            last_authenticated_at: "2026-03-12T00:00:00.000Z".to_string(),
        })
        .await?;
    store
        .write_session(&StoredSession {
            // No expiry => never treated as expiring.
            token: "seed-token".to_string(),
            expires_at: None,
            saved_at: "2026-03-12T00:00:00.000Z".to_string(),
        })
        .await?;
    // Saved credentials let reauthenticate() recover a 401 headlessly via the mock login.
    store
        .write_credentials(&StoredCredentials {
            email: "jane@example.com".to_string(),
            password: "secret".to_string(),
        })
        .await?;

    let auth_manager = docmost_mcp::auth::manager::AuthManager::new(
        StartupConfig {
            base_url: Some(base_url.clone()),
            interactive_auth: false,
        },
        Some(temp.path().to_path_buf()),
    )?;
    // Sanity: the seeded session resolves without hitting the network.
    let session: AuthenticatedSession = auth_manager.get_authenticated_session().await?;
    assert_eq!(session.token, "seed-token");

    Ok((DocmostClient::new(auth_manager), state, base_url))
}

async fn create_route(
    State(state): State<CapturedState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(status) = injected_status(&state, &state.create_attempts) {
        return (status, Json(json!({ "message": "injected failure" })));
    }
    state
        .json_bodies
        .lock()
        .unwrap()
        .push(("create".to_string(), body));
    (
        StatusCode::OK,
        Json(json!({
            "data": { "id": "page-1", "slugId": "slug-1", "title": "Created", "spaceId": "space-1" },
            "success": true,
            "status": 200
        })),
    )
}

async fn update_route(
    State(state): State<CapturedState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(status) = injected_status(&state, &state.update_attempts) {
        return (status, Json(json!({ "message": "injected failure" })));
    }
    state
        .json_bodies
        .lock()
        .unwrap()
        .push(("update".to_string(), body));
    (
        StatusCode::OK,
        Json(json!({
            "data": { "id": "page-1", "slugId": "slug-1", "title": "Updated" },
            "success": true,
            "status": 200
        })),
    )
}

/// Captures the raw multipart body so tests can assert the spaceId field and the
/// uploaded markdown file content.
async fn import_route(
    State(state): State<CapturedState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    if let Some(status) = injected_status(&state, &state.import_attempts) {
        return (status, Json(json!({ "message": "injected failure" })));
    }
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("multipart/form-data"),
        "import must be multipart, got: {content_type}"
    );
    let raw = String::from_utf8_lossy(&body).to_string();
    state
        .multipart_bodies
        .lock()
        .unwrap()
        .push(("import".to_string(), raw));
    (
        StatusCode::OK,
        Json(json!({
            "data": { "id": "imported-1", "slugId": "islug-1", "title": "Imported", "spaceId": "space-1" },
            "success": true,
            "status": 200
        })),
    )
}

/// Mock attachment upload. Like Docmost 0.96, it replies with the bare attachment (no
/// `{ data }` envelope) unless `envelope_upload` is set.
async fn upload_route(
    State(state): State<CapturedState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    if let Some(status) = injected_status(&state, &state.upload_attempts) {
        return (status, Json(json!({ "message": "injected failure" })));
    }
    if state.stall_upload.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("multipart/form-data"),
        "upload must be multipart, got: {content_type}"
    );
    state.upload_bodies.lock().unwrap().push(body.to_vec());
    state.upload_auth.lock().unwrap().push(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string(),
    );
    let attachment = json!({
        "id": "0199aaaa-0000-7000-8000-000000000001",
        "fileName": "diagram.png",
        "fileSize": 6,
        "fileExt": ".png",
        "mimeType": "image/png",
        "type": "file",
        "pageId": "page-1",
        "spaceId": "space-1",
        "url": "http://docs.example.com/api/files/0199aaaa-0000-7000-8000-000000000001/diagram.png"
    });
    if state.garble_upload.load(Ordering::SeqCst) {
        return (StatusCode::OK, Json(json!({ "unexpected": true })));
    }
    if state.envelope_upload.load(Ordering::SeqCst) {
        return (
            StatusCode::OK,
            Json(json!({ "data": attachment, "success": true, "status": 200 })),
        );
    }
    (StatusCode::OK, Json(attachment))
}

/// Mock page lookup used to resolve a slug ID to the page UUID.
async fn page_info_route(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if body["pageId"] == json!("slug-1") {
        return (
            StatusCode::OK,
            Json(json!({ "data": { "id": PAGE_UUID, "slugId": "slug-1" }, "success": true })),
        );
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "message": "Page not found" })),
    )
}

const PAGE_UUID: &str = "0199bbbb-0000-7000-8000-000000000002";

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Mock Docmost login: returns the auth token via a Set-Cookie header, matching the real
/// server contract the auth manager parses.
async fn login_route(
    State(state): State<CapturedState>,
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    Json<Value>,
) {
    state.login_hits.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        [(SET_COOKIE, "authToken=reauth-token-123; Path=/; HttpOnly")],
        Json(json!({ "data": { "userId": "user-1" }, "success": true })),
    )
}

fn last_json(state: &CapturedState, route: &str) -> Value {
    state
        .json_bodies
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(name, _)| name == route)
        .map(|(_, body)| body.clone())
        .unwrap_or_else(|| panic!("no recorded {route} JSON request"))
}

fn last_multipart(state: &CapturedState, route: &str) -> String {
    state
        .multipart_bodies
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(name, _)| name == route)
        .map(|(_, body)| body.clone())
        .unwrap_or_else(|| panic!("no recorded {route} multipart request"))
}

#[tokio::test]
async fn create_page_with_body_uses_import_with_markdown_file() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    let page = client
        .create_page("space-1", "My Page", Some("Hello **world**"), None)
        .await?;
    // Response comes from the import endpoint.
    assert_eq!(page.id.as_deref(), Some("imported-1"));
    assert_eq!(page.slug_id.as_deref(), Some("islug-1"));

    let raw = last_multipart(&state, "import");
    // spaceId text field is present.
    assert!(
        raw.contains("name=\"spaceId\"") && raw.contains("space-1"),
        "missing spaceId field in:\n{raw}"
    );
    // A .md file part is uploaded.
    assert!(
        raw.contains("name=\"file\"") && raw.contains("filename=\"page.md\""),
        "missing .md file part in:\n{raw}"
    );
    // The title is prepended as a level-1 heading so the importer uses it as the title.
    assert!(
        raw.contains("# My Page"),
        "title heading missing in:\n{raw}"
    );
    // The body markdown is included verbatim (not pre-converted to ProseMirror JSON).
    assert!(raw.contains("Hello **world**"), "body missing in:\n{raw}");
    assert!(
        !raw.contains("\"type\":\"doc\""),
        "body must be raw markdown, not ProseMirror JSON, in:\n{raw}"
    );
    Ok(())
}

#[tokio::test]
async fn create_page_title_only_uses_create_endpoint() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    // No body -> plain create endpoint, parent honored.
    client
        .create_page("space-1", "Title only", None, Some("parent-1"))
        .await?;

    let body = last_json(&state, "create");
    assert_eq!(body["spaceId"], json!("space-1"));
    assert_eq!(body["title"], json!("Title only"));
    assert_eq!(body["parentPageId"], json!("parent-1"));
    assert!(
        body.get("content").is_none(),
        "title-only create must not send content"
    );
    // And it must NOT have hit the import endpoint.
    assert!(
        state
            .multipart_bodies
            .lock()
            .unwrap()
            .iter()
            .all(|(name, _)| name != "import"),
        "title-only create should not use import"
    );
    Ok(())
}

#[tokio::test]
async fn create_page_title_only_without_parent_omits_parent_field() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    client
        .create_page("space-1", "Root Page", None, None)
        .await?;

    let body = last_json(&state, "create");
    assert_eq!(body["spaceId"], json!("space-1"));
    assert_eq!(body["title"], json!("Root Page"));
    assert!(
        body.get("parentPageId").is_none(),
        "no parent supplied => parentPageId must be omitted, got: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn create_page_blank_markdown_falls_back_to_title_only() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    // Whitespace-only markdown is treated as "no body".
    client
        .create_page("space-1", "Blanky", Some("   \n  "), None)
        .await?;

    let body = last_json(&state, "create");
    assert_eq!(body["title"], json!("Blanky"));
    assert!(
        state.multipart_bodies.lock().unwrap().is_empty(),
        "blank markdown should not trigger import"
    );
    Ok(())
}

#[tokio::test]
async fn create_page_with_body_ignores_parent_page_id() -> Result<()> {
    // Characterization test for a documented limitation: the import endpoint has no
    // parent parameter, so a body-bearing create silently lands at the space root and
    // `parent_page_id` is dropped. If this ever changes, update the tool docs/response.
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    client
        .create_page(
            "space-1",
            "Child?",
            Some("body text"),
            Some("parent-should-be-ignored"),
        )
        .await?;

    // It went through import (not create), and the parent id is nowhere in the request.
    let raw = last_multipart(&state, "import");
    assert!(
        !raw.contains("parent-should-be-ignored"),
        "parent id must not leak into the import request:\n{raw}"
    );
    assert!(
        state.json_bodies.lock().unwrap().is_empty(),
        "body create must not hit the plain create endpoint"
    );
    Ok(())
}

#[tokio::test]
async fn import_prepends_title_and_preserves_multiline_body() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    let body = "## Section\n\nLine one.\n\n- a\n- b";
    client
        .create_page("space-1", "Doc Title", Some(body), None)
        .await?;

    let raw = last_multipart(&state, "import");
    // Title prepended as an H1 ahead of the original body, which is preserved verbatim.
    let file_start = raw
        .find("# Doc Title")
        .expect("prepended title heading present");
    for needle in ["## Section", "Line one.", "- a", "- b"] {
        let at = raw
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle} in:\n{raw}"));
        assert!(
            at > file_start,
            "body must follow the title heading: {needle}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn create_page_retries_import_on_unauthorized() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.fail_first_401.store(true, Ordering::SeqCst);

    // First import attempt returns 401 -> reauth via login -> second attempt succeeds.
    let page = client
        .create_page("space-1", "Retry Import", Some("body"), None)
        .await?;

    assert_eq!(page.id.as_deref(), Some("imported-1"));
    assert_eq!(
        state.login_hits.load(Ordering::SeqCst),
        1,
        "should have reauthenticated exactly once"
    );
    assert_eq!(
        state.import_attempts.load(Ordering::SeqCst),
        2,
        "import should be attempted twice (401 then success)"
    );
    // Exactly one successful import body was recorded (the retry).
    assert_eq!(state.multipart_bodies.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn update_page_retries_on_unauthorized() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.fail_first_401.store(true, Ordering::SeqCst);

    let page = client.update_page("page-1", Some("Renamed"), None).await?;

    assert_eq!(page.id.as_deref(), Some("page-1"));
    assert_eq!(state.login_hits.load(Ordering::SeqCst), 1);
    let body = last_json(&state, "update");
    assert_eq!(body["title"], json!("Renamed"));
    Ok(())
}

#[tokio::test]
async fn create_page_surfaces_server_error_without_panicking() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    // Simulate a permission failure on the plain create endpoint.
    state.force_status.store(403, Ordering::SeqCst);

    let error = client
        .create_page("space-1", "Forbidden", None, None)
        .await
        .expect_err("403 must surface as an error");
    assert!(
        error.to_string().contains("403"),
        "error should mention the status: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn import_surfaces_server_error_without_panicking() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.force_status.store(403, Ordering::SeqCst);

    let error = client
        .create_page("space-1", "Forbidden", Some("body"), None)
        .await
        .expect_err("403 on import must surface as an error");
    assert!(
        error.to_string().contains("403"),
        "error should mention the status: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn update_page_sends_operation_and_format_with_content() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    let content = markdown_to_prosemirror("new body");
    client
        .update_page("page-1", Some("New Title"), Some(&content))
        .await?;

    let body = last_json(&state, "update");
    assert_eq!(body["pageId"], json!("page-1"));
    assert_eq!(body["title"], json!("New Title"));
    assert!(body["content"].is_object());
    // The critical, easy-to-forget bit: Docmost ignores content unless BOTH
    // operation and format accompany it.
    assert_eq!(body["operation"], json!("replace"));
    assert_eq!(body["format"], json!("json"));
    Ok(())
}

#[tokio::test]
async fn update_page_title_only_omits_content_operation_format() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    client.update_page("page-1", Some("Renamed"), None).await?;

    let body = last_json(&state, "update");
    assert_eq!(body["pageId"], json!("page-1"));
    assert_eq!(body["title"], json!("Renamed"));
    assert!(body.get("content").is_none());
    assert!(body.get("operation").is_none());
    assert!(body.get("format").is_none());
    Ok(())
}

#[tokio::test]
async fn update_page_with_no_changes_sends_only_page_id() -> Result<()> {
    // Neither a title nor a body: the payload carries just the page id.
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    client.update_page("page-9", None, None).await?;

    let body = last_json(&state, "update");
    assert_eq!(body["pageId"], json!("page-9"));
    assert!(body.get("title").is_none());
    assert!(body.get("content").is_none());
    Ok(())
}

/// Bytes that are not valid UTF-8, so the test proves the file travels as raw binary.
const PNG_ISH: &[u8] = &[0x89, b'P', b'N', b'G', 0x00, 0xff];

#[tokio::test]
async fn upload_attachment_sends_page_id_then_binary_file_part() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    let attachment = client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await?;
    assert_eq!(attachment.id, "0199aaaa-0000-7000-8000-000000000001");
    assert_eq!(attachment.file_name.as_deref(), Some("diagram.png"));
    assert_eq!(attachment.file_size, Some(6));
    assert_eq!(attachment.mime_type.as_deref(), Some("image/png"));
    assert!(
        attachment
            .url
            .as_deref()
            .is_some_and(|u| u.ends_with("/diagram.png"))
    );
    // Unmodelled fields are kept rather than dropped.
    assert_eq!(attachment.extra.get("type"), Some(&json!("file")));

    let raw = state.upload_bodies.lock().unwrap().last().cloned().unwrap();
    let page_field = find_bytes(&raw, b"name=\"pageId\"").expect("pageId field");
    let file_part = find_bytes(&raw, b"name=\"file\"; filename=\"diagram.png\"")
        .expect("file part with filename");
    // Docmost only sees fields that precede the file part.
    assert!(
        page_field < file_part,
        "pageId must come before the file part"
    );
    assert!(find_bytes(&raw, PAGE_UUID.as_bytes()).is_some_and(|at| at < file_part));
    assert!(
        find_bytes(&raw, b"content-type: image/png").is_some()
            || find_bytes(&raw, b"Content-Type: image/png").is_some()
    );
    assert!(find_bytes(&raw, PNG_ISH).is_some_and(|at| at > file_part));
    Ok(())
}

#[tokio::test]
async fn upload_attachment_accepts_enveloped_response() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.envelope_upload.store(true, Ordering::SeqCst);

    let attachment = client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await?;
    assert_eq!(attachment.id, "0199aaaa-0000-7000-8000-000000000001");
    Ok(())
}

#[tokio::test]
async fn upload_attachment_retries_on_unauthorized() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.fail_first_401.store(true, Ordering::SeqCst);

    client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await?;
    assert_eq!(state.login_hits.load(Ordering::SeqCst), 1);
    assert_eq!(state.upload_attempts.load(Ordering::SeqCst), 2);
    // The rebuilt form on the retry still carries the whole file.
    let raw = state.upload_bodies.lock().unwrap().last().cloned().unwrap();
    assert!(find_bytes(&raw, PNG_ISH).is_some());
    Ok(())
}

#[tokio::test]
async fn upload_attachment_surfaces_server_error() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.force_status.store(403, Ordering::SeqCst);

    let error = client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await
        .expect_err("403 must surface as an error");
    assert!(error.to_string().contains("403"), "{error}");
    assert!(
        !docmost_mcp::docmost_client::is_outcome_unknown(&error),
        "an error status is a confirmed rejection"
    );
    assert!(state.upload_bodies.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn upload_attachment_marks_a_gateway_error_as_uncertain() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    for status in [502, 504, 500] {
        state.force_status.store(status, Ordering::SeqCst);
        let error = client
            .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
            .await
            .expect_err("a 5xx must surface as an error");
        assert!(
            docmost_mcp::docmost_client::is_outcome_unknown(&error),
            "{status}: a proxy can answer this after Docmost stored the file: {error}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn upload_attachment_marks_an_unreadable_success_as_uncertain() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    state.garble_upload.store(true, Ordering::SeqCst);

    let error = client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await
        .expect_err("a reply that isn't an attachment must be an error");
    assert!(
        docmost_mcp::docmost_client::is_outcome_unknown(&error),
        "{error}"
    );
    assert!(
        error.to_string().contains("may already have stored"),
        "{error}"
    );
    assert_eq!(state.upload_bodies.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn upload_attachment_resolves_a_slug_to_the_page_uuid() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;

    client
        .upload_attachment("slug-1", "diagram.png", "image/png", PNG_ISH)
        .await?;
    let raw = state.upload_bodies.lock().unwrap().last().cloned().unwrap();
    assert!(find_bytes(&raw, PAGE_UUID.as_bytes()).is_some());
    assert!(
        find_bytes(&raw, b"slug-1").is_none(),
        "the slug must not be sent"
    );

    let error = client
        .upload_attachment("no-such-slug", "diagram.png", "image/png", PNG_ISH)
        .await
        .expect_err("unknown page must fail before uploading");
    assert!(error.to_string().contains("404"), "{error}");
    assert_eq!(state.upload_bodies.lock().unwrap().len(), 1);
    Ok(())
}

// ---- staged uploads (docmost_begin_upload + PUT /uploads/{token}) -----------

const MCP_PUBLIC_URL: &str = "http://mcp.example";

/// The upload route audits every write. Point the log at one file for the whole test
/// binary, since tests run in parallel and the variable is process-wide. The file sits in
/// its own temporary directory, because the audit logger sets the log's parent to 0700:
/// putting it straight in the system temp directory would try to chmod `/tmp` itself.
fn use_test_audit_log() {
    static AUDIT_DIR: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    let dir = AUDIT_DIR.get_or_init(|| TempDir::new().expect("audit temp dir"));
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        std::env::set_var("DOCMOST_MCP_AUDIT_LOG", dir.path().join("mutations.jsonl"));
    });
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

async fn put_to(app: &Router, url: &str, body: Vec<u8>) -> Result<(StatusCode, Value)> {
    let path = url
        .strip_prefix(MCP_PUBLIC_URL)
        .expect("URL under the public base");
    let response = app
        .clone()
        .oneshot(Request::put(path).body(Body::from(body))?)
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
async fn staged_upload_sends_the_raw_bytes_once() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::new(&format!("{MCP_PUBLIC_URL}/"), 1024);

    let begun = stager
        .begin(
            client,
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
        .await?;
    assert!(
        begun.url.starts_with(&format!("{MCP_PUBLIC_URL}/uploads/")),
        "{}",
        begun.url
    );
    assert_eq!(stager.pending_count().await, 1);

    let app = staged_upload_routes(stager.clone());
    let (status, body) = put_to(&app, &begun.url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uploaded"], json!(true));
    assert_eq!(
        body["path"],
        json!("/api/files/0199aaaa-0000-7000-8000-000000000001/diagram.png")
    );
    assert_eq!(
        body["markdown"],
        json!("![diagram.png](/api/files/0199aaaa-0000-7000-8000-000000000001/diagram.png)")
    );

    // The exact bytes reached Docmost's upload endpoint, after the pageId field.
    let raw = state.upload_bodies.lock().unwrap().last().cloned().unwrap();
    let file_part = find_bytes(&raw, b"name=\"file\"; filename=\"diagram.png\"").unwrap();
    assert!(find_bytes(&raw, PAGE_UUID.as_bytes()).is_some_and(|at| at < file_part));
    assert!(find_bytes(&raw, PNG_ISH).is_some_and(|at| at > file_part));

    // Single use: the same URL is now gone, and nothing else reached Docmost.
    let (status, _) = put_to(&app, &begun.url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(state.upload_bodies.lock().unwrap().len(), 1);
    assert_eq!(stager.pending_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn staged_upload_refuses_mismatched_bodies_before_reaching_docmost() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::new(MCP_PUBLIC_URL, 1024);
    let app = staged_upload_routes(stager.clone());
    let begin = || {
        stager.begin(
            client.clone(),
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
    };

    // Same length, one byte changed: only the hash can catch it.
    let mut altered = PNG_ISH.to_vec();
    altered[1] ^= 0x01;
    let url = begin().await?.url;
    let (status, body) = put_to(&app, &url, altered).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("SHA-256"),
        "{body}"
    );
    // A rejected attempt uses the URL up, even for the right file afterwards.
    let (status, _) = put_to(&app, &url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let url = begin().await?.url;
    let (status, body) = put_to(&app, &url, PNG_ISH[..4].to_vec()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("declared"),
        "{body}"
    );

    let url = begin().await?.url;
    let mut longer = PNG_ISH.to_vec();
    longer.extend_from_slice(b"extra");
    let (status, _) = put_to(&app, &url, longer).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (status, _) = put_to(
        &app,
        &format!("{MCP_PUBLIC_URL}/uploads/not-a-real-token"),
        PNG_ISH.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert!(
        state.upload_bodies.lock().unwrap().is_empty(),
        "no rejected body may reach Docmost"
    );
    assert_eq!(stager.pending_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn staged_upload_url_expires() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::with_ttl(MCP_PUBLIC_URL, 1024, std::time::Duration::from_millis(20));
    let url = stager
        .begin(
            client,
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
        .await?
        .url;
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    let (status, _) = put_to(
        &staged_upload_routes(stager.clone()),
        &url,
        PNG_ISH.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(stager.pending_count().await, 0);
    assert!(state.upload_bodies.lock().unwrap().is_empty());
    Ok(())
}

/// A body that sends two bytes and then never finishes, like a stalled `curl`.
fn stalled_body() -> Body {
    use futures::StreamExt;
    let start = futures::stream::once(async {
        Ok::<Bytes, std::io::Error>(Bytes::from_static(&PNG_ISH[..2]))
    });
    Body::from_stream(start.chain(futures::stream::pending()))
}

#[tokio::test]
async fn staged_upload_gives_up_on_a_body_that_stalls() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager =
        UploadStager::new(MCP_PUBLIC_URL, 1024).with_deadline(std::time::Duration::from_millis(50));
    let url = stager
        .begin(
            client,
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
        .await?
        .url;
    let app = staged_upload_routes(stager.clone());
    let path = url.strip_prefix(MCP_PUBLIC_URL).unwrap().to_string();

    let response = app
        .clone()
        .oneshot(Request::put(path.as_str()).body(stalled_body())?)
        .await?;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(state.upload_bodies.lock().unwrap().is_empty());
    // A timed-out attempt uses the URL up, like any other refused one.
    let (status, _) = put_to(&app, &url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn staged_upload_refuses_when_busy_without_using_the_url_up() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::new(MCP_PUBLIC_URL, 1024)
        .with_max_in_flight(1)
        .with_deadline(std::time::Duration::from_millis(300));
    let begin = || {
        stager.begin(
            client.clone(),
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
    };
    let stalled_url = begin().await?.url;
    let waiting_url = begin().await?.url;
    let app = staged_upload_routes(stager.clone());

    // Occupy the only slot with a body that never finishes.
    let stalled_path = stalled_url
        .strip_prefix(MCP_PUBLIC_URL)
        .unwrap()
        .to_string();
    let holder = tokio::spawn({
        let app = app.clone();
        async move {
            app.oneshot(
                Request::put(stalled_path.as_str())
                    .body(stalled_body())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, body) = put_to(&app, &waiting_url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");

    // Once the stalled upload times out and frees its slot, the same URL still works.
    assert_eq!(holder.await?, StatusCode::REQUEST_TIMEOUT);
    let (status, body) = put_to(&app, &waiting_url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state.upload_bodies.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn pinned_client_keeps_the_session_it_was_approved_with() -> Result<()> {
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let pinned = client.pinned().await?;

    // The server's saved session changes to another account before the upload arrives.
    StateStore::new(Some(temp.path().to_path_buf()))?
        .write_session(&StoredSession {
            token: "switched-token".to_string(),
            expires_at: None,
            saved_at: "2026-03-12T00:00:00.000Z".to_string(),
        })
        .await?;

    pinned
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await?;
    client
        .upload_attachment(PAGE_UUID, "diagram.png", "image/png", PNG_ISH)
        .await?;
    let auth = state.upload_auth.lock().unwrap().clone();
    assert_eq!(
        auth[0], "Bearer seed-token",
        "the pinned client must not switch accounts"
    );
    // The unpinned client does follow the saved session, which is what pinning guards against.
    assert_eq!(auth[1], "Bearer switched-token");
    Ok(())
}

#[tokio::test]
async fn staged_upload_frees_its_slot_when_docmost_hangs() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::new(MCP_PUBLIC_URL, 1024)
        .with_max_in_flight(1)
        .with_deadline(std::time::Duration::from_millis(300));
    let begin = || {
        stager.begin(
            client.clone(),
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
    };
    let stuck_url = begin().await?.url;
    let next_url = begin().await?.url;
    let app = staged_upload_routes(stager.clone());

    // The body arrives intact, but Docmost never answers.
    state.stall_upload.store(true, Ordering::SeqCst);
    let (status, body) = put_to(&app, &stuck_url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(
        body["uploaded"],
        Value::Null,
        "the outcome is unknown, not a failure"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("may already have stored"),
        "{body}"
    );
    let audit = std::fs::read_to_string(std::env::var("DOCMOST_MCP_AUDIT_LOG")?)?;
    assert!(
        audit.contains("\"timed_out\""),
        "the timeout must be audited"
    );

    // The deadline freed the only slot, so the next upload goes through.
    state.stall_upload.store(false, Ordering::SeqCst);
    let (status, body) = put_to(&app, &next_url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test]
async fn staged_upload_reports_an_unreadable_success_as_uncertain() -> Result<()> {
    use_test_audit_log();
    let temp = TempDir::new()?;
    let (client, state, _) = spawn(&temp).await?;
    let stager = UploadStager::new(MCP_PUBLIC_URL, 1024);
    let url = stager
        .begin(
            client.clone(),
            PAGE_UUID,
            "diagram.png",
            "image/png",
            PNG_ISH.len(),
            sha256_of(PNG_ISH),
        )
        .await?
        .url;
    let app = staged_upload_routes(stager.clone());

    state.garble_upload.store(true, Ordering::SeqCst);
    let (status, body) = put_to(&app, &url, PNG_ISH.to_vec()).await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(
        body["uploaded"],
        Value::Null,
        "Docmost may have it, so not a failure"
    );
    assert!(
        body["error"].as_str().unwrap().contains("check the page"),
        "{body}"
    );
    let audit = std::fs::read_to_string(std::env::var("DOCMOST_MCP_AUDIT_LOG")?)?;
    assert!(
        audit.contains("\"uncertain\""),
        "the outcome must be audited as uncertain"
    );
    Ok(())
}
