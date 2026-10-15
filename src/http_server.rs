use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use futures::{FutureExt, StreamExt, stream};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower::ServiceExt;

use crate::{
    auth::manager::SessionRejectedHook,
    oauth::{DEFAULT_BRAND, OAuthConfig, OAuthState},
    server::DocmostMcpServer,
    types::{AuthenticatedSession, StartupConfig},
};

const MIN_BEARER_TOKEN_BYTES: usize = 32;
/// SSE frames a response may open with before its first JSON-RPC message (the
/// rmcp priming event). Anything else ends the hold and the stream flows on.
const MAX_HELD_FRAMES: usize = 4;

fn validate_bearer_token(token: &str) -> Result<()> {
    if token.len() < MIN_BEARER_TOKEN_BYTES {
        bail!(
            "DOCMOST_MCP_BEARER_TOKEN must be at least {MIN_BEARER_TOKEN_BYTES} bytes; generate one with `openssl rand -hex 32`"
        );
    }

    let normalized = token.trim().to_ascii_lowercase();
    if normalized.contains("replace-with")
        || normalized.contains("change-me")
        || normalized.contains("changeme")
    {
        bail!(
            "DOCMOST_MCP_BEARER_TOKEN still contains an example value; generate one with `openssl rand -hex 32`"
        );
    }

    Ok(())
}

type McpService = StreamableHttpService<DocmostMcpServer, LocalSessionManager>;

#[derive(Clone)]
struct AppState {
    admin_token: Option<Arc<[u8]>>,
    admin_service: McpService,
    user_services: Arc<RwLock<HashMap<String, McpService>>>,
    mcp_config: StreamableHttpServerConfig,
    oauth: Option<OAuthState>,
}

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub bind: SocketAddr,
    pub bearer_token: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub oauth: Option<OAuthConfig>,
}

impl HttpServerConfig {
    pub fn from_env_and_bind(bind: &str) -> Result<Self> {
        let bind: SocketAddr = bind
            .parse()
            .with_context(|| format!("DOCMOST_MCP_BIND is not a valid socket address: {bind}"))?;
        let bearer_token = env::var("DOCMOST_MCP_BEARER_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty());
        if let Some(token) = &bearer_token {
            validate_bearer_token(token)?;
        }

        let default_hosts = match bind.ip() {
            address if address.is_loopback() => vec![
                format!("localhost:{}", bind.port()),
                format!("127.0.0.1:{}", bind.port()),
                format!("[::1]:{}", bind.port()),
            ],
            address => vec![format!("{address}:{}", bind.port())],
        };
        let allowed_hosts =
            comma_separated_env("DOCMOST_MCP_ALLOWED_HOSTS").unwrap_or(default_hosts);
        let allowed_origins =
            comma_separated_env("DOCMOST_MCP_ALLOWED_ORIGINS").unwrap_or_else(|| {
                vec![
                    format!("http://localhost:{}", bind.port()),
                    format!("http://127.0.0.1:{}", bind.port()),
                ]
            });

        if allowed_hosts.is_empty() {
            bail!("DOCMOST_MCP_ALLOWED_HOSTS must contain at least one host");
        }
        if allowed_origins.is_empty() {
            bail!("DOCMOST_MCP_ALLOWED_ORIGINS must contain at least one origin");
        }

        let account_auth_enabled = matches!(
            env::var("DOCMOST_MCP_ACCOUNT_AUTH").ok().as_deref(),
            Some("1") | Some("true")
        );
        let oauth = if account_auth_enabled {
            Some(OAuthConfig {
                public_url: env::var("DOCMOST_MCP_PUBLIC_URL")
                    .context("DOCMOST_MCP_PUBLIC_URL is required for account authentication")?,
                docmost_base_url: env::var("DOCMOST_BASE_URL")
                    .context("DOCMOST_BASE_URL is required for account authentication")?,
                browser_url: env::var("DOCMOST_MCP_BROWSER_URL").ok(),
                client_id_key_path: Some(client_id_key_path()?),
                refresh_token_key_path: Some(refresh_token_key_path()?),
                brand: env::var("DOCMOST_MCP_BRAND").unwrap_or_else(|_| DEFAULT_BRAND.to_string()),
            })
        } else {
            None
        };
        if bearer_token.is_none() && oauth.is_none() {
            bail!(
                "Set DOCMOST_MCP_BEARER_TOKEN or enable per-account auth with DOCMOST_MCP_ACCOUNT_AUTH=true"
            );
        }

        Ok(Self {
            bind,
            bearer_token,
            allowed_hosts,
            allowed_origins,
            oauth,
        })
    }
}

/// `DOCMOST_MCP_CLIENT_ID_KEY_FILE`, else `~/.docmost-local-mcp/client-id.key`
/// (next to the mutation audit log).
fn client_id_key_path() -> Result<std::path::PathBuf> {
    if let Some(path) = env::var("DOCMOST_MCP_CLIENT_ID_KEY_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(path.into());
    }
    Ok(dirs::home_dir()
        .context("Unable to determine home directory for the client_id key")?
        .join(".docmost-local-mcp/client-id.key"))
}

/// `DOCMOST_MCP_REFRESH_KEY_FILE`, else
/// `~/.docmost-local-mcp/refresh-token.key` (next to the mutation audit log).
fn refresh_token_key_path() -> Result<std::path::PathBuf> {
    if let Some(path) = env::var("DOCMOST_MCP_REFRESH_KEY_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(path.into());
    }
    Ok(dirs::home_dir()
        .context("Unable to determine home directory for the refresh-token key")?
        .join(".docmost-local-mcp/refresh-token.key"))
}

fn comma_separated_env(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

pub async fn serve_http(startup_config: StartupConfig, config: HttpServerConfig) -> Result<()> {
    let bind = config.bind;
    let app = build_router(startup_config, config)?;

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("Failed to bind Docmost MCP HTTP server to {bind}"))?;
    let actual_bind = listener.local_addr().unwrap_or(bind);
    tracing::info!(%actual_bind, endpoint = %format!("http://{actual_bind}/mcp"), "Docmost MCP HTTP server listening");
    axum::serve(listener, app)
        .await
        .context("Docmost MCP HTTP server stopped unexpectedly")
}

fn build_router(startup_config: StartupConfig, config: HttpServerConfig) -> Result<Router> {
    build_app(startup_config, config).map(|(router, _)| router)
}

/// The router plus its OAuth state, which tests use to issue grants directly.
fn build_app(
    startup_config: StartupConfig,
    config: HttpServerConfig,
) -> Result<(Router, Option<OAuthState>)> {
    let mcp_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(config.allowed_origins);
    let admin_service = StreamableHttpService::new(
        move || DocmostMcpServer::new(startup_config.clone()).map_err(std::io::Error::other),
        LocalSessionManager::default().into(),
        mcp_config.clone(),
    );
    let oauth = config.oauth.map(OAuthState::new).transpose()?;
    let state = AppState {
        admin_token: config
            .bearer_token
            .map(|token| Arc::from(token.into_bytes())),
        admin_service,
        user_services: Arc::new(RwLock::new(HashMap::new())),
        mcp_config,
        oauth: oauth.clone(),
    };

    let mut router = Router::new()
        .route("/health", get(health))
        .route("/mcp", any(handle_mcp))
        .route("/mcp/", any(handle_mcp))
        .with_state(state);
    if let Some(oauth) = oauth.clone() {
        router = router.merge(oauth.routes());
    }
    Ok((router, oauth))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "docmost-mcp" }))
}

async fn handle_mcp(State(state): State<AppState>, request: Request<Body>) -> Response {
    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let admin_authenticated = supplied.is_some_and(|value| {
        state.admin_token.as_ref().is_some_and(|expected| {
            let supplied = value.as_bytes();
            supplied.len() == expected.len() && supplied.ct_eq(expected.as_ref()).into()
        })
    });
    if admin_authenticated {
        return call_mcp_service(state.admin_service, request).await;
    }

    if let (Some(oauth), Some(token)) = (&state.oauth, supplied)
        && let Some(session) = oauth.access_session(token).await
    {
        let token = token.to_string();
        let key = OAuthState::session_fingerprint(&session);
        let active_sessions = oauth.active_session_fingerprints().await;
        let service = {
            let mut services = state.user_services.write().await;
            services.retain(|fingerprint, _| active_sessions.contains(fingerprint));
            services
                .entry(key.clone())
                .or_insert_with(|| {
                    let on_rejected = session_rejected_hook(&state, oauth, key);
                    user_mcp_service(session, on_rejected, state.mcp_config.clone())
                })
                .clone()
        };
        let is_post = request.method() == Method::POST;
        let response = call_mcp_service(service, request).await;
        if !is_post {
            return response;
        }
        return unauthorized_if_grant_revoked(&state, oauth, &token, response).await;
    }

    unauthorized(&state)
}

/// When Docmost rejects a user's session, drop every grant that carries it and
/// the MCP service built on it, so the client is sent back through OAuth.
fn session_rejected_hook(
    state: &AppState,
    oauth: &OAuthState,
    fingerprint: String,
) -> SessionRejectedHook {
    let oauth = oauth.clone();
    let services = state.user_services.clone();
    Arc::new(move || {
        let oauth = oauth.clone();
        let services = services.clone();
        let fingerprint = fingerprint.clone();
        async move {
            oauth.revoke_session(&fingerprint).await;
            services.write().await.remove(&fingerprint);
            tracing::info!("Docmost rejected an account session; revoked its MCP grants");
        }
        .boxed()
    })
}

fn user_mcp_service(
    session: AuthenticatedSession,
    on_rejected: SessionRejectedHook,
    config: StreamableHttpServerConfig,
) -> McpService {
    StreamableHttpService::new(
        move || {
            DocmostMcpServer::new_with_session(session.clone(), on_rejected.clone())
                .map_err(std::io::Error::other)
        },
        LocalSessionManager::default().into(),
        config,
    )
}

/// Answer 401 for the very call that discovered a rejected Docmost session.
///
/// rmcp returns a request's status and headers before the tool runs, and the
/// result follows on the SSE stream, so a tool error arrives under a 200 and
/// the client still believes it is connected. The response is therefore held
/// back until its first JSON-RPC message: if that message is an error and the
/// grant that authorized the request was revoked meanwhile, the client gets
/// the normal 401 challenge instead and re-runs OAuth straight away.
///
/// Successful results always pass through, even if the grant was revoked
/// concurrently by another call, so a write that Docmost accepted is never
/// reported as unauthorized. Streams that open with anything other than the
/// priming event (a keep-alive during a slow call, for instance) pass through
/// too; the grant is gone either way, so the next request gets the 401.
async fn unauthorized_if_grant_revoked(
    state: &AppState,
    oauth: &OAuthState,
    token: &str,
    response: Response,
) -> Response {
    if response.status() != StatusCode::OK {
        return response;
    }
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let (parts, body) = response.into_parts();
    let mut frames = body.into_data_stream();
    let mut held = Vec::new();
    let mut first_message = None;
    while held.len() < MAX_HELD_FRAMES {
        let Some(frame) = frames.next().await else {
            break;
        };
        let event = match &frame {
            Ok(bytes) if is_json => HeldFrame::Message(bytes.clone()),
            Ok(bytes) => classify_sse_frame(bytes),
            Err(_) => HeldFrame::Other,
        };
        held.push(frame);
        match event {
            HeldFrame::Priming => {}
            HeldFrame::Message(message) => {
                first_message = Some(message);
                break;
            }
            HeldFrame::Other => break,
        }
    }

    if first_message.is_some_and(|message| is_jsonrpc_error(&message))
        && oauth.access_session(token).await.is_none()
    {
        return unauthorized(state);
    }
    Response::from_parts(parts, Body::from_stream(stream::iter(held).chain(frames)))
}

enum HeldFrame {
    Priming,
    Message(Bytes),
    Other,
}

/// rmcp writes one SSE event per body frame, each message as a single
/// `data:` line. An event with no data is the priming event.
fn classify_sse_frame(frame: &Bytes) -> HeldFrame {
    let Ok(text) = std::str::from_utf8(frame) else {
        return HeldFrame::Other;
    };
    if text.starts_with(':') {
        return HeldFrame::Other;
    }
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
        .collect::<String>();
    if data.is_empty() {
        HeldFrame::Priming
    } else {
        HeldFrame::Message(Bytes::from(data))
    }
}

fn is_jsonrpc_error(message: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(message)
        .is_ok_and(|message| message.get("error").is_some())
}

async fn call_mcp_service(service: McpService, request: Request<Body>) -> Response {
    match service.oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(error) => match error {},
    }
}

fn unauthorized(state: &AppState) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid or missing bearer token" })),
    )
        .into_response();
    let challenge = state.oauth.as_ref().map_or_else(
        || "Bearer".to_string(),
        |oauth| {
            format!(
                "Bearer resource_metadata=\"{}\"",
                oauth.resource_metadata_url()
            )
        },
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN};

    #[test]
    fn parses_comma_separated_values() {
        unsafe { env::set_var("DOCMOST_MCP_TEST_LIST", " a.example, b.example ") };
        assert_eq!(
            comma_separated_env("DOCMOST_MCP_TEST_LIST"),
            Some(vec!["a.example".to_string(), "b.example".to_string()])
        );
        unsafe { env::remove_var("DOCMOST_MCP_TEST_LIST") };
    }

    #[test]
    fn rejects_example_bearer_tokens_even_when_they_are_long_enough() {
        let error = validate_bearer_token("replace-with-at-least-32-random-bytes")
            .expect_err("example bearer token must be rejected");
        assert!(error.to_string().contains("example value"));
    }

    #[test]
    fn accepts_generated_length_bearer_tokens() {
        validate_bearer_token("9035bc2907f9f10ca6dcbe33a96ab7ec20ac97eb7e80cdfe771f589aa7508e86")
            .expect("random 32-byte hex token should be accepted");
    }

    #[tokio::test]
    async fn http_endpoint_requires_bearer_and_rejects_untrusted_origin() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let app = build_router(
            StartupConfig::default(),
            HttpServerConfig {
                bind: address,
                bearer_token: Some(token.to_string()),
                allowed_hosts: vec![address.to_string()],
                allowed_origins: vec![format!("http://{address}")],
                oauth: None,
            },
        )?;
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/mcp");

        let unauthorized = client.post(&endpoint).send().await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "http-test", "version": "1.0.0" }
            }
        });
        let trusted = client
            .post(&endpoint)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, format!("http://{address}"))
            .json(&initialize)
            .send()
            .await?;
        assert!(trusted.status().is_success(), "status={}", trusted.status());

        let untrusted_origin = client
            .post(&endpoint)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "https://attacker.example")
            .json(&initialize)
            .send()
            .await?;
        assert_eq!(untrusted_origin.status(), StatusCode::FORBIDDEN);

        task.abort();
        Ok(())
    }

    /// Mock Docmost that accepts any bearer token not in `revoked`.
    async fn spawn_mock_docmost(
        revoked: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        use axum::{http::HeaderMap, routing::post};

        fn session_is_live(
            revoked: &std::sync::Mutex<std::collections::HashSet<String>>,
            headers: &HeaderMap,
        ) -> bool {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .is_some_and(|token| !revoked.lock().unwrap().contains(token))
        }

        let me_revoked = revoked.clone();
        let app = Router::new()
            .route(
                "/api/users/me",
                post(move |headers: HeaderMap| async move {
                    if !session_is_live(&me_revoked, &headers) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    Json(json!({ "data": { "user": { "email": "user@example.com" } } }))
                        .into_response()
                }),
            )
            .route(
                "/api/spaces",
                post(move |headers: HeaderMap| async move {
                    if !session_is_live(&revoked, &headers) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    Json(json!({ "data": { "items": [] } })).into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((address, task))
    }

    fn test_session(base_url: &str, email: &str, token: &str) -> AuthenticatedSession {
        AuthenticatedSession {
            base_url: base_url.to_string(),
            email: email.to_string(),
            token: token.to_string(),
            expires_at: None,
        }
    }

    struct McpTestClient {
        client: reqwest::Client,
        endpoint: String,
        origin: String,
        token: String,
        session_id: Option<String>,
    }

    impl McpTestClient {
        async fn post(&self, body: serde_json::Value) -> Result<reqwest::Response> {
            let mut request = self
                .client
                .post(&self.endpoint)
                .header(AUTHORIZATION, format!("Bearer {}", self.token))
                .header(ACCEPT, "application/json, text/event-stream")
                .header(CONTENT_TYPE, "application/json")
                .header(ORIGIN, &self.origin)
                .json(&body);
            if let Some(session_id) = &self.session_id {
                request = request.header("mcp-session-id", session_id);
            }
            Ok(request.send().await?)
        }

        async fn initialize(&mut self) -> Result<()> {
            let response = self
                .post(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": { "name": "revocation-test", "version": "1.0.0" }
                    }
                }))
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            self.session_id = response
                .headers()
                .get("mcp-session-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            response.text().await?;
            let initialized = self
                .post(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
                .await?;
            assert!(initialized.status().is_success());
            Ok(())
        }

        async fn list_spaces(&self) -> Result<reqwest::Response> {
            self.post(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "docmost_list_spaces", "arguments": {} }
            }))
            .await
        }
    }

    /// The first JSON-RPC message on an SSE response body.
    fn first_sse_message(body: &str) -> serde_json::Value {
        body.lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .find(|data| !data.is_empty())
            .and_then(|data| serde_json::from_str(data).ok())
            .expect("SSE body carries a JSON-RPC message")
    }

    fn assert_oauth_challenge(response: &reqwest::Response, metadata_url: &str) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(format!("Bearer resource_metadata=\"{metadata_url}\"").as_str())
        );
    }

    #[tokio::test]
    async fn rejected_docmost_session_revokes_its_grants_and_answers_401() -> Result<()> {
        let revoked = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let (docmost, docmost_task) = spawn_mock_docmost(revoked.clone()).await?;
        let docmost_url = format!("http://{docmost}");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let public_url = format!("http://{address}");
        let (app, oauth) = build_app(
            StartupConfig::default(),
            HttpServerConfig {
                bind: address,
                bearer_token: None,
                allowed_hosts: vec![address.to_string()],
                allowed_origins: vec![public_url.clone()],
                oauth: Some(OAuthConfig {
                    public_url: public_url.clone(),
                    docmost_base_url: docmost_url.clone(),
                    browser_url: None,
                    brand: DEFAULT_BRAND.to_string(),
                    client_id_key_path: None,
                    refresh_token_key_path: None,
                }),
            },
        )?;
        let oauth = oauth.expect("account auth is enabled");
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let metadata_url = oauth.resource_metadata_url();

        let (alice_access, alice_refresh) = oauth
            .issue_tokens_for_test(
                "client-a",
                test_session(&docmost_url, "alice@example.com", "alice-docmost"),
            )
            .await;
        let (bob_access, bob_refresh) = oauth
            .issue_tokens_for_test(
                "client-b",
                test_session(&docmost_url, "bob@example.com", "bob-docmost"),
            )
            .await;
        let (_, carol_refresh) = oauth
            .issue_tokens_for_test(
                "client-c",
                test_session(&docmost_url, "carol@example.com", "carol-docmost"),
            )
            .await;

        let http = reqwest::Client::new();
        let mcp_client = |token: &str| McpTestClient {
            client: http.clone(),
            endpoint: format!("{public_url}/mcp"),
            origin: public_url.clone(),
            token: token.to_string(),
            session_id: None,
        };
        let mut alice = mcp_client(&alice_access);
        let mut bob = mcp_client(&bob_access);
        alice.initialize().await?;
        bob.initialize().await?;

        let before = alice.list_spaces().await?;
        assert_eq!(before.status(), StatusCode::OK);
        assert!(
            first_sse_message(&before.text().await?)
                .get("result")
                .is_some()
        );

        // Alice signs out of Docmost; her MCP grants are still live.
        revoked.lock().unwrap().insert("alice-docmost".to_string());

        // The call that discovers the rejection answers 401 itself.
        let discovering = alice.list_spaces().await?;
        assert_oauth_challenge(&discovering, &metadata_url);

        // So does every later request on her access token, and her refresh
        // token no longer mints new credentials.
        assert_oauth_challenge(&alice.list_spaces().await?, &metadata_url);
        let refresh = |token: String| {
            let http = http.clone();
            let endpoint = format!("{public_url}/oauth/token");
            async move {
                http.post(endpoint)
                    .form(&[("grant_type", "refresh_token"), ("refresh_token", &token)])
                    .send()
                    .await
            }
        };
        let refused = refresh(alice_refresh).await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            refused.json::<serde_json::Value>().await?["error"],
            "invalid_grant"
        );

        // Bob's grants are untouched.
        let bob_call = bob.list_spaces().await?;
        assert_eq!(bob_call.status(), StatusCode::OK);
        assert!(
            first_sse_message(&bob_call.text().await?)
                .get("result")
                .is_some()
        );
        assert_eq!(refresh(bob_refresh).await?.status(), StatusCode::OK);

        // A session Docmost revoked before any tool call noticed is caught at
        // refresh time instead of being handed a fresh access token.
        revoked.lock().unwrap().insert("carol-docmost".to_string());
        let refused = refresh(carol_refresh).await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(!oauth.active_session_fingerprints().await.contains(
            &OAuthState::session_fingerprint(&test_session(
                &docmost_url,
                "carol@example.com",
                "carol-docmost"
            ))
        ));

        task.abort();
        docmost_task.abort();
        Ok(())
    }

    #[test]
    fn only_messages_end_the_hold_on_an_sse_response() {
        assert!(matches!(
            classify_sse_frame(&Bytes::from_static(b"data: \nid: 0\nretry: 3000\n\n")),
            HeldFrame::Priming
        ));
        assert!(matches!(
            classify_sse_frame(&Bytes::from_static(b":\n\n")),
            HeldFrame::Other
        ));
        let HeldFrame::Message(message) = classify_sse_frame(&Bytes::from_static(
            b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32603,\"message\":\"x\"}}\n\n",
        )) else {
            panic!("a data event is a message");
        };
        assert!(is_jsonrpc_error(&message));
        assert!(!is_jsonrpc_error(
            br#"{"jsonrpc":"2.0","id":2,"result":{}}"#
        ));
    }
}
