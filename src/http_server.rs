use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower::ServiceExt;

use crate::{
    oauth::{DEFAULT_BRAND, OAuthConfig, OAuthState},
    server::DocmostMcpServer,
    staged_upload::{self, DEFAULT_MAX_STAGED_BYTES, UploadStager},
    types::{AuthenticatedSession, StartupConfig},
};

const MIN_BEARER_TOKEN_BYTES: usize = 32;

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
    stager: Option<UploadStager>,
}

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub bind: SocketAddr,
    pub bearer_token: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub oauth: Option<OAuthConfig>,
    /// This server's externally reachable base URL (`DOCMOST_MCP_PUBLIC_URL`). Staged
    /// uploads are offered only when it is set, since their URLs are built under it.
    pub public_url: Option<String>,
    /// Largest staged upload accepted, in bytes (`DOCMOST_MCP_MAX_UPLOAD_BYTES`).
    pub max_staged_upload_bytes: usize,
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
                brand: env::var("DOCMOST_MCP_BRAND").unwrap_or_else(|_| DEFAULT_BRAND.to_string()),
            })
        } else {
            None
        };
        let public_url = staged_upload_public_url(env::var("DOCMOST_MCP_PUBLIC_URL").ok());
        let max_staged_upload_bytes = match env::var("DOCMOST_MCP_MAX_UPLOAD_BYTES") {
            Ok(value) => value.trim().parse::<usize>().ok().filter(|n| *n > 0).with_context(|| {
                format!("DOCMOST_MCP_MAX_UPLOAD_BYTES must be a positive number of bytes, got {value:?}")
            })?,
            Err(_) => DEFAULT_MAX_STAGED_BYTES,
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
            public_url,
            max_staged_upload_bytes,
        })
    }
}

/// The base for staged-upload URLs. It goes through the same origin validation as account
/// auth, so a token and file are never sent over plain HTTP outside localhost and the URL
/// has no path, query or fragment to break `/uploads/{token}`. Account auth already fails
/// startup on an invalid value; in bearer-only mode the variable was unused before staged
/// uploads, so an invalid value turns them off with a warning rather than refusing to
/// start a working deployment.
fn staged_upload_public_url(raw: Option<String>) -> Option<String> {
    let raw = raw.filter(|value| !value.trim().is_empty())?;
    match crate::oauth::normalize_public_url(raw.trim()) {
        Ok(url) => Some(url),
        Err(error) => {
            tracing::warn!(%error, "DOCMOST_MCP_PUBLIC_URL is not a valid public origin; staged uploads are disabled");
            None
        }
    }
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
    let mcp_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(config.allowed_origins);
    let stager = config
        .public_url
        .as_deref()
        .map(|url| UploadStager::new(url, config.max_staged_upload_bytes));
    let admin_stager = stager.clone();
    let admin_service = StreamableHttpService::new(
        move || {
            DocmostMcpServer::new(startup_config.clone())
                .map(|server| server.with_stager(admin_stager.clone()))
                .map_err(std::io::Error::other)
        },
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
        stager: stager.clone(),
    };

    let mut router = Router::new()
        .route("/health", get(health))
        .route("/mcp", any(handle_mcp))
        .route("/mcp/", any(handle_mcp))
        .with_state(state);
    if let Some(oauth) = oauth {
        router = router.merge(oauth.routes());
    }
    if let Some(stager) = stager {
        router = router.merge(staged_upload::routes(stager));
    }
    Ok(router)
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
        let key = OAuthState::session_fingerprint(&session);
        let active_sessions = oauth.active_session_fingerprints().await;
        let service = {
            let mut services = state.user_services.write().await;
            services.retain(|fingerprint, _| active_sessions.contains(fingerprint));
            services
                .entry(key)
                .or_insert_with(|| {
                    user_mcp_service(session, state.mcp_config.clone(), state.stager.clone())
                })
                .clone()
        };
        return call_mcp_service(service, request).await;
    }

    unauthorized(&state)
}

fn user_mcp_service(
    session: AuthenticatedSession,
    config: StreamableHttpServerConfig,
    stager: Option<UploadStager>,
) -> McpService {
    StreamableHttpService::new(
        move || {
            DocmostMcpServer::new_with_session(session.clone())
                .map(|server| server.with_stager(stager.clone()))
                .map_err(std::io::Error::other)
        },
        LocalSessionManager::default().into(),
        config,
    )
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
    fn staged_upload_public_url_requires_a_valid_https_origin() {
        let url = |value: &str| staged_upload_public_url(Some(value.to_string()));
        assert_eq!(
            url("https://mcp.example.com/").as_deref(),
            Some("https://mcp.example.com")
        );
        assert_eq!(
            url("http://127.0.0.1:8787").as_deref(),
            Some("http://127.0.0.1:8787")
        );
        assert_eq!(staged_upload_public_url(None), None);
        assert_eq!(url("  "), None);
        for bad in [
            "http://mcp.example.com",
            "https://mcp.example.com/base",
            "https://mcp.example.com/?x=1",
            "https://mcp.example.com/#frag",
            "https://user:pw@mcp.example.com",
            "not a url",
        ] {
            assert_eq!(url(bad), None, "{bad:?} must not enable staged uploads");
        }
    }

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
                public_url: None,
                max_staged_upload_bytes: DEFAULT_MAX_STAGED_BYTES,
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
}
