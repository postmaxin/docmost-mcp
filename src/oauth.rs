use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload, rand_core::RngCore},
};
use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;

use crate::{
    auth::manager::AuthManager,
    startup_config::normalize_base_url,
    types::{AuthenticatedSession, LoginInput},
};

const AUTHORIZATION_CODE_TTL_MINUTES: i64 = 5;
const PENDING_LOGIN_TTL_MINUTES: i64 = 10;
const ACCESS_TOKEN_TTL_MINUTES: i64 = 60;
const LOGIN_FAILURE_WINDOW_MINUTES: i64 = 15;
const MAX_LOGIN_FAILURES_PER_ACCOUNT: usize = 5;
/// Upper bound on a registration's serialized metadata (redirect URIs plus
/// name). The metadata travels inside the client_id, which travels in URLs.
const MAX_CLIENT_METADATA_BYTES: usize = 2_048;
/// Anything longer cannot have been issued here (see MAX_CLIENT_METADATA_BYTES),
/// so it is rejected before any decoding work.
const MAX_CLIENT_ID_LENGTH: usize = 4_096;
/// Versions the client_id format so it can change without misreading old IDs.
const CLIENT_ID_PREFIX: &str = "dmc1";
const MAX_PENDING_AUTHORIZATIONS: usize = 4_096;
const MAX_COMPLETED_AUTHORIZATIONS: usize = 4_096;
const MAX_ACCESS_GRANTS: usize = 8_192;
/// Upper bound on the refresh-token families tracked for rotation. One family
/// is one authorization (consent), however often it has been refreshed.
const MAX_REFRESH_FAMILIES: usize = 4_096;
/// Versions the sealed refresh-token format so it can change without
/// misreading old tokens. Also bound into the AEAD associated data.
const REFRESH_TOKEN_PREFIX: &str = "dmr1";
/// Anything longer cannot have been issued here, so it is rejected before
/// any decoding work.
const MAX_REFRESH_TOKEN_LENGTH: usize = 8_192;
const AES_GCM_NONCE_BYTES: usize = 12;
const DEFAULT_SCOPE: &str = "docmost";
/// Product name on the sign-in pages when the operator sets no `DOCMOST_MCP_BRAND`.
pub const DEFAULT_BRAND: &str = "Docmost";
const MAX_BRAND_LENGTH: usize = 60;
/// Shown in place of a client's name when it registered without one. The pages
/// must never name a specific MCP client: Claude Code, Claude Desktop, Codex and
/// Cursor all speak this protocol, and the user is looking at whichever they used.
const UNNAMED_CLIENT: &str = "your MCP client";

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub public_url: String,
    pub docmost_base_url: String,
    /// Product name shown on the sign-in and authorized pages. Deployments that
    /// rebrand Docmost set `DOCMOST_MCP_BRAND`; everyone else gets `DEFAULT_BRAND`.
    pub brand: String,
    /// Public Docmost origin, with /oauth/* forwarded to this server.
    pub browser_url: Option<String>,
    /// File holding the key that signs client_ids, created on first start.
    /// Persisting it keeps issued client_ids valid across restarts: clients
    /// cache their client_id and go straight to /oauth/authorize, so a new
    /// key would strand them on an `invalid_client` page. None generates a
    /// key per process (tests).
    pub client_id_key_path: Option<PathBuf>,
    /// File holding the AES-256-GCM key that seals refresh tokens, created on
    /// first start. Persisting it keeps issued refresh tokens redeemable
    /// across restarts, so clients refresh instead of signing in again.
    /// None generates a key per process (tests).
    pub refresh_token_key_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct OAuthState {
    inner: Arc<OAuthInner>,
}

struct OAuthInner {
    browser_url: Option<String>,
    public_url: String,
    resource_url: String,
    docmost_base_url: String,
    brand: String,
    /// Signs client_ids (see OAuthConfig::client_id_key_path).
    client_id_key: [u8; 32],
    pending: RwLock<HashMap<String, PendingAuthorization>>,
    completed: RwLock<HashMap<String, CompletedAuthorization>>,
    codes: RwLock<HashMap<String, AuthorizationCode>>,
    access_tokens: RwLock<HashMap<String, AccessGrant>>,
    /// Seals refresh tokens (see OAuthConfig::refresh_token_key_path). The
    /// server stores no refresh tokens; the client holds them, encrypted.
    refresh_cipher: Aes256Gcm,
    /// Associated data for sealed refresh tokens: format version, this MCP
    /// resource and the Docmost it fronts, so a token only opens here.
    refresh_token_aad: String,
    /// Rotation state per refresh-token family, keyed by family id. Memory
    /// only: it holds no credentials, and is rebuilt as clients refresh.
    refresh_families: RwLock<HashMap<String, RefreshFamily>>,
    login_failures: RwLock<HashMap<String, Vec<DateTime<Utc>>>>,
}

/// A dynamically registered client. Registrations are not stored: the
/// client_id is the registration, signed (see `issue_client_id`), so
/// anonymous registration cannot exhaust server memory or lock out real
/// clients. Nothing is kept for a client until someone authorizes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RegisteredClient {
    #[serde(rename = "r")]
    redirect_uris: Vec<String>,
    /// Self-declared at registration, so it is untrusted input and is always
    /// escaped before it reaches a page.
    #[serde(rename = "n", default, skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
}

#[derive(Clone)]
struct PendingAuthorization {
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    scope: String,
    csrf_hash: String,
    consent_session_hash: Option<String>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct CompletedAuthorization {
    location: String,
    /// Carried so a refreshed browser replays the same page it saw the first
    /// time, naming the same client.
    client_name: Option<String>,
    expires_at: DateTime<Utc>,
}

struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    session: AuthenticatedSession,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct AccessGrant {
    session: AuthenticatedSession,
    expires_at: DateTime<Utc>,
}

/// What a refresh token carries. It is sealed with AES-256-GCM and handed to
/// the client (`dmr1.<base64url nonce || ciphertext>`); nothing is stored
/// server-side, so it survives a restart. The Docmost session inside is
/// therefore never written to this server's disk; the client holds it,
/// encrypted under a key only this server has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RefreshGrant {
    /// SHA-256 of the client_id it was issued to (fixed size whatever the
    /// client_id format).
    #[serde(rename = "c")]
    client_hash: String,
    #[serde(rename = "s")]
    scope: String,
    #[serde(rename = "m")]
    email: String,
    /// The Docmost session token (authToken JWT).
    #[serde(rename = "t")]
    token: String,
    #[serde(rename = "x", default, skip_serializing_if = "Option::is_none")]
    session_expires_at: Option<String>,
    #[serde(rename = "e", with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
    /// Random id shared by every token rotated from one authorization.
    #[serde(rename = "f")]
    family: String,
    /// Position in the family's rotation; with `family`, this token's unique id.
    #[serde(rename = "g")]
    generation: u64,
}

/// Rotation state for one refresh-token family. Only the newest generation
/// is redeemable; presenting an older one means a token was copied, so the
/// whole family is revoked (RFC 9700 section 4.14.2).
struct RefreshFamily {
    /// The generation of the one token in this family that may be redeemed.
    current: u64,
    revoked: bool,
    session_fingerprint: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegistrationResponse {
    client_id: String,
    client_id_issued_at: i64,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    request_id: String,
    csrf: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

impl OAuthState {
    pub fn new(config: OAuthConfig) -> anyhow::Result<Self> {
        let public_url = normalize_public_url(&config.public_url)?;
        let browser_url = config
            .browser_url
            .as_deref()
            .map(normalize_public_url)
            .transpose()?;
        let resource_url = format!("{public_url}/mcp");
        let docmost_base_url = normalize_base_url(&config.docmost_base_url);
        let refresh_key = match &config.refresh_token_key_path {
            Some(path) => load_or_create_key(path)?,
            None => random_key(),
        };
        Ok(Self {
            inner: Arc::new(OAuthInner {
                browser_url,
                refresh_token_aad: format!(
                    "{REFRESH_TOKEN_PREFIX}\n{resource_url}\n{docmost_base_url}"
                ),
                resource_url,
                public_url,
                docmost_base_url,
                brand: normalize_brand(&config.brand),
                client_id_key: match &config.client_id_key_path {
                    Some(path) => load_or_create_key(path)?,
                    None => random_key(),
                },
                pending: RwLock::new(HashMap::new()),
                completed: RwLock::new(HashMap::new()),
                codes: RwLock::new(HashMap::new()),
                access_tokens: RwLock::new(HashMap::new()),
                refresh_cipher: Aes256Gcm::new(&refresh_key.into()),
                refresh_families: RwLock::new(HashMap::new()),
                login_failures: RwLock::new(HashMap::new()),
            }),
        })
    }

    pub fn routes(self) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server_metadata),
            )
            .route(
                "/.well-known/openid-configuration",
                get(authorization_server_metadata),
            )
            .route("/oauth/register", post(register_client))
            .route(
                "/oauth/authorize",
                get(authorize).post(complete_authorization),
            )
            .route("/oauth/token", post(exchange_token))
            .route("/oauth/resume", get(resume_native_authorization))
            .layer(DefaultBodyLimit::max(16 * 1_024))
            .with_state(self)
    }

    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.inner.public_url
        )
    }

    pub async fn access_session(&self, token: &str) -> Option<AuthenticatedSession> {
        let key = token_hash(token);
        let grant = self.inner.access_tokens.read().await.get(&key).cloned();
        match grant {
            Some(grant) if grant.expires_at > Utc::now() => Some(grant.session),
            Some(_) => {
                self.inner.access_tokens.write().await.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn session_fingerprint(session: &AuthenticatedSession) -> String {
        token_hash(&session.token)
    }

    pub async fn active_session_fingerprints(&self) -> HashSet<String> {
        cleanup_expired(self).await;
        let mut active = HashSet::new();
        active.extend(
            self.inner
                .access_tokens
                .read()
                .await
                .values()
                .map(|grant| Self::session_fingerprint(&grant.session)),
        );
        active.extend(
            self.inner
                .refresh_families
                .read()
                .await
                .values()
                .filter(|family| !family.revoked)
                .map(|family| family.session_fingerprint.clone()),
        );
        active
    }

    /// Invalidate every grant that carries the Docmost session with this
    /// fingerprint: access tokens, refresh tokens, and unredeemed codes.
    ///
    /// Called once Docmost rejects the session (logout, revocation, expiry).
    /// The client then gets a 401 from `/mcp`, its refresh is refused, and it
    /// falls back to a fresh authorization, which captures a new session.
    pub async fn revoke_session(&self, fingerprint: &str) {
        let carries = |session: &AuthenticatedSession| {
            constant_time_equal(&Self::session_fingerprint(session), fingerprint)
        };
        self.inner
            .access_tokens
            .write()
            .await
            .retain(|_, grant| !carries(&grant.session));
        // Refresh tokens are sealed and held by the client, so they cannot be
        // deleted; revoke their families instead. A family this process has
        // not seen since a restart is caught when it refreshes: Docmost
        // rejects the session there too.
        for family in self.inner.refresh_families.write().await.values_mut() {
            if constant_time_equal(&family.session_fingerprint, fingerprint) {
                family.revoked = true;
            }
        }
        self.inner
            .codes
            .write()
            .await
            .retain(|_, grant| !carries(&grant.session));
    }
}

#[cfg(test)]
impl OAuthState {
    /// Issue an access and refresh token for `session` without the browser flow.
    pub(crate) async fn issue_tokens_for_test(
        &self,
        client_id: &str,
        session: AuthenticatedSession,
    ) -> (String, String) {
        let response = issue_tokens(
            self,
            token_hash(client_id),
            DEFAULT_SCOPE.to_string(),
            session,
            (random_token(16), 1),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("token response body");
        let tokens: serde_json::Value = serde_json::from_slice(&body).expect("token JSON");
        (
            tokens["access_token"]
                .as_str()
                .expect("access token")
                .into(),
            tokens["refresh_token"]
                .as_str()
                .expect("refresh token")
                .into(),
        )
    }
}

async fn protected_resource_metadata(State(state): State<OAuthState>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": state.inner.resource_url,
        "authorization_servers": [state.inner.public_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [DEFAULT_SCOPE]
    }))
}

async fn authorization_server_metadata(State(state): State<OAuthState>) -> Json<serde_json::Value> {
    let base = &state.inner.public_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{}/oauth/authorize", state.inner.browser_url.as_deref().unwrap_or(base)),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [DEFAULT_SCOPE]
    }))
}

async fn register_client(
    State(state): State<OAuthState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    if request.redirect_uris.is_empty()
        || request.redirect_uris.len() > 10
        || request
            .redirect_uris
            .iter()
            .any(|uri| uri.len() > 2_048 || !valid_redirect_uri(uri))
        || request
            .client_name
            .as_deref()
            .is_some_and(|name| name.len() > 200)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Every redirect URI must be HTTPS, or loopback HTTP for a native client.",
        );
    }

    let issued_at = Utc::now().timestamp();
    let client = RegisteredClient {
        redirect_uris: request.redirect_uris.clone(),
        client_name: request
            .client_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string),
    };
    let Some(client_id) = issue_client_id(&state.inner.client_id_key, &client) else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "The redirect URIs and client name are too long in total.",
        );
    };

    (
        StatusCode::CREATED,
        Json(RegistrationResponse {
            client_id,
            client_id_issued_at: issued_at,
            redirect_uris: request.redirect_uris,
            token_endpoint_auth_method: "none",
            client_name: request.client_name,
        }),
    )
        .into_response()
}

async fn authorize(
    State(state): State<OAuthState>,
    Query(query): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    if !native_host_matches(&state, &headers) {
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "Use the authorization endpoint advertised by OAuth discovery.",
        );
    }
    let pending = match validate_authorize_request(&state, query).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };

    cleanup_expired(&state).await;
    if state.inner.pending.read().await.len() >= MAX_PENDING_AUTHORIZATIONS
        || state.inner.completed.read().await.len() >= MAX_COMPLETED_AUTHORIZATIONS
    {
        return oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization capacity is temporarily exhausted.",
        );
    }

    let request_id = random_token(24);
    let csrf = random_token(24);
    let mut pending = pending;
    pending.csrf_hash = token_hash(&csrf);
    state
        .inner
        .pending
        .write()
        .await
        .insert(request_id.clone(), pending);

    let client_name = state
        .inner
        .pending
        .read()
        .await
        .get(&request_id)
        .and_then(|p| p.client_name.clone());
    let native = if state.inner.browser_url.is_some() {
        native_session(&state, &headers).await
    } else {
        None
    };
    bind_native_consent(&state, &request_id, native.as_ref()).await;
    let html = if state.inner.browser_url.is_some() {
        render_native_page(
            &request_id,
            &csrf,
            native.as_ref(),
            &state.inner.brand,
            client_name.as_deref(),
        )
    } else {
        render_login_page(&request_id, &csrf, None, &state.inner.brand)
    };
    let cookie = format!(
        "mcp_auth_csrf={csrf}; Path=/oauth; Max-Age=600; HttpOnly; Secure; SameSite=Strict"
    );
    let mut response = hardened_auth_response(Html(html).into_response());
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated cookie is valid"),
    );
    response
}

async fn complete_authorization(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !native_host_matches(&state, &headers) {
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "Use the configured Docmost authorization origin.",
        );
    }
    let pending = state
        .inner
        .pending
        .read()
        .await
        .get(&form.request_id)
        .cloned();
    let Some(pending) = pending else {
        let completed = state
            .inner
            .completed
            .read()
            .await
            .get(&form.request_id)
            .cloned();
        if let Some(completed) = completed.filter(|grant| grant.expires_at > Utc::now()) {
            return authorization_response(
                &completed.location,
                &state.inner.brand,
                completed.client_name.as_deref(),
            );
        }
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "This login request is no longer valid.",
        );
    };
    if pending.expires_at <= Utc::now() {
        state.inner.pending.write().await.remove(&form.request_id);
        return oauth_html_error(StatusCode::BAD_REQUEST, "This login request has expired.");
    }

    let cookie_csrf = cookie_value(&headers, "mcp_auth_csrf");
    let csrf_matches = cookie_csrf.as_deref().is_some_and(|cookie| {
        constant_time_equal(&token_hash(cookie), &pending.csrf_hash)
            && constant_time_equal(&token_hash(&form.csrf), &pending.csrf_hash)
    });
    if !csrf_matches {
        return oauth_html_error(StatusCode::BAD_REQUEST, "Login security check failed.");
    }

    let session = if state.inner.browser_url.is_some() {
        let Some(session) = native_session(&state, &headers).await else {
            return oauth_html_error(
                StatusCode::UNAUTHORIZED,
                "Sign in to Docmost before authorizing this connection.",
            );
        };
        if pending.consent_session_hash.as_deref() != Some(token_hash(&session.token).as_str()) {
            return oauth_html_error(
                StatusCode::BAD_REQUEST,
                "Your Docmost account changed. Return to the authorization page and confirm the current account.",
            );
        }
        session
    } else {
        let normalized_email = form.email.trim().to_ascii_lowercase();
        if normalized_email.is_empty()
            || normalized_email.len() > 320
            || form.password.is_empty()
            || form.password.len() > 1_024
        {
            return oauth_html_error(StatusCode::BAD_REQUEST, "Email or password is invalid.");
        }
        if login_is_rate_limited(&state, &normalized_email).await {
            return oauth_html_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed sign-in attempts. Try again in 15 minutes.",
            );
        }

        let session = match AuthManager::authenticate_once(LoginInput {
            base_url: state.inner.docmost_base_url.clone(),
            email: normalized_email.clone(),
            password: form.password,
        })
        .await
        {
            Ok(session) => session,
            Err(_) => {
                record_login_failure(&state, &normalized_email).await;
                return hardened_auth_response(
                    (
                        StatusCode::UNAUTHORIZED,
                        Html(render_login_page(
                            &form.request_id,
                            &form.csrf,
                            Some("Email or password was not accepted by Docmost."),
                            &state.inner.brand,
                        )),
                    )
                        .into_response(),
                );
            }
        };
        clear_login_failures(&state, &normalized_email).await;

        session
    };

    let code = random_token(32);
    let mut redirect = match Url::parse(&pending.redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_html_error(StatusCode::BAD_REQUEST, "Invalid redirect URI."),
    };
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("code", &code);
        if let Some(state_value) = pending.state {
            pairs.append_pair("state", &state_value);
        }
    }
    let location = redirect.to_string();
    let expires_at = Utc::now() + Duration::minutes(AUTHORIZATION_CODE_TTL_MINUTES);
    state.inner.codes.write().await.insert(
        token_hash(&code),
        AuthorizationCode {
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri,
            code_challenge: pending.code_challenge,
            scope: pending.scope,
            session,
            expires_at,
        },
    );
    state.inner.completed.write().await.insert(
        form.request_id.clone(),
        CompletedAuthorization {
            location: location.clone(),
            client_name: pending.client_name.clone(),
            expires_at,
        },
    );
    state.inner.pending.write().await.remove(&form.request_id);

    authorization_response(
        &location,
        &state.inner.brand,
        pending.client_name.as_deref(),
    )
}

fn authorization_response(location: &str, brand: &str, client_name: Option<&str>) -> Response {
    // Commit a same-origin document before navigating to the registered client.
    // Chrome applies the login form's form-action 'self' to HTTP redirects too,
    // so a cross-origin 303 after a successful login can leave the form stuck.
    // An explicit link also preserves the reliable handoff to loopback clients.
    let escaped_location = escape_html(location);
    let brand = escape_html(brand);
    let client = display_client_name(client_name);
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{brand} authorized</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f5f6f8;margin:0;display:grid;place-items:center;min-height:100vh;color:#17202a}}
main{{width:min(420px,calc(100% - 40px));background:white;padding:32px;border-radius:14px;box-shadow:0 10px 30px #0002}}
h1{{font-size:1.35rem;margin:0 0 8px}}p{{color:#59636e;line-height:1.5}}
a{{box-sizing:border-box;display:block;width:100%;margin-top:24px;padding:12px;border-radius:8px;background:#202938;color:white;text-align:center;text-decoration:none;font-weight:700}}
small{{display:block;margin-top:16px;color:#697482;line-height:1.45}}
</style></head><body><main><h1>{brand} authorized</h1>
<p>Your {brand} account was accepted. Continue to {client} to finish connecting the MCP.</p>
<a id="continue-to-client" href="{escaped_location}">Continue to {client}</a>
<small>Use the Continue button to return to your MCP client and finish connecting.</small>
</main></body></html>"#
    );
    let mut response = hardened_auth_response(Html(html).into_response());
    clear_csrf_cookie(&mut response);
    response
}

fn clear_csrf_cookie(response: &mut Response) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "mcp_auth_csrf=; Path=/oauth; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        ),
    );
}

async fn exchange_token(State(state): State<OAuthState>, Form(form): Form<TokenForm>) -> Response {
    if form
        .resource
        .as_deref()
        .is_some_and(|resource| resource != state.inner.resource_url)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The requested resource is not this MCP server.",
        );
    }

    match form.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, form).await,
        "refresh_token" => exchange_refresh_token(&state, form).await,
        _ => oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Supported grants are authorization_code and refresh_token.",
        ),
    }
}

async fn exchange_authorization_code(state: &OAuthState, form: TokenForm) -> Response {
    let Some(code) = form.code else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required.",
        );
    };
    let Some(client_id) = form.client_id else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required.",
        );
    };
    let Some(redirect_uri) = form.redirect_uri else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required.",
        );
    };
    let Some(verifier) = form.code_verifier else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required.",
        );
    };
    if !valid_pkce_value(&verifier, 43, 128) {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier must contain 43 to 128 unreserved characters.",
        );
    }

    let grant = state.inner.codes.write().await.remove(&token_hash(&code));
    let Some(grant) = grant else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code is invalid or was already used.",
        );
    };
    if grant.expires_at <= Utc::now()
        || grant.client_id != client_id
        || grant.redirect_uri != redirect_uri
        || !constant_time_equal(&pkce_challenge(&verifier), &grant.code_challenge)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code validation failed.",
        );
    }

    issue_tokens(
        state,
        token_hash(&grant.client_id),
        grant.scope,
        grant.session,
        (random_token(16), 1),
    )
    .await
}

async fn exchange_refresh_token(state: &OAuthState, form: TokenForm) -> Response {
    let Some(refresh_token) = form.refresh_token else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required.",
        );
    };
    let Some(grant) = open_refresh_token(&state.inner, &refresh_token) else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token is invalid.",
        );
    };
    if grant.expires_at <= Utc::now() {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Docmost session expired; sign in again.",
        );
    }
    if form
        .client_id
        .as_deref()
        .is_some_and(|client_id| !constant_time_equal(&token_hash(client_id), &grant.client_hash))
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token was not issued to this client.",
        );
    }
    if let Err(response) = claim_refresh_generation(state, &grant).await {
        return *response;
    }

    let session = AuthenticatedSession {
        base_url: state.inner.docmost_base_url.clone(),
        email: grant.email,
        token: grant.token,
        expires_at: grant.session_expires_at,
    };
    // The refresh token outlives any restart, so ask Docmost whether the
    // session it carries is still good before minting tokens from it. Signing
    // out of Docmost (or an admin revoking the session) thereby also cuts off
    // agents at their next refresh. Only an explicit rejection counts: if
    // Docmost cannot be reached, every tool call fails anyway until it can.
    if let DocmostSession::Rejected = docmost_session(state, session.token.clone()).await {
        // Same as a rejection seen during a tool call: drop the session's
        // access tokens and codes and revoke its refresh families, so the
        // client goes back through OAuth for a fresh session.
        state
            .revoke_session(&OAuthState::session_fingerprint(&session))
            .await;
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Docmost no longer accepts this session; sign in again.",
        );
    }

    issue_tokens(
        state,
        grant.client_hash,
        grant.scope,
        session,
        (grant.family, grant.generation + 1),
    )
    .await
}

/// Single use: marks this token's generation spent, so a second redemption
/// (a copied token, or a concurrent request) fails. Presenting a spent
/// generation revokes the whole family. A family this process has not seen
/// (it was issued before a restart) starts being tracked here.
async fn claim_refresh_generation(
    state: &OAuthState,
    grant: &RefreshGrant,
) -> Result<(), Box<Response>> {
    cleanup_expired(state).await;
    let mut families = state.inner.refresh_families.write().await;
    let reused = || {
        Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token was already used; sign in again.",
        ))
    };
    let full = families.len() >= MAX_REFRESH_FAMILIES;
    match families.get_mut(&grant.family) {
        Some(family) if family.revoked => Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "This authorization was revoked; sign in again.",
        ))),
        Some(family) if family.current != grant.generation => {
            family.revoked = true;
            Err(reused())
        }
        Some(family) => {
            family.current = grant.generation + 1;
            Ok(())
        }
        None if full => Err(Box::new(oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization grant capacity is temporarily exhausted.",
        ))),
        None => {
            families.insert(
                grant.family.clone(),
                RefreshFamily {
                    current: grant.generation + 1,
                    revoked: false,
                    session_fingerprint: token_hash(&grant.token),
                    expires_at: grant.expires_at,
                },
            );
            Ok(())
        }
    }
}

/// Issues an access token and the refresh token at `refresh` (family id,
/// generation). Generation 1 starts a new family.
async fn issue_tokens(
    state: &OAuthState,
    client_hash: String,
    scope: String,
    session: AuthenticatedSession,
    refresh: (String, u64),
) -> Response {
    cleanup_expired(state).await;
    let (family, generation) = refresh;
    if state.inner.access_tokens.read().await.len() >= MAX_ACCESS_GRANTS
        || (generation == 1
            && state.inner.refresh_families.read().await.len() >= MAX_REFRESH_FAMILIES)
    {
        return oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization grant capacity is temporarily exhausted.",
        );
    }

    let now = Utc::now();
    let docmost_expiry = session
        .expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let access_expiry = docmost_expiry
        .map(|expiry| expiry.min(now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES)))
        .unwrap_or(now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES));
    if access_expiry <= now + Duration::seconds(30) {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Docmost session is already expired; sign in again.",
        );
    }

    let refresh_expiry = docmost_expiry.unwrap_or(access_expiry);
    let grant = RefreshGrant {
        client_hash,
        scope: scope.clone(),
        email: session.email.clone(),
        token: session.token.clone(),
        session_expires_at: session.expires_at.clone(),
        expires_at: refresh_expiry,
        family: family.clone(),
        generation,
    };
    let Some(refresh_token) = seal_refresh_token(&state.inner, &grant) else {
        return oauth_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Could not issue a refresh token.",
        );
    };
    state
        .inner
        .refresh_families
        .write()
        .await
        .entry(family)
        .and_modify(|entry| entry.expires_at = refresh_expiry)
        .or_insert_with(|| RefreshFamily {
            current: generation,
            revoked: false,
            session_fingerprint: token_hash(&session.token),
            expires_at: refresh_expiry,
        });

    let access_token = random_token(32);
    state.inner.access_tokens.write().await.insert(
        token_hash(&access_token),
        AccessGrant {
            session,
            expires_at: access_expiry,
        },
    );

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: (access_expiry - now).num_seconds(),
        scope,
        refresh_token: Some(refresh_token),
    })
    .into_response()
}

async fn validate_authorize_request(
    state: &OAuthState,
    query: AuthorizeQuery,
) -> Result<PendingAuthorization, Box<Response>> {
    if query.response_type != "code" {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only authorization code flow is supported.",
        )));
    }
    if query.code_challenge_method.as_deref() != Some("S256") {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required.",
        )));
    }
    let Some(code_challenge) = query.code_challenge else {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge is required.",
        )));
    };
    if code_challenge.len() != 43
        || !code_challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge must be a 43-character base64url SHA-256 value.",
        )));
    }
    if query
        .resource
        .as_deref()
        .is_some_and(|resource| resource != state.inner.resource_url)
    {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The requested resource is not this MCP server.",
        )));
    }
    let scope = query.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    if scope.split_whitespace().any(|value| value != DEFAULT_SCOPE)
        || !scope.split_whitespace().any(|value| value == DEFAULT_SCOPE)
    {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "The only supported scope is docmost.",
        )));
    }

    let Some(client) = decode_client_id(&state.inner.client_id_key, &query.client_id) else {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Register this MCP client before authorizing.",
        )));
    };
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(Box::new(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri is not registered for this client.",
        )));
    }

    let client_name = client.client_name;

    Ok(PendingAuthorization {
        client_id: query.client_id,
        client_name,
        redirect_uri: query.redirect_uri,
        state: query.state,
        code_challenge,
        scope,
        csrf_hash: String::new(),
        consent_session_hash: None,
        expires_at: Utc::now() + Duration::minutes(PENDING_LOGIN_TTL_MINUTES),
    })
}

async fn bind_native_consent(
    state: &OAuthState,
    request_id: &str,
    session: Option<&AuthenticatedSession>,
) {
    if let Some(pending) = state.inner.pending.write().await.get_mut(request_id) {
        pending.consent_session_hash = session.map(|s| token_hash(&s.token));
    }
}

fn native_host_matches(state: &OAuthState, headers: &HeaderMap) -> bool {
    let Some(browser_url) = &state.inner.browser_url else {
        return true;
    };
    let expected = Url::parse(browser_url).expect("validated browser URL");
    let authority = &expected[url::Position::BeforeHost..url::Position::AfterPort];
    headers.get(header::HOST).and_then(|h| h.to_str().ok()) == Some(authority)
}

// Native mode never accepts a browser-supplied identity or password. Docmost
// validates its HttpOnly session cookie on every consent page and submission.
async fn native_session(state: &OAuthState, headers: &HeaderMap) -> Option<AuthenticatedSession> {
    let token = cookie_value(headers, "authToken")?;
    let token = urlencoding::decode(&token).ok()?.into_owned();
    match docmost_session(state, token).await {
        DocmostSession::Valid(session) => Some(session),
        DocmostSession::Rejected | DocmostSession::Unavailable => None,
    }
}

/// Docmost's verdict on a session token, from `/api/users/me`.
enum DocmostSession {
    Valid(AuthenticatedSession),
    /// Docmost answered 401 or 403: signed out, revoked or expired.
    Rejected,
    /// No usable answer (network error, 5xx, unexpected body).
    Unavailable,
}

async fn docmost_session(state: &OAuthState, token: String) -> DocmostSession {
    let Ok(http) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
    else {
        return DocmostSession::Unavailable;
    };
    let Ok(response) = http
        .post(format!("{}/api/users/me", state.inner.docmost_base_url))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
    else {
        return DocmostSession::Unavailable;
    };
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return DocmostSession::Rejected;
    }
    if !response.status().is_success() {
        return DocmostSession::Unavailable;
    }
    let Ok(body) = response.json::<serde_json::Value>().await else {
        return DocmostSession::Unavailable;
    };
    let Some(email) = body
        .pointer("/data/user/email")
        .or_else(|| body.pointer("/user/email"))
        .and_then(|email| email.as_str())
    else {
        return DocmostSession::Unavailable;
    };
    DocmostSession::Valid(AuthenticatedSession {
        base_url: state.inner.docmost_base_url.clone(),
        email: email.to_string(),
        expires_at: crate::auth::manager::get_jwt_expiry_iso(&token),
        token,
    })
}

#[derive(Deserialize)]
struct ResumeQuery {
    request_id: String,
}

async fn resume_native_authorization(
    State(state): State<OAuthState>,
    Query(query): Query<ResumeQuery>,
    headers: HeaderMap,
) -> Response {
    if !native_host_matches(&state, &headers) {
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "Use the configured Docmost authorization origin.",
        );
    }
    if state.inner.browser_url.is_none() {
        return oauth_html_error(StatusCode::NOT_FOUND, "Native login is not enabled.");
    }
    let pending = state
        .inner
        .pending
        .read()
        .await
        .get(&query.request_id)
        .cloned();
    let csrf = cookie_value(&headers, "mcp_auth_csrf").unwrap_or_default();
    let client_name = pending.as_ref().and_then(|p| p.client_name.clone());
    if !pending.is_some_and(|p| {
        p.expires_at > Utc::now() && constant_time_equal(&token_hash(&csrf), &p.csrf_hash)
    }) {
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "This authorization request has expired or its security check failed.",
        );
    }
    let session = native_session(&state, &headers).await;
    bind_native_consent(&state, &query.request_id, session.as_ref()).await;
    hardened_auth_response(
        Html(render_native_page(
            &query.request_id,
            &csrf,
            session.as_ref(),
            &state.inner.brand,
            client_name.as_deref(),
        ))
        .into_response(),
    )
}

fn render_native_page(
    request_id: &str,
    csrf: &str,
    session: Option<&AuthenticatedSession>,
    brand: &str,
    client_name: Option<&str>,
) -> String {
    let client = display_client_name(client_name);
    let brand = escape_html(brand);
    let request_id = escape_html(request_id);
    let csrf = escape_html(csrf);
    let content = if let Some(session) = session {
        format!(
            r#"<h1>Connect {brand} to {client}</h1><p>Authorize as <!--email_off-->{}<!--/email_off--> using your existing Docmost session.</p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{request_id}"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Authorize connection</button></form>
<p>Your account's space permissions apply. Writes still require explicit confirmation.</p>"#,
            escape_html(&session.email)
        )
    } else {
        // Open the ordinary login in a tab: Docmost's SPA controls its own
        // post-login navigation. This waiting document resumes independently,
        // without requiring a patch to Docmost or sharing cookies across hosts.
        format!(
            r#"<meta http-equiv="refresh" content="3;url=/oauth/resume?request_id={request_id}">
<h1>Sign in to {brand}</h1><p>Use the existing Docmost login screen. This page will continue once you have signed in.</p>
<a href="/login" target="_blank" rel="noopener noreferrer">Open Docmost sign in</a>
<p>After signing in, return to this tab to authorize the connection.</p>"#
        )
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect {brand}</title>
<style>body{{font-family:system-ui,sans-serif;background:#f5f6f8;display:grid;place-items:center;min-height:100vh;margin:0;color:#17202a}}main{{max-width:420px;background:white;padding:32px;border-radius:14px}}button,a{{display:inline-block;padding:12px;border:0;border-radius:8px;background:#202938;color:white;font:inherit;text-decoration:none}}p{{line-height:1.5}}</style></head><body><main>{content}</main></body></html>"#
    )
}

fn render_login_page(request_id: &str, csrf: &str, error: Option<&str>, brand: &str) -> String {
    let error = error
        .map(|message| format!("<p class=\"error\">{}</p>", escape_html(message)))
        .unwrap_or_default();
    let brand = escape_html(brand);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to {brand} MCP</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f5f6f8;margin:0;display:grid;place-items:center;min-height:100vh;color:#17202a}}
main{{width:min(420px,calc(100% - 40px));background:white;padding:32px;border-radius:14px;box-shadow:0 10px 30px #0002}}
h1{{font-size:1.35rem;margin:0 0 8px}}p{{color:#59636e}}label{{display:block;font-weight:600;margin-top:18px}}
input{{box-sizing:border-box;width:100%;margin-top:7px;padding:11px 12px;border:1px solid #c9ced6;border-radius:8px;font:inherit}}
button{{width:100%;margin-top:24px;padding:12px;border:0;border-radius:8px;background:#202938;color:white;font:inherit;font-weight:700;cursor:pointer}}
.error{{color:#b42318;background:#fef3f2;padding:10px;border-radius:8px}}small{{display:block;margin-top:16px;color:#697482;line-height:1.45}}
</style></head><body><main><h1>Sign in to {brand} MCP</h1>
<p>Use your {brand} account. The MCP relays this login to {brand} over HTTPS and never stores your password.</p>
{error}<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="{}"><input type="hidden" name="csrf" value="{}">
<label>Email<input name="email" type="email" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in and authorize</button></form>
<small>The MCP receives a time-limited Docmost session with the same spaces and permissions as your account.</small>
</main></body></html>"#,
        escape_html(request_id),
        escape_html(csrf)
    )
}

fn oauth_json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

fn oauth_html_error(status: StatusCode, message: &str) -> Response {
    hardened_auth_response((
        status,
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Authorization failed</title><h1>Authorization failed</h1><p>{}</p>",
            escape_html(message)
        )),
    )
        .into_response())
}

fn hardened_auth_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn normalize_public_url(value: &str) -> anyhow::Result<String> {
    let parsed = Url::parse(value)?;
    if parsed.scheme() != "https" && !is_loopback_host(parsed.host_str()) {
        anyhow::bail!("DOCMOST_MCP_PUBLIC_URL must use HTTPS outside localhost");
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!(
            "DOCMOST_MCP_PUBLIC_URL must be an origin without credentials, path, query, or fragment"
        );
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn valid_redirect_uri(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.fragment().is_none()
            && (url.scheme() == "https"
                || (url.scheme() == "http" && is_loopback_host(url.host_str())))
    })
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn random_key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Reads a 32-byte key, creating it (mode 0600, directory 0700) if absent.
/// Creation is exclusive, so concurrent first starts agree on one key. A file
/// of any other length is an error rather than being silently replaced.
fn load_or_create_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    use anyhow::Context as _;
    use std::io::Write as _;

    match std::fs::read(path) {
        Ok(bytes) => {
            return bytes.try_into().map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!(
                    "{} must hold exactly 32 bytes (found {}); delete it to generate a new key",
                    path.display(),
                    bytes.len()
                )
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to read {}", path.display()));
        }
    }

    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    let key = random_key();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&key)
                .and_then(|()| file.sync_all())
                .with_context(|| format!("Failed to write {}", path.display()))?;
            Ok(key)
        }
        // Another process created it first: use theirs.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => load_or_create_key(path),
        Err(error) => Err(error).with_context(|| format!("Failed to create {}", path.display())),
    }
}

/// `dmc1.<base64url JSON metadata>.<base64url HMAC-SHA256 of the first two
/// parts>`. None when the metadata exceeds MAX_CLIENT_METADATA_BYTES.
fn issue_client_id(key: &[u8; 32], client: &RegisteredClient) -> Option<String> {
    let metadata = serde_json::to_vec(client).ok()?;
    if metadata.len() > MAX_CLIENT_METADATA_BYTES {
        return None;
    }
    let signed = format!("{CLIENT_ID_PREFIX}.{}", URL_SAFE_NO_PAD.encode(metadata));
    let tag = URL_SAFE_NO_PAD.encode(client_id_mac(key, &signed).finalize().into_bytes());
    Some(format!("{signed}.{tag}"))
}

/// The registration a client_id carries, if this server issued it (under the
/// current key) and it is unmodified.
fn decode_client_id(key: &[u8; 32], client_id: &str) -> Option<RegisteredClient> {
    if client_id.len() > MAX_CLIENT_ID_LENGTH {
        return None;
    }
    let (signed, tag) = client_id.rsplit_once('.')?;
    let (prefix, metadata) = signed.split_once('.')?;
    if prefix != CLIENT_ID_PREFIX {
        return None;
    }
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    // Constant-time comparison.
    client_id_mac(key, signed).verify_slice(&tag).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(metadata).ok()?).ok()
}

fn client_id_mac(key: &[u8; 32], signed: &str) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(signed.as_bytes());
    mac
}

/// `dmr1.<base64url(nonce || AES-256-GCM ciphertext and tag)>`, with a fresh
/// random 96-bit nonce per token.
fn seal_refresh_token(inner: &OAuthInner, grant: &RefreshGrant) -> Option<String> {
    let plaintext = serde_json::to_vec(grant).ok()?;
    let mut nonce = [0_u8; AES_GCM_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = inner
        .refresh_cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: inner.refresh_token_aad.as_bytes(),
            },
        )
        .ok()?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Some(format!(
        "{REFRESH_TOKEN_PREFIX}.{}",
        URL_SAFE_NO_PAD.encode(sealed)
    ))
}

/// The grant a refresh token carries, if this server sealed it (under the
/// current key, for this resource) and it is unmodified. Expiry and reuse are
/// checked by the caller.
fn open_refresh_token(inner: &OAuthInner, token: &str) -> Option<RefreshGrant> {
    if token.len() > MAX_REFRESH_TOKEN_LENGTH {
        return None;
    }
    let (prefix, sealed) = token.split_once('.')?;
    if prefix != REFRESH_TOKEN_PREFIX {
        return None;
    }
    let sealed = URL_SAFE_NO_PAD.decode(sealed).ok()?;
    if sealed.len() <= AES_GCM_NONCE_BYTES {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(AES_GCM_NONCE_BYTES);
    let plaintext = inner
        .refresh_cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: inner.refresh_token_aad.as_bytes(),
            },
        )
        .ok()?;
    serde_json::from_slice(&plaintext).ok()
}

fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn valid_pkce_value(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == name).then(|| value.to_string())
            })
        })
}

async fn cleanup_expired(state: &OAuthState) {
    let now = Utc::now();
    state
        .inner
        .pending
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .completed
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .codes
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .access_tokens
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .refresh_families
        .write()
        .await
        .retain(|_, family| family.expires_at > now);
    let window_start = now - Duration::minutes(LOGIN_FAILURE_WINDOW_MINUTES);
    state
        .inner
        .login_failures
        .write()
        .await
        .retain(|_, attempts| {
            attempts.retain(|attempt| *attempt > window_start);
            !attempts.is_empty()
        });
}

async fn login_is_rate_limited(state: &OAuthState, email: &str) -> bool {
    cleanup_expired(state).await;
    state
        .inner
        .login_failures
        .read()
        .await
        .get(&token_hash(email))
        .is_some_and(|attempts| attempts.len() >= MAX_LOGIN_FAILURES_PER_ACCOUNT)
}

async fn record_login_failure(state: &OAuthState, email: &str) {
    state
        .inner
        .login_failures
        .write()
        .await
        .entry(token_hash(email))
        .or_default()
        .push(Utc::now());
}

async fn clear_login_failures(state: &OAuthState, email: &str) {
    state
        .inner
        .login_failures
        .write()
        .await
        .remove(&token_hash(email));
}

/// Trim an operator-supplied brand down to something safe to render, falling back
/// to `DEFAULT_BRAND` when it is blank. Length is capped so a stray value cannot
/// blow out the page title.
fn normalize_brand(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return DEFAULT_BRAND.to_string();
    }
    trimmed.chars().take(MAX_BRAND_LENGTH).collect()
}

/// Render a registered client's name for display, escaped.
///
/// Any client can register with any `client_name`, so this string is attacker
/// controlled and must never reach a page unescaped.
fn display_client_name(client_name: Option<&str>) -> String {
    client_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(escape_html)
        .unwrap_or_else(|| UNNAMED_CLIENT.to_string())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, http::header::SET_COOKIE, routing::post};
    use reqwest::{Client, redirect::Policy};
    use serde::Deserialize;
    use tokio::net::TcpListener;

    #[derive(Deserialize)]
    struct TestRegistrationResponse {
        client_id: String,
    }

    #[derive(Deserialize)]
    struct TestTokenResponse {
        access_token: String,
    }

    #[test]
    fn pkce_matches_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn only_https_or_loopback_redirects_are_allowed() {
        assert!(valid_redirect_uri("https://client.example/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:43210/callback"));
        assert!(!valid_redirect_uri("http://client.example/callback"));
        assert!(!valid_redirect_uri("javascript:alert(1)"));
    }

    fn test_client() -> RegisteredClient {
        RegisteredClient {
            redirect_uris: vec!["http://127.0.0.1:53682/callback".into()],
            client_name: Some("Test client".into()),
        }
    }

    #[test]
    fn client_ids_carry_their_registration() {
        let key = [7_u8; 32];
        let client = test_client();
        let client_id = issue_client_id(&key, &client).expect("small metadata is accepted");
        assert!(client_id.starts_with("dmc1."));
        assert_eq!(decode_client_id(&key, &client_id), Some(client));
    }

    #[test]
    fn client_ids_reject_tampering_and_foreign_keys() {
        let key = [7_u8; 32];
        let client_id = issue_client_id(&key, &test_client()).unwrap();
        let (signed, _) = client_id.rsplit_once('.').unwrap();

        // Signed by another server (or before a restart).
        assert_eq!(decode_client_id(&[8_u8; 32], &client_id), None);
        // Redirect URIs swapped for an attacker's, keeping the old tag.
        let forged = issue_client_id(
            &key,
            &RegisteredClient {
                redirect_uris: vec!["https://attacker.example/callback".into()],
                client_name: None,
            },
        )
        .unwrap();
        let forged_metadata = forged.split('.').nth(1).unwrap();
        let tag = client_id.rsplit_once('.').unwrap().1;
        assert_eq!(
            decode_client_id(&key, &format!("dmc1.{forged_metadata}.{tag}")),
            None
        );
        // Truncated or malformed.
        assert_eq!(decode_client_id(&key, signed), None);
        assert_eq!(decode_client_id(&key, &format!("{signed}.")), None);
        assert_eq!(
            decode_client_id(&key, &client_id.replacen("dmc1", "dmc2", 1)),
            None
        );
        assert_eq!(
            decode_client_id(&key, &"a".repeat(MAX_CLIENT_ID_LENGTH + 1)),
            None
        );
        assert_eq!(decode_client_id(&key, ""), None);
    }

    #[test]
    fn client_id_key_persists_across_restarts() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state/client-id.key");
        let first = load_or_create_key(&path)?;
        let client_id = issue_client_id(&first, &test_client()).unwrap();

        // A restart reads the same key, so the cached client_id still works.
        let second = load_or_create_key(&path)?;
        assert_eq!(first, second);
        assert_eq!(decode_client_id(&second, &client_id), Some(test_client()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
            let parent = std::fs::metadata(path.parent().unwrap())?;
            assert_eq!(parent.permissions().mode() & 0o777, 0o700);
        }

        std::fs::write(&path, b"short")?;
        assert!(load_or_create_key(&path).is_err());
        Ok(())
    }

    #[test]
    fn oversized_client_metadata_is_refused() {
        let client = RegisteredClient {
            redirect_uris: (0..10)
                .map(|i| format!("https://client.example/{i}/{}", "x".repeat(300)))
                .collect(),
            client_name: None,
        };
        assert_eq!(issue_client_id(&[7_u8; 32], &client), None);
    }

    #[tokio::test]
    async fn registration_has_no_capacity_limit_and_stores_nothing() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let state = OAuthState::new(OAuthConfig {
            public_url: base.clone(),
            docmost_base_url: "http://127.0.0.1:9".into(),
            brand: DEFAULT_BRAND.into(),
            browser_url: None,
            client_id_key_path: None,
            refresh_token_key_path: None,
        })?;
        let router = state.clone().routes();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = Client::builder().redirect(Policy::none()).build()?;

        // Well past the old 1,024-client cap.
        let mut last = None;
        for i in 0..1_100 {
            let response = client
                .post(format!("{base}/oauth/register"))
                .json(&json!({"redirect_uris": [format!("http://127.0.0.1:{}/cb", 1_000 + i)]}))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED);
            last = Some(response.json::<TestRegistrationResponse>().await?.client_id);
        }

        // The last registration still authorizes; a tampered one does not.
        let challenge = pkce_challenge("verifier-verifier-verifier-verifier-verifier");
        let authorize = |client_id: String| {
            client
                .get(format!("{base}/oauth/authorize"))
                .query(&[
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", "http://127.0.0.1:2099/cb"),
                    ("code_challenge", challenge.as_str()),
                    ("code_challenge_method", "S256"),
                ])
                .send()
        };
        let last = last.unwrap();
        assert_eq!(authorize(last.clone()).await?.status(), StatusCode::OK);
        let tampered = format!("{}A", last);
        let response = authorize(tampered).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.text().await?.contains("invalid_client"));

        server.abort();
        Ok(())
    }

    #[test]
    fn public_url_requires_https_outside_loopback() {
        assert!(normalize_public_url("https://mcp.example").is_ok());
        assert!(normalize_public_url("http://localhost:8787").is_ok());
        assert!(normalize_public_url("http://mcp.example").is_err());
        assert!(normalize_public_url("https://mcp.example/path").is_err());
        assert!(normalize_public_url("https://user@mcp.example").is_err());
    }

    #[test]
    fn brand_falls_back_to_docmost_and_is_bounded() {
        assert_eq!(normalize_brand(""), DEFAULT_BRAND);
        assert_eq!(normalize_brand("   "), DEFAULT_BRAND);
        assert_eq!(normalize_brand("  PREP Docs  "), "PREP Docs");
        assert_eq!(
            normalize_brand(&"x".repeat(500)).chars().count(),
            MAX_BRAND_LENGTH
        );
    }

    #[test]
    fn unnamed_clients_get_a_generic_label() {
        // The pages must never hardcode one client's name: this server is used from
        // Claude Code, Claude Desktop, Codex and Cursor alike.
        assert_eq!(display_client_name(None), UNNAMED_CLIENT);
        assert_eq!(display_client_name(Some("   ")), UNNAMED_CLIENT);
        assert_eq!(display_client_name(Some("Cursor")), "Cursor");
    }

    #[test]
    fn client_name_is_escaped_before_it_reaches_a_page() {
        // client_name is self-declared at registration, so any client can supply
        // markup. It lands in both the heading and the button label.
        let displayed = display_client_name(Some("<script>alert(1)</script>"));
        assert!(!displayed.contains('<'), "unescaped markup: {displayed}");
        assert_eq!(displayed, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn login_page_shows_the_configured_brand_and_no_vendor_name() {
        let page = render_login_page("request-1", "csrf-1", None, "PREP Docs");
        assert!(page.contains("Sign in to PREP Docs MCP"));
        assert!(page.contains("Use your PREP Docs account"));
        assert!(!page.contains("Codex"), "no client should be named here");
    }

    #[tokio::test]
    async fn native_login_validates_cookie_and_requires_consent_and_csrf() -> anyhow::Result<()> {
        async fn me(headers: HeaderMap) -> Response {
            match headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
            {
                Some("Bearer alice-session") => {
                    Json(json!({"data":{"user":{"email":"alice@example.com"}}})).into_response()
                }
                Some("Bearer bob-session") => {
                    Json(json!({"data":{"user":{"email":"bob@example.com"}}})).into_response()
                }
                _ => StatusCode::UNAUTHORIZED.into_response(),
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mock = tokio::spawn(async move {
            let _ = axum::serve(listener, Router::new().route("/api/users/me", post(me))).await;
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address_oauth = listener.local_addr()?;
        let base = format!("http://{address_oauth}");
        let state = OAuthState::new(OAuthConfig {
            public_url: base.clone(),
            docmost_base_url: format!("http://{address}"),
            brand: DEFAULT_BRAND.to_string(),
            browser_url: Some(base.clone()),
            client_id_key_path: None,
            refresh_token_key_path: None,
        })?;
        let server = {
            let router = state.clone().routes();
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            })
        };
        let client = Client::builder().redirect(Policy::none()).build()?;
        let registration: TestRegistrationResponse = client.post(format!("{base}/oauth/register")).json(&json!({"redirect_uris":["https://client.example/callback"],"client_name":"Native test"})).send().await?.json().await?;
        let metadata: serde_json::Value = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(
            metadata["authorization_endpoint"],
            format!("{base}/oauth/authorize")
        );
        let verifier = "a".repeat(64);
        let response = client
            .get(format!("{base}/oauth/authorize"))
            .query(&[
                ("client_id", registration.client_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", "https://client.example/callback"),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await?;
        let csrf_cookie = response.headers()[SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let wait_html = response.text().await?;
        assert!(wait_html.contains("href=\"/login\""));
        assert!(!wait_html.contains("name=\"password\""));
        assert!(!wait_html.contains("PREP"));
        assert!(state.inner.codes.read().await.is_empty());
        let request_id = state
            .inner
            .pending
            .read()
            .await
            .keys()
            .next()
            .unwrap()
            .clone();
        let csrf = csrf_cookie.split_once('=').unwrap().1;
        let resume = format!("{base}/oauth/resume?request_id={request_id}");
        assert_eq!(
            client.get(&resume).send().await?.status(),
            StatusCode::BAD_REQUEST
        );
        let invalid = client
            .get(&resume)
            .header(header::COOKIE, format!("{csrf_cookie}; authToken=forged"))
            .send()
            .await?
            .text()
            .await?;
        assert!(invalid.contains("Open Docmost sign in"));
        let cookie = format!("{csrf_cookie}; authToken=alice-session");
        let consent = client
            .get(&resume)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .text()
            .await?;
        assert!(consent.contains("<!--email_off-->alice@example.com<!--/email_off-->"));
        assert!(consent.contains("Native test"));
        assert!(!consent.contains("name=\"password\""));
        assert!(state.inner.codes.read().await.is_empty());
        let form = [("request_id", request_id.as_str()), ("csrf", csrf)];
        assert_eq!(
            client
                .post(format!("{base}/oauth/authorize"))
                .form(&form)
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .post(format!("{base}/oauth/authorize"))
                .header(header::COOKIE, &csrf_cookie)
                .form(&form)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        // Revalidate at POST and reject an account switch until fresh consent.
        let bob_cookie = format!("{csrf_cookie}; authToken=bob-session");
        assert_eq!(
            client
                .post(format!("{base}/oauth/authorize"))
                .header(header::COOKIE, &bob_cookie)
                .form(&form)
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let bob_consent = client
            .get(&resume)
            .header(header::COOKIE, &bob_cookie)
            .send()
            .await?
            .text()
            .await?;
        assert!(bob_consent.contains("bob@example.com"));
        let response = client
            .post(format!("{base}/oauth/authorize"))
            .header(
                header::COOKIE,
                format!("{csrf_cookie}; authToken=bob-session"),
            )
            .form(&form)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let grants = state.inner.codes.read().await;
        assert_eq!(grants.len(), 1);
        let grant = grants.values().next().unwrap();
        assert_eq!(grant.session.email, "bob@example.com");
        assert_eq!(grant.code_challenge, pkce_challenge(&verifier));
        drop(grants);
        mock.abort();
        server.abort();
        Ok(())
    }

    #[test]
    fn native_browser_origin_and_rendering_are_guarded() {
        let state = OAuthState::new(OAuthConfig {
            public_url: "https://mcp.example.com".into(),
            docmost_base_url: "http://docmost:3000".into(),
            brand: DEFAULT_BRAND.into(),
            browser_url: Some("https://docs.example.com".into()),
            client_id_key_path: None,
            refresh_token_key_path: None,
        })
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("mcp.example.com"));
        assert!(!native_host_matches(&state, &headers));
        headers.insert(header::HOST, HeaderValue::from_static("docs.example.com"));
        assert!(native_host_matches(&state, &headers));
        let session = AuthenticatedSession {
            base_url: "http://docmost:3000".into(),
            email: "<script>".into(),
            token: "secret".into(),
            expires_at: None,
        };
        let html = render_native_page("id", "csrf", Some(&session), "Docmost", Some("<script>"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("secret"));
    }
    #[tokio::test]
    async fn repeated_login_failures_lock_one_account_without_touching_others() {
        let state = OAuthState::new(OAuthConfig {
            public_url: "http://localhost:8787".to_string(),
            docmost_base_url: "http://localhost:3000".to_string(),
            brand: DEFAULT_BRAND.to_string(),
            browser_url: None,
            client_id_key_path: None,
            refresh_token_key_path: None,
        })
        .expect("state builds");

        for _ in 0..MAX_LOGIN_FAILURES_PER_ACCOUNT {
            record_login_failure(&state, "victim@example.com").await;
        }

        assert!(login_is_rate_limited(&state, "victim@example.com").await);
        // Lockout is per account, so one user cannot lock another out.
        assert!(!login_is_rate_limited(&state, "bystander@example.com").await);

        clear_login_failures(&state, "victim@example.com").await;
        assert!(!login_is_rate_limited(&state, "victim@example.com").await);
    }

    #[tokio::test]
    async fn oauth_tokens_are_bound_to_separate_docmost_accounts() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct MockLogin {
            email: String,
        }

        async fn mock_login(Json(login): Json<MockLogin>) -> Response {
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "exp": (Utc::now() + Duration::hours(2)).timestamp(),
                    "email": login.email
                }))
                .expect("payload serializes"),
            );
            let token = format!("header.{payload}.signature");
            let mut response = Json(json!({ "ok": true })).into_response();
            response.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("authToken={token}; Path=/; HttpOnly"))
                    .expect("cookie is valid"),
            );
            response
        }

        let docmost_listener = TcpListener::bind("127.0.0.1:0").await?;
        let docmost_address = docmost_listener.local_addr()?;
        let docmost_task = tokio::spawn(async move {
            let app = Router::new().route("/api/auth/login", post(mock_login));
            let _ = axum::serve(docmost_listener, app).await;
        });

        let oauth_listener = TcpListener::bind("127.0.0.1:0").await?;
        let oauth_address = oauth_listener.local_addr()?;
        let oauth_state = OAuthState::new(OAuthConfig {
            public_url: format!("http://{oauth_address}"),
            docmost_base_url: format!("http://{docmost_address}"),
            brand: DEFAULT_BRAND.to_string(),
            browser_url: None,
            client_id_key_path: None,
            refresh_token_key_path: None,
        })?;
        let oauth_task = {
            let app = oauth_state.clone().routes();
            tokio::spawn(async move {
                let _ = axum::serve(oauth_listener, app).await;
            })
        };

        let alice = authenticate_test_account(
            &oauth_state,
            oauth_address,
            "alice@example.com",
            "http://127.0.0.1:49123/callback",
        )
        .await?;
        let bob = authenticate_test_account(
            &oauth_state,
            oauth_address,
            "bob@example.com",
            "https://chatgpt.com/connector/oauth/test-callback",
        )
        .await?;

        assert_ne!(alice.access_token, bob.access_token);
        assert_eq!(
            oauth_state
                .access_session(&alice.access_token)
                .await
                .expect("alice session")
                .email,
            "alice@example.com"
        );
        assert_eq!(
            oauth_state
                .access_session(&bob.access_token)
                .await
                .expect("bob session")
                .email,
            "bob@example.com"
        );

        oauth_task.abort();
        docmost_task.abort();
        Ok(())
    }

    async fn authenticate_test_account(
        state: &OAuthState,
        oauth_address: std::net::SocketAddr,
        email: &str,
        callback: &str,
    ) -> anyhow::Result<TestTokenResponse> {
        let client = Client::builder().redirect(Policy::none()).build()?;
        let base = format!("http://{oauth_address}");
        let registration: TestRegistrationResponse = client
            .post(format!("{base}/oauth/register"))
            .json(&json!({
                "redirect_uris": [callback],
                "client_name": "test client"
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let verifier = random_token(32);
        let authorize = client
            .get(format!("{base}/oauth/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", registration.client_id.as_str()),
                ("redirect_uri", callback),
                ("state", "test-state"),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
                ("resource", state.inner.resource_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?;
        let cookie = authorize
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .expect("CSRF cookie")
            .to_string();
        let html = authorize.text().await?;
        let request_id = hidden_value(&html, "request_id").expect("request id");
        let csrf = hidden_value(&html, "csrf").expect("csrf token");

        let login_form = [
            ("request_id", request_id.as_str()),
            ("csrf", csrf.as_str()),
            ("email", email),
            ("password", "correct-password"),
        ];
        let authorized = client
            .post(format!("{base}/oauth/authorize"))
            .header(header::COOKIE, cookie)
            .form(&login_form)
            .send()
            .await?;
        assert_eq!(authorized.status(), StatusCode::OK);
        // A cross-origin HTTP redirect after a POST is blocked by Chrome when
        // the sign-in page has form-action 'self'. Both hosted and loopback
        // clients must get a committed document with an explicit callback link.
        assert!(authorized.headers().get(header::LOCATION).is_none());
        assert!(
            authorized.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()?
                .contains("form-action 'self'")
        );
        let authorized_html = authorized.text().await?;
        // The bridge names whichever client registered, never a hardcoded one.
        assert!(authorized_html.contains("Continue to test client"));
        let location = callback_href(&authorized_html).expect("authorization callback link");

        // Browsers can submit the form twice before following the first redirect.
        // The cleared CSRF cookie means the duplicate must replay the completed
        // callback bridge rather than trying to authorize the account again.
        let duplicate = client
            .post(format!("{base}/oauth/authorize"))
            .form(&login_form)
            .send()
            .await?;
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate_html = duplicate.text().await?;
        assert_eq!(
            callback_href(&duplicate_html).as_deref(),
            Some(location.as_str())
        );

        let redirect = Url::parse(&location)?;
        assert!(
            redirect
                .query_pairs()
                .any(|(key, value)| key == "state" && value == "test-state")
        );
        let code = redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .expect("authorization code");

        Ok(client
            .post(format!("{base}/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", registration.client_id.as_str()),
                ("redirect_uri", callback),
                ("code_verifier", verifier.as_str()),
                ("resource", state.inner.resource_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn hidden_value(html: &str, name: &str) -> Option<String> {
        let marker = format!("name=\"{name}\" value=\"");
        let remainder = html.split_once(&marker)?.1;
        Some(remainder.split_once('"')?.0.to_string())
    }

    fn callback_href(html: &str) -> Option<String> {
        let marker = "id=\"continue-to-client\" href=\"";
        let remainder = html.split_once(marker)?.1;
        Some(remainder.split_once('"')?.0.replace("&amp;", "&"))
    }

    // --- Sealed refresh tokens ---

    const TEST_CLIENT: &str = "test-client";

    fn refresh_test_state(
        docmost_base_url: &str,
        refresh_token_key_path: Option<PathBuf>,
    ) -> OAuthState {
        OAuthState::new(OAuthConfig {
            public_url: "http://localhost:8787".into(),
            docmost_base_url: docmost_base_url.into(),
            brand: DEFAULT_BRAND.into(),
            browser_url: None,
            refresh_token_key_path,
            client_id_key_path: None,
        })
        .expect("state builds")
    }

    fn test_session(token: &str) -> AuthenticatedSession {
        AuthenticatedSession {
            base_url: String::new(),
            email: "alice@example.com".into(),
            token: token.into(),
            expires_at: Some((Utc::now() + Duration::hours(2)).to_rfc3339()),
        }
    }

    fn test_refresh_grant() -> RefreshGrant {
        RefreshGrant {
            client_hash: token_hash(TEST_CLIENT),
            scope: DEFAULT_SCOPE.into(),
            email: "alice@example.com".into(),
            token: "alice-session".into(),
            session_expires_at: None,
            // Whole seconds: the sealed form keeps expiry to the second.
            expires_at: DateTime::from_timestamp((Utc::now() + Duration::hours(2)).timestamp(), 0)
                .unwrap(),
            family: "family-1".into(),
            generation: 1,
        }
    }

    async fn json_response(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        (status, serde_json::from_slice(&body).expect("JSON body"))
    }

    /// Issues tokens as a completed authorization would. Returns (access, refresh).
    async fn issue_test_tokens(state: &OAuthState, session_token: &str) -> (String, String) {
        let (status, body) = json_response(
            issue_tokens(
                state,
                token_hash(TEST_CLIENT),
                DEFAULT_SCOPE.into(),
                test_session(session_token),
                (random_token(16), 1),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["access_token"].as_str().unwrap().into(),
            body["refresh_token"].as_str().unwrap().into(),
        )
    }

    async fn refresh_with(
        state: &OAuthState,
        refresh_token: &str,
        client_id: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        json_response(
            exchange_refresh_token(
                state,
                TokenForm {
                    grant_type: "refresh_token".into(),
                    code: None,
                    redirect_uri: None,
                    client_id: client_id.map(Into::into),
                    code_verifier: None,
                    refresh_token: Some(refresh_token.into()),
                    resource: None,
                },
            )
            .await,
        )
        .await
    }

    /// A Docmost that accepts every session except those in `revoked`, and
    /// fails with 500 for `outage-session`.
    async fn spawn_session_docmost(
        revoked: Arc<std::sync::Mutex<HashSet<String>>>,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        async fn me(
            State(revoked): State<Arc<std::sync::Mutex<HashSet<String>>>>,
            headers: HeaderMap,
        ) -> Response {
            let token = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or_default()
                .to_string();
            if token == "outage-session" {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if token.is_empty() || revoked.lock().unwrap().contains(&token) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Json(json!({"data":{"user":{"email":"alice@example.com"}}})).into_response()
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let app = Router::new()
            .route("/api/users/me", post(me))
            .with_state(revoked);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, task))
    }

    #[test]
    fn sealed_refresh_tokens_round_trip_and_reject_tampering() {
        let state = refresh_test_state("http://docmost:3000", None);
        let grant = test_refresh_grant();
        let token = seal_refresh_token(&state.inner, &grant).expect("seals");
        assert!(token.starts_with("dmr1."));
        // Sealed, not merely encoded: the Docmost session is not readable.
        assert!(!token.contains("alice"));
        let decoded = URL_SAFE_NO_PAD.decode(&token[5..]).unwrap();
        assert!(!String::from_utf8_lossy(&decoded).contains("alice-session"));
        assert_eq!(
            open_refresh_token(&state.inner, &token),
            Some(grant.clone())
        );
        // A fresh nonce every time.
        assert_ne!(
            seal_refresh_token(&state.inner, &grant),
            Some(token.clone())
        );

        // Any modified byte fails authentication.
        let mut bytes = URL_SAFE_NO_PAD.decode(&token[5..]).unwrap();
        for index in [0, AES_GCM_NONCE_BYTES, bytes.len() / 2, bytes.len() - 1] {
            bytes[index] ^= 1;
            let tampered = format!("dmr1.{}", URL_SAFE_NO_PAD.encode(&bytes));
            assert_eq!(open_refresh_token(&state.inner, &tampered), None);
            bytes[index] ^= 1;
        }
        // Truncated, malformed, wrong version, oversized.
        assert_eq!(
            open_refresh_token(&state.inner, &token[..token.len() - 4]),
            None
        );
        assert_eq!(open_refresh_token(&state.inner, "dmr1."), None);
        assert_eq!(open_refresh_token(&state.inner, "dmr1.!!!"), None);
        assert_eq!(open_refresh_token(&state.inner, &token[5..]), None);
        assert_eq!(
            open_refresh_token(&state.inner, &token.replacen("dmr1", "dmr2", 1)),
            None
        );
        assert_eq!(
            open_refresh_token(
                &state.inner,
                &format!("dmr1.{}", "A".repeat(MAX_REFRESH_TOKEN_LENGTH))
            ),
            None
        );
        assert_eq!(open_refresh_token(&state.inner, ""), None);
    }

    #[test]
    fn refresh_tokens_only_open_under_their_key_and_deployment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let key_path = dir.path().join("refresh-token.key");
        let state = refresh_test_state("http://docmost:3000", Some(key_path.clone()));
        let token = seal_refresh_token(&state.inner, &test_refresh_grant()).unwrap();

        // Another server's key (or the key file deleted and regenerated).
        let other_key = refresh_test_state("http://docmost:3000", None);
        assert_eq!(open_refresh_token(&other_key.inner, &token), None);
        // Same key, but fronting another Docmost: the session is not for it.
        let other_docmost = refresh_test_state("http://other-docmost:3000", Some(key_path));
        assert_eq!(open_refresh_token(&other_docmost.inner, &token), None);
        Ok(())
    }

    #[test]
    fn refresh_key_persists_across_restarts() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state/refresh-token.key");
        let first = load_or_create_key(&path)?;
        assert_eq!(load_or_create_key(&path)?, first);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
            let parent = std::fs::metadata(path.parent().unwrap())?;
            assert_eq!(parent.permissions().mode() & 0o777, 0o700);
        }

        std::fs::write(&path, b"short")?;
        assert!(load_or_create_key(&path).is_err());
        let error = OAuthState::new(OAuthConfig {
            public_url: "http://localhost:8787".into(),
            docmost_base_url: "http://docmost:3000".into(),
            brand: DEFAULT_BRAND.into(),
            browser_url: None,
            refresh_token_key_path: Some(path),
            client_id_key_path: None,
        })
        .err()
        .expect("a wrong-length key is a startup error");
        assert!(error.to_string().contains("exactly 32 bytes"));
        Ok(())
    }

    #[tokio::test]
    async fn refresh_tokens_rotate_and_reuse_revokes_the_family() -> anyhow::Result<()> {
        let (docmost, task) = spawn_session_docmost(Default::default()).await?;
        let state = refresh_test_state(&docmost, None);
        let (_, first) = issue_test_tokens(&state, "alice-session").await;

        let (status, body) = refresh_with(&state, &first, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let second = body["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(second, first);
        let access = body["access_token"].as_str().unwrap();
        assert_eq!(
            state.access_session(access).await.unwrap().email,
            "alice@example.com"
        );

        // Replaying the spent token fails, and because it means a copy is
        // out there, the current token stops working too.
        let (status, body) = refresh_with(&state, &first, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        let (status, body) = refresh_with(&state, &second, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");

        // Other authorizations are unaffected.
        let (_, other) = issue_test_tokens(&state, "alice-session").await;
        assert_eq!(refresh_with(&state, &other, None).await.0, StatusCode::OK);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn refresh_token_survives_a_restart() -> anyhow::Result<()> {
        let (docmost, task) = spawn_session_docmost(Default::default()).await?;
        let dir = tempfile::tempdir()?;
        let key_path = dir.path().join("refresh-token.key");
        let before = refresh_test_state(&docmost, Some(key_path.clone()));
        let (access, refresh) = issue_test_tokens(&before, "alice-session").await;
        drop(before);

        // A new process: no grants in memory, same key file.
        let after = refresh_test_state(&docmost, Some(key_path));
        assert!(after.access_session(&access).await.is_none());
        let (status, body) = refresh_with(&after, &refresh, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let session = after
            .access_session(body["access_token"].as_str().unwrap())
            .await
            .expect("new access token works");
        assert_eq!(session.email, "alice@example.com");
        assert_eq!(session.token, "alice-session");
        assert_eq!(session.base_url, after.inner.docmost_base_url);
        // Single use resumes from the first redemption after the restart.
        assert_eq!(
            refresh_with(&after, &refresh, Some(TEST_CLIENT)).await.0,
            StatusCode::BAD_REQUEST
        );
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn expired_refresh_tokens_are_refused() -> anyhow::Result<()> {
        let (docmost, task) = spawn_session_docmost(Default::default()).await?;
        let state = refresh_test_state(&docmost, None);
        let expired = seal_refresh_token(
            &state.inner,
            &RefreshGrant {
                expires_at: Utc::now() - Duration::seconds(1),
                ..test_refresh_grant()
            },
        )
        .unwrap();
        let (status, body) = refresh_with(&state, &expired, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn refresh_tokens_are_bound_to_their_client() -> anyhow::Result<()> {
        let (docmost, task) = spawn_session_docmost(Default::default()).await?;
        let state = refresh_test_state(&docmost, None);
        let (_, refresh) = issue_test_tokens(&state, "alice-session").await;
        let (status, body) = refresh_with(&state, &refresh, Some("another-client")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        // The refusal did not spend the token for its real client.
        assert_eq!(
            refresh_with(&state, &refresh, Some(TEST_CLIENT)).await.0,
            StatusCode::OK
        );
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn refresh_revalidates_the_docmost_session() -> anyhow::Result<()> {
        let revoked = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let (docmost, task) = spawn_session_docmost(revoked.clone()).await?;
        let state = refresh_test_state(&docmost, None);
        let (_, alice) = issue_test_tokens(&state, "alice-session").await;
        let (_, bob) = issue_test_tokens(&state, "bob-session").await;

        // Alice signs out of Docmost: her agent is cut off at its next refresh.
        revoked.lock().unwrap().insert("alice-session".to_string());
        let (status, body) = refresh_with(&state, &alice, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(
            refresh_with(&state, &bob, Some(TEST_CLIENT)).await.0,
            StatusCode::OK
        );

        // An outage is not a revocation: Docmost still checks the session on
        // every tool call, so refresh goes ahead.
        let (_, outage) = issue_test_tokens(&state, "outage-session").await;
        assert_eq!(
            refresh_with(&state, &outage, Some(TEST_CLIENT)).await.0,
            StatusCode::OK
        );
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn revoking_a_session_revokes_its_refresh_families() -> anyhow::Result<()> {
        let revoked = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let (docmost, task) = spawn_session_docmost(revoked.clone()).await?;
        let state = refresh_test_state(&docmost, None);
        let (alice_access, alice) = issue_test_tokens(&state, "alice-session").await;
        let (_, bob) = issue_test_tokens(&state, "bob-session").await;

        // A tool call saw Docmost reject Alice's session. Even though Docmost
        // would now answer for it (the check is not what stops this), her
        // sealed refresh token is dead for the life of the process.
        state
            .revoke_session(&OAuthState::session_fingerprint(&test_session(
                "alice-session",
            )))
            .await;
        assert!(state.access_session(&alice_access).await.is_none());
        let (status, body) = refresh_with(&state, &alice, Some(TEST_CLIENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(
            refresh_with(&state, &bob, Some(TEST_CLIENT)).await.0,
            StatusCode::OK
        );

        // A rejection discovered at refresh revokes the same way: the
        // session's live access tokens go too.
        let (carol_access, carol) = issue_test_tokens(&state, "carol-session").await;
        revoked.lock().unwrap().insert("carol-session".to_string());
        assert_eq!(
            refresh_with(&state, &carol, Some(TEST_CLIENT)).await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(state.access_session(&carol_access).await.is_none());
        task.abort();
        Ok(())
    }
}
