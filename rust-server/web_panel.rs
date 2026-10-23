use crate::model::secret_eq;
use crate::{
    App, lock_unpoison, log_event,
    model::{
        self, ClientGroup, PasswordEntry, RoutingRule, is_expired, now, random_password,
        random_token,
    },
    protocol, read_unpoison,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct WebState {
    app: Arc<App>,
}

#[derive(Deserialize)]
struct LoginRequest {
    user: String,
    pass: String,
}

#[derive(Deserialize)]
struct CreateClientRequest {
    name: String,
    days: i64,
    #[serde(default)]
    workers: Option<u32>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    vk_token: bool,
    #[serde(default, alias = "dtls_port")]
    peer_port: Option<u16>,
    #[serde(default)]
    local_port: Option<u16>,
    #[serde(default)]
    group_id: Option<String>,
}

fn validate_workers(workers: Option<u32>) -> Result<Option<u32>, &'static str> {
    match workers {
        None | Some(0) => Ok(None),
        Some(w) if (3..=100).contains(&w) => Ok(Some(w)),
        _ => Err("workers must be 0 (default) or between 3 and 100"),
    }
}

#[derive(Deserialize)]
struct ExtendClientRequest {
    days: i64,
}

#[derive(Deserialize)]
struct SettingsRequest {
    #[serde(default)]
    main_password: Option<String>,
    #[serde(default)]
    dns_provider: Option<String>,
    #[serde(default)]
    dns_primary: Option<String>,
    #[serde(default)]
    dns_secondary: Option<String>,
    #[serde(default)]
    auto_restart_interval_hours: Option<u8>,
    #[serde(default)]
    vk_token: Option<String>,
    #[serde(default)]
    vk_hashes: Option<String>,
}

#[derive(Clone, Copy)]
struct DnsProvider {
    id: &'static str,
    primary: &'static str,
    secondary: &'static str,
}

const DNS_PROVIDERS: [DnsProvider; 13] = [
    DnsProvider {
        id: "yandex",
        primary: "77.88.8.8",
        secondary: "77.88.8.1",
    },
    DnsProvider {
        id: "cloudflare",
        primary: "1.1.1.1",
        secondary: "1.0.0.1",
    },
    DnsProvider {
        id: "google",
        primary: "8.8.8.8",
        secondary: "8.8.4.4",
    },
    DnsProvider {
        id: "adguard",
        primary: "94.140.14.14",
        secondary: "94.140.15.14",
    },
    DnsProvider {
        id: "xbox",
        primary: "111.88.96.54",
        secondary: "111.88.96.55",
    },
    DnsProvider {
        id: "comms",
        primary: "83.220.169.155",
        secondary: "212.109.195.93",
    },
    DnsProvider {
        id: "geohide",
        primary: "193.233.112.67",
        secondary: "193.233.112.88",
    },
    DnsProvider {
        id: "quad9",
        primary: "9.9.9.9",
        secondary: "149.112.112.112",
    },
    DnsProvider {
        id: "opendns",
        primary: "208.67.222.222",
        secondary: "208.67.220.220",
    },
    DnsProvider {
        id: "rostelecom",
        primary: "95.189.32.74",
        secondary: "195.208.5.1",
    },
    DnsProvider {
        id: "nextdns",
        primary: "45.90.28.181",
        secondary: "45.90.30.181",
    },
    DnsProvider {
        id: "bizone",
        primary: "195.208.6.1",
        secondary: "195.208.7.1",
    },
    DnsProvider {
        id: "nsdi",
        primary: "195.208.4.1",
        secondary: "195.208.5.1",
    },
];

fn dns_provider_by_id(id: &str) -> Option<DnsProvider> {
    DNS_PROVIDERS
        .iter()
        .copied()
        .find(|provider| provider.id == id)
}

pub(crate) fn dns_provider_is_known(id: &str) -> bool {
    dns_provider_by_id(id).is_some()
}

pub(crate) fn dns_provider_id(dns: &str) -> Option<&'static str> {
    DNS_PROVIDERS
        .iter()
        .find(|provider| dns == format!("{},{}", provider.primary, provider.secondary))
        .map(|provider| provider.id)
}

fn provider_dns(provider: DnsProvider) -> String {
    format!("{},{}", provider.primary, provider.secondary)
}

pub(crate) fn provider_dns_by_id(id: &str) -> Option<String> {
    dns_provider_by_id(id).map(provider_dns)
}

fn manual_dns(primary: Option<&str>, secondary: Option<&str>) -> Result<String, &'static str> {
    let Some(primary) = primary else {
        return Err("primary DNS is required");
    };
    let primary = primary.trim();
    let secondary = secondary.unwrap_or_default().trim();
    if primary.is_empty() {
        return Err("primary DNS is required");
    }
    if primary.parse::<Ipv4Addr>().is_err()
        || (!secondary.is_empty() && secondary.parse::<Ipv4Addr>().is_err())
    {
        return Err("DNS must be a valid IPv4 address");
    }
    Ok(if secondary.is_empty() {
        primary.to_owned()
    } else {
        format!("{primary},{secondary}")
    })
}

pub(crate) fn deploy_dns_profile_or_yandex(existing_dns: &str) -> String {
    let addresses: Vec<_> = existing_dns
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .collect();
    if addresses
        .iter()
        .any(|&a| a == "95.182.120.241" || a == "37.230.192.51")
    {
        return "193.233.112.67,193.233.112.88".to_owned();
    }
    if addresses
        .iter()
        .any(|&a| a == "111.88.96.50" || a == "111.88.96.51")
    {
        return "111.88.96.54,111.88.96.55".to_owned();
    }
    let first = addresses.first().copied();
    let selected = DNS_PROVIDERS
        .iter()
        .filter_map(|provider| {
            let matches = addresses
                .iter()
                .filter(|address| **address == provider.primary || **address == provider.secondary)
                .count();
            (matches > 0).then_some((
                provider,
                (
                    matches,
                    usize::from(first == Some(provider.primary)),
                    usize::from(first == Some(provider.secondary)),
                ),
            ))
        })
        .max_by_key(|(_, score)| *score)
        .map(|(provider, _)| *provider)
        .unwrap_or(DNS_PROVIDERS[0]);
    provider_dns(selected)
}

const WEB_BODY_LIMIT_BYTES: usize = 16 * 1024;
const MAX_LOGIN_FIELD_BYTES: usize = 256;
const MAX_CLIENT_NAME_BYTES: usize = 128;
const MAX_PROXY_PROFILE_NAME_BYTES: usize = 64;

fn validate_text_field(
    value: &str,
    max_bytes: usize,
    message: &'static str,
) -> Result<(), &'static str> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(message);
    }
    Ok(())
}

fn validate_login_request(request: &LoginRequest) -> Result<(), &'static str> {
    validate_text_field(
        &request.user,
        MAX_LOGIN_FIELD_BYTES,
        "login fields are too long or invalid",
    )?;
    validate_text_field(
        &request.pass,
        MAX_LOGIN_FIELD_BYTES,
        "login fields are too long or invalid",
    )
}

fn validate_client_name(name: &str) -> Result<(), &'static str> {
    validate_text_field(
        name,
        MAX_CLIENT_NAME_BYTES,
        "client name is too long or invalid",
    )
}

fn validate_proxy_profile_name(name: &str) -> Result<(), &'static str> {
    validate_text_field(
        name,
        MAX_PROXY_PROFILE_NAME_BYTES,
        "proxy profile name is too long or invalid",
    )
}

#[derive(Serialize)]
struct ClientInfo {
    password: String,
    down: i64,
    up: i64,
    expires: i64,
    active: bool,
    active_sessions: usize,
    vk_hash: String,
    ports: String,
    ip: String,
    name: String,
    vk_hashes: String,
    vk_token: bool,
    peer_port: u16,
    local_port: u16,
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    routing_rule_id: String,
    #[serde(flatten)]
    links: ImportLinks,
    #[serde(default)]
    sub_uuid: String,
    #[serde(default)]
    workers: Option<u32>,
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

pub const CSQTT_CIPHER_KEY_SEED: &str = "csqtt-chiper-key";

pub fn encrypt_csqtt_link(payload: &str) -> String {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    let key_hash = Sha256::digest(CSQTT_CIPHER_KEY_SEED.as_bytes());
    let unbound = match UnboundKey::new(&AES_256_GCM, &key_hash) {
        Ok(k) => k,
        Err(_) => {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
            return format!("csqtt://{b64}");
        }
    };
    let key = LessSafeKey::new(unbound);

    let mut iv = [0u8; 12];
    type HmacSha256 = Hmac<Sha256>;
    if let Ok(mut mac) = HmacSha256::new_from_slice(&key_hash) {
        mac.update(payload.as_bytes());
        let result = mac.finalize().into_bytes();
        iv.copy_from_slice(&result[..12]);
    } else {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut iv);
    }
    let nonce = match Nonce::try_assume_unique_for_key(&iv) {
        Ok(n) => n,
        Err(_) => {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
            return format!("csqtt://{b64}");
        }
    };

    let mut in_out = payload.as_bytes().to_vec();
    if key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .is_err()
    {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        return format!("csqtt://{b64}");
    }

    let mut combined = Vec::with_capacity(12 + in_out.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(&in_out);

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined);
    format!("csqtt://{b64}")
}

#[allow(dead_code)]
pub fn decrypt_csqtt_link(raw_link: &str) -> Option<String> {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let payload = raw_link.trim().strip_prefix("csqtt://")?.trim();
    let clean = payload.replace(['\n', '\r'], "");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&clean))
        .ok()?;

    if bytes.len() >= 28 {
        let key_hash = Sha256::digest(CSQTT_CIPHER_KEY_SEED.as_bytes());
        if let Ok(unbound) = UnboundKey::new(&AES_256_GCM, &key_hash) {
            let key = LessSafeKey::new(unbound);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&bytes[..12]);
            if let Ok(nonce) = Nonce::try_assume_unique_for_key(&iv) {
                let mut ciphertext = bytes[12..].to_vec();
                if let Ok(decrypted) = key.open_in_place(nonce, Aad::empty(), &mut ciphertext)
                    && let Ok(s) = String::from_utf8(decrypted.to_vec())
                {
                    return Some(s);
                }
            }
        }
    }

    None
}

fn make_client_link(
    host: &str,
    port: u16,
    password: &str,
    vk_hashes: &str,
    vk_token: bool,
    shared_token: &str,
) -> String {
    let mut payload = format!(
        "connect?v=2&host={}&peer={}",
        url_encode(host),
        if port == 0 { 46000 } else { port },
    );
    if !password.is_empty() {
        payload.push_str("&password=");
        payload.push_str(&url_encode(password));
    }
    let hashes: Vec<&str> = vk_hashes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if !hashes.is_empty() {
        payload.push_str("&hashes=");
        payload.push_str(
            &hashes
                .iter()
                .map(|h| url_encode(h))
                .collect::<Vec<_>>()
                .join("+"),
        );
    } else if vk_token && !shared_token.is_empty() {
        payload.push_str("&token=");
        payload.push_str(&url_encode(shared_token));
    }
    encrypt_csqtt_link(&payload)
}

#[inline]
fn make_main_link(host: &str, port: u16, db: &model::Database) -> String {
    let vk_hashes = if db.main_vk_hashes.is_empty() {
        &db.vk_hashes
    } else {
        &db.main_vk_hashes
    };
    make_client_link(
        host,
        port,
        &db.main_password,
        vk_hashes,
        db.main_vk_token_enabled,
        &db.vk_access_token,
    )
}

#[inline]
fn make_entry_link(
    host: &str,
    port: u16,
    password: &str,
    entry: &model::PasswordEntry,
    shared_token: &str,
) -> String {
    make_client_link(
        host,
        port,
        password,
        &entry.vk_hashes,
        entry.vk_token_enabled,
        shared_token,
    )
}

const CAESAR_SHIFT: u8 = 47;
pub(crate) const MAX_WEB_SESSIONS: usize = 256;
pub(crate) const MAX_LOGIN_LIMITS: usize = 4_096;
const MAX_WEB_CONNECTIONS: usize = 64;

fn caesar_decode(value: &str) -> String {
    if let Some(rest) = value.strip_prefix("c1:")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest)
    {
        let decoded: Vec<u8> = bytes.iter().map(|b| b.wrapping_sub(CAESAR_SHIFT)).collect();
        if let Ok(s) = String::from_utf8(decoded) {
            return s;
        }
    }
    value.to_owned()
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn cookie_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter_map(|part| part.strip_prefix("csqtt_session=").map(str::to_owned))
        .collect()
}

fn authorized(app: &App, headers: &HeaderMap) -> bool {
    if cookie_tokens(headers).iter().any(|token| {
        app.web_sessions
            .get(&hash_token(token))
            .map(|expiry| *expiry > now())
            .unwrap_or(false)
    }) {
        return true;
    }

    if let Some(key) = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        && !key.is_empty()
    {
        if secret_eq(key, &app.web_pass) || secret_eq(key, &app.startup_main_password) {
            return true;
        }
        if let Ok(db) = app.db.try_read()
            && secret_eq(key, &db.main_password)
        {
            return true;
        }
        if app
            .web_sessions
            .get(&hash_token(key))
            .is_some_and(|expiry| *expiry > now())
        {
            return true;
        }
    }

    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        && let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
    {
        let token = token.trim();
        if !token.is_empty() {
            if secret_eq(token, &app.web_pass) || secret_eq(token, &app.startup_main_password) {
                return true;
            }
            if let Ok(db) = app.db.try_read()
                && secret_eq(token, &db.main_password)
            {
                return true;
            }
            if app
                .web_sessions
                .get(&hash_token(token))
                .is_some_and(|expiry| *expiry > now())
            {
                return true;
            }
        }
    }

    false
}

async fn auth_middleware(
    State(state): State<WebState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if authorized(&state.app, request.headers()) {
        return next.run(request).await;
    }
    let has_auth_header = request.headers().contains_key("x-api-key")
        || request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.starts_with("Bearer ") || s.starts_with("bearer "))
            .unwrap_or(false)
        || !cookie_tokens(request.headers()).is_empty();

    if !has_auth_header {
        if let Some(token) = request.extensions().get::<Arc<StealthAbortController>>() {
            token.abort();
        }
        return stealth_abort_response();
    }

    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if !cookie_tokens(request.headers()).is_empty() {
        response.headers_mut().insert(
            header::SET_COOKIE,
            expired_session_cookie().parse().unwrap(),
        );
    }
    response
}

fn expired_session_cookie() -> &'static str {
    "csqtt_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"
}

const STEALTH_ABORT_HEADER: &str = "x-csqtt-stealth-rst";

fn stealth_abort_response() -> Response {
    (
        StatusCode::OK,
        [
            (header::HeaderName::from_static(STEALTH_ABORT_HEADER), "1"),
            (header::CONNECTION, "close"),
        ],
        "",
    )
        .into_response()
}

fn render_root(state: &WebState, headers: &HeaderMap) -> Response {
    if authorized(&state.app, headers) {
        let mut response = Html(render_web_html(PANEL_HTML)).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        );
        return response;
    }
    let mut response = Html(render_web_html(LOGIN_HTML)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    if !cookie_tokens(headers).is_empty() {
        response.headers_mut().insert(
            header::SET_COOKIE,
            expired_session_cookie().parse().unwrap(),
        );
    }
    response
}

async fn panel_root(State(state): State<WebState>, headers: HeaderMap) -> Response {
    render_root(&state, &headers)
}

async fn favicon() -> Response {
    pwa_response(PWA_ICON_SVG, "image/svg+xml", "public, max-age=604800")
}

async fn fallback_reject(token: Option<Extension<Arc<StealthAbortController>>>) -> Response {
    if let Some(Extension(controller)) = token {
        controller.abort();
    }
    stealth_abort_response()
}

fn pwa_response(
    body: impl IntoResponse,
    content_type: &'static str,
    cache_control: &'static str,
) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(cache_control),
    );
    response
}

fn pwa_binary_response(
    body: Vec<u8>,
    content_type: &'static str,
    cache_control: &'static str,
) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(cache_control),
    );
    response
}

async fn root_with_secret(
    State(state): State<WebState>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    if authorized(&state.app, &headers) {
        let secret = state.app.web_secret_path.trim().trim_matches('/');
        let target = if secret.is_empty() {
            "/".to_string()
        } else {
            format!("/{}/", secret)
        };
        return Redirect::temporary(&target).into_response();
    }
    fallback_reject(token).await
}

async fn pwa_manifest(State(state): State<WebState>) -> Response {
    let secret = state.app.web_secret_path.trim().trim_matches('/');
    if secret.is_empty() {
        pwa_response(
            PWA_MANIFEST,
            "application/manifest+json; charset=utf-8",
            "no-cache",
        )
    } else {
        let prefix = format!("/{}", secret);
        let base = format!("{}/", prefix);
        let manifest = PWA_MANIFEST
            .replace("\"id\": \"/\"", &format!("\"id\": \"{}\"", base))
            .replace(
                "\"start_url\": \"/\"",
                &format!("\"start_url\": \"{}\"", base),
            )
            .replace("\"scope\": \"/\"", &format!("\"scope\": \"{}\"", base))
            .replace(
                "\"/pwa-icon-192.png\"",
                &format!("\"{}/pwa-icon-192.png\"", prefix),
            )
            .replace(
                "\"/pwa-icon-512.png\"",
                &format!("\"{}/pwa-icon-512.png\"", prefix),
            )
            .replace("\"/pwa-icon.svg\"", &format!("\"{}/pwa-icon.svg\"", prefix));
        pwa_response(
            manifest,
            "application/manifest+json; charset=utf-8",
            "no-cache",
        )
    }
}

async fn pwa_service_worker() -> Response {
    let mut response = pwa_response(
        PWA_SERVICE_WORKER,
        "application/javascript; charset=utf-8",
        "no-cache",
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("service-worker-allowed"),
        header::HeaderValue::from_static("/"),
    );
    response
}

async fn pwa_icon() -> Response {
    pwa_response(PWA_ICON_SVG, "image/svg+xml", "public, max-age=604800")
}

async fn pwa_icon_192() -> Response {
    pwa_binary_response(
        PWA_ICON_192_PNG.clone(),
        "image/png",
        "public, max-age=604800",
    )
}

async fn pwa_icon_512() -> Response {
    pwa_binary_response(
        PWA_ICON_512_PNG.clone(),
        "image/png",
        "public, max-age=604800",
    )
}

async fn qrcode_js() -> Response {
    pwa_response(
        QRCODE_JS,
        "application/javascript; charset=utf-8",
        "public, max-age=604800, immutable",
    )
}

async fn login(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if let Err(message) = validate_login_request(&request) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    let source = addr.ip().to_string();
    if let Ok(forwarded) = std::env::var("CSQTT_TRUST_XFF")
        && (forwarded == "1" || forwarded.eq_ignore_ascii_case("true"))
        && let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    {
        log_event(
            &state.app,
            "INFO",
            "AUTH",
            &format!("Login attempt from {source} (XFF: {forwarded})"),
        );
    }

    let current = now();
    if let Some(value) = state.app.login_limits.get(&source)
        && value.1 > current
        && value.0 >= 3
    {
        return (StatusCode::TOO_MANY_REQUESTS, "too many attempts").into_response();
    }

    let user = caesar_decode(&request.user);
    let pass = caesar_decode(&request.pass);
    let valid = secret_eq(&user, &state.app.web_user) & secret_eq(&pass, &state.app.web_pass);

    if !valid {
        if !state.record_failed_login(source, current) {
            return (StatusCode::TOO_MANY_REQUESTS, "too many login sources").into_response();
        }
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    state.app.login_limits.remove(&source);
    let token = random_token(32);
    if !state.web_session_insert(token.clone()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many active web sessions",
        )
            .into_response();
    }
    let cookie =
        format!("csqtt_session={token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax; Secure");
    let mut response = (StatusCode::OK, [(header::SET_COOKIE, cookie)], "ok").into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    response
}

impl WebState {
    fn record_failed_login(&self, source: String, current: i64) -> bool {
        let _admission = lock_unpoison(&self.app.web_auth_admission);
        self.app.login_limits.retain(|_, value| value.1 > current);
        if !self.app.login_limits.contains_key(&source)
            && self.app.login_limits.len() >= MAX_LOGIN_LIMITS
        {
            return false;
        }
        self.app
            .login_limits
            .entry(source)
            .and_modify(|value| {
                if value.1 <= current {
                    *value = (1, current + 180);
                } else {
                    value.0 = value.0.saturating_add(1);
                }
            })
            .or_insert((1, current + 180));
        true
    }

    fn web_session_insert(&self, token: String) -> bool {
        let _admission = lock_unpoison(&self.app.web_auth_admission);
        let current = now();
        self.app.web_sessions.retain(|_, expiry| *expiry > current);
        if self.app.web_sessions.len() >= MAX_WEB_SESSIONS {
            return false;
        }
        let key = hash_token(&token);
        self.app.web_sessions.insert(key, current + 86400);
        true
    }
}

async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let tokens = cookie_tokens(&headers);
    if !tokens.is_empty() {
        for token in &tokens {
            state.app.web_sessions.remove(&hash_token(token));
        }
    }
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expired_session_cookie())],
        "ok",
    )
        .into_response()
}

async fn logout_all(State(state): State<WebState>) -> Response {
    state.app.web_sessions.clear();
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expired_session_cookie())],
        "ok",
    )
        .into_response()
}

async fn refresh_credentials_report(state: &WebState) -> Result<(), String> {
    match crate::protocol::refresh_credentials(&state.app).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let message = format!("{error:#}");
            log_event(
                &state.app,
                "ERROR",
                "AUTH",
                &format!("Change saved but credential reload failed: {message}"),
            );
            Err(message)
        }
    }
}

async fn wait_for_persistence(state: &WebState, revision: u64) -> Result<(), Response> {
    match tokio::time::timeout(
        Duration::from_secs(15),
        state.app.db_persistence.wait(revision),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            eprintln!("[WEB] Failed to persist database mutation: {error:#}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist change",
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            "database persistence is taking too long; refresh before retrying",
        )
            .into_response()),
    }
}

fn proc_kib(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn read_proc_text<'a>(path: &str, buffer: &'a mut [u8]) -> Option<&'a str> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.read(buffer).ok()?;
    std::str::from_utf8(&buffer[..len]).ok()
}

#[derive(Clone, Copy, Default)]
struct ProcessMemory {
    rss: u64,
    peak: u64,
    anonymous: u64,
    file: u64,
    shared: u64,
    swap: u64,
}

fn process_memory(text: &str) -> ProcessMemory {
    ProcessMemory {
        rss: proc_kib(text, "VmRSS:").unwrap_or(0),
        peak: proc_kib(text, "VmHWM:").unwrap_or(0),
        anonymous: proc_kib(text, "RssAnon:").unwrap_or(0),
        file: proc_kib(text, "RssFile:").unwrap_or(0),
        shared: proc_kib(text, "RssShmem:").unwrap_or(0),
        swap: proc_kib(text, "VmSwap:").unwrap_or(0),
    }
}

#[derive(Clone, Copy, Default)]
struct ProcessMemoryRollup {
    pss: u64,
    pss_anon: u64,
    anonymous: u64,
    file: u64,
    shmem: u64,
    private: u64,
    shared: u64,
    swap_pss: u64,
}

fn process_memory_rollup(text: &str) -> ProcessMemoryRollup {
    let private_clean = proc_kib(text, "Private_Clean:").unwrap_or(0);
    let private_dirty = proc_kib(text, "Private_Dirty:").unwrap_or(0);
    let shared_clean = proc_kib(text, "Shared_Clean:").unwrap_or(0);
    let shared_dirty = proc_kib(text, "Shared_Dirty:").unwrap_or(0);
    ProcessMemoryRollup {
        pss: proc_kib(text, "Pss:").unwrap_or(0),
        pss_anon: proc_kib(text, "Pss_Anon:").unwrap_or(0),
        anonymous: proc_kib(text, "Anonymous:").unwrap_or(0),
        file: proc_kib(text, "Pss_File:").unwrap_or(0),
        shmem: proc_kib(text, "Pss_Shmem:").unwrap_or(0),
        private: private_clean.saturating_add(private_dirty),
        shared: shared_clean.saturating_add(shared_dirty),
        swap_pss: proc_kib(text, "SwapPss:").unwrap_or(0),
    }
}

#[derive(Default)]
struct SystemStatsCache {
    sampled_at: Option<Instant>,
    process_memory: ProcessMemory,
    process_rollup: ProcessMemoryRollup,
    total_ram: u64,
}

static SYSTEM_STATS_CACHE: LazyLock<Mutex<SystemStatsCache>> =
    LazyLock::new(|| Mutex::new(SystemStatsCache::default()));
const SYSTEM_STATS_CACHE_TTL: Duration = Duration::from_secs(60);

fn cached_system_stats() -> (ProcessMemory, ProcessMemoryRollup, u64) {
    let mut cache = lock_unpoison(&SYSTEM_STATS_CACHE);
    let refresh = cache
        .sampled_at
        .is_none_or(|sampled_at| sampled_at.elapsed() >= SYSTEM_STATS_CACHE_TTL);
    if refresh {
        let mut buffer = [0_u8; 4096];
        cache.process_memory = read_proc_text("/proc/self/status", &mut buffer)
            .map(process_memory)
            .unwrap_or_default();
        cache.process_rollup = read_proc_text("/proc/self/smaps_rollup", &mut buffer)
            .map(process_memory_rollup)
            .unwrap_or_default();
        cache.total_ram = read_proc_text("/proc/meminfo", &mut buffer)
            .and_then(|text| proc_kib(text, "MemTotal:"))
            .unwrap_or(0);
        cache.sampled_at = Some(Instant::now());
    }
    (cache.process_memory, cache.process_rollup, cache.total_ram)
}

fn format_memory_kib(kib: u64) -> String {
    let (value, unit) = if kib >= 1024 * 1024 {
        (kib as f64 / (1024.0 * 1024.0), "GB")
    } else {
        (kib as f64 / 1024.0, "MB")
    };
    let mut value = format!("{value:.2}");
    while value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    format!("{value} {unit}")
}

fn format_total_memory_kib(kib: u64) -> String {
    if kib >= 1024 * 1024 {
        let mut value = format!("{:.1}", kib as f64 / (1024.0 * 1024.0));
        if value.ends_with(".0") {
            value.truncate(value.len() - 2);
        }
        format!("{value} GB")
    } else {
        format!("{} MB", (kib + 512) / 1024)
    }
}

async fn stats(State(state): State<WebState>, _headers: HeaderMap) -> impl IntoResponse {
    let (process_memory, process_rollup, total_ram) = cached_system_stats();
    let io = *read_unpoison(&protocol::GLOBAL_IO_COUNTERS);

    let cpu_total = state.app.cpu_percent.load(Ordering::Relaxed);
    let cpu_cores = state.app.cpu_cores.load(Ordering::Relaxed).max(1);
    let cpu_capacity = cpu_cores.saturating_mul(100);
    let cpu_normalized = cpu_total
        .saturating_mul(100)
        .checked_div(cpu_capacity)
        .unwrap_or(0)
        .min(100);
    let log_ring_bytes = crate::lock_unpoison(&state.app.logs)
        .iter()
        .map(String::len)
        .sum::<usize>();
    let db = state.app.db.read().await;
    let (
        local_proxy_active,
        local_proxy_tcp_sessions,
        local_proxy_udp_flows,
        local_proxy_tcp_peak,
        local_proxy_udp_peak,
        local_proxy_tcp_total,
        local_proxy_udp_total,
    ) = {
        let route = state.app.proxy_route.read().await;
        let active = route.as_ref().is_some_and(|route| route.is_alive());
        let proxy_stats = route
            .as_ref()
            .map(|route| route.diagnostic_snapshot())
            .unwrap_or_default();
        (
            active,
            proxy_stats.tcp_active,
            proxy_stats.udp_active,
            proxy_stats.tcp_peak,
            proxy_stats.udp_peak,
            proxy_stats.tcp_total,
            proxy_stats.udp_total,
        )
    };
    Json(serde_json::json!({
        "ram": format!("{} / {}", format_memory_kib(process_memory.rss), format_total_memory_kib(total_ram)),
        "ram_used": format_memory_kib(process_memory.rss),
        "ram_total": format_total_memory_kib(total_ram),
        "ram_peak": format_memory_kib(process_memory.peak),
        "ram_anonymous": format_memory_kib(process_memory.anonymous),
        "ram_file": format_memory_kib(process_memory.file),
        "ram_shared": format_memory_kib(process_memory.shared),
        "ram_swap": format_memory_kib(process_memory.swap),
        "ram_pss": format_memory_kib(process_rollup.pss),
        "ram_private": format_memory_kib(process_rollup.private),
        "ram_shared_rollup": format_memory_kib(process_rollup.shared),
        "ram_anon_rollup": format_memory_kib(process_rollup.pss_anon),
        "ram_anonymous_rollup": format_memory_kib(process_rollup.anonymous),
        "ram_file_rollup": format_memory_kib(process_rollup.file),
        "ram_shmem_rollup": format_memory_kib(process_rollup.shmem),
        "ram_swap_pss": format_memory_kib(process_rollup.swap_pss),
        "ram_used_kib": process_memory.rss,
        "ram_peak_kib": process_memory.peak,
        "ram_anonymous_kib": process_memory.anonymous,
        "ram_file_kib": process_memory.file,
        "ram_shared_kib": process_memory.shared,
        "ram_swap_kib": process_memory.swap,
        "ram_pss_kib": process_rollup.pss,
        "ram_private_kib": process_rollup.private,
        "ram_shared_rollup_kib": process_rollup.shared,
        "ram_anon_rollup_kib": process_rollup.pss_anon,
        "ram_anonymous_rollup_kib": process_rollup.anonymous,
        "ram_file_rollup_kib": process_rollup.file,
        "ram_shmem_rollup_kib": process_rollup.shmem,
        "ram_swap_pss_kib": process_rollup.swap_pss,
        "cpu_total": cpu_total,
        "cpu_capacity": cpu_capacity,
        "cpu_normalized": cpu_normalized,
        "status": "Active",
        "peer_port": state.app.listen.port(),
        "public_ip": state.app.public_ip.read().await.clone(),
        "uptime": now().saturating_sub(state.app.started),
        "active": state.app.sessions.len(),
        "total": state.app.total_connections.load(Ordering::Relaxed),
        "up": state.app.bytes_from_client.load(Ordering::Relaxed),
        "down": state.app.bytes_to_client.load(Ordering::Relaxed),
        "udp_rx_packets": io.udp_rx_packets,
        "udp_rx_bytes": io.udp_rx_bytes,
        "udp_rx_errors": io.udp_rx_errors,
        "udp_tx_packets": io.udp_tx_packets,
        "udp_tx_bytes": io.udp_tx_bytes,
        "udp_tx_errors": io.udp_tx_errors,
        "passwords": db.passwords.len(),
        "transport": "RTP/SRTP",
        "tunnel": "userspace-tun",
        "allocator": crate::allocator_name(),
        "local_proxy_enabled": !db.local_proxy.active_profile_id.is_empty(),
        "local_proxy_port": db.local_proxy.active_profile().map(|p| p.port).unwrap_or(0),
        "local_proxy_active": local_proxy_active,
        "local_proxy_port_listening": state.app.proxy_port_listening.load(Ordering::Acquire),
        "local_proxy_health_error": crate::read_unpoison(&state.app.proxy_health_error).clone(),
        "local_proxy_tcp_sessions": local_proxy_tcp_sessions,
        "local_proxy_udp_flows": local_proxy_udp_flows,
        "local_proxy_tcp_peak": local_proxy_tcp_peak,
        "local_proxy_udp_peak": local_proxy_udp_peak,
        "local_proxy_tcp_total": local_proxy_tcp_total,
        "local_proxy_udp_total": local_proxy_udp_total,
        "hot_sessions": protocol::ACTIVE_SESSIONS_GAUGE.load(Ordering::Relaxed),
        "hot_session_capacity": protocol::HOT_SESSION_CAPACITY_GAUGE.load(Ordering::Relaxed),
        "public_session_capacity": state.app.sessions.capacity(),
        "mem_engine_epochs": protocol::epoch_snapshot_len(),
        "mem_password_epochs": state.app.password_epochs.len(),
        "mem_password_epoch_capacity": state.app.password_epochs.capacity(),
        "mem_derived_keys": state.app.derived_keys.len(),
        "mem_web_sessions": state.app.web_sessions.len(),
        "mem_web_session_capacity": MAX_WEB_SESSIONS,
        "mem_login_limits": state.app.login_limits.len(),
        "mem_login_limit_capacity": MAX_LOGIN_LIMITS,
        "mem_log_ring": crate::lock_unpoison(&state.app.logs).len(),
        "mem_log_bytes": log_ring_bytes,
        "mem_dpi_ring": protocol::dpi_ring_len(),
        "mem_stream_repairs": protocol::STREAM_REPAIRS_GAUGE.load(Ordering::Relaxed),
        "mem_stream_inventory": protocol::STREAM_INVENTORY_GAUGE.load(Ordering::Relaxed),
        "memory_trim_count": state.app.memory_trim_count.load(Ordering::Relaxed),
        "memory_trim_last_unix": state.app.memory_trim_last_unix.load(Ordering::Relaxed)
    }))
}

async fn memory_trim(State(state): State<WebState>) -> Response {
    match crate::trim_memory(&state.app).await {
        Ok(allocator_collected) => Json(serde_json::json!({
            "compacted": true,
            "allocator_collected": allocator_collected,
            "allocator_collection_scope": "not-supported-by-system-allocator",
            "trim_count": state.app.memory_trim_count.load(Ordering::Relaxed),
            "trimmed_at": state.app.memory_trim_last_unix.load(Ordering::Relaxed),
        }))
        .into_response(),
        Err(error) => {
            log_event(
                &state.app,
                "WARNING",
                "MEMORY",
                &format!("Memory trim skipped: {error:#}"),
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "memory trim is temporarily unavailable",
            )
                .into_response()
        }
    }
}

async fn settings_get(State(state): State<WebState>) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let dns = db.dns.clone();
    let mut parts = dns.splitn(2, ',');
    let primary = parts.next().unwrap_or("77.88.8.8").trim().to_owned();
    let secondary = parts.next().unwrap_or("77.88.8.1").trim().to_owned();
    let provider = if db.dns_provider == "custom" || dns_provider_by_id(&db.dns_provider).is_some()
    {
        db.dns_provider.as_str()
    } else {
        dns_provider_id(&dns).unwrap_or("custom")
    };
    let vk_hashes = if !db.vk_hashes.is_empty() {
        db.vk_hashes.clone()
    } else {
        db.passwords
            .values()
            .find(|p| !p.vk_hashes.is_empty())
            .map(|p| p.vk_hashes.clone())
            .unwrap_or_default()
    };
    Json(serde_json::json!({
        "main_password": db.main_password,
        "dns_provider": provider,
        "dns_primary": primary,
        "dns_secondary": secondary,
        "auto_restart_interval_hours": db.auto_restart_interval_hours(),
        "vk_token": db.vk_access_token,
        "vk_hashes": vk_hashes,
        "peer_port": state.app.listen.port(),
        "restart_required": db.main_password != state.app.startup_main_password
    }))
}

async fn settings_post(
    State(state): State<WebState>,
    Json(request): Json<SettingsRequest>,
) -> Response {
    if let Some(password) = request.main_password.as_ref()
        && !password.is_empty()
        && password.len() > 128
    {
        return (
            StatusCode::BAD_REQUEST,
            "password length must be 1..128 or empty",
        )
            .into_response();
    }
    let dns = match request.dns_provider.as_deref() {
        Some("custom") | None
            if request.dns_primary.is_some() || request.dns_secondary.is_some() =>
        {
            match manual_dns(
                request.dns_primary.as_deref(),
                request.dns_secondary.as_deref(),
            ) {
                Ok(dns) => Some((dns, "custom".to_owned())),
                Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
            }
        }
        Some("custom") => {
            return (StatusCode::BAD_REQUEST, "primary DNS is required").into_response();
        }
        Some(provider_id) => {
            let Some(provider) = dns_provider_by_id(provider_id) else {
                return (StatusCode::BAD_REQUEST, "unknown DNS provider").into_response();
            };
            Some((provider_dns(provider), provider_id.to_owned()))
        }
        None => None,
    };
    if let Some(hours) = request.auto_restart_interval_hours
        && !matches!(hours, 0 | 12 | 24 | 48 | 72)
    {
        return (
            StatusCode::BAD_REQUEST,
            "auto restart interval must be 0, 12, 24, 48, or 72 hours",
        )
            .into_response();
    }
    let requested_vk_access_token = match request.vk_token {
        Some(token) => match normalize_vk_access_token(&token) {
            Ok(token) => Some(token),
            Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
        },
        None => None,
    };
    let requested_vk_hashes = match request.vk_hashes {
        Some(raw) => match normalize_client_vk_hashes(&raw) {
            Ok(hashes) => Some(hashes),
            Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
        },
        None => None,
    };
    let requested_auto_restart_interval = request.auto_restart_interval_hours;
    let (revision, retired_main_password, applied_dns) = {
        let mut db = state.app.db.write().await;
        let retired_main_password = if let Some(password) = request.main_password {
            if db.passwords.contains_key(&password) {
                return (
                    StatusCode::BAD_REQUEST,
                    "Пароль совпадает с паролем клиента",
                )
                    .into_response();
            }
            (db.main_password != password)
                .then(|| std::mem::replace(&mut db.main_password, password))
        } else {
            None
        };
        let applied_dns = dns
            .as_ref()
            .and_then(|(dns, _)| (db.dns != *dns).then(|| dns.clone()));
        if let Some((dns, provider)) = dns.as_ref() {
            db.dns.clone_from(dns);
            db.dns_provider.clone_from(provider);
        }
        if let Some(hours) = requested_auto_restart_interval {
            db.set_auto_restart_interval_hours(hours);
        }
        if let Some(token) = requested_vk_access_token {
            db.vk_access_token = token;
        }
        if let Some(hashes) = requested_vk_hashes {
            db.vk_hashes = hashes;
        }
        (
            state.app.db_persistence.submit(db.clone()),
            retired_main_password,
            applied_dns,
        )
    };
    match state.app.db_persistence.wait(revision).await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("[SETTINGS] Failed to persist settings: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist settings",
            )
                .into_response();
        }
    }
    if let Some(hours) = requested_auto_restart_interval {
        state.app.auto_restart_interval_tx.send_replace(hours);
    }
    let main_password_changed = retired_main_password.is_some();
    if let Some(password) = retired_main_password
        && !password.is_empty()
    {
        state.app.derived_keys.remove(&password);
    }
    if main_password_changed && let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved").into_response();
    }
    if let Some(dns) = applied_dns {
        *state.app.dns.write().await = dns;
        match crate::protocol::broadcast_tunnel_configuration(&state.app).await {
            Ok(sent) => log_event(
                &state.app,
                "INFO",
                "DNS",
                &format!("DNS configuration applied to {sent} active paths"),
            ),
            Err(error) => {
                let warning = format!("saved but DNS apply failed: {error:#}");
                return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved")
                    .into_response();
            }
        }
    }
    let restart_required = {
        let db = state.app.db.read().await;
        db.main_password != state.app.startup_main_password
    };
    Json(serde_json::json!({ "restart_required": restart_required })).into_response()
}

fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn parse_host_header(host: &str) -> Option<(String, Option<String>)> {
    let host = host.trim();
    if host.is_empty() || host.len() > 255 {
        return None;
    }
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let (name, rest) = rest.split_once(']')?;
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p.to_string()),
            None if rest.is_empty() => None,
            None => return None,
        };
        (name.to_string(), port)
    } else if let Some((name, port)) = host.rsplit_once(':') {
        (name.to_string(), Some(port.to_string()))
    } else {
        (host.to_string(), None)
    };

    if let Some(port) = port.as_deref()
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }

    if name.parse::<std::net::IpAddr>().is_err() && !is_valid_hostname(&name) {
        return None;
    }
    Some((name, port))
}

async fn resolve_client_host(headers: &HeaderMap, state: &WebState) -> String {
    let host_header = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_host_header)
        .map(|(name, _)| name)
        .unwrap_or_default();

    let is_local_or_unspecified = host_header.is_empty()
        || host_header == "0.0.0.0"
        || host_header == "127.0.0.1"
        || host_header == "localhost"
        || host_header == "::1";

    if !is_local_or_unspecified {
        return host_header.to_string();
    }

    let public_ip = state.app.public_ip.read().await.clone();
    if !public_ip.is_empty() && public_ip != "0.0.0.0" && public_ip != "127.0.0.1" {
        return public_ip;
    }

    let listen_ip = state.app.listen.ip().to_string();
    if listen_ip != "0.0.0.0" && listen_ip != "127.0.0.1" {
        return listen_ip;
    }

    if !host_header.is_empty() {
        return host_header.to_string();
    }

    "0.0.0.0".to_string()
}

#[derive(Deserialize, Default)]
struct ClientListQuery {
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    search: Option<String>,
}

fn count_active_sessions(
    sessions: &dashmap::DashMap<u64, Arc<crate::protocol::Session>>,
    password: &str,
) -> usize {
    if password.is_empty() {
        return 0;
    }
    let mut count = 0;
    for entry in sessions.iter() {
        if entry.value().password == password {
            count += 1;
        }
    }
    count
}

async fn clients_get(
    State(state): State<WebState>,
    headers: HeaderMap,
    Query(query): Query<ClientListQuery>,
) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let host = resolve_client_host(&headers, &state).await;

    let mut list: Vec<ClientInfo> = db
        .passwords
        .iter()
        .map(|(password, entry)| {
            let client_peer_port = if entry.dtls_port == 0 {
                state.app.listen.port()
            } else {
                entry.dtls_port
            };
            ClientInfo {
                password: password.clone(),
                down: entry.down_bytes,
                up: entry.up_bytes,
                expires: entry.expires_at,
                active: !entry.is_deactivated && !is_expired(entry),
                active_sessions: count_active_sessions(&state.app.sessions, password),
                vk_hash: entry.vk_hash.clone(),
                ports: entry.ports.clone(),
                ip: if entry.ip.is_empty() {
                    "10.66.67.3".to_string()
                } else {
                    entry.ip.clone()
                },
                name: entry.name.clone(),
                vk_hashes: entry.vk_hashes.clone(),
                vk_token: entry.vk_token_enabled,
                peer_port: client_peer_port,
                local_port: entry.local_port,
                group_id: entry.group_id.clone(),
                routing_rule_id: entry.routing_rule_id.clone(),
                links: ImportLinks::new(make_entry_link(
                    &host,
                    client_peer_port,
                    password,
                    entry,
                    &db.vk_access_token,
                )),
                sub_uuid: entry.sub_uuid.clone(),
                workers: entry.workers,
            }
        })
        .collect();
    if !db.main_password.is_empty() {
        let mut session_up = 0;
        let mut session_down = 0;
        for s in state.app.sessions.iter() {
            let sess = s.value();
            if secret_eq(&sess.password, &db.main_password) {
                session_up += sess.up_bytes.load(Ordering::Relaxed) as i64;
                session_down += sess.down_bytes.load(Ordering::Relaxed) as i64;
            }
        }

        let main_peer_port = state.app.listen.port();
        list.push(ClientInfo {
            password: db.main_password.clone(),
            down: db.main_down_bytes + session_down,
            up: db.main_up_bytes + session_up,
            expires: 0,
            active: true,
            active_sessions: count_active_sessions(&state.app.sessions, &db.main_password),
            vk_hash: String::new(),
            ports: String::new(),
            ip: "10.66.67.2".to_string(),
            name: "Владелец".to_string(),
            vk_hashes: if db.main_vk_hashes.is_empty() {
                db.vk_hashes.clone()
            } else {
                db.main_vk_hashes.clone()
            },
            vk_token: db.main_vk_token_enabled,
            peer_port: main_peer_port,
            local_port: 0,
            group_id: String::new(),
            routing_rule_id: db.main_routing_rule_id.clone(),
            links: ImportLinks::new(make_main_link(&host, main_peer_port, &db)),
            sub_uuid: db.main_sub_uuid.clone(),
            workers: db.main_workers,
        });
    }

    if let Some(ref gid) = query.group_id {
        let g = gid.trim();
        if g == "root" || g == "ungrouped" {
            list.retain(|c| c.group_id.is_empty());
        } else {
            list.retain(|c| c.group_id == g);
        }
    }
    if let Some(act) = query.active {
        list.retain(|c| c.active == act);
    }
    if let Some(ref s) = query.search {
        let q = s.trim().to_lowercase();
        if !q.is_empty() {
            list.retain(|c| {
                c.name.to_lowercase().contains(&q) || c.password.to_lowercase().contains(&q)
            });
        }
    }

    Json(list)
}

async fn group_clients_get(
    State(state): State<WebState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let db = state.app.db.read().await;
    if !db.groups.contains_key(&id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "group not found" })),
        )
            .into_response();
    }
    let host = resolve_client_host(&headers, &state).await;
    let effective_vk_token = db
        .groups
        .get(&id)
        .and_then(|g| g.vk_token.as_deref())
        .unwrap_or(&db.vk_access_token);
    let list: Vec<ClientInfo> = db
        .passwords
        .iter()
        .filter(|(_, entry)| entry.group_id == id)
        .map(|(password, entry)| {
            let client_peer_port = if entry.dtls_port == 0 {
                state.app.listen.port()
            } else {
                entry.dtls_port
            };
            ClientInfo {
                password: password.clone(),
                down: entry.down_bytes,
                up: entry.up_bytes,
                expires: entry.expires_at,
                active: !entry.is_deactivated && !is_expired(entry),
                active_sessions: count_active_sessions(&state.app.sessions, password),
                vk_hash: entry.vk_hash.clone(),
                ports: entry.ports.clone(),
                ip: if entry.ip.is_empty() {
                    "10.66.67.3".to_string()
                } else {
                    entry.ip.clone()
                },
                name: entry.name.clone(),
                vk_hashes: entry.vk_hashes.clone(),
                vk_token: entry.vk_token_enabled,
                peer_port: client_peer_port,
                local_port: entry.local_port,
                group_id: entry.group_id.clone(),
                routing_rule_id: entry.routing_rule_id.clone(),
                links: ImportLinks::new(make_entry_link(
                    &host,
                    client_peer_port,
                    password,
                    entry,
                    effective_vk_token,
                )),
                sub_uuid: entry.sub_uuid.clone(),
                workers: entry.workers,
            }
        })
        .collect();
    Json(list).into_response()
}

fn normalize_client_vk_hashes(raw: &str) -> Result<String, &'static str> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 1024 {
        return Err("VK hashes are too long");
    }
    if value.chars().any(char::is_whitespace) {
        return Err("VK hashes must be comma-separated without spaces");
    }
    let hashes: Vec<_> = value.split(',').collect();
    if hashes.len() > 6 || hashes.iter().any(|hash| hash.len() < 16) {
        return Err("provide 1 to 6 valid VK hashes");
    }
    Ok(hashes.join(","))
}

fn normalize_vk_access_token(raw: &str) -> Result<String, &'static str> {
    let token = raw.trim();
    if token.is_empty() {
        return Ok(String::new());
    }
    if token.len() > 4096 || token.chars().any(char::is_whitespace) {
        return Err("VK token is too long or contains whitespace");
    }
    Ok(token.to_owned())
}

async fn clients_create(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(request): Json<CreateClientRequest>,
) -> Response {
    if let Err(message) = validate_client_name(&request.name) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    if request.days < 0 || request.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be 0..3650").into_response();
    }
    let vk_hashes = match normalize_client_vk_hashes(&request.hash) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    if request.vk_token && !vk_hashes.is_empty() {
        return (StatusCode::BAD_REQUEST, "choose VK hashes or VK token").into_response();
    }

    let default_peer_port = state.app.listen.port();
    let peer_port = request.peer_port.unwrap_or(default_peer_port);
    let local_port = request.local_port.unwrap_or(0);
    let ports = format!("{},0,{}", peer_port, local_port);
    let group_id = request.group_id.unwrap_or_default();
    let validated_workers = match validate_workers(request.workers) {
        Ok(w) => w,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    let host = resolve_client_host(&headers, &state).await;

    let (password, expires, revision, link, sub_uuid) = {
        let mut db = state.app.db.write().await;
        if request.vk_token && db.vk_access_token.is_empty() {
            return (StatusCode::BAD_REQUEST, "configure a VK token first").into_response();
        }
        db.passwords.retain(|_, entry| !is_expired(entry));

        let client_name = if request.name.trim().is_empty() {
            model::generate_unique_client_name(model::existing_client_names_in_scope(
                &db, &group_id, None,
            ))
        } else {
            let trimmed = request.name.trim().to_string();
            if model::is_client_name_taken(
                model::existing_client_names_in_scope(&db, &group_id, None),
                &trimmed,
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    "Участник с таким именем уже существует",
                )
                    .into_response();
            }
            trimmed
        };

        let password = if let Some(ref custom_pw) = request.password {
            let pw = custom_pw.trim();
            if pw.is_empty() || pw.len() > 128 {
                return (
                    StatusCode::BAD_REQUEST,
                    "password must be 1..128 characters",
                )
                    .into_response();
            }
            if db.passwords.contains_key(pw) || pw == db.main_password {
                return (StatusCode::BAD_REQUEST, "password already exists").into_response();
            }
            pw.to_string()
        } else {
            let candidate = (0..64)
                .map(|_| random_password())
                .find(|c| !db.passwords.contains_key(c) && c != &db.main_password);
            let Some(p) = candidate else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            p
        };

        let expires = if request.days == 0 {
            0
        } else {
            now().saturating_add(request.days.saturating_mul(86400))
        };
        let sub_uuid = model::random_uuid_v4();
        let ip = model::get_next_ip(&db).unwrap_or_default();
        db.passwords.insert(
            password.clone(),
            PasswordEntry {
                ip,
                expires_at: expires,
                down_bytes: 0,
                up_bytes: 0,
                vk_hash: vk_hashes.clone(),
                ports,
                is_deactivated: false,
                name: client_name,
                vk_hashes: vk_hashes.clone(),
                vk_token_enabled: request.vk_token,
                dtls_port: peer_port,
                wg_port: 0,
                local_port,
                group_id: group_id.clone(),
                routing_rule_id: String::new(),
                sub_uuid: sub_uuid.clone(),
                workers: validated_workers,
            },
        );
        let link = make_client_link(
            &host,
            peer_port,
            &password,
            &vk_hashes,
            request.vk_token,
            &db.vk_access_token,
        );
        let revision = state.app.db_persistence.submit(db.clone());
        (password, expires, revision, link, sub_uuid)
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    let reload_error = refresh_credentials_report(&state).await.err();

    Json(serde_json::json!({
        "password": password,
        "expires": expires,
        "peer_port": peer_port,
        "local_port": local_port,
        "vk_hashes": vk_hashes,
        "vk_token": request.vk_token,
        "group_id": group_id,
        "workers": validated_workers.unwrap_or(0),
        "reload_error": reload_error,
        "link": link,
        "sub_uuid": sub_uuid,
    }))
    .into_response()
}

async fn client_update(
    State(state): State<WebState>,
    Path(password): Path<String>,
    Json(request): Json<CreateClientRequest>,
) -> Response {
    if let Err(message) = validate_client_name(&request.name) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    if request.days < 0 || request.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be 0..3650").into_response();
    }
    let vk_hashes = match normalize_client_vk_hashes(&request.hash) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    if request.vk_token && !vk_hashes.is_empty() {
        return (StatusCode::BAD_REQUEST, "choose VK hashes or VK token").into_response();
    }
    let validated_workers = match validate_workers(request.workers) {
        Ok(w) => w,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    let revision = {
        let mut db = state.app.db.write().await;
        if request.vk_token && db.vk_access_token.is_empty() {
            return (StatusCode::BAD_REQUEST, "configure a VK token first").into_response();
        }
        if secret_eq(&password, &db.main_password) {
            db.main_vk_hashes = vk_hashes;
            db.main_vk_token_enabled = request.vk_token;
            db.main_workers = validated_workers;
            state.app.db_persistence.submit(db.clone())
        } else {
            let current_group_id = match db.passwords.get(&password) {
                Some(e) => e.group_id.clone(),
                None => return StatusCode::NOT_FOUND.into_response(),
            };
            let target_group_id = request.group_id.as_deref().unwrap_or(&current_group_id);
            let scope_names =
                model::existing_client_names_in_scope(&db, target_group_id, Some(&password));
            let client_name = if request.name.trim().is_empty() {
                model::generate_unique_client_name(&scope_names)
            } else {
                let trimmed = request.name.trim().to_string();
                if model::is_client_name_taken(&scope_names, &trimmed) {
                    return (
                        StatusCode::BAD_REQUEST,
                        "Участник с таким именем уже существует",
                    )
                        .into_response();
                }
                trimmed
            };

            let entry = db.passwords.get_mut(&password).unwrap();

            let default_peer_port = state.app.listen.port();
            let fallback_port = if entry.dtls_port == 0 {
                default_peer_port
            } else {
                entry.dtls_port
            };
            let peer_port = request.peer_port.unwrap_or(fallback_port);
            let local_port = request.local_port.unwrap_or(0);

            entry.name = client_name;
            entry.expires_at = if request.days == 0 {
                0
            } else {
                now().saturating_add(request.days.saturating_mul(86400))
            };
            entry.vk_hash = vk_hashes.clone();
            entry.vk_hashes = vk_hashes;
            entry.vk_token_enabled = request.vk_token;
            entry.dtls_port = peer_port;
            entry.wg_port = 0;
            entry.local_port = local_port;
            entry.ports = format!("{},0,{}", peer_port, local_port);
            if let Some(ref g_id) = request.group_id {
                entry.group_id = g_id.clone();
            }
            entry.workers = validated_workers;
            state.app.db_persistence.submit(db.clone())
        }
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved").into_response();
    }
    StatusCode::OK.into_response()
}

async fn client_toggle(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        let Some(entry) = db.passwords.get_mut(&password) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        entry.is_deactivated = !entry.is_deactivated;
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }

    crate::protocol::drop_password_sessions(&state.app, &password);
    if let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved").into_response();
    }

    StatusCode::OK.into_response()
}

async fn client_unbind(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    crate::protocol::drop_password_sessions(&state.app, &password);
    crate::protocol::forget_idle_password_epoch(&state.app, &password);
    StatusCode::OK.into_response()
}

async fn client_delete(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        if db.passwords.remove(&password).is_none() {
            return StatusCode::NOT_FOUND.into_response();
        };
        state.app.derived_keys.remove(&password);
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }

    crate::protocol::drop_password_sessions(&state.app, &password);
    if let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved").into_response();
    }

    StatusCode::OK.into_response()
}

async fn client_get(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(password): Path<String>,
) -> Response {
    let db = state.app.db.read().await;
    let host = resolve_client_host(&headers, &state).await;

    if secret_eq(&password, &db.main_password) {
        let mut session_up = 0;
        let mut session_down = 0;
        let mut active_sessions = 0;
        for entry in state.app.sessions.iter() {
            let sess = entry.value();
            if secret_eq(&sess.password, &db.main_password) {
                active_sessions += 1;
                session_up += sess.up_bytes.load(Ordering::Relaxed) as i64;
                session_down += sess.down_bytes.load(Ordering::Relaxed) as i64;
            }
        }

        let main_peer_port = state.app.listen.port();
        let info = ClientInfo {
            password: db.main_password.clone(),
            down: db.main_down_bytes + session_down,
            up: db.main_up_bytes + session_up,
            expires: 0,
            active: true,
            active_sessions,
            vk_hash: String::new(),
            ports: String::new(),
            ip: "10.66.67.2".to_string(),
            name: "Главный пароль".to_string(),
            vk_hashes: if db.main_vk_hashes.is_empty() {
                db.vk_hashes.clone()
            } else {
                db.main_vk_hashes.clone()
            },
            vk_token: db.main_vk_token_enabled,
            peer_port: main_peer_port,
            local_port: 0,
            group_id: String::new(),
            routing_rule_id: db.main_routing_rule_id.clone(),
            links: ImportLinks::new(make_main_link(&host, main_peer_port, &db)),
            sub_uuid: db.main_sub_uuid.clone(),
            workers: db.main_workers,
        };
        return Json(info).into_response();
    }

    if let Some(entry) = db.passwords.get(&password) {
        let active_sessions = count_active_sessions(&state.app.sessions, &password);
        let client_peer_port = if entry.dtls_port == 0 {
            state.app.listen.port()
        } else {
            entry.dtls_port
        };
        let info = ClientInfo {
            password: password.clone(),
            down: entry.down_bytes,
            up: entry.up_bytes,
            expires: entry.expires_at,
            active: !entry.is_deactivated && !is_expired(entry),
            active_sessions,
            vk_hash: entry.vk_hash.clone(),
            ports: entry.ports.clone(),
            ip: if entry.ip.is_empty() {
                "10.66.67.3".to_string()
            } else {
                entry.ip.clone()
            },
            name: entry.name.clone(),
            vk_hashes: entry.vk_hashes.clone(),
            vk_token: entry.vk_token_enabled,
            peer_port: client_peer_port,
            local_port: entry.local_port,
            group_id: entry.group_id.clone(),
            routing_rule_id: entry.routing_rule_id.clone(),
            links: ImportLinks::new(make_entry_link(
                &host,
                client_peer_port,
                &password,
                entry,
                &db.vk_access_token,
            )),
            sub_uuid: entry.sub_uuid.clone(),
            workers: entry.workers,
        };
        return Json(info).into_response();
    }

    (StatusCode::NOT_FOUND, "client not found").into_response()
}

async fn client_reset_traffic(
    State(state): State<WebState>,
    Path(password): Path<String>,
) -> Response {
    let result = {
        let mut db = state.app.db.write().await;
        if secret_eq(&password, &db.main_password) {
            db.main_up_bytes = 0;
            db.main_down_bytes = 0;
            for s in state.app.sessions.iter() {
                if s.value().password == password {
                    s.value().up_bytes.store(0, Ordering::Relaxed);
                    s.value().down_bytes.store(0, Ordering::Relaxed);
                }
            }
            let revision = state.app.db_persistence.submit(db.clone());
            Some(revision)
        } else if let Some(entry) = db.passwords.get_mut(&password) {
            entry.up_bytes = 0;
            entry.down_bytes = 0;
            for s in state.app.sessions.iter() {
                if s.value().password == password {
                    s.value().up_bytes.store(0, Ordering::Relaxed);
                    s.value().down_bytes.store(0, Ordering::Relaxed);
                }
            }
            let revision = state.app.db_persistence.submit(db.clone());
            Some(revision)
        } else {
            None
        }
    };

    let Some(revision) = result else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };

    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn client_extend(
    State(state): State<WebState>,
    Path(password): Path<String>,
    Json(request): Json<ExtendClientRequest>,
) -> Response {
    if request.days <= 0 || request.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be 1..3650").into_response();
    }
    let current = now();
    let result = {
        let mut db = state.app.db.write().await;
        if let Some(entry) = db.passwords.get_mut(&password) {
            let base = if entry.expires_at > current {
                entry.expires_at
            } else {
                current
            };
            let new_expires = base.saturating_add(request.days.saturating_mul(86400));
            entry.expires_at = new_expires;
            let revision = state.app.db_persistence.submit(db.clone());
            Some((new_expires, revision))
        } else {
            None
        }
    };

    let Some((expires, revision)) = result else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };

    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    let _ = refresh_credentials_report(&state).await;
    Json(serde_json::json!({ "ok": true, "expires": expires })).into_response()
}

#[derive(Serialize)]
struct ClientLinkItem {
    name: String,
    password: String,
    #[serde(flatten)]
    links: ImportLinks,
    expires: i64,
    peer_port: u16,
    group_id: String,
    #[serde(default)]
    sub_uuid: String,
}

async fn api_links_get(State(state): State<WebState>, headers: HeaderMap) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let host = resolve_client_host(&headers, &state).await;
    let mut list: Vec<ClientLinkItem> = db
        .passwords
        .iter()
        .map(|(password, entry)| {
            let client_peer_port = if entry.dtls_port == 0 {
                state.app.listen.port()
            } else {
                entry.dtls_port
            };
            ClientLinkItem {
                name: entry.name.clone(),
                password: password.clone(),
                links: ImportLinks::new(make_entry_link(
                    &host,
                    client_peer_port,
                    password,
                    entry,
                    &db.vk_access_token,
                )),
                expires: entry.expires_at,
                peer_port: client_peer_port,
                group_id: entry.group_id.clone(),
                sub_uuid: entry.sub_uuid.clone(),
            }
        })
        .collect();
    if !db.main_password.is_empty() {
        let main_peer_port = state.app.listen.port();
        list.push(ClientLinkItem {
            name: "Владелец".to_owned(),
            password: db.main_password.clone(),
            links: ImportLinks::new(make_main_link(&host, main_peer_port, &db)),
            expires: 0,
            peer_port: main_peer_port,
            group_id: String::new(),
            sub_uuid: db.main_sub_uuid.clone(),
        });
    }
    Json(list)
}

#[derive(Deserialize)]
struct BatchVkRequest {
    #[serde(default)]
    vk_token: Option<String>,
    #[serde(default)]
    vk_hashes: Option<String>,
    #[serde(default)]
    apply_to_all_clients: Option<bool>,
}

async fn api_links_batch_vk(
    State(state): State<WebState>,
    Json(request): Json<BatchVkRequest>,
) -> Response {
    let token = match request.vk_token {
        Some(t) => match normalize_vk_access_token(&t) {
            Ok(v) => Some(v),
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        },
        None => None,
    };
    let hashes = match request.vk_hashes {
        Some(h) => match normalize_client_vk_hashes(&h) {
            Ok(v) => Some(v),
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        },
        None => None,
    };
    let apply_all = request.apply_to_all_clients.unwrap_or(true);
    let mut updated_count = 0usize;
    let revision = {
        let mut db = state.app.db.write().await;
        if let Some(ref t) = token {
            db.vk_access_token = t.clone();
        }
        if let Some(ref h) = hashes {
            db.vk_hashes = h.clone();
        }
        if apply_all {
            if let Some(ref h) = hashes {
                db.main_vk_hashes = h.clone();
            }
            if let Some(ref t) = token {
                db.main_vk_token_enabled = !t.is_empty();
            }
            for entry in db.passwords.values_mut() {
                if let Some(ref h) = hashes {
                    entry.vk_hashes = h.clone();
                }
                if let Some(ref t) = token {
                    entry.vk_token_enabled = !t.is_empty();
                }
                updated_count += 1;
            }
        }
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    let _ = refresh_credentials_report(&state).await;
    Json(serde_json::json!({
        "ok": true,
        "updated_clients": updated_count
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ClientVkUpdateRequest {
    #[serde(default)]
    vk_token: Option<bool>,
    #[serde(default)]
    vk_hashes: Option<String>,
}

async fn api_client_vk_update(
    State(state): State<WebState>,
    Path(password): Path<String>,
    Json(request): Json<ClientVkUpdateRequest>,
) -> Response {
    let hashes = match request.vk_hashes {
        Some(h) => match normalize_client_vk_hashes(&h) {
            Ok(v) => Some(v),
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        },
        None => None,
    };
    let revision = {
        let mut db = state.app.db.write().await;
        if secret_eq(&password, &db.main_password) {
            if let Some(h) = hashes {
                db.main_vk_hashes = h;
            }
            if let Some(token_enabled) = request.vk_token {
                db.main_vk_token_enabled = token_enabled;
            }
            state.app.db_persistence.submit(db.clone())
        } else {
            let Some(entry) = db.passwords.get_mut(&password) else {
                return (StatusCode::NOT_FOUND, "client not found").into_response();
            };
            if let Some(h) = hashes {
                entry.vk_hashes = h;
            }
            if let Some(token_enabled) = request.vk_token {
                entry.vk_token_enabled = token_enabled;
            }
            state.app.db_persistence.submit(db.clone())
        }
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    let _ = refresh_credentials_report(&state).await;
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
struct ApiDnsRequest {
    #[serde(default)]
    dns_provider: Option<String>,
    #[serde(default)]
    dns_primary: Option<String>,
    #[serde(default)]
    dns_secondary: Option<String>,
}

async fn api_settings_dns(
    State(state): State<WebState>,
    Json(request): Json<ApiDnsRequest>,
) -> Response {
    let dns = match request.dns_provider.as_deref() {
        Some("custom") | None
            if request.dns_primary.is_some() || request.dns_secondary.is_some() =>
        {
            match manual_dns(
                request.dns_primary.as_deref(),
                request.dns_secondary.as_deref(),
            ) {
                Ok(dns) => (dns, "custom".to_owned()),
                Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
            }
        }
        Some("custom") => {
            return (StatusCode::BAD_REQUEST, "primary DNS is required").into_response();
        }
        Some(provider_id) => {
            let Some(provider) = dns_provider_by_id(provider_id) else {
                return (StatusCode::BAD_REQUEST, "unknown DNS provider").into_response();
            };
            (provider_dns(provider), provider_id.to_owned())
        }
        None => return (StatusCode::BAD_REQUEST, "missing DNS parameters").into_response(),
    };
    let (revision, applied_dns) = {
        let mut db = state.app.db.write().await;
        let applied_dns = (db.dns != dns.0).then(|| dns.0.clone());
        db.dns = dns.0;
        db.dns_provider = dns.1;
        (state.app.db_persistence.submit(db.clone()), applied_dns)
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if let Some(new_dns) = applied_dns {
        *state.app.dns.write().await = new_dns;
        let _ = crate::protocol::broadcast_tunnel_configuration(&state.app).await;
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
struct RestartIntervalRequest {
    interval_hours: u8,
}

async fn api_settings_restart_interval(
    State(state): State<WebState>,
    Json(request): Json<RestartIntervalRequest>,
) -> Response {
    if !matches!(request.interval_hours, 0 | 12 | 24 | 48 | 72) {
        return (
            StatusCode::BAD_REQUEST,
            "auto restart interval must be 0, 12, 24, 48, or 72 hours",
        )
            .into_response();
    }
    let revision = {
        let mut db = state.app.db.write().await;
        db.set_auto_restart_interval_hours(request.interval_hours);
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    state
        .app
        .auto_restart_interval_tx
        .send_replace(request.interval_hours);
    Json(serde_json::json!({ "ok": true, "interval_hours": request.interval_hours }))
        .into_response()
}

#[derive(Deserialize)]
struct MasterPasswordRequest {
    password: String,
}

async fn api_settings_master_password(
    State(state): State<WebState>,
    Json(request): Json<MasterPasswordRequest>,
) -> Response {
    if !request.password.is_empty() && request.password.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            "password length must be 1..128 or empty",
        )
            .into_response();
    }
    let (revision, retired_password) = {
        let mut db = state.app.db.write().await;
        if !request.password.is_empty() && db.passwords.contains_key(&request.password) {
            return (
                StatusCode::BAD_REQUEST,
                "Пароль совпадает с паролем клиента",
            )
                .into_response();
        }
        let retired = (db.main_password != request.password)
            .then(|| std::mem::replace(&mut db.main_password, request.password));
        (state.app.db_persistence.submit(db.clone()), retired)
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if let Some(p) = retired_password
        && !p.is_empty()
    {
        state.app.derived_keys.remove(&p);
    }
    let _ = refresh_credentials_report(&state).await;
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Serialize, Deserialize, Clone)]
struct ServerExportData {
    version: u32,
    exported_at: i64,
    main_password: String,
    dns: String,
    dns_provider: String,
    auto_restart_interval_hours: Option<u8>,
    vk_access_token: String,
    vk_hashes: String,
    groups: std::collections::BTreeMap<String, ClientGroup>,
    routing_rules: std::collections::BTreeMap<String, RoutingRule>,
    clients: Vec<ExportClientEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ExportClientEntry {
    password: String,
    name: String,
    expires_at: i64,
    down_bytes: i64,
    up_bytes: i64,
    #[serde(default)]
    vk_hash: String,
    #[serde(default)]
    vk_hashes: String,
    #[serde(default)]
    vk_token_enabled: bool,
    #[serde(default)]
    ports: String,
    #[serde(default)]
    dtls_port: u16,
    #[serde(default)]
    local_port: u16,
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    routing_rule_id: String,
    #[serde(default)]
    is_deactivated: bool,
    #[serde(default)]
    sub_uuid: String,
    #[serde(default)]
    workers: Option<u32>,
    #[serde(default)]
    ip: String,
}

async fn api_export_get(State(state): State<WebState>) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let clients: Vec<ExportClientEntry> = db
        .passwords
        .iter()
        .map(|(pwd, entry)| ExportClientEntry {
            password: pwd.clone(),
            name: entry.name.clone(),
            expires_at: entry.expires_at,
            down_bytes: entry.down_bytes,
            up_bytes: entry.up_bytes,
            vk_hash: entry.vk_hash.clone(),
            vk_hashes: entry.vk_hashes.clone(),
            vk_token_enabled: entry.vk_token_enabled,
            ports: entry.ports.clone(),
            dtls_port: entry.dtls_port,
            local_port: entry.local_port,
            group_id: entry.group_id.clone(),
            routing_rule_id: entry.routing_rule_id.clone(),
            is_deactivated: entry.is_deactivated,
            sub_uuid: entry.sub_uuid.clone(),
            workers: entry.workers,
            ip: entry.ip.clone(),
        })
        .collect();
    let export = ServerExportData {
        version: 1,
        exported_at: now(),
        main_password: db.main_password.clone(),
        dns: db.dns.clone(),
        dns_provider: db.dns_provider.clone(),
        auto_restart_interval_hours: db.auto_restart_interval_hours,
        vk_access_token: db.vk_access_token.clone(),
        vk_hashes: db.vk_hashes.clone(),
        groups: db.groups.clone(),
        routing_rules: db.routing_rules.clone(),
        clients,
    };
    Json(export)
}

#[derive(Deserialize)]
struct ServerImportPayload {
    #[serde(default)]
    import_clients: Option<bool>,
    #[serde(default)]
    import_settings: Option<bool>,
    #[serde(default)]
    config: Option<ServerExportData>,
    #[serde(flatten)]
    direct_config: Option<ServerExportData>,
}

async fn api_import_post(
    State(state): State<WebState>,
    Json(payload): Json<ServerImportPayload>,
) -> Response {
    let export_opt = payload.config.or(payload.direct_config);
    let Some(export) = export_opt else {
        return (StatusCode::BAD_REQUEST, "invalid or empty config").into_response();
    };
    let do_clients = payload.import_clients.unwrap_or(true);
    let do_settings = payload.import_settings.unwrap_or(true);
    let mut added_clients = 0usize;
    let mut applied_dns = None;
    let mut applied_interval = None;

    let revision = {
        let mut db = state.app.db.write().await;
        if do_clients {
            for c in export.clients {
                if !db.passwords.contains_key(&c.password) {
                    let sub_uuid = if c.sub_uuid.trim().is_empty() {
                        model::random_uuid_v4()
                    } else {
                        c.sub_uuid
                    };
                    let ip = if c.ip.is_empty() {
                        model::get_next_ip(&db).unwrap_or_default()
                    } else {
                        c.ip
                    };
                    let client_name = if c.name.trim().is_empty()
                        || model::is_client_name_taken(
                            model::existing_client_names_in_scope(&db, &c.group_id, None),
                            &c.name,
                        ) {
                        model::generate_unique_client_name(model::existing_client_names_in_scope(
                            &db,
                            &c.group_id,
                            None,
                        ))
                    } else {
                        c.name
                    };
                    db.passwords.insert(
                        c.password.clone(),
                        PasswordEntry {
                            ip,
                            expires_at: c.expires_at,
                            down_bytes: c.down_bytes,
                            up_bytes: c.up_bytes,
                            vk_hash: c.vk_hash,
                            ports: c.ports,
                            is_deactivated: c.is_deactivated,
                            name: client_name,
                            vk_hashes: c.vk_hashes,
                            vk_token_enabled: c.vk_token_enabled,
                            dtls_port: c.dtls_port,
                            wg_port: 0,
                            local_port: c.local_port,
                            group_id: c.group_id,
                            routing_rule_id: c.routing_rule_id,
                            sub_uuid,
                            workers: c.workers.filter(|&w| (3..=100).contains(&w)),
                        },
                    );
                    added_clients += 1;
                }
            }
            for (gid, g) in export.groups {
                db.groups.entry(gid).or_insert(g);
            }
            for (rid, r) in export.routing_rules {
                db.routing_rules.entry(rid).or_insert(r);
            }
        }
        if do_settings {
            if !export.main_password.is_empty() && !db.passwords.contains_key(&export.main_password)
            {
                db.main_password = export.main_password;
            }
            if !export.dns.is_empty() {
                applied_dns = (db.dns != export.dns).then(|| export.dns.clone());
                db.dns = export.dns;
                db.dns_provider = export.dns_provider;
            }
            if let Some(hours) = export.auto_restart_interval_hours {
                db.set_auto_restart_interval_hours(hours);
                applied_interval = Some(hours);
            }
            if !export.vk_access_token.is_empty() {
                db.vk_access_token = export.vk_access_token;
            }
            if !export.vk_hashes.is_empty() {
                db.vk_hashes = export.vk_hashes;
            }
        }
        state.app.db_persistence.submit(db.clone())
    };

    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if let Some(dns) = applied_dns {
        *state.app.dns.write().await = dns;
        let _ = crate::protocol::broadcast_tunnel_configuration(&state.app).await;
    }
    if let Some(hours) = applied_interval {
        state.app.auto_restart_interval_tx.send_replace(hours);
    }
    let _ = refresh_credentials_report(&state).await;

    Json(serde_json::json!({
        "ok": true,
        "added_clients": added_clients,
        "settings_imported": do_settings
    }))
    .into_response()
}

#[derive(Serialize)]
struct GroupInfo {
    id: String,
    name: String,
    routing_rule_id: String,
    admin_uuid: String,
    sub_uuid: String,
    member_count: usize,
    up: i64,
    down: i64,
    active_sessions: usize,
}

async fn groups_get(State(state): State<WebState>) -> Response {
    let db = state.app.db.read().await;
    let mut list = Vec::new();
    for group in db.groups.values() {
        let mut member_count = 0;
        let mut up = 0i64;
        let mut down = 0i64;
        let mut active_sessions = 0;
        for (_pass, p_entry) in &db.passwords {
            if p_entry.group_id == group.id {
                member_count += 1;
                up += p_entry.up_bytes;
                down += p_entry.down_bytes;
                active_sessions += count_active_sessions(&state.app.sessions, _pass);
            }
        }
        list.push(GroupInfo {
            id: group.id.clone(),
            name: group.name.clone(),
            routing_rule_id: group.routing_rule_id.clone(),
            admin_uuid: group.admin_uuid.clone(),
            sub_uuid: group.sub_uuid.clone(),
            member_count,
            up,
            down,
            active_sessions,
        });
    }
    Json(list).into_response()
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: String,
}

async fn groups_create(
    State(state): State<WebState>,
    Json(request): Json<CreateGroupRequest>,
) -> Response {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 64 {
        return (StatusCode::BAD_REQUEST, "invalid group name").into_response();
    }
    let id = format!("grp_{}", random_token(8));
    let group = ClientGroup {
        id: id.clone(),
        name: name.to_string(),
        routing_rule_id: String::new(),
        admin_uuid: String::new(),
        sub_uuid: model::random_uuid_v4(),
        workers: None,
        vk_token: None,
        vk_hashes: None,
    };
    let revision = {
        let mut db = state.app.db.write().await;
        db.groups.insert(id, group.clone());
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    Json(group).into_response()
}

#[derive(Deserialize)]
struct UpdateGroupRequest {
    name: Option<String>,
    routing_rule_id: Option<String>,
}

async fn groups_update(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateGroupRequest>,
) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        let Some(group) = db.groups.get_mut(&id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if let Some(name) = request.name {
            let n = name.trim();
            if n.is_empty() || n.len() > 64 {
                return (StatusCode::BAD_REQUEST, "invalid group name").into_response();
            }
            group.name = n.to_string();
        }
        if let Some(r_id) = request.routing_rule_id {
            group.routing_rule_id = r_id;
        }
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    let _ = crate::protocol::broadcast_tunnel_configuration(&state.app).await;
    StatusCode::OK.into_response()
}

async fn groups_delete(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let (revision, deleted_passwords) = {
        let mut db = state.app.db.write().await;
        if db.groups.remove(&id).is_none() {
            return StatusCode::NOT_FOUND.into_response();
        }
        let mut deleted = Vec::new();
        db.passwords.retain(|pwd, entry| {
            if entry.group_id == id {
                deleted.push(pwd.clone());
                false
            } else {
                true
            }
        });
        for pwd in &deleted {
            state.app.derived_keys.remove(pwd);
        }
        let rev = state.app.db_persistence.submit(db.clone());
        (rev, deleted)
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    for pwd in &deleted_passwords {
        crate::protocol::drop_password_sessions(&state.app, pwd);
    }
    if let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (StatusCode::OK, [("x-csqtt-reload-error", warning)], "saved").into_response();
    }
    StatusCode::OK.into_response()
}

async fn group_admin_link_post(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db.groups.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    };
    if group.admin_uuid.is_empty() {
        group.admin_uuid = model::random_uuid_v4();
    }
    let admin_uuid = group.admin_uuid.clone();
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "admin_uuid": admin_uuid
        })),
    )
        .into_response()
}

async fn group_admin_link_regenerate(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db.groups.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    };
    group.admin_uuid = model::random_uuid_v4();
    let admin_uuid = group.admin_uuid.clone();
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "admin_uuid": admin_uuid
        })),
    )
        .into_response()
}

async fn group_admin_link_delete(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db.groups.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    };
    group.admin_uuid.clear();
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true
        })),
    )
        .into_response()
}

async fn group_admin_page(
    State(state): State<WebState>,
    Path(admin_uuid): Path<String>,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let db = state.app.db.read().await;
    let exists = db
        .groups
        .values()
        .any(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid);
    if !exists {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    Html(render_web_html(GROUP_ADMIN_HTML)).into_response()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// All import formats belong to the same access. Never change its password or server mode.
#[derive(Serialize)]
struct ImportLinks {
    link: String,
    legacy_link: String,
    ios_link: String,
    requires_vk_hashes: bool,
}

impl ImportLinks {
    fn new(link: String) -> Self {
        let (legacy_link, ios_link) = compatibility_links(&link);
        let requires_vk_hashes = !legacy_link.split('&').any(|field| {
            field
                .strip_prefix("hashes=")
                .is_some_and(|hashes| !hashes.is_empty())
        });
        Self {
            link,
            legacy_link,
            ios_link,
            requires_vk_hashes,
        }
    }
}

fn render_web_html(template: &str) -> String {
    template
        .replace("__PANEL_STYLE__", include_str!("web/panel.css"))
        .replace(
            "__CLIENT_PROFILE_JS__",
            include_str!("web/client-profile.js"),
        )
}

// Alternative import formats use the same authenticated subscription, password and VK calls.
fn compatibility_links(csqtt_link: &str) -> (String, String) {
    let Some(payload) = decrypt_csqtt_link(csqtt_link) else {
        return (String::new(), String::new());
    };
    let Some(query) = payload.strip_prefix("connect?") else {
        return (String::new(), String::new());
    };
    let fields: std::collections::HashMap<_, _> = query
        .split('&')
        .filter_map(|item| item.split_once('='))
        .collect();
    let decode = |value: &str| -> Option<String> {
        let mut bytes = Vec::new();
        let mut iter = value.as_bytes().iter().copied();
        while let Some(byte) = iter.next() {
            if byte == b'%' {
                let hi = (iter.next()? as char).to_digit(16)?;
                let lo = (iter.next()? as char).to_digit(16)?;
                bytes.push((hi * 16 + lo) as u8);
            } else {
                bytes.push(byte);
            }
        }
        String::from_utf8(bytes).ok()
    };
    let get = |key| {
        fields
            .get(key)
            .and_then(|value| decode(value))
            .unwrap_or_default()
    };
    let host = get("host");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let calls = fields
        .get("hashes")
        .map(|raw| {
            raw.split('+')
                .filter_map(decode)
                .map(|hash| {
                    if hash.starts_with("https://") || hash.starts_with("http://") {
                        hash
                    } else {
                        format!("https://vk.ru/call/join/{hash}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let settings = serde_json::json!({
        "version": 1, "type": "connection", "settings": {
            "useCsqtt": true, "csqttPassword": get("password"),
            "peerAddress": format!("{}:{}", host, get("peer")), "vkLink": calls,
        }
    });
    use base64::Engine;
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(settings.to_string());
    (
        format!("csqtt://{payload}"),
        format!("vkturnproxy://import?data={data}"),
    )
}

fn render_client_sub_html(client_name: &str, csqtt_link: &str) -> String {
    let name_esc = html_escape(client_name);
    let link_esc = html_escape(csqtt_link);
    let (legacy, ios) = compatibility_links(csqtt_link);
    render_web_html(CLIENT_SUB_HTML)
        .replace(
            "__REQUIRES_VK_HASHES__",
            if ImportLinks::new(csqtt_link.to_owned()).requires_vk_hashes {
                "true"
            } else {
                "false"
            },
        )
        .replace("__LEGACY_LINK__", &html_escape(&legacy))
        .replace("__IOS_LINK__", &html_escape(&ios))
        .replace("__CLIENT_NAME__", &name_esc)
        .replace("__CSQTT_LINK__", &link_esc)
}

fn render_group_sub_html(group_name: &str, clients_json: &str, count: usize) -> String {
    let name_esc = html_escape(group_name);
    let json_esc = js_json_embed(clients_json);
    render_web_html(GROUP_SUB_HTML)
        .replace("__GROUP_NAME__", &name_esc)
        .replace("__CLIENTS_COUNT__", &count.to_string())
        .replace("__CLIENTS_JSON__", &json_esc)
}

fn js_json_embed(json: &str) -> String {
    json.replace('<', "\\u003C")
        .replace('>', "\\u003E")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

async fn client_sub_page(
    State(state): State<WebState>,
    Path(sub_uuid): Path<String>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let sub_uuid = sub_uuid.trim();
    if sub_uuid.is_empty() {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    let db = state.app.db.read().await;
    let host = resolve_client_host(&headers, &state).await;

    if !db.main_sub_uuid.is_empty() && db.main_sub_uuid == sub_uuid && !db.main_password.is_empty()
    {
        let main_peer_port = state.app.listen.port();
        let link = make_main_link(&host, main_peer_port, &db);
        return Html(render_client_sub_html("Владелец", &link)).into_response();
    }

    let client_entry = db
        .passwords
        .iter()
        .find(|(_, entry)| !entry.sub_uuid.is_empty() && entry.sub_uuid == sub_uuid);
    let Some((password, entry)) = client_entry else {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    };
    let client_peer_port = if entry.dtls_port == 0 {
        state.app.listen.port()
    } else {
        entry.dtls_port
    };
    let effective_vk_token = if !entry.group_id.is_empty() {
        db.groups
            .get(&entry.group_id)
            .and_then(|g| g.vk_token.as_deref())
            .unwrap_or(&db.vk_access_token)
    } else {
        &db.vk_access_token
    };
    let link = make_entry_link(&host, client_peer_port, password, entry, effective_vk_token);
    let client_name = if entry.name.is_empty() {
        "Клиент".to_string()
    } else {
        entry.name.clone()
    };
    Html(render_client_sub_html(&client_name, &link)).into_response()
}

async fn client_sub_json(
    State(state): State<WebState>,
    Path(sub_uuid): Path<String>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let sub_uuid = sub_uuid.trim();
    if sub_uuid.is_empty() {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    let db = state.app.db.read().await;
    let host = resolve_client_host(&headers, &state).await;

    if !db.main_sub_uuid.is_empty() && db.main_sub_uuid == sub_uuid && !db.main_password.is_empty()
    {
        let main_peer_port = state.app.listen.port();
        let link = make_main_link(&host, main_peer_port, &db);
        let (legacy_link, ios_link) = compatibility_links(&link);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "name": "Владелец",
                "link": link,
                "legacy_link": legacy_link,
                "ios_link": ios_link,
                "requires_vk_hashes": ImportLinks::new(link.clone()).requires_vk_hashes,
                "sub_uuid": db.main_sub_uuid,
            })),
        )
            .into_response();
    }

    let client_entry = db
        .passwords
        .iter()
        .find(|(_, entry)| !entry.sub_uuid.is_empty() && entry.sub_uuid == sub_uuid);
    let Some((password, entry)) = client_entry else {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    };
    let client_peer_port = if entry.dtls_port == 0 {
        state.app.listen.port()
    } else {
        entry.dtls_port
    };
    let effective_vk_token = if !entry.group_id.is_empty() {
        db.groups
            .get(&entry.group_id)
            .and_then(|g| g.vk_token.as_deref())
            .unwrap_or(&db.vk_access_token)
    } else {
        &db.vk_access_token
    };
    let link = make_entry_link(&host, client_peer_port, password, entry, effective_vk_token);
    let (legacy_link, ios_link) = compatibility_links(&link);
    let client_name = if entry.name.is_empty() {
        "Клиент".to_string()
    } else {
        entry.name.clone()
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "name": client_name,
            "link": link,
                "legacy_link": legacy_link,
                "ios_link": ios_link,
                "requires_vk_hashes": ImportLinks::new(link.clone()).requires_vk_hashes,
            "sub_uuid": entry.sub_uuid,
        })),
    )
        .into_response()
}

#[derive(Serialize)]
struct GroupSubClientItem {
    name: String,
    #[serde(flatten)]
    links: ImportLinks,
    sub_uuid: String,
}

async fn group_sub_page(
    State(state): State<WebState>,
    Path(group_sub_uuid): Path<String>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let group_sub_uuid = group_sub_uuid.trim();
    if group_sub_uuid.is_empty() {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    let db = state.app.db.read().await;
    let group_entry = db
        .groups
        .values()
        .find(|g| !g.sub_uuid.is_empty() && g.sub_uuid == group_sub_uuid);
    let Some(group) = group_entry else {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    };

    let host = resolve_client_host(&headers, &state).await;
    let effective_vk_token = group.vk_token.as_deref().unwrap_or(&db.vk_access_token);
    let mut items = Vec::new();
    for (password, entry) in &db.passwords {
        if entry.group_id == group.id {
            let client_peer_port = if entry.dtls_port == 0 {
                state.app.listen.port()
            } else {
                entry.dtls_port
            };
            let link =
                make_entry_link(&host, client_peer_port, password, entry, effective_vk_token);
            let name = if entry.name.is_empty() {
                "Клиент".to_string()
            } else {
                entry.name.clone()
            };
            items.push(GroupSubClientItem {
                name,
                links: ImportLinks::new(link),
                sub_uuid: entry.sub_uuid.clone(),
            });
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let count = items.len();
    let clients_json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
    Html(render_group_sub_html(&group.name, &clients_json, count)).into_response()
}

async fn group_sub_json(
    State(state): State<WebState>,
    Path(group_sub_uuid): Path<String>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let group_sub_uuid = group_sub_uuid.trim();
    if group_sub_uuid.is_empty() {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    let db = state.app.db.read().await;
    let group_entry = db
        .groups
        .values()
        .find(|g| !g.sub_uuid.is_empty() && g.sub_uuid == group_sub_uuid);
    let Some(group) = group_entry else {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    };

    let host = resolve_client_host(&headers, &state).await;
    let effective_vk_token = group.vk_token.as_deref().unwrap_or(&db.vk_access_token);
    let mut items = Vec::new();
    for (password, entry) in &db.passwords {
        if entry.group_id == group.id {
            let client_peer_port = if entry.dtls_port == 0 {
                state.app.listen.port()
            } else {
                entry.dtls_port
            };
            let link =
                make_entry_link(&host, client_peer_port, password, entry, effective_vk_token);
            let name = if entry.name.is_empty() {
                "Клиент".to_string()
            } else {
                entry.name.clone()
            };
            items.push(GroupSubClientItem {
                name,
                links: ImportLinks::new(link),
                sub_uuid: entry.sub_uuid.clone(),
            });
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group": {
                "id": group.id,
                "name": group.name,
                "sub_uuid": group.sub_uuid,
            },
            "clients": items,
        })),
    )
        .into_response()
}

async fn universal_sub_json(
    State(state): State<WebState>,
    Path(uuid): Path<String>,
    headers: HeaderMap,
    token: Option<Extension<Arc<StealthAbortController>>>,
) -> Response {
    let trimmed = uuid.trim();
    if trimmed.is_empty() {
        if let Some(Extension(ctrl)) = token {
            ctrl.abort();
        }
        return stealth_abort_response();
    }
    let is_client = {
        let db = state.app.db.read().await;
        (!db.main_sub_uuid.is_empty() && db.main_sub_uuid == trimmed)
            || db
                .passwords
                .values()
                .any(|p| !p.sub_uuid.is_empty() && p.sub_uuid == trimmed)
    };
    if is_client {
        return client_sub_json(State(state), Path(uuid), headers, token).await;
    }
    let is_group = {
        let db = state.app.db.read().await;
        db.groups
            .values()
            .any(|g| !g.sub_uuid.is_empty() && g.sub_uuid == trimmed)
    };
    if is_group {
        return group_sub_json(State(state), Path(uuid), headers, token).await;
    }
    if let Some(Extension(ctrl)) = token {
        ctrl.abort();
    }
    stealth_abort_response()
}

async fn client_sub_link_regenerate(
    State(state): State<WebState>,
    Path(password): Path<String>,
) -> Response {
    let (revision, new_sub) = {
        let mut db = state.app.db.write().await;
        if secret_eq(&password, &db.main_password) {
            db.main_sub_uuid = model::random_uuid_v4();
            let new_sub = db.main_sub_uuid.clone();
            let rev = state.app.db_persistence.submit(db.clone());
            (rev, new_sub)
        } else if let Some(entry) = db.passwords.get_mut(&password) {
            entry.sub_uuid = model::random_uuid_v4();
            let new_sub = entry.sub_uuid.clone();
            let rev = state.app.db_persistence.submit(db.clone());
            (rev, new_sub)
        } else {
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "sub_uuid": new_sub
        })),
    )
        .into_response()
}

async fn group_sub_link_regenerate(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Response {
    let (revision, new_sub) = {
        let mut db = state.app.db.write().await;
        let Some(group) = db.groups.get_mut(&id) else {
            return (StatusCode::NOT_FOUND, "group not found").into_response();
        };
        group.sub_uuid = model::random_uuid_v4();
        let new_sub = group.sub_uuid.clone();
        let rev = state.app.db_persistence.submit(db.clone());
        (rev, new_sub)
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "sub_uuid": new_sub
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct BatchToggleRequest {
    passwords: Vec<String>,
    active: bool,
}

async fn api_clients_batch_toggle(
    State(state): State<WebState>,
    Json(req): Json<BatchToggleRequest>,
) -> Response {
    let mut updated = 0usize;
    let mut passwords_to_disconnect = Vec::new();
    let revision = {
        let mut db = state.app.db.write().await;
        for pwd in &req.passwords {
            if let Some(entry) = db.passwords.get_mut(pwd) {
                entry.is_deactivated = !req.active;
                updated += 1;
                if !req.active {
                    passwords_to_disconnect.push(pwd.clone());
                }
            }
        }
        if updated > 0 {
            Some(state.app.db_persistence.submit(db.clone()))
        } else {
            None
        }
    };
    if let Some(rev) = revision {
        let _ = wait_for_persistence(&state, rev).await;
    }
    for pwd in &passwords_to_disconnect {
        crate::protocol::drop_password_sessions(&state.app, pwd);
    }
    if updated > 0 {
        let _ = refresh_credentials_report(&state).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "updated": updated })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct BatchExtendRequest {
    passwords: Vec<String>,
    days: i64,
}

async fn api_clients_batch_extend(
    State(state): State<WebState>,
    Json(req): Json<BatchExtendRequest>,
) -> Response {
    if req.days <= 0 || req.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be between 1 and 3650").into_response();
    }
    let add_secs = req.days.saturating_mul(86400);
    let current_time = now();
    let mut updated = 0usize;
    let revision = {
        let mut db = state.app.db.write().await;
        for pwd in &req.passwords {
            if let Some(entry) = db.passwords.get_mut(pwd) {
                let base = if entry.expires_at > current_time {
                    entry.expires_at
                } else {
                    current_time
                };
                entry.expires_at = base.saturating_add(add_secs);
                updated += 1;
            }
        }
        if updated > 0 {
            Some(state.app.db_persistence.submit(db.clone()))
        } else {
            None
        }
    };
    if let Some(rev) = revision {
        let _ = wait_for_persistence(&state, rev).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "updated": updated })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct BatchPasswordsRequest {
    passwords: Vec<String>,
}

async fn api_clients_batch_reset_traffic(
    State(state): State<WebState>,
    Json(req): Json<BatchPasswordsRequest>,
) -> Response {
    let mut updated = 0usize;
    let revision = {
        let mut db = state.app.db.write().await;
        for pwd in &req.passwords {
            if pwd == &db.main_password {
                db.main_down_bytes = 0;
                db.main_up_bytes = 0;
                updated += 1;
            } else if let Some(entry) = db.passwords.get_mut(pwd) {
                entry.down_bytes = 0;
                entry.up_bytes = 0;
                updated += 1;
            }
        }
        if updated > 0 {
            Some(state.app.db_persistence.submit(db.clone()))
        } else {
            None
        }
    };
    if let Some(rev) = revision {
        let _ = wait_for_persistence(&state, rev).await;
    }
    for pwd in &req.passwords {
        for s in state.app.sessions.iter() {
            if &s.password == pwd {
                s.down_bytes.store(0, Ordering::Relaxed);
                s.up_bytes.store(0, Ordering::Relaxed);
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "updated": updated })),
    )
        .into_response()
}

async fn api_clients_batch_delete(
    State(state): State<WebState>,
    Json(req): Json<BatchPasswordsRequest>,
) -> Response {
    let mut deleted = 0usize;
    let revision = {
        let mut db = state.app.db.write().await;
        for pwd in &req.passwords {
            if db.passwords.remove(pwd).is_some() {
                state.app.derived_keys.remove(pwd);
                deleted += 1;
            }
        }
        if deleted > 0 {
            Some(state.app.db_persistence.submit(db.clone()))
        } else {
            None
        }
    };
    if let Some(rev) = revision {
        let _ = wait_for_persistence(&state, rev).await;
    }
    for pwd in &req.passwords {
        crate::protocol::drop_password_sessions(&state.app, pwd);
    }
    if deleted > 0 {
        let _ = refresh_credentials_report(&state).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "deleted": deleted })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct BatchGroupAssignRequest {
    passwords: Vec<String>,
    group_id: String,
}

async fn api_clients_batch_group(
    State(state): State<WebState>,
    Json(req): Json<BatchGroupAssignRequest>,
) -> Response {
    let mut moved = 0usize;
    let revision = {
        let mut db = state.app.db.write().await;
        let gid = req.group_id.trim();
        if !gid.is_empty() && !db.groups.contains_key(gid) {
            return (StatusCode::BAD_REQUEST, "target group not found").into_response();
        }
        for pwd in &req.passwords {
            if let Some(entry) = db.passwords.get_mut(pwd) {
                entry.group_id = gid.to_string();
                moved += 1;
            }
        }
        if moved > 0 {
            Some(state.app.db_persistence.submit(db.clone()))
        } else {
            None
        }
    };
    if let Some(rev) = revision {
        let _ = wait_for_persistence(&state, rev).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "moved": moved })),
    )
        .into_response()
}

#[derive(Deserialize, Default)]
struct DpiDiagnosticsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn api_diagnostics_dpi(Query(query): Query<DpiDiagnosticsQuery>) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let frames: Vec<protocol::DpiFrame> = protocol::DPI_RING
        .read()
        .map(|ring| {
            let count = limit.min(ring.len());
            ring.iter().skip(ring.len() - count).cloned().collect()
        })
        .unwrap_or_default();
    Json(serde_json::json!({
        "ok": true,
        "ring_len": protocol::dpi_ring_len(),
        "frames": frames,
    }))
}

async fn group_admin_data_get(
    State(state): State<WebState>,
    Path(admin_uuid): Path<String>,
) -> Response {
    let db = state.app.db.read().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let server_ip = state.app.public_ip.read().await.clone();
    let host = if server_ip.is_empty() {
        "0.0.0.0".to_string()
    } else {
        server_ip.clone()
    };
    let peer_port = state.app.listen.port();
    let effective_vk_token = group.vk_token.as_deref().unwrap_or(&db.vk_access_token);
    let effective_vk_hashes = group.vk_hashes.as_deref().unwrap_or(&db.vk_hashes);
    let mut clients = Vec::new();
    for (_pass, p_entry) in &db.passwords {
        if p_entry.group_id == group.id {
            let link = make_entry_link(&host, peer_port, _pass, p_entry, effective_vk_token);
            let imports = ImportLinks::new(link);
            clients.push(serde_json::json!({
                "password": _pass,
                "name": p_entry.name,
                "expires": p_entry.expires_at,
                "up": p_entry.up_bytes,
                "down": p_entry.down_bytes,
                "active": !p_entry.is_deactivated && !model::is_expired(p_entry),
                "is_deactivated": p_entry.is_deactivated,
                "active_sessions": count_active_sessions(&state.app.sessions, _pass),
                "ip": if p_entry.ip.is_empty() { "10.66.67.3" } else { &p_entry.ip },
                "device_ip": if p_entry.ip.is_empty() { "10.66.67.3" } else { &p_entry.ip },
                "group_id": p_entry.group_id,
                "peer_port": p_entry.wg_port,
                "vk_hashes": p_entry.vk_hashes,
                "vk_token": p_entry.vk_token_enabled,
                "sub_uuid": p_entry.sub_uuid,
                "workers": p_entry.workers.unwrap_or(0),
                "link": imports.link,
                "legacy_link": imports.legacy_link,
                "ios_link": imports.ios_link,
                "requires_vk_hashes": imports.requires_vk_hashes,
            }));
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group": {
                "id": group.id,
                "name": group.name,
                "workers": group.workers.unwrap_or(0),
                "vk_token": effective_vk_token,
                "vk_hashes": effective_vk_hashes,
            },
            "clients": clients,
            "server_ip": server_ip,
            "peer_port": peer_port
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct GroupAdminSettingsRequest {
    #[serde(default)]
    vk_token: Option<String>,
    #[serde(default)]
    vk_hashes: Option<String>,
    #[serde(default)]
    workers: Option<u32>,
}

async fn group_admin_settings_post(
    State(state): State<WebState>,
    Path(admin_uuid): Path<String>,
    Json(payload): Json<GroupAdminSettingsRequest>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values_mut()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    if let Some(token) = payload.vk_token {
        let normalized = match normalize_vk_access_token(&token) {
            Ok(t) => t,
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        };
        group.vk_token = Some(normalized);
    }
    if let Some(hashes) = payload.vk_hashes {
        let normalized = match normalize_client_vk_hashes(&hashes) {
            Ok(h) => h,
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        };
        group.vk_hashes = Some(normalized);
    }
    if let Some(w) = payload.workers {
        match validate_workers(Some(w)) {
            Ok(validated) => group.workers = validated,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    }
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    let _ = refresh_credentials_report(&state).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(Deserialize)]
struct GroupAdminCreateClientRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    days: i64,
    #[serde(default)]
    workers: Option<u32>,
}

async fn group_admin_client_create(
    State(state): State<WebState>,
    Path(admin_uuid): Path<String>,
    Json(payload): Json<GroupAdminCreateClientRequest>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group_id) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
        .map(|g| g.id.clone())
    else {
        return stealth_abort_response();
    };
    let client_name = if payload.name.trim().is_empty() {
        model::generate_unique_client_name(model::existing_client_names_in_scope(
            &db, &group_id, None,
        ))
    } else {
        let trimmed = payload.name.trim().to_string();
        if let Err(msg) = validate_client_name(&trimmed) {
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
        if model::is_client_name_taken(
            model::existing_client_names_in_scope(&db, &group_id, None),
            &trimmed,
        ) {
            return (
                StatusCode::BAD_REQUEST,
                "Участник с таким именем уже существует в этой группе",
            )
                .into_response();
        }
        trimmed
    };
    let validated_workers = match validate_workers(payload.workers) {
        Ok(w) => w,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let mut pass = model::random_password();
    while db.passwords.contains_key(&pass) {
        pass = model::random_password();
    }
    let now_ts = model::now();
    let expires_at = if payload.days > 0 {
        now_ts.saturating_add(payload.days.saturating_mul(86400))
    } else {
        0
    };
    let sub_uuid = model::random_uuid_v4();
    let ip = model::get_next_ip(&db).unwrap_or_default();
    let entry = model::PasswordEntry {
        ip,
        expires_at,
        down_bytes: 0,
        up_bytes: 0,
        vk_hash: String::new(),
        ports: String::new(),
        is_deactivated: false,
        name: client_name,
        vk_hashes: String::new(),
        vk_token_enabled: false,
        dtls_port: 0,
        wg_port: 0,
        local_port: 0,
        group_id,
        routing_rule_id: String::new(),
        sub_uuid: sub_uuid.clone(),
        workers: validated_workers,
    };
    db.passwords.insert(pass.clone(), entry);
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    if let Err(message) = refresh_credentials_report(&state).await {
        let warning = format!("saved but reload failed: {message}");
        return (
            StatusCode::OK,
            [("x-csqtt-reload-error", warning)],
            Json(serde_json::json!({
                "ok": true,
                "password": pass,
                "sub_uuid": sub_uuid
            })),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "password": pass,
            "sub_uuid": sub_uuid
        })),
    )
        .into_response()
}

async fn group_admin_client_toggle(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let Some(entry) = db.passwords.get_mut(&password) else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };
    if entry.group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    entry.is_deactivated = !entry.is_deactivated;
    let is_deactivated = entry.is_deactivated;
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    if is_deactivated {
        crate::protocol::drop_password_sessions(&state.app, &password);
    }
    let _ = refresh_credentials_report(&state).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "is_deactivated": is_deactivated
        })),
    )
        .into_response()
}

async fn group_admin_client_reset_traffic(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let Some(entry) = db.passwords.get_mut(&password) else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };
    if entry.group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    entry.up_bytes = 0;
    entry.down_bytes = 0;
    for s in state.app.sessions.iter() {
        if s.value().password == password {
            s.value().up_bytes.store(0, Ordering::Relaxed);
            s.value().down_bytes.store(0, Ordering::Relaxed);
        }
    }
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn group_admin_client_extend(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let Some(entry) = db.passwords.get_mut(&password) else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };
    if entry.group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let now_ts = model::now();
    let base = if entry.expires_at > now_ts {
        entry.expires_at
    } else {
        now_ts
    };
    entry.expires_at = base.saturating_add(30 * 86400);
    let expires = entry.expires_at;
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    let _ = refresh_credentials_report(&state).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "expires": expires })),
    )
        .into_response()
}

async fn group_admin_client_unbind(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
) -> Response {
    let db = state.app.db.read().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let Some(entry) = db.passwords.get(&password) else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };
    if entry.group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    drop(db);
    crate::protocol::drop_password_sessions(&state.app, &password);
    crate::protocol::forget_idle_password_epoch(&state.app, &password);
    let _ = refresh_credentials_report(&state).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(Deserialize)]
struct GroupAdminUpdateClientRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    days: Option<i64>,
    #[serde(default)]
    workers: Option<u32>,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    vk_token: Option<bool>,
}

async fn group_admin_client_update(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
    Json(payload): Json<GroupAdminUpdateClientRequest>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let current_group_id = match db.passwords.get(&password) {
        Some(e) => e.group_id.clone(),
        None => return (StatusCode::NOT_FOUND, "client not found").into_response(),
    };
    if current_group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let validated_name = if let Some(name) = payload.name {
        let trimmed = name.trim().to_string();
        let scope_names = model::existing_client_names_in_scope(&db, &group_id, Some(&password));
        let client_name = if trimmed.is_empty() {
            model::generate_unique_client_name(&scope_names)
        } else {
            if let Err(msg) = validate_client_name(&trimmed) {
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
            if model::is_client_name_taken(&scope_names, &trimmed) {
                return (
                    StatusCode::BAD_REQUEST,
                    "Участник с таким именем уже существует в этой группе",
                )
                    .into_response();
            }
            trimmed
        };
        Some(client_name)
    } else {
        None
    };

    let entry = db.passwords.get_mut(&password).unwrap();
    if let Some(name) = validated_name {
        entry.name = name;
    }
    if let Some(days) = payload.days {
        if days > 0 {
            entry.expires_at = model::now().saturating_add(days.saturating_mul(86400));
        } else {
            entry.expires_at = 0;
        }
    }
    if let Some(w) = payload.workers {
        match validate_workers(Some(w)) {
            Ok(validated) => entry.workers = validated,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    }
    if let Some(ref h) = payload.hash {
        let vk_hashes = match normalize_client_vk_hashes(h) {
            Ok(v) => v,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        };
        entry.vk_hash = vk_hashes.clone();
        entry.vk_hashes = vk_hashes;
    }
    if let Some(vt) = payload.vk_token {
        entry.vk_token_enabled = vt;
        if vt {
            entry.vk_hash.clear();
            entry.vk_hashes.clear();
        }
    }
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    let _ = refresh_credentials_report(&state).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn group_admin_client_delete(
    State(state): State<WebState>,
    Path((admin_uuid, password)): Path<(String, String)>,
) -> Response {
    let mut db = state.app.db.write().await;
    let Some(group) = db
        .groups
        .values()
        .find(|g| !g.admin_uuid.is_empty() && g.admin_uuid == admin_uuid)
    else {
        return stealth_abort_response();
    };
    let group_id = group.id.clone();
    let Some(entry) = db.passwords.get(&password) else {
        return (StatusCode::NOT_FOUND, "client not found").into_response();
    };
    if entry.group_id != group_id {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    db.passwords.remove(&password);
    let snapshot = db.clone();
    drop(db);
    state.app.db_persistence.submit(snapshot);
    crate::protocol::drop_password_sessions(&state.app, &password);
    let _ = refresh_credentials_report(&state).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(Serialize)]
struct RoutingRuleInfo {
    id: String,
    name: String,
    is_whitelist: bool,
    mode: String,
    packages: Vec<String>,
    template_domains: bool,
    direct_domains: Vec<String>,
    domains: Vec<String>,
    domains_is_whitelist: bool,
    domains_mode: String,
    ip_is_whitelist: bool,
    ip_mode: String,
    ips: Vec<String>,
    assigned_groups: Vec<String>,
    target_group_ids: Vec<String>,
    assigned_clients: Vec<String>,
    target_client_passwords: Vec<String>,
}

async fn routing_rules_get(State(state): State<WebState>) -> Response {
    let db = state.app.db.read().await;
    let mut list = Vec::new();
    for rule in db.routing_rules.values() {
        let mut assigned_groups = Vec::new();
        for group in db.groups.values() {
            if group.routing_rule_id == rule.id {
                assigned_groups.push(group.id.clone());
            }
        }
        let mut assigned_clients = Vec::new();
        if !db.main_password.is_empty() && db.main_routing_rule_id == rule.id {
            assigned_clients.push(db.main_password.clone());
        }
        for (pass, entry) in &db.passwords {
            if entry.routing_rule_id == rule.id {
                assigned_clients.push(pass.clone());
            }
        }
        list.push(RoutingRuleInfo {
            id: rule.id.clone(),
            name: rule.name.clone(),
            is_whitelist: rule.is_whitelist,
            mode: if rule.is_whitelist {
                "whitelist".to_string()
            } else {
                "blacklist".to_string()
            },
            packages: rule.packages.clone(),
            template_domains: rule.template_domains,
            direct_domains: rule.direct_domains.clone(),
            domains: rule.direct_domains.clone(),
            domains_is_whitelist: rule.domains_is_whitelist,
            domains_mode: if rule.domains_is_whitelist {
                "whitelist".to_string()
            } else {
                "blacklist".to_string()
            },
            ip_is_whitelist: rule.ip_is_whitelist,
            ip_mode: if rule.ip_is_whitelist {
                "whitelist".to_string()
            } else {
                "blacklist".to_string()
            },
            ips: rule.ips.clone(),
            assigned_groups: assigned_groups.clone(),
            target_group_ids: assigned_groups,
            assigned_clients: assigned_clients.clone(),
            target_client_passwords: assigned_clients,
        });
    }
    Json(list).into_response()
}

const TEMPLATE_DOMAINS_TXT: &str = include_str!("../app/src/main/assets/domains.txt");

async fn template_domains_get() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        TEMPLATE_DOMAINS_TXT,
    )
}

#[derive(Deserialize)]
struct CreateRoutingRuleRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_whitelist: bool,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    template_domains: bool,
    #[serde(default)]
    direct_domains: Vec<String>,
    #[serde(default)]
    domains: Option<Vec<String>>,
    #[serde(default)]
    domains_mode: Option<String>,
    #[serde(default)]
    domains_is_whitelist: bool,
    #[serde(default)]
    ip_mode: Option<String>,
    #[serde(default)]
    ip_is_whitelist: bool,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    assigned_groups: Vec<String>,
    #[serde(default)]
    target_group_ids: Option<Vec<String>>,
    #[serde(default)]
    assigned_clients: Vec<String>,
    #[serde(default)]
    target_client_passwords: Option<Vec<String>>,
}

async fn routing_rules_create(
    State(state): State<WebState>,
    Json(request): Json<CreateRoutingRuleRequest>,
) -> Response {
    let name_str = request.name.trim();
    let name = if name_str.is_empty() {
        "Правило".to_string()
    } else {
        name_str.chars().take(64).collect::<String>()
    };
    let is_whitelist = if let Some(ref m) = request.mode {
        m == "whitelist"
    } else {
        request.is_whitelist
    };
    let direct_domains = if !request.direct_domains.is_empty() {
        request.direct_domains
    } else {
        request.domains.unwrap_or_default()
    };
    let domains_is_whitelist = if let Some(ref m) = request.domains_mode {
        m == "whitelist"
    } else {
        request.domains_is_whitelist
    };
    let ip_is_whitelist = if let Some(ref m) = request.ip_mode {
        m == "whitelist"
    } else {
        request.ip_is_whitelist
    };
    let assigned_groups = if !request.assigned_groups.is_empty() {
        request.assigned_groups
    } else {
        request.target_group_ids.unwrap_or_default()
    };
    let assigned_clients = if !request.assigned_clients.is_empty() {
        request.assigned_clients
    } else {
        request.target_client_passwords.unwrap_or_default()
    };
    let id = format!("rule_{}", random_token(8));
    let rule = RoutingRule {
        id: id.clone(),
        name,
        is_whitelist,
        packages: request.packages,
        template_domains: request.template_domains,
        direct_domains,
        domains_is_whitelist,
        ip_is_whitelist,
        ips: request.ips,
    };
    let revision = {
        let mut db = state.app.db.write().await;
        for g_id in &assigned_groups {
            if let Some(g) = db.groups.get_mut(g_id) {
                g.routing_rule_id = id.clone();
            }
        }
        for c_pass in &assigned_clients {
            if let Some(p) = db.passwords.get_mut(c_pass) {
                p.routing_rule_id = id.clone();
            }
        }
        if !db.main_password.is_empty() && assigned_clients.contains(&db.main_password) {
            db.main_routing_rule_id = id.clone();
        }
        db.routing_rules.insert(id, rule.clone());
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    Json(rule).into_response()
}

async fn routing_rules_update(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(request): Json<CreateRoutingRuleRequest>,
) -> Response {
    let name_str = request.name.trim();
    let name = if name_str.is_empty() {
        "Правило".to_string()
    } else {
        name_str.chars().take(64).collect::<String>()
    };
    let is_whitelist = if let Some(ref m) = request.mode {
        m == "whitelist"
    } else {
        request.is_whitelist
    };
    let direct_domains = if !request.direct_domains.is_empty() {
        request.direct_domains
    } else {
        request.domains.unwrap_or_default()
    };
    let domains_is_whitelist = if let Some(ref m) = request.domains_mode {
        m == "whitelist"
    } else {
        request.domains_is_whitelist
    };
    let ip_is_whitelist = if let Some(ref m) = request.ip_mode {
        m == "whitelist"
    } else {
        request.ip_is_whitelist
    };
    let assigned_groups = if !request.assigned_groups.is_empty() {
        request.assigned_groups
    } else {
        request.target_group_ids.unwrap_or_default()
    };
    let assigned_clients = if !request.assigned_clients.is_empty() {
        request.assigned_clients
    } else {
        request.target_client_passwords.unwrap_or_default()
    };
    let revision = {
        let mut db = state.app.db.write().await;
        let Some(rule) = db.routing_rules.get_mut(&id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        rule.name = name;
        rule.is_whitelist = is_whitelist;
        rule.packages = request.packages;
        rule.template_domains = request.template_domains;
        rule.direct_domains = direct_domains;
        rule.domains_is_whitelist = domains_is_whitelist;
        rule.ip_is_whitelist = ip_is_whitelist;
        rule.ips = request.ips;

        for group in db.groups.values_mut() {
            if assigned_groups.contains(&group.id) {
                group.routing_rule_id = id.clone();
            } else if group.routing_rule_id == id {
                group.routing_rule_id.clear();
            }
        }
        for (pass, entry) in db.passwords.iter_mut() {
            if assigned_clients.contains(pass) {
                entry.routing_rule_id = id.clone();
            } else if entry.routing_rule_id == id {
                entry.routing_rule_id.clear();
            }
        }
        if !db.main_password.is_empty() {
            if assigned_clients.contains(&db.main_password) {
                db.main_routing_rule_id = id.clone();
            } else if db.main_routing_rule_id == id {
                db.main_routing_rule_id.clear();
            }
        }
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    StatusCode::OK.into_response()
}

async fn routing_rules_delete(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        if db.routing_rules.remove(&id).is_none() {
            return StatusCode::NOT_FOUND.into_response();
        }
        for group in db.groups.values_mut() {
            if group.routing_rule_id == id {
                group.routing_rule_id.clear();
            }
        }
        for entry in db.passwords.values_mut() {
            if entry.routing_rule_id == id {
                entry.routing_rule_id.clear();
            }
        }
        if db.main_routing_rule_id == id {
            db.main_routing_rule_id.clear();
        }
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    StatusCode::OK.into_response()
}

async fn reboot(State(state): State<WebState>) -> Response {
    if state.app.restart_pending.swap(true, Ordering::AcqRel) {
        return (
            StatusCode::ACCEPTED,
            [
                (header::RETRY_AFTER, "3"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    }

    match crate::request_managed_restart(&state.app, "panel") {
        Ok(()) => (
            StatusCode::ACCEPTED,
            [
                (header::RETRY_AFTER, "3"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response(),
        Err(error) => {
            state.app.restart_pending.store(false, Ordering::Release);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("restart failed: {error:#}"),
            )
                .into_response()
        }
    }
}

async fn web_session_janitor(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(300));
    loop {
        timer.tick().await;
        let current = now();
        app.web_sessions.retain(|_, expiry| *expiry > current);
        app.login_limits.retain(|_, value| value.1 > current);
        app.web_sessions.shrink_to_fit();
        app.login_limits.shrink_to_fit();
    }
}

#[derive(Debug)]
pub struct StealthAbortController {
    aborted: AtomicBool,
    last_activity_ms: AtomicU64,
    birth_ms: AtomicU64,
    #[cfg(unix)]
    raw_fd: std::sync::Mutex<Option<std::os::fd::RawFd>>,
}

static WEB_CONNECTION_CONTROLLERS: Mutex<Vec<std::sync::Weak<StealthAbortController>>> =
    Mutex::new(Vec::new());

const WEB_IDLE_ABORT_MS: u64 = 120_000;
const WEB_MAX_CONNECTION_LIFETIME_MS: u64 = 30 * 60_000;

fn web_watchdog_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn web_slowloris_watchdog() {
    let mut timer = tokio::time::interval(Duration::from_millis(5_000));
    loop {
        timer.tick().await;
        let now = web_watchdog_now_ms();
        let stale = {
            let mut registry = WEB_CONNECTION_CONTROLLERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.shrink_to_fit();
            let mut stale = Vec::new();
            registry.retain(|weak| match weak.upgrade() {
                Some(controller) => {
                    stale.push(controller);
                    true
                }
                None => false,
            });
            stale
        };
        if stale.is_empty() {
            continue;
        }
        for controller in stale {
            if controller.aborted.load(Ordering::Relaxed) {
                continue;
            }
            let idle_for = now.saturating_sub(controller.last_activity_ms.load(Ordering::Acquire));
            if idle_for > WEB_IDLE_ABORT_MS {
                controller.abort();
                continue;
            }
            let registered_at = controller.birth_ms.load(Ordering::Acquire);
            if registered_at != 0
                && now.saturating_sub(registered_at) > WEB_MAX_CONNECTION_LIFETIME_MS
            {
                controller.abort();
            }
        }
    }
}

fn register_web_controller(controller: &Arc<StealthAbortController>) {
    let time = web_watchdog_now_ms();
    controller.last_activity_ms.store(time, Ordering::Release);
    controller.birth_ms.store(time, Ordering::Release);
    let mut registry = WEB_CONNECTION_CONTROLLERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if registry.len() > 4 * MAX_WEB_CONNECTIONS {
        registry.retain(|weak| weak.strong_count() > 0);
    }
    registry.push(Arc::downgrade(controller));
}

impl StealthAbortController {
    pub fn new(#[allow(unused_variables)] stream: &tokio::net::TcpStream) -> Self {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Self {
                aborted: AtomicBool::new(false),
                last_activity_ms: AtomicU64::new(web_watchdog_now_ms()),
                birth_ms: AtomicU64::new(0),
                raw_fd: std::sync::Mutex::new(Some(stream.as_raw_fd())),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                aborted: AtomicBool::new(false),
                last_activity_ms: AtomicU64::new(web_watchdog_now_ms()),
                birth_ms: AtomicU64::new(0),
            }
        }
    }

    pub fn touch(&self) {
        self.last_activity_ms
            .store(web_watchdog_now_ms(), Ordering::Release);
    }

    pub fn abort(&self) {
        if self.aborted.swap(true, Ordering::SeqCst) {
            return;
        }
        #[cfg(unix)]
        {
            let guard = self
                .raw_fd
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(fd) = *guard {
                let linger = libc::linger {
                    l_onoff: 1,
                    l_linger: 0,
                };
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&linger as *const libc::linger).cast(),
                        std::mem::size_of::<libc::linger>() as libc::socklen_t,
                    );
                    libc::shutdown(fd, libc::SHUT_RDWR);
                }
            }
        }
    }

    fn detach(&self) {
        #[cfg(unix)]
        {
            *self
                .raw_fd
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Relaxed)
    }
}

pub enum DualProtocolStream {
    #[allow(dead_code)]
    Plain {
        stream: tokio::net::TcpStream,
        controller: Arc<StealthAbortController>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
    Tls {
        stream: Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
        controller: Arc<StealthAbortController>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
}

impl DualProtocolStream {
    pub fn controller(&self) -> &Arc<StealthAbortController> {
        match self {
            DualProtocolStream::Plain { controller, .. } => controller,
            DualProtocolStream::Tls { controller, .. } => controller,
        }
    }

    #[allow(deprecated)]
    fn abort_tcp(&self) {
        self.controller().abort();
        match self {
            DualProtocolStream::Plain { stream, .. } => {
                let _ = stream.set_linger(Some(Duration::ZERO));
            }
            DualProtocolStream::Tls { stream, .. } => {
                let _ = stream.get_ref().0.set_linger(Some(Duration::ZERO));
            }
        }
    }
}

impl Drop for DualProtocolStream {
    fn drop(&mut self) {
        self.controller().detach();
    }
}

impl tokio::io::AsyncRead for DualProtocolStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.controller().is_aborted() {
            self.abort_tcp();
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stealth connection reset",
            )));
        }
        match &mut *self {
            DualProtocolStream::Plain { stream, .. } => {
                let poll = std::pin::Pin::new(stream).poll_read(cx, buf);
                if matches!(poll, std::task::Poll::Ready(Ok(())) if !buf.filled().is_empty()) {
                    self.controller().touch();
                }
                poll
            }
            DualProtocolStream::Tls { stream, .. } => {
                let stream = stream.as_mut();
                let poll = std::pin::Pin::new(stream).poll_read(cx, buf);
                if matches!(poll, std::task::Poll::Ready(Ok(())) if !buf.filled().is_empty()) {
                    self.controller().touch();
                }
                poll
            }
        }
    }
}

impl tokio::io::AsyncWrite for DualProtocolStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.controller().is_aborted()
            || buf
                .windows(STEALTH_ABORT_HEADER.len())
                .any(|w| w == STEALTH_ABORT_HEADER.as_bytes())
        {
            self.abort_tcp();
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stealth connection reset",
            )));
        }
        match &mut *self {
            DualProtocolStream::Plain { stream, .. } => {
                let poll = std::pin::Pin::new(stream).poll_write(cx, buf);
                if poll.is_ready() {
                    self.controller().touch();
                }
                poll
            }
            DualProtocolStream::Tls { stream, .. } => {
                let stream = stream.as_mut();
                let poll = std::pin::Pin::new(stream).poll_write(cx, buf);
                if poll.is_ready() {
                    self.controller().touch();
                }
                poll
            }
        }
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.controller().is_aborted() {
            self.abort_tcp();
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stealth connection reset",
            )));
        }
        match &mut *self {
            DualProtocolStream::Plain { stream, .. } => {
                std::pin::Pin::new(stream).poll_write_vectored(cx, bufs)
            }
            DualProtocolStream::Tls { stream, .. } => {
                std::pin::Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs)
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            DualProtocolStream::Plain { stream, .. } => stream.is_write_vectored(),
            DualProtocolStream::Tls { stream, .. } => stream.is_write_vectored(),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.controller().is_aborted() {
            self.abort_tcp();
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stealth connection reset",
            )));
        }
        match &mut *self {
            DualProtocolStream::Plain { stream, .. } => std::pin::Pin::new(stream).poll_flush(cx),
            DualProtocolStream::Tls { stream, .. } => {
                std::pin::Pin::new(stream.as_mut()).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.controller().is_aborted() {
            self.abort_tcp();
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stealth connection reset",
            )));
        }
        match &mut *self {
            DualProtocolStream::Plain { stream, .. } => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
            DualProtocolStream::Tls { stream, .. } => {
                std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx)
            }
        }
    }
}

fn collapse_consecutive_slashes(path: &str) -> String {
    if !path.contains("//") {
        return path.to_string();
    }
    let mut result = String::with_capacity(path.len());
    let mut prev_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !prev_slash {
                result.push(c);
                prev_slash = true;
            }
        } else {
            result.push(c);
            prev_slash = false;
        }
    }
    result
}

#[derive(Clone)]
pub struct StealthConnectionService<S> {
    inner: S,
    controller: Arc<StealthAbortController>,
}

impl<S, ReqBody> tower_service::Service<axum::http::Request<ReqBody>>
    for StealthConnectionService<S>
where
    S: tower_service::Service<axum::http::Request<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<ReqBody>) -> Self::Future {
        req.extensions_mut().insert(self.controller.clone());
        let uri = req.uri().clone();
        let path = uri.path();
        if path.contains("//") {
            let new_path = collapse_consecutive_slashes(path);
            let new_uri_str = if let Some(query) = uri.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path
            };
            if let Ok(new_uri) = new_uri_str.parse() {
                *req.uri_mut() = new_uri;
            }
        }
        self.inner.call(req)
    }
}

#[derive(Clone)]
pub struct DualAcceptor {
    tls_acceptor: axum_server::tls_rustls::RustlsAcceptor,
    connections: Arc<tokio::sync::Semaphore>,
    app: Arc<App>,
}

impl DualAcceptor {
    pub fn new(config: axum_server::tls_rustls::RustlsConfig, app: Arc<App>) -> Self {
        Self {
            tls_acceptor: axum_server::tls_rustls::RustlsAcceptor::new(config),
            connections: Arc::new(tokio::sync::Semaphore::new(MAX_WEB_CONNECTIONS)),
            app,
        }
    }
}

async fn is_valid_secret_path(raw_path: &str, app: &Arc<App>) -> bool {
    let path_no_query = raw_path.split('?').next().unwrap_or("").trim();
    let normalized = collapse_consecutive_slashes(path_no_query);
    let secret = app.web_secret_path.trim().trim_matches('/');
    if !secret.is_empty() {
        let prefix = format!("/{}", secret);
        if normalized == prefix || normalized.starts_with(&format!("{}/", prefix)) {
            return true;
        }
    } else {
        return true;
    }

    let trimmed = normalized.trim_matches('/');
    let first_segment = trimmed.split('/').next().unwrap_or("");
    if !first_segment.is_empty() {
        let db = app.db.read().await;
        if !db.main_sub_uuid.is_empty() && db.main_sub_uuid == first_segment {
            return true;
        }
        if db
            .passwords
            .values()
            .any(|p| !p.sub_uuid.is_empty() && p.sub_uuid == first_segment)
        {
            return true;
        }
        if db.groups.values().any(|g| {
            (!g.sub_uuid.is_empty() && g.sub_uuid == first_segment)
                || (!g.admin_uuid.is_empty() && g.admin_uuid == first_segment)
        }) {
            return true;
        }
    }

    false
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for DualAcceptor
where
    S: Send + Clone + 'static,
{
    type Stream = DualProtocolStream;
    type Service = StealthConnectionService<S>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    #[allow(deprecated)]
    fn accept(&self, mut stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let tls_acceptor = self.tls_acceptor.clone();
        let connections = self.connections.clone();
        let app = self.app.clone();
        Box::pin(async move {
            let permit = connections.try_acquire_owned().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "web connection limit",
                )
            })?;
            let mut buf = [0u8; 1];
            let _ = tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut buf))
                .await
                .map_err(|_| {
                    let _ = stream.set_linger(Some(Duration::ZERO));
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "web connection timed out")
                })??;
            if buf[0] == 0x16 {
                let controller = Arc::new(StealthAbortController::new(&stream));
                register_web_controller(&controller);
                let (tls_stream, service) = tokio::time::timeout(
                    Duration::from_secs(10),
                    tls_acceptor.accept(stream, service),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
                })??;
                Ok((
                    DualProtocolStream::Tls {
                        stream: Box::new(tls_stream),
                        controller: controller.clone(),
                        _permit: permit,
                    },
                    StealthConnectionService {
                        inner: service,
                        controller,
                    },
                ))
            } else {
                let mut http_buf = [0u8; 2048];
                let n =
                    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut http_buf))
                        .await
                    {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => {
                            let _ = stream.set_linger(Some(Duration::ZERO));
                            drop(stream);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "plain HTTP rejected",
                            ));
                        }
                    };
                let req_str = String::from_utf8_lossy(&http_buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let _method = parts.next().unwrap_or("");
                let raw_path = parts.next().unwrap_or("");

                let host_header = req_str
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, h)| h.trim())
                    .unwrap_or("");

                if is_valid_secret_path(raw_path, &app).await {
                    let public_ip = app.public_ip.read().await.clone();
                    let target_host = match parse_host_header(host_header) {
                        Some((name, _))
                            if name.parse::<std::net::IpAddr>().is_ok() || name == public_ip =>
                        {
                            if host_header.contains(':')
                                || app.web_port == 443
                                || app.web_port == 80
                            {
                                host_header.to_string()
                            } else {
                                format!("{}:{}", host_header, app.web_port)
                            }
                        }
                        _ => {
                            let ip_str = if !public_ip.is_empty() && public_ip != "0.0.0.0" {
                                public_ip
                            } else {
                                "127.0.0.1".to_string()
                            };
                            if app.web_port == 443 {
                                ip_str
                            } else {
                                format!("{}:{}", ip_str, app.web_port)
                            }
                        }
                    };

                    let redirect_url = format!("https://{}{}", target_host, raw_path);
                    let resp = format!(
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: {redirect_url}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        stream.write_all(resp.as_bytes()),
                    )
                    .await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                    drop(stream);
                    Err(std::io::Error::other("redirected HTTP to HTTPS"))
                } else {
                    let _ = stream.set_linger(Some(Duration::ZERO));
                    drop(stream);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "plain HTTP rejected (dead RST)",
                    ))
                }
            }
        })
    }
}

#[derive(Deserialize)]
struct LogsToggleRequest {
    active: bool,
}

async fn logs_get(State(state): State<WebState>) -> impl IntoResponse {
    let lines = lock_unpoison(&state.app.logs)
        .iter()
        .cloned()
        .collect::<Vec<String>>();
    Json(serde_json::json!({
        "path": state.app.log_file_path.to_string_lossy(),
        "active": state.app.logging_active.load(Ordering::Relaxed),
        "lines": lines
    }))
}

async fn logs_toggle(
    State(state): State<WebState>,
    Json(request): Json<LogsToggleRequest>,
) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        db.logging_active = Some(request.active);
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    state
        .app
        .logging_active
        .store(request.active, Ordering::Relaxed);

    StatusCode::OK.into_response()
}

async fn logs_clear(State(state): State<WebState>) -> Response {
    lock_unpoison(&state.app.logs).clear();

    let path = state.app.log_file_path.clone();
    tokio::spawn(async move {
        let _ = tokio::fs::remove_file(&path).await;
    });

    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct ProfileRequest {
    #[serde(default)]
    name: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

async fn local_proxy_get(State(state): State<WebState>) -> impl IntoResponse {
    let (proxy_state, active, tcp_sessions, udp_flows) = {
        let db = state.app.db.read().await;
        let route = state.app.proxy_route.read().await;
        let active = route.as_ref().is_some_and(|r| r.is_alive());
        let (tcp_sessions, udp_flows) =
            route.as_ref().map(|r| r.stats_snapshot()).unwrap_or((0, 0));
        (db.local_proxy.clone(), active, tcp_sessions, udp_flows)
    };
    let profiles: Vec<serde_json::Value> = proxy_state
        .profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "port": p.port,
                "username": p.username,
                "password": p.password,
            })
        })
        .collect();
    Json(serde_json::json!({
        "active_profile_id": proxy_state.active_profile_id,
        "profiles": profiles,
        "route_active": active,
        "port_listening": state.app.proxy_port_listening.load(std::sync::atomic::Ordering::Acquire),
        "health_error": crate::read_unpoison(&state.app.proxy_health_error).clone(),
        "tcp_sessions": tcp_sessions,
        "udp_flows": udp_flows,
    }))
}

async fn local_proxy_create(
    State(state): State<WebState>,
    Json(request): Json<ProfileRequest>,
) -> Response {
    if let Err(message) = validate_proxy_profile_name(&request.name) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    let port = if request.port == 0 {
        crate::model::DEFAULT_LOCAL_PROXY_PORT
    } else {
        request.port
    };
    let profile = crate::model::LocalProxyProfile {
        id: crate::model::LocalProxyProfile::new_id(),
        name: if request.name.is_empty() {
            format!("SOCKS5 :{port}")
        } else {
            request.name
        },
        port,
        username: request.username,
        password: request.password,
    };
    if let Err(error) = crate::proxy_route::validate_config(&profile) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let id = profile.id.clone();
    let revision = {
        let mut db = state.app.db.write().await;
        if db.local_proxy.profiles.len() >= 20 {
            return (StatusCode::BAD_REQUEST, "Too many profiles (max 20)").into_response();
        }
        db.local_proxy.profiles.push(profile);
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile created: {id}"),
    );
    let port_listening = crate::proxy_route::port_is_listening(port).await;
    Json(serde_json::json!({ "id": id, "port_listening": port_listening })).into_response()
}

async fn local_proxy_update(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(request): Json<ProfileRequest>,
) -> Response {
    if let Err(message) = validate_proxy_profile_name(&request.name) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    let port = if request.port == 0 {
        crate::model::DEFAULT_LOCAL_PROXY_PORT
    } else {
        request.port
    };
    let temp_profile = crate::model::LocalProxyProfile {
        id: id.clone(),
        name: request.name.clone(),
        port,
        username: request.username.clone(),
        password: request.password.clone(),
    };
    if let Err(error) = crate::proxy_route::validate_config(&temp_profile) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let (was_active, revision) = {
        let mut db = state.app.db.write().await;
        let was_active = db.local_proxy.active_profile_id == id;
        let Some(profile) = db.local_proxy.find_profile_mut(&id) else {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        };
        if !request.name.is_empty() {
            profile.name = request.name;
        }
        profile.port = port;
        profile.username = request.username;
        profile.password = request.password;
        (was_active, state.app.db_persistence.submit(db.clone()))
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if was_active {
        state.app.proxy_trigger.notify_one();
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile updated: {id}"),
    );
    let port_listening = crate::proxy_route::port_is_listening(port).await;
    Json(serde_json::json!({ "updated": true, "port_listening": port_listening })).into_response()
}

async fn local_proxy_delete(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let (was_active, revision) = {
        let mut db = state.app.db.write().await;
        let was_active = db.local_proxy.active_profile_id == id;
        if !db.local_proxy.remove_profile(&id) {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        }
        (was_active, state.app.db_persistence.submit(db.clone()))
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    if was_active {
        state.app.proxy_trigger.notify_one();
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile deleted: {id}"),
    );
    Json(serde_json::json!({ "deleted": true })).into_response()
}

async fn wait_proxy_route_applied(state: &WebState, want_active: bool) -> Result<(), String> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let route_active = state.app.proxy_route.read().await.is_some();
        let health_error = read_unpoison(&state.app.proxy_health_error).clone();
        if want_active {
            if route_active && health_error.is_none() {
                return Ok(());
            }
            if let Some(error) = health_error {
                return Err(error);
            }
        } else if !route_active {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("route is still applying; check status in a few seconds".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn local_proxy_activate(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        if db.local_proxy.find_profile(&id).is_none() {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        }
        db.local_proxy.active_profile_id = id.clone();
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        "Local SOCKS5 settings saved; applying TPROXY route",
    );
    state.app.proxy_trigger.notify_one();
    match wait_proxy_route_applied(&state, true).await {
        Ok(()) => Json(serde_json::json!({ "activated": true })).into_response(),
        Err(error) => (StatusCode::BAD_GATEWAY, error).into_response(),
    }
}

async fn local_proxy_deactivate(State(state): State<WebState>) -> Response {
    let revision = {
        let mut db = state.app.db.write().await;
        db.local_proxy.active_profile_id.clear();
        state.app.db_persistence.submit(db.clone())
    };
    if let Err(response) = wait_for_persistence(&state, revision).await {
        return response;
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        "Local SOCKS5 routing disabled; restoring direct route",
    );
    state.app.proxy_trigger.notify_one();
    match wait_proxy_route_applied(&state, false).await {
        Ok(()) => Json(serde_json::json!({ "deactivated": true })).into_response(),
        Err(error) => (StatusCode::BAD_GATEWAY, error).into_response(),
    }
}

async fn logs_download(State(state): State<WebState>) -> impl IntoResponse {
    let path = state.app.log_file_path.clone();
    if let Ok(file) = tokio::fs::File::open(&path).await {
        let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file));
        let headers = [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"csqtt.log\"",
            ),
        ];
        (headers, body).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Log file not found").into_response()
    }
}

async fn security_headers(mut request: Request<Body>, next: Next) -> Response {
    let controller = request
        .extensions()
        .get::<Arc<StealthAbortController>>()
        .cloned();
    let uri = request.uri().clone();
    let path = uri.path();
    if path.contains("//") {
        let new_path = collapse_consecutive_slashes(path);
        let new_uri_str = if let Some(query) = uri.query() {
            format!("{}?{}", new_path, query)
        } else {
            new_path
        };
        if let Ok(new_uri) = new_uri_str.parse() {
            *request.uri_mut() = new_uri;
        }
    }
    let mut response = next.run(request).await;
    if response.headers().contains_key(STEALTH_ABORT_HEADER) {
        if let Some(controller) = controller {
            controller.abort();
        }
        return response;
    }
    let h = response.headers_mut();
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        header::HeaderName::from_static("strict-transport-security"),
        header::HeaderValue::from_static("max-age=15552000"),
    );
    response
}

pub async fn run(
    app: Arc<App>,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) -> anyhow::Result<()> {
    let state = WebState { app: app.clone() };
    let protected = Router::new()
        .route("/api/stats", get(stats))
        .route("/api/memory/trim", post(memory_trim))
        .route("/api/settings", get(settings_get).post(settings_post))
        .route("/api/clients", get(clients_get).post(clients_create))
        .route(
            "/api/clients/{password}",
            get(client_get).post(client_update).delete(client_delete),
        )
        .route("/api/clients/{password}/toggle", post(client_toggle))
        .route("/api/clients/{password}/unbind", post(client_unbind))
        .route(
            "/api/clients/{password}/reset-traffic",
            post(client_reset_traffic),
        )
        .route("/api/clients/{password}/extend", post(client_extend))
        .route(
            "/api/clients/{password}/sub-link/regenerate",
            post(client_sub_link_regenerate),
        )
        .route("/api/groups", get(groups_get).post(groups_create))
        .route("/api/groups/{id}", put(groups_update).delete(groups_delete))
        .route(
            "/api/groups/{id}/admin-link",
            post(group_admin_link_post).delete(group_admin_link_delete),
        )
        .route(
            "/api/groups/{id}/admin-link/regenerate",
            post(group_admin_link_regenerate),
        )
        .route(
            "/api/groups/{id}/sub-link/regenerate",
            post(group_sub_link_regenerate),
        )
        .route(
            "/api/routing-rules",
            get(routing_rules_get).post(routing_rules_create),
        )
        .route(
            "/api/routing-rules/{id}",
            put(routing_rules_update).delete(routing_rules_delete),
        )
        .route("/api/template-domains", get(template_domains_get))
        .route("/api/logs", get(logs_get))
        .route("/api/logs/toggle", post(logs_toggle))
        .route("/api/logs/clear", post(logs_clear))
        .route("/api/logs/download", get(logs_download))
        .route(
            "/api/local-proxy",
            get(local_proxy_get).post(local_proxy_create),
        )
        .route(
            "/api/local-proxy/profiles/{id}",
            put(local_proxy_update).delete(local_proxy_delete),
        )
        .route("/api/local-proxy/activate/{id}", post(local_proxy_activate))
        .route("/api/local-proxy/deactivate", post(local_proxy_deactivate))
        .route("/api/logout", post(logout))
        .route("/api/logout_all", post(logout_all))
        .route("/api/links", get(api_links_get))
        .route("/api/links/batch-vk", post(api_links_batch_vk))
        .route("/api/clients/{password}/vk", put(api_client_vk_update))
        .route("/api/settings/dns", post(api_settings_dns))
        .route(
            "/api/settings/restart-interval",
            post(api_settings_restart_interval),
        )
        .route(
            "/api/settings/master-password",
            post(api_settings_master_password),
        )
        .route("/api/clients/batch-toggle", post(api_clients_batch_toggle))
        .route("/api/clients/batch-extend", post(api_clients_batch_extend))
        .route(
            "/api/clients/batch-reset-traffic",
            post(api_clients_batch_reset_traffic),
        )
        .route("/api/clients/batch-delete", post(api_clients_batch_delete))
        .route("/api/clients/batch-group", post(api_clients_batch_group))
        .route("/api/groups/{id}/clients", get(group_clients_get))
        .route("/api/diagnostics/dpi", get(api_diagnostics_dpi))
        .route("/api/export", get(api_export_get))
        .route("/api/import", post(api_import_post))
        .route("/api/reboot", post(reboot))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let panel_routes = Router::new()
        .route("/", get(panel_root))
        .route("/manifest.webmanifest", get(pwa_manifest))
        .route("/sw.js", get(pwa_service_worker))
        .route("/pwa-icon.svg", get(pwa_icon))
        .route("/pwa-icon-192.png", get(pwa_icon_192))
        .route("/pwa-icon-512.png", get(pwa_icon_512))
        .route("/qrcode.min.js", get(qrcode_js))
        .route("/favicon.ico", get(favicon))
        .route("/api/login", post(login))
        .merge(protected);

    let mut router = Router::new();
    let secret = app.web_secret_path.trim().trim_matches('/');
    if secret.is_empty() {
        router = router.merge(panel_routes);
    } else {
        let prefix = format!("/{}", secret);
        let trailing_prefix = format!("{}/", prefix);
        router = router
            .route("/", get(root_with_secret))
            .route(&trailing_prefix, get(panel_root))
            .nest(&prefix, panel_routes);
        router = router
            .route("/manifest.webmanifest", get(pwa_manifest))
            .route("/sw.js", get(pwa_service_worker))
            .route("/pwa-icon.svg", get(pwa_icon))
            .route("/pwa-icon-192.png", get(pwa_icon_192))
            .route("/pwa-icon-512.png", get(pwa_icon_512))
            .route("/qrcode.min.js", get(qrcode_js))
            .route("/favicon.ico", get(favicon));
    }

    let router = router
        .route("/{uuid}/admin", get(group_admin_page))
        .route("/{uuid}/admin/", get(group_admin_page))
        .route("/{uuid}/api/data", get(group_admin_data_get))
        .route("/api/group-admin/{uuid}/data", get(group_admin_data_get))
        .route("/{uuid}/api/settings", post(group_admin_settings_post))
        .route(
            "/api/group-admin/{uuid}/settings",
            post(group_admin_settings_post),
        )
        .route("/{uuid}/api/clients", post(group_admin_client_create))
        .route(
            "/api/group-admin/{uuid}/clients",
            post(group_admin_client_create),
        )
        .route(
            "/{uuid}/api/clients/{password}",
            put(group_admin_client_update).delete(group_admin_client_delete),
        )
        .route(
            "/api/group-admin/{uuid}/clients/{password}",
            put(group_admin_client_update).delete(group_admin_client_delete),
        )
        .route(
            "/{uuid}/api/clients/{password}/toggle",
            post(group_admin_client_toggle),
        )
        .route(
            "/api/group-admin/{uuid}/clients/{password}/toggle",
            post(group_admin_client_toggle),
        )
        .route(
            "/{uuid}/api/clients/{password}/reset-traffic",
            post(group_admin_client_reset_traffic),
        )
        .route(
            "/api/group-admin/{uuid}/clients/{password}/reset-traffic",
            post(group_admin_client_reset_traffic),
        )
        .route(
            "/{uuid}/api/clients/{password}/extend",
            post(group_admin_client_extend),
        )
        .route(
            "/api/group-admin/{uuid}/clients/{password}/extend",
            post(group_admin_client_extend),
        )
        .route(
            "/{uuid}/api/clients/{password}/unbind",
            post(group_admin_client_unbind),
        )
        .route(
            "/api/group-admin/{uuid}/clients/{password}/unbind",
            post(group_admin_client_unbind),
        )
        .route("/{uuid}/sub", get(client_sub_page))
        .route("/{uuid}/sub/", get(client_sub_page))
        .route("/{uuid}/json", get(universal_sub_json))
        .route("/{uuid}/json/", get(universal_sub_json))
        .route("/{uuid}/sub.json", get(client_sub_json))
        .route("/api/sub/{uuid}", get(client_sub_json))
        .route("/api/sub/{uuid}/", get(client_sub_json))
        .route("/{uuid}/sub-group", get(group_sub_page))
        .route("/{uuid}/sub-group/", get(group_sub_page))
        .route("/{uuid}/sub-group.json", get(group_sub_json))
        .route("/api/sub-group/{uuid}", get(group_sub_json))
        .route("/api/sub-group/{uuid}/", get(group_sub_json))
        .fallback(fallback_reject)
        .layer(DefaultBodyLimit::max(WEB_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    tokio::spawn(web_session_janitor(app.clone()));
    tokio::spawn(web_slowloris_watchdog());
    println!("[WEB] HTTP/HTTPS listening on 0.0.0.0:{}", app.web_port);
    let acceptor = DualAcceptor::new(tls_config, app.clone());
    axum_server::Server::bind(SocketAddr::from(([0, 0, 0, 0], app.web_port)))
        .acceptor(acceptor)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

const PWA_MANIFEST: &str = r##"{
  "id": "/",
  "name": "CSQTT",
  "short_name": "CSQTT",
  "description": "Панель управления сервером CSQTT",
  "lang": "ru",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "display_override": ["window-controls-overlay", "standalone"],
  "prefer_related_applications": false,
  "background_color": "#0a0a0c",
  "theme_color": "#0a0a0c",
  "icons": [
    {
      "src": "/pwa-icon-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "/pwa-icon-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "/pwa-icon.svg",
      "sizes": "any",
      "type": "image/svg+xml",
      "purpose": "any maskable"
    }
  ]
}"##;

const PWA_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="122" fill="#0a0a0c"/><defs><linearGradient id="c" x1="128" y1="152" x2="390" y2="360" gradientUnits="userSpaceOnUse"><stop stop-color="#55adff"/><stop offset="1" stop-color="#0875f5"/></linearGradient></defs><path fill="url(#c)" d="M374 151a148 148 0 1 0 0 210l-44-37a91 91 0 1 1 0-136z"/></svg>"##;

static PWA_ICON_192_PNG: LazyLock<Vec<u8>> = LazyLock::new(|| {
    base64::engine::general_purpose::STANDARD
        .decode("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")
        .unwrap_or_default()
});

static PWA_ICON_512_PNG: LazyLock<Vec<u8>> = LazyLock::new(|| {
    base64::engine::general_purpose::STANDARD
        .decode("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")
        .unwrap_or_default()
});

const PWA_SERVICE_WORKER: &str = r##"const CACHE_NAME = 'csqtt-panel-shell-compatible-2';
const base = self.location.pathname.replace(/\/sw\.js$/, '');
const SHELL_ASSETS = ['/manifest.webmanifest', '/pwa-icon.svg', '/pwa-icon-192.png', '/pwa-icon-512.png', '/qrcode.min.js'].map(p => (base ? base : '') + p);

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    try {
      const cache = await caches.open(CACHE_NAME);
      await cache.addAll(SHELL_ASSETS);
    } catch (_) {}
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter(name => name !== CACHE_NAME).map(name => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/') || url.pathname.includes('/api/')) return;

  if (SHELL_ASSETS.includes(url.pathname)) {
    event.respondWith(caches.match(request).then(cached => cached || fetch(request)));
  }
});
"##;

const QRCODE_JS: &str = r##"var qrcode=function(){function i(t,r){function a(t,r){g=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(l=4*u+17),e(0,0),e(l-7,0),e(0,l-7),i(),o(),v(t,r),7<=u&&h(t),null==n&&(n=w(u,f,c)),d(n,r)}var u=t,f=y[r],g=null,l=0,n=null,c=[],s={},e=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||l<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||l<=r+n||(g[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},o=function(){for(var t=8;t<l-8;t+=1)null==g[t][6]&&(g[t][6]=t%2==0);for(var r=8;r<l-8;r+=1)null==g[6][r]&&(g[6][r]=r%2==0)},i=function(){for(var t=B.getPatternPosition(u),r=0;r<t.length;r+=1)for(var e=0;e<t.length;e+=1){var n=t[r],o=t[e];if(null==g[n][o])for(var i=-2;i<=2;i+=1)for(var a=-2;a<=2;a+=1)g[n+i][o+a]=-2==i||2==i||-2==a||2==a||0==i&&0==a}},h=function(t){for(var r=B.getBCHTypeNumber(u),e=0;e<18;e+=1){var n=!t&&1==(r>>e&1);g[Math.floor(e/3)][e%3+l-8-3]=n}for(e=0;e<18;e+=1){n=!t&&1==(r>>e&1);g[e%3+l-8-3][Math.floor(e/3)]=n}},v=function(t,r){for(var e=f<<3|r,n=B.getBCHTypeInfo(e),o=0;o<15;o+=1){var i=!t&&1==(n>>o&1);o<6?g[o][8]=i:o<8?g[o+1][8]=i:g[l-15+o][8]=i}for(o=0;o<15;o+=1){i=!t&&1==(n>>o&1);o<8?g[8][l-o-1]=i:o<9?g[8][15-o-1+1]=i:g[8][15-o-1]=i}g[l-8][8]=!t},d=function(t,r){for(var e=-1,n=l-1,o=7,i=0,a=B.getMaskFunction(r),u=l-1;0<u;u-=2)for(6==u&&(u-=1);;){for(var f=0;f<2;f+=1)if(null==g[n][u-f]){var c=!1;i<t.length&&(c=1==(t[i]>>>o&1)),a(n,u-f)&&(c=!c),g[n][u-f]=c,-1==(o-=1)&&(i+=1,o=7)}if((n+=e)<0||l<=n){n-=e,e=-e;break}}},w=function(t,r,e){for(var n=b.getRSBlocks(t,r),o=M(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=C(i[u],l.getLength()-1).mod(l);a[u]=new Array(l.getLength()-1);for(g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=0<=s?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};s.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=x(t);break;case"Alphanumeric":e=m(t);break;case"Byte":e=L(t);break;case"Kanji":e=D(t);break;default:throw"mode:"+r}c.push(e),n=null},s.isDark=function(t,r){if(t<0||l<=t||r<0||l<=r)throw t+","+r;return g[t][r]},s.getModuleCount=function(){return l},s.make=function(){if(u<1){for(var t=1;t<40;t++){for(var r=b.getRSBlocks(t,f),e=M(),n=0;n<c.length;n++){var o=c[n];e.put(o.getMode(),4),e.put(o.getLength(),B.getLengthInBits(o.getMode(),t)),o.write(e)}var i=0;for(n=0;n<r.length;n++)i+=r[n].dataCount;if(e.getLengthInBits()<=8*i)break}u=t}a(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){a(!0,e);var n=B.getLostPoint(s);(0==e||n<t)&&(t=n,r=e)}return r}())},s.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<s.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<s.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=s.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},s.createSvgTag=function(t,r,e,n){var o={};"object"==typeof t&&(t=(o=t).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,f,c=s.getModuleCount()*t+2*r,g="";for(f="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",g+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',g+=o.scalable?"":' width="'+c+'px" height="'+c+'px"',g+=' viewBox="0 0 '+c+" "+c+'" ',g+=' preserveAspectRatio="xMinYMin meet"',g+=n.text||e.text?' role="img" aria-labelledby="'+p([n.id,e.id].join(" ").trim())+'"':"",g+=">",g+=n.text?'<title id="'+p(n.id)+'">'+p(n.text)+"</title>":"",g+=e.text?'<description id="'+p(e.id)+'">'+p(e.text)+"</description>":"",g+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',g+='<path d="',a=0;a<s.getModuleCount();a+=1)for(u=a*t+r,i=0;i<s.getModuleCount();i+=1)s.isDark(a,i)&&(g+="M"+(i*t+r)+","+u+f);return g+='" stroke="transparent" fill="black"/>',g+="</svg>"},s.createDataURL=function(o,t){o=o||2,t=void 0===t?4*o:t;var r=s.getModuleCount()*o+2*t,i=t,a=r-t;return I(r,r,function(t,r){if(i<=t&&t<a&&i<=r&&r<a){var e=Math.floor((t-i)/o),n=Math.floor((r-i)/o);return s.isDark(n,e)?0:1}return 1})},s.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=s.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=s.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=p(e),o+='"'),o+="/>"};var p=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return s.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*s.getModuleCount()+2*t,u=t,f=a-t,c={"██":"█","█ ":"▀"," █":"▄","  ":" "},g={"██":"▀","█ ":"▀"," █":" ","  ":" "},l="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<f&&u<=r&&r<f&&s.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<f&&u<=r+1&&r+1<f&&s.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",l+=t<1&&f<=r+1?g[i]:c[i];l+="\n"}return a%2&&0<t?l.substring(0,l.length-a-1)+Array(1+a).join("▀"):l.substring(0,l.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=s.getModuleCount()*t+2*r,u=r,f=a-r,c=Array(t+1).join("██"),g=Array(t+1).join("  "),l="",h="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),h="",n=0;n<a;n+=1)i=1,u<=n&&n<f&&u<=e&&e<f&&s.isDark(o,Math.floor((n-u)/t))&&(i=0),h+=i?c:g;for(o=0;o<t;o+=1)l+=h+"\n"}return l.substring(0,l.length-1)},s.renderTo2dContext=function(t,r){r=r||2;for(var e=s.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=s.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},s}i.stringToBytes=(i.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,i.createStringToBytes=function(u,f){var i=function(){function t(){var t=r.read();if(-1==t)throw"eof";return t}for(var r=S(u),e=0,n={};;){var o=r.read();if(-1==o)break;var i=t(),a=t()<<8|t();n[String.fromCharCode(o<<8|i)]=a,e+=1}if(e!=f)throw e+" != "+f;return n}(),a="?".charCodeAt(0);return function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);if(n<128)r.push(n);else{var o=i[t.charAt(e)];"number"==typeof o?(255&o)==o?r.push(o):(r.push(o>>>8),r.push(255&o)):r.push(a)}}return r}};var r,t,a=1,u=2,o=4,f=8,y={L:1,M:0,Q:3,H:2},e=0,n=1,c=2,g=3,l=4,h=5,s=6,v=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],(t={}).getBCHTypeInfo=function(t){for(var r=t<<10;0<=d(r)-d(1335);)r^=1335<<d(r)-d(1335);return 21522^(t<<10|r)},t.getBCHTypeNumber=function(t){for(var r=t<<12;0<=d(r)-d(7973);)r^=7973<<d(r)-d(7973);return t<<12|r},t.getPatternPosition=function(t){return r[t-1]},t.getMaskFunction=function(t){switch(t){case e:return function(t,r){return(t+r)%2==0};case n:return function(t,r){return t%2==0};case c:return function(t,r){return r%3==0};case g:return function(t,r){return(t+r)%3==0};case l:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case h:return function(t,r){return t*r%2+t*r%3==0};case s:return function(t,r){return(t*r%2+t*r%3)%2==0};case v:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},t.getErrorCorrectPolynomial=function(t){for(var r=C([1],0),e=0;e<t;e+=1)r=r.multiply(C([1,w.gexp(e)],0));return r},t.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case o:case f:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case o:return 16;case f:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case o:return 16;case f:return 12;default:throw"mode:"+t}}},t.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);5<i&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},t);function d(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r}var w=function(){for(var r=new Array(256),e=new Array(256),t=0;t<8;t+=1)r[t]=1<<t;for(t=8;t<256;t+=1)r[t]=r[t-4]^r[t-5]^r[t-6]^r[t-8];for(t=0;t<255;t+=1)e[r[t]]=t;var n={glog:function(t){if(t<1)throw"glog("+t+")";return e[t]},gexp:function(t){for(;t<0;)t+=255;for(;256<=t;)t-=255;return r[t]}};return n}();function C(n,o){if(void 0===n.length)throw n.length+"/"+o;var r=function(){for(var t=0;t<n.length&&0==n[t];)t+=1;for(var r=new Array(n.length-t+o),e=0;e<n.length-t;e+=1)r[e]=n[e+t];return r}(),i={getAt:function(t){return r[t]},getLength:function(){return r.length},multiply:function(t){for(var r=new Array(i.getLength()+t.getLength()-1),e=0;e<i.getLength();e+=1)for(var n=0;n<t.getLength();n+=1)r[e+n]^=w.gexp(w.glog(i.getAt(e))+w.glog(t.getAt(n)));return C(r,0)},mod:function(t){if(i.getLength()-t.getLength()<0)return i;for(var r=w.glog(i.getAt(0))-w.glog(t.getAt(0)),e=new Array(i.getLength()),n=0;n<i.getLength();n+=1)e[n]=i.getAt(n);for(n=0;n<t.getLength();n+=1)e[n]^=w.gexp(w.glog(t.getAt(n))+r);return C(e,0).mod(t)}};return i}function p(){var e=[],o={writeByte:function(t){e.push(255&t)},writeShort:function(t){o.writeByte(t),o.writeByte(t>>>8)},writeBytes:function(t,r,e){r=r||0,e=e||t.length;for(var n=0;n<e;n+=1)o.writeByte(t[n+r])},writeString:function(t){for(var r=0;r<t.length;r+=1)o.writeByte(t.charCodeAt(r))},toByteArray:function(){return e},toString:function(){var t="";t+="[";for(var r=0;r<e.length;r+=1)0<r&&(t+=","),t+=e[r];return t+="]"}};return o}var k,A,b=(k=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],(A={}).getRSBlocks=function(t,r){var e=function(t,r){switch(r){case y.L:return k[4*(t-1)+0];case y.M:return k[4*(t-1)+1];case y.Q:return k[4*(t-1)+2];case y.H:return k[4*(t-1)+3];default:return}}(t,r);if(void 0===e)throw"bad rs block @ typeNumber:"+t+"/errorCorrectionLevel:"+r;for(var n,o,i=e.length/3,a=[],u=0;u<i;u+=1)for(var f=e[3*u+0],c=e[3*u+1],g=e[3*u+2],l=0;l<f;l+=1)a.push((n=g,o=void 0,(o={}).totalCount=c,o.dataCount=n,o));return a},A),M=function(){var e=[],n=0,o={getBuffer:function(){return e},getAt:function(t){var r=Math.floor(t/8);return 1==(e[r]>>>7-t%8&1)},put:function(t,r){for(var e=0;e<r;e+=1)o.putBit(1==(t>>>r-e-1&1))},getLengthInBits:function(){return n},putBit:function(t){var r=Math.floor(n/8);e.length<=r&&e.push(0),t&&(e[r]|=128>>>n%8),n+=1}};return o},x=function(t){var r=a,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+2<r.length;)t.put(o(r.substring(e,e+3)),10),e+=3;e<r.length&&(r.length-e==1?t.put(o(r.substring(e,e+1)),4):r.length-e==2&&t.put(o(r.substring(e,e+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return e},m=function(t){var r=u,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+1<r.length;)t.put(45*o(r.charAt(e))+o(r.charAt(e+1)),11),e+=2;e<r.length&&t.put(o(r.charAt(e)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return e},L=function(t){var r=o,e=i.stringToBytes(t),n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=0;r<e.length;r+=1)t.put(e[r],8)}};return n},D=function(t){var r=f,e=i.stringToBytesFuncs.SJIS;if(!e)throw"sjis not supported.";!function(){var t=e("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=e(t),n={getMode:function(){return r},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return n},S=function(t){var e=t,n=0,o=0,i=0,r={read:function(){for(;i<8;){if(n>=e.length){if(0==i)return-1;throw"unexpected end of file./"+i}var t=e.charAt(n);if(n+=1,"="==t)return i=0,-1;t.match(/^\s$/)||(o=o<<6|a(t.charCodeAt(0)),i+=6)}var r=o>>>i-8&255;return i-=8,r}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return r},I=function(t,r,e){for(var n=function(t,r){var n=t,o=r,l=new Array(t*r),e={setPixel:function(t,r,e){l[r*n+t]=e},write:function(t){t.writeString("GIF87a"),t.writeShort(n),t.writeShort(o),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(n),t.writeShort(o),t.writeByte(0);var r=i(2);t.writeByte(2);for(var e=0;255<r.length-e;)t.writeByte(255),t.writeBytes(r,e,255),e+=255;t.writeByte(r.length-e),t.writeBytes(r,e,r.length-e),t.writeByte(0),t.writeString(";")}},i=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,o=h(),i=0;i<r;i+=1)o.add(String.fromCharCode(i));o.add(String.fromCharCode(r)),o.add(String.fromCharCode(e));var a=p(),u=function(t){var e=t,n=0,o=0,r={write:function(t,r){if(t>>>r!=0)throw"length over";for(;8<=n+r;)e.writeByte(255&(t<<n|o)),r-=8-n,t>>>=8-n,n=o=0;o|=t<<n,n+=r},flush:function(){0<n&&e.writeByte(o)}};return r}(a);u.write(r,n);var f=0,c=String.fromCharCode(l[f]);for(f+=1;f<l.length;){var g=String.fromCharCode(l[f]);f+=1,o.contains(c+g)?c+=g:(u.write(o.indexOf(c),n),o.size()<4095&&(o.size()==1<<n&&(n+=1),o.add(c+g)),c=g)}return u.write(o.indexOf(c),n),u.write(e,n),u.flush(),a.toByteArray()},h=function(){var r={},e=0,n={add:function(t){if(n.contains(t))throw"dup key:"+t;r[t]=e,e+=1},size:function(){return e},indexOf:function(t){return r[t]},contains:function(t){return void 0!==r[t]}};return n};return e}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=p();n.write(a);for(var u=function(){function e(t){a+=String.fromCharCode(r(63&t))}var n=0,o=0,i=0,a="",t={},r=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return t.writeByte=function(t){for(n=n<<8|255&t,o+=8,i+=1;6<=o;)e(n>>>o-6),o-=6},t.flush=function(){if(0<o&&(e(n<<6-o),o=n=0),i%3!=0)for(var t=3-i%3,r=0;r<t;r+=1)a+="="},t.toString=function(){return a},t}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return i}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||57344<=n?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}(function(){return qrcode});"##;

const LOGIN_HTML: &str = include_str!("web/login.html");

const CLIENT_SUB_HTML: &str = include_str!("web/client-sub.html");

const GROUP_SUB_HTML: &str = include_str!("web/group-sub.html");

const GROUP_ADMIN_HTML: &str = include_str!("web/group-admin.html");

const PANEL_HTML: &str = include_str!("web/panel.html");

#[cfg(test)]
mod tests {
    use super::{
        DNS_PROVIDERS, LOGIN_HTML, MAX_CLIENT_NAME_BYTES, PANEL_HTML, PWA_ICON_192_PNG,
        PWA_ICON_512_PNG, PWA_MANIFEST, PWA_SERVICE_WORKER, count_active_sessions,
        decrypt_csqtt_link, deploy_dns_profile_or_yandex, dns_provider_by_id, dns_provider_id,
        encrypt_csqtt_link, make_client_link, manual_dns, normalize_client_vk_hashes,
        normalize_vk_access_token, process_memory, process_memory_rollup, provider_dns,
        validate_client_name, validate_proxy_profile_name, validate_workers,
    };

    #[test]
    fn dns_provider_catalog_is_complete_and_has_exact_yandex_default() {
        assert_eq!(DNS_PROVIDERS.len(), 13);
        let yandex = dns_provider_by_id("yandex").unwrap();
        assert_eq!(provider_dns(yandex), "77.88.8.8,77.88.8.1");
        assert_eq!(dns_provider_id("1.1.1.1,1.0.0.1"), Some("cloudflare"));
        assert_eq!(
            dns_provider_id("45.90.28.181,45.90.30.181"),
            Some("nextdns")
        );
        assert_eq!(dns_provider_id("195.208.6.1,195.208.7.1"), Some("bizone"));
        assert_eq!(dns_provider_id("195.208.4.1,195.208.5.1"), Some("nsdi"));
        assert_eq!(dns_provider_id("10.0.0.1"), None);
    }

    #[test]
    fn legacy_deploy_dns_migration_normalizes_known_partial_profiles_or_uses_yandex() {
        assert_eq!(
            deploy_dns_profile_or_yandex("111.88.96.55,203.0.113.7"),
            "111.88.96.54,111.88.96.55"
        );
        assert_eq!(
            deploy_dns_profile_or_yandex("111.88.96.51,203.0.113.7"),
            "111.88.96.54,111.88.96.55"
        );
        assert_eq!(
            deploy_dns_profile_or_yandex("95.182.120.241,203.0.113.7"),
            "193.233.112.67,193.233.112.88"
        );
        assert_eq!(
            deploy_dns_profile_or_yandex("8.8.8.8,1.1.1.1"),
            "8.8.8.8,8.8.4.4"
        );
        assert_eq!(
            deploy_dns_profile_or_yandex("203.0.113.7,198.51.100.9"),
            "77.88.8.8,77.88.8.1"
        );
    }

    #[test]
    fn manual_dns_accepts_one_or_two_ipv4_addresses() {
        assert_eq!(manual_dns(Some("1.1.1.1"), None).unwrap(), "1.1.1.1");
        assert_eq!(
            manual_dns(Some(" 1.1.1.1 "), Some(" 1.0.0.1 ")).unwrap(),
            "1.1.1.1,1.0.0.1"
        );
    }

    #[test]
    fn manual_dns_rejects_empty_primary_and_invalid_ipv4() {
        assert!(manual_dns(None, None).is_err());
        assert!(manual_dns(Some(""), None).is_err());
        assert!(manual_dns(Some("1.1.1.256"), None).is_err());
        assert!(manual_dns(Some("1.1.1.1"), Some("not-an-ip")).is_err());
    }

    #[test]
    fn panel_uses_the_complete_dns_provider_list_without_network_checks() {
        assert!(PANEL_HTML.contains("DNS Адреса"));
        assert!(PANEL_HTML.contains("id=\"dns_provider\""));
        assert!(PANEL_HTML.contains("<option value=\"custom\">Ручной DNS</option>"));
        assert!(PANEL_HTML.contains("id=\"dns_manual\""));
        assert!(PANEL_HTML.contains("placeholder=\"ipv4,ipv4\""));
        assert!(PANEL_HTML.contains("Yandex DNS"));
        assert!(PANEL_HTML.contains("Rostelecom DNS"));
        assert!(PANEL_HTML.contains("NextDNS"));
        assert!(PANEL_HTML.contains("BI.ZONE DNS"));
        assert!(PANEL_HTML.contains("НСДИ DNS"));
        assert!(PANEL_HTML.contains("dns_provider: provider"));
        assert!(!PANEL_HTML.contains("/api/dns-providers"));
        assert!(!PANEL_HTML.contains("dns_provider_health"));
        assert!(!PANEL_HTML.contains("refreshDnsProviderPings"));
        assert!(PANEL_HTML.contains("dns_provider: 'custom'"));
        assert!(PANEL_HTML.contains("syncDnsControls"));
    }

    #[test]
    fn persisted_text_fields_have_byte_and_control_character_limits() {
        assert!(validate_client_name("normal client").is_ok());
        assert!(validate_client_name(&"x".repeat(MAX_CLIENT_NAME_BYTES)).is_ok());
        assert!(validate_client_name(&"x".repeat(MAX_CLIENT_NAME_BYTES + 1)).is_err());
        assert!(validate_client_name("bad\nname").is_err());
        assert!(validate_proxy_profile_name(&"x".repeat(64)).is_ok());
        assert!(validate_proxy_profile_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn client_vk_hashes_accept_empty_or_one_to_six_values() {
        assert_eq!(normalize_client_vk_hashes("").unwrap(), "");
        for count in 1..=6 {
            let hashes = (1..=count)
                .map(|index| format!("abcdefghijklmnop{index}"))
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(normalize_client_vk_hashes(&hashes).unwrap(), hashes);
        }
    }

    #[test]
    fn client_vk_hashes_reject_spaces_short_values_and_more_than_six() {
        assert!(normalize_client_vk_hashes("abcdefghijklmnop, abcdefghijklmnop").is_err());
        assert!(normalize_client_vk_hashes("short").is_err());
        let seven = (1..=7)
            .map(|index| format!("abcdefghijklmnop{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(normalize_client_vk_hashes(&seven).is_err());
    }

    #[test]
    fn vk_token_accepts_one_compact_value_or_empty() {
        assert_eq!(
            normalize_vk_access_token("  vk1.token-_%2B  ").unwrap(),
            "vk1.token-_%2B"
        );
        assert_eq!(normalize_vk_access_token(" ").unwrap(), "");
        assert!(normalize_vk_access_token("token with space").is_err());
        assert!(normalize_vk_access_token(&"x".repeat(4097)).is_err());
    }

    #[test]
    fn mobile_panel_keeps_compact_labels_and_consistent_memory_value() {
        assert!(PANEL_HTML.contains("Использование памяти"));
        assert!(PANEL_HTML.contains("#ram_val { white-space: nowrap;"));
        assert!(PANEL_HTML.contains("id=\"ram_detail\""));
        assert!(PANEL_HTML.contains("x.ram_used"));
        assert!(PANEL_HTML.contains("text-size-adjust: none"));
        assert!(PANEL_HTML.contains(".toggle-row label"));
        assert!(PANEL_HTML.contains("white-space: nowrap"));
    }

    #[test]
    fn panel_displays_compact_udp_traffic_counters() {
        assert!(PANEL_HTML.contains("id=\"traffic_ingress\""));
        assert!(PANEL_HTML.contains("x.udp_rx_packets"));
        assert!(PANEL_HTML.contains("x.udp_tx_packets"));
        assert!(PANEL_HTML.contains("const compactCounter = input =>"));
        assert!(
            PANEL_HTML.contains("const units = [\"\", \"K\", \"M\", \"G\", \"T\", \"P\", \"E\"]")
        );
        assert!(PANEL_HTML.contains("#traffic_ingress { white-space: nowrap;"));
        assert!(PANEL_HTML.contains(
            "RX ${compactCounter(x.udp_rx_packets)} · TX ${compactCounter(x.udp_tx_packets)}"
        ));
        assert!(!PANEL_HTML.contains("UDP RX ${Number(x.udp_rx_packets) || 0}"));
    }

    #[test]
    fn pwa_uses_standalone_shell_without_caching_authenticated_panel_data() {
        assert!(PWA_MANIFEST.contains("\"display\": \"standalone\""));
        assert!(PWA_MANIFEST.contains("\"start_url\": \"/\""));
        assert!(PWA_MANIFEST.contains("\"sizes\": \"192x192\""));
        assert!(PWA_MANIFEST.contains("pwa-icon-192.png"));
        assert!(PWA_MANIFEST.contains("pwa-icon-512.png"));
        assert!(LOGIN_HTML.contains("manifest.webmanifest"));
        assert!(PANEL_HTML.contains("manifest.webmanifest"));
        assert!(LOGIN_HTML.contains("pwa-icon-192.png"));
        assert!(PANEL_HTML.contains("pwa-icon-192.png"));
        assert!(PWA_SERVICE_WORKER.contains("url.pathname.startsWith('/api/')"));
        assert!(PWA_SERVICE_WORKER.contains("SHELL_ASSETS"));
        assert!(!PWA_SERVICE_WORKER.contains("OFFLINE_PAGE"));
        assert!(!PWA_SERVICE_WORKER.contains("request.mode === 'navigate'"));
    }

    #[test]
    fn participant_cards_contain_ip_info() {
        assert!(PANEL_HTML.contains("IP:"));
    }

    #[test]
    fn pwa_raster_icon_fallbacks_are_valid_pngs() {
        const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
        assert!(PWA_ICON_192_PNG.starts_with(PNG_SIGNATURE));
        assert!(PWA_ICON_512_PNG.starts_with(PNG_SIGNATURE));
        assert!(PWA_ICON_512_PNG.len() > PWA_ICON_192_PNG.len());
    }

    #[test]
    fn process_memory_reads_linux_status_fields() {
        let memory = process_memory(
            "VmHWM:\t850000 kB\nVmRSS:\t400000 kB\nRssAnon:\t350000 kB\nRssFile:\t45000 kB\nRssShmem:\t5000 kB\nVmSwap:\t12000 kB\n",
        );
        assert_eq!(memory.rss, 400000);
        assert_eq!(memory.peak, 850000);
        assert_eq!(memory.anonymous, 350000);
        assert_eq!(memory.file, 45000);
        assert_eq!(memory.shared, 5000);
        assert_eq!(memory.swap, 12000);
    }

    #[test]
    fn process_memory_rollup_reads_attribution_fields() {
        let memory = process_memory_rollup(
            "Pss:\t700 kB\nPss_Anon:\t650 kB\nPss_File:\t40 kB\nPss_Shmem:\t10 kB\nAnonymous:\t680 kB\nShared_Clean:\t12 kB\nShared_Dirty:\t3 kB\nPrivate_Clean:\t20 kB\nPrivate_Dirty:\t640 kB\nSwapPss:\t7 kB\n",
        );
        assert_eq!(memory.pss, 700);
        assert_eq!(memory.pss_anon, 650);
        assert_eq!(memory.anonymous, 680);
        assert_eq!(memory.file, 40);
        assert_eq!(memory.shmem, 10);
        assert_eq!(memory.private, 660);
        assert_eq!(memory.shared, 15);
        assert_eq!(memory.swap_pss, 7);
    }

    #[test]
    fn csqtt_link_encryption_and_decryption() {
        let payload = "connect?v=2&host=1.2.3.4&peer=46000&password=testpass";
        let encrypted1 = encrypt_csqtt_link(payload);
        let encrypted2 = encrypt_csqtt_link(payload);
        assert!(encrypted1.starts_with("csqtt://"));
        assert_eq!(
            encrypted1, encrypted2,
            "link encryption must be deterministic for identical payload"
        );
        let decrypted = decrypt_csqtt_link(&encrypted1).expect("decryption should succeed");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn csqtt_link_legacy_plaintext_rejected() {
        use base64::Engine;
        let payload = "connect?v=2&host=1.2.3.4&peer=46000&password=legacy";
        let legacy_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let legacy_link = format!("csqtt://{legacy_b64}");
        assert!(decrypt_csqtt_link(&legacy_link).is_none());
    }

    #[test]
    fn alternative_import_links_preserve_secret_and_every_vk_call() {
        use base64::Engine;
        let link = make_client_link(
            "2001:db8::1",
            46000,
            "p@ss&word",
            "abcdefghijklmnop1,abcdefghijklmnop2",
            false,
            "",
        );
        let (legacy, ios) = super::compatibility_links(&link);
        assert!(legacy.starts_with("csqtt://connect?v=2&host=2001%3Adb8%3A%3A1"));
        assert!(legacy.contains("password=p%40ss%26word"));
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(ios.strip_prefix("vkturnproxy://import?data=").unwrap())
            .unwrap();
        let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(config["settings"]["csqttPassword"], "p@ss&word");
        assert_eq!(config["settings"]["peerAddress"], "[2001:db8::1]:46000");
        assert_eq!(config["settings"]["useCsqtt"], true);
        assert_eq!(
            config["settings"]["vkLink"],
            "https://vk.ru/call/join/abcdefghijklmnop1\nhttps://vk.ru/call/join/abcdefghijklmnop2"
        );
        let html = super::render_client_sub_html("<name>", &link);
        assert!(html.contains("&lt;name&gt;"));
        assert!(!html.contains("__LEGACY_LINK__"));
        assert!(!html.contains("__IOS_LINK__"));
    }

    #[test]
    fn serialized_subscription_keeps_modern_link_and_exposes_legacy_formats() {
        let link = make_client_link(
            "203.0.113.8",
            46000,
            "12345678",
            "call-one,call-two",
            false,
            "",
        );
        let item = super::GroupSubClientItem {
            name: "Tablet".to_owned(),
            links: super::ImportLinks::new(link.clone()),
            sub_uuid: "subscription-id".to_owned(),
        };
        let json = serde_json::to_value(item).unwrap();
        assert_eq!(json["link"], link);
        assert!(
            json["legacy_link"]
                .as_str()
                .unwrap()
                .contains("password=12345678")
        );
        assert!(
            json["ios_link"]
                .as_str()
                .unwrap()
                .starts_with("vkturnproxy://import?data=")
        );
        assert_eq!(json["requires_vk_hashes"], false);
        assert!(
            json.get("links").is_none(),
            "existing consumers still read the top-level link field"
        );
    }

    #[test]
    fn legacy_profile_warns_when_only_a_vk_token_is_configured() {
        let link = make_client_link("203.0.113.8", 46000, "password", "", true, "vk-token");
        let imports = super::ImportLinks::new(link.clone());
        assert!(imports.requires_vk_hashes);
        let html = super::render_client_sub_html("<script>alert('name')</script>", &link);
        assert!(html.contains("data-requires-vk-hashes=\"true\""));
        assert!(!html.contains("<script>alert('name')</script>"));
        assert!(!html.contains("__CLIENT_PROFILE_JS__"));
        assert!(!html.contains("__PANEL_STYLE__"));
    }

    #[test]
    fn make_client_link_contains_password_and_aes_roundtrip() {
        let link = make_client_link("1.2.3.4", 46000, "abc1234567890123", "", false, "");
        assert!(link.starts_with("csqtt://"));
        let decrypted = decrypt_csqtt_link(&link).expect("must decrypt");
        assert!(decrypted.contains("password=abc1234567890123"));
        assert!(!decrypted.contains("client="));
        assert!(!decrypted.contains("&workers="));
    }

    #[test]
    fn owner_link_contains_owner_password_without_workers() {
        let link = make_client_link("1.2.3.4", 46000, "ownerpass1234567", "", false, "");
        let decrypted = decrypt_csqtt_link(&link).expect("must decrypt");
        assert!(decrypted.contains("password=ownerpass1234567"));
        assert!(!decrypted.contains("client="));
        assert!(!decrypted.contains("&workers="));
    }

    #[test]
    fn count_active_sessions_isolates_passwords() {
        use crate::protocol::Session;
        use dashmap::DashMap;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let sessions = DashMap::new();
        let debug_flag = Arc::new(AtomicBool::new(false));
        let addr: SocketAddr = "127.0.0.1:46001".parse().unwrap();

        let s1 = Session::new(
            1,
            addr,
            "pass_a",
            1,
            "salt1",
            false,
            debug_flag.clone(),
            100,
        );
        sessions.insert(1, s1);

        assert_eq!(count_active_sessions(&sessions, "pass_a"), 1);
        assert_eq!(count_active_sessions(&sessions, "pass_b"), 0);

        let s_owner = Session::new(2, addr, "owner_pass", 2, "salt2", false, debug_flag, 100);
        sessions.insert(2, s_owner);

        assert_eq!(count_active_sessions(&sessions, "owner_pass"), 1);
        assert_eq!(count_active_sessions(&sessions, "pass_a"), 1);
        assert_eq!(count_active_sessions(&sessions, "pass_b"), 0);
    }

    #[test]
    fn workers_validation() {
        assert_eq!(validate_workers(None), Ok(None));
        assert_eq!(validate_workers(Some(0)), Ok(None));
        assert_eq!(validate_workers(Some(3)), Ok(Some(3)));
        assert_eq!(validate_workers(Some(36)), Ok(Some(36)));
        assert_eq!(validate_workers(Some(99)), Ok(Some(99)));
        assert_eq!(validate_workers(Some(100)), Ok(Some(100)));
        assert!(validate_workers(Some(1)).is_err());
        assert!(validate_workers(Some(2)).is_err());
        assert!(validate_workers(Some(101)).is_err());
    }
}
