//! SSO via OpenID Connect (authorization-code flow).
//!
//! GET /api/auth/oidc/login  → redirects to the IdP.
//! GET /api/auth/oidc/callback → exchanges the code, verifies the id_token
//! (RS256 against the IdP's JWKS), maps claims → role/org, issues a QuantaWatch
//! session, and redirects to the dashboard with the token.

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::Role;
use crate::config::OidcConfig;
use crate::state::AppState;

/// Map id_token claims to a (username, role, org) using the OIDC config.
pub fn map_claims(claims: &Value, cfg: &OidcConfig) -> (String, Role, String) {
    let username = claims["email"].as_str()
        .or_else(|| claims["preferred_username"].as_str())
        .or_else(|| claims["sub"].as_str())
        .unwrap_or("sso-user").to_string();

    // Groups may be an array or a single string.
    let groups: Vec<String> = match &claims[&cfg.groups_claim] {
        Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    };
    let has = |g: &Option<String>| g.as_ref().map(|grp| groups.iter().any(|x| x == grp)).unwrap_or(false);
    let role = if has(&cfg.admin_group) { Role::Admin }
        else if has(&cfg.operator_group) { Role::Operator }
        else { Role::Viewer };

    let org = cfg.org_claim.as_ref()
        .and_then(|c| claims[c].as_str())
        .map(String::from)
        .unwrap_or_else(|| cfg.default_org.clone());

    (username, role, org)
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

async fn discover(client: &reqwest::Client, issuer: &str) -> Result<Discovery, String> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    client.get(&url).send().await.map_err(|e| e.to_string())?
        .json::<Discovery>().await.map_err(|e| e.to_string())
}

pub async fn login(State(state): State<AppState>) -> impl IntoResponse {
    let Some(cfg) = state.auth_manager.oidc().cloned() else {
        return (StatusCode::NOT_FOUND, "OIDC not configured").into_response();
    };
    let disc = match discover(&state.http_client, &cfg.issuer).await {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("OIDC discovery failed: {e}")).into_response(),
    };
    let csrf = state.auth_manager.begin_oidc();
    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        disc.authorization_endpoint,
        urlencoding(&cfg.client_id),
        urlencoding(&cfg.redirect_uri),
        urlencoding("openid email profile groups"),
        csrf,
    );
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let Some(cfg) = state.auth_manager.oidc().cloned() else {
        return (StatusCode::NOT_FOUND, "OIDC not configured").into_response();
    };
    if let Some(err) = params.error {
        return (StatusCode::UNAUTHORIZED, format!("IdP error: {err}")).into_response();
    }
    let (Some(code), Some(csrf)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    if !state.auth_manager.consume_oidc_state(&csrf) {
        return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response();
    }
    let Ok(secret) = std::env::var(&cfg.client_secret_env) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "client secret env not set").into_response();
    };

    let disc = match discover(&state.http_client, &cfg.issuer).await {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("discovery failed: {e}")).into_response(),
    };

    // Exchange the code for tokens.
    let token_resp = state.http_client.post(&disc.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &cfg.redirect_uri),
            ("client_id", &cfg.client_id),
            ("client_secret", &secret),
        ])
        .send().await;
    let id_token = match token_resp {
        Ok(r) => r.json::<Value>().await.ok().and_then(|j| j["id_token"].as_str().map(String::from)),
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token exchange failed: {e}")).into_response(),
    };
    let Some(id_token) = id_token else {
        return (StatusCode::BAD_GATEWAY, "no id_token in response").into_response();
    };

    // Verify the id_token against the IdP JWKS (RS256).
    let claims = match verify_id_token(&state.http_client, &disc.jwks_uri, &id_token, &cfg).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("id_token verification failed: {e}")).into_response(),
    };

    let (username, role, org) = map_claims(&claims, &cfg);
    let (token, _ttl) = state.auth_manager.create_external_session(&username, role, &org);
    tracing::info!(user = %username, role = role.label(), org = %org, "OIDC login");

    let sep = if cfg.app_url.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{}{sep}sso={token}", cfg.app_url)).into_response()
}

async fn verify_id_token(
    client: &reqwest::Client, jwks_uri: &str, token: &str, cfg: &OidcConfig,
) -> Result<Value, String> {
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};

    let header = decode_header(token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or("id_token missing kid")?;

    let jwks: Value = client.get(jwks_uri).send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    let key = jwks["keys"].as_array().and_then(|keys| keys.iter().find(|k| k["kid"].as_str() == Some(&kid)))
        .ok_or("no matching JWKS key")?;
    let (n, e) = (key["n"].as_str().ok_or("jwk missing n")?, key["e"].as_str().ok_or("jwk missing e")?);
    let decoding = DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&cfg.client_id]);
    validation.set_issuer(&[cfg.issuer.trim_end_matches('/')]);
    let data = decode::<Value>(token, &decoding, &validation).map_err(|e| e.to_string())?;
    Ok(data.claims)
}

fn urlencoding(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{:02X}", b),
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp".into(), client_id: "cid".into(), client_secret_env: "X".into(),
            redirect_uri: "https://gw/cb".into(), app_url: "/".into(), groups_claim: "groups".into(),
            admin_group: Some("qw-admins".into()), operator_group: Some("qw-ops".into()),
            org_claim: Some("org".into()), default_org: "default".into(),
        }
    }

    #[test]
    fn maps_admin_group_and_org() {
        let claims = json!({ "email": "a@x.com", "groups": ["qw-admins"], "org": "acme" });
        let (u, r, o) = map_claims(&claims, &cfg());
        assert_eq!(u, "a@x.com");
        assert_eq!(r, Role::Admin);
        assert_eq!(o, "acme");
    }

    #[test]
    fn defaults_to_viewer_and_default_org() {
        let claims = json!({ "sub": "u1", "groups": ["other"] });
        let (u, r, o) = map_claims(&claims, &cfg());
        assert_eq!(u, "u1");
        assert_eq!(r, Role::Viewer);
        assert_eq!(o, "default");
    }
}
