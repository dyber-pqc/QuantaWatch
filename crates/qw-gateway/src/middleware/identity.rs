use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    http::HeaderValue,
};
use uuid::Uuid;
use crate::state::{AppState, SessionInfo};

const SESSION_HEADER: &str = "x-quantawatch-session";
const AGENT_HEADER: &str = "x-quantawatch-agent";

/// Identity middleware: assigns/validates session IDs.
pub async fn identity_layer(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Check for existing session
    let session_id = request.headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let agent_name = request.headers()
        .get(AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| "default".to_string());

    let session_id = match session_id {
        Some(id) if state.sessions.contains_key(&id) => id,
        _ => {
            // Create new session
            let id = Uuid::new_v4().to_string();
            let client_ip = request.headers()
                .get("x-forwarded-for")
                .or_else(|| request.headers().get("x-real-ip"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            let created_at = chrono::Utc::now();
            state.sessions.insert(id.clone(), SessionInfo {
                session_id: id.clone(),
                agent_name: agent_name.clone(),
                provider: String::new(),
                model: String::new(),
                created_at,
                request_count: 0,
                total_tokens: 0,
                client_ip: client_ip.clone(),
            });
            // Persist the session (best-effort, default tenant) so it survives restart.
            state.store.upsert_session(qw_store::DEFAULT_TENANT, &qw_store::SessionRow {
                session_id: id.clone(),
                agent_name: agent_name.clone(),
                provider: String::new(),
                model: String::new(),
                created_at,
                request_count: 0,
                total_tokens: 0,
                client_ip,
            });
            tracing::debug!(session_id = %id, agent = %agent_name, "New session created");
            id
        }
    };

    // Inject session ID into request extensions
    request.extensions_mut().insert(SessionContext {
        session_id: session_id.clone(),
        agent_name,
    });

    let mut response = next.run(request).await;

    // Add session header to response
    if let Ok(val) = HeaderValue::from_str(&session_id) {
        response.headers_mut().insert(SESSION_HEADER, val);
    }

    response
}

/// Session context inserted into request extensions.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub agent_name: String,
}
