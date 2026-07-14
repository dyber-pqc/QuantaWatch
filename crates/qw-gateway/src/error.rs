use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("threat detected: {0}")]
    ThreatDetected(String),

    #[error("upstream error: {0}")]
    UpstreamError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            GatewayError::ProviderNotFound(msg) => {
                (StatusCode::NOT_FOUND, "provider_not_found", msg.clone())
            }
            GatewayError::PolicyDenied(msg) => {
                (StatusCode::FORBIDDEN, "policy_denied", msg.clone())
            }
            GatewayError::ThreatDetected(msg) => {
                (StatusCode::BAD_REQUEST, "threat_detected", msg.clone())
            }
            GatewayError::UpstreamError(msg) => {
                (StatusCode::BAD_GATEWAY, "upstream_error", msg.clone())
            }
            GatewayError::ConfigError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "config_error",
                msg.clone(),
            ),
            GatewayError::SessionError(msg) => {
                (StatusCode::UNAUTHORIZED, "session_error", msg.clone())
            }
            GatewayError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                msg.clone(),
            ),
        };

        let body = json!({
            "error": {
                "type": error_type,
                "message": message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
