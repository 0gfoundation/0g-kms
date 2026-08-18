use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("app not found on-chain: {0}")]
    AppNotFound(String),

    /// The caller sent something malformed — bad hex, a pubkey that is not a valid curve point.
    /// Kept apart from CryptoError on purpose: this is the caller's mistake and the service
    /// behaved correctly, so it must not land in the same bucket as "our crypto broke", which is
    /// what an error-rate alert pages on.
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("chain error: {0}")]
    ChainError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("config error: {0}")]
    ConfigError(String),
}

impl IntoResponse for KmsError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            KmsError::InvalidTimestamp(_) | KmsError::InvalidSignature(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            KmsError::AppNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            KmsError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            KmsError::ChainError(_) | KmsError::CryptoError(_) | KmsError::ConfigError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
