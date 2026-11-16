use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use locksy_core::api::ErrorBody;

/// Erreur renvoyée au client : un code stable et un message en français.
/// Les détails techniques restent dans les journaux du serveur.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn rate_limited(retry_after: i64) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("Trop de tentatives. Réessayez dans {retry_after} secondes."),
        )
    }

    pub fn internal(context: &str) -> Self {
        tracing::error!(context, "erreur interne");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Erreur interne du serveur.")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.code.to_string(), message: self.message })).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "base de données");
        ApiError::internal("base de données")
    }
}
