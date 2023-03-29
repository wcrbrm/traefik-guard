pub use axum::body::Full;
pub use axum::extract::*;
pub use axum::http::StatusCode;
pub use axum::response::*;
pub use serde::{Deserialize, Serialize};
pub use std::sync::{Arc, Mutex};
pub use tracing::*;
pub use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, ToSchema)]
pub struct HttpErrMessage {
    error: String,
    message: String,
}

#[instrument(level = "warn")]
pub fn err400(message: &str) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(HttpErrMessage {
            error: "Bad Request".to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

#[instrument(level = "warn")]
pub fn err500(message: &str) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(HttpErrMessage {
            error: "Server Error".to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

#[instrument(level = "warn")]
pub fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(HttpErrMessage {
            error: "Error".to_string(),
            message: "Not implemented".to_string(),
        }),
    )
        .into_response()
}
