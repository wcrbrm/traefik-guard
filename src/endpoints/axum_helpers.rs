use axum::http::StatusCode;
use axum::response::*;
use std::net::Ipv4Addr;
use tracing::*;
use utoipa::ToSchema;

#[derive(serde::Serialize, ToSchema)]
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

pub fn real_ip(
    insecure_ip: axum_client_ip::InsecureClientIp,
    secure_ip: axum_client_ip::SecureClientIp,
) -> Option<Ipv4Addr> {
    let mut ipv4 = match secure_ip.0.to_string().parse::<Ipv4Addr>() {
        Ok(x) => {
            if x.is_loopback() || x.is_private() {
                None
            } else {
                Some(x)
            }
        }
        _ => None,
    };
    if let None = ipv4 {
        ipv4 = match insecure_ip.0.to_string().parse::<Ipv4Addr>() {
            Ok(x) => {
                if x.is_loopback() || x.is_private() {
                    None
                } else {
                    Some(x)
                }
            }
            _ => None,
        };
    };
    ipv4
}
