use crate::proto::{Reaction, Visitor};
use crate::tags::TagMap;
use crate::AppState;
use axum::body::Full;
use axum::extract::*;
use axum::http::header::{HeaderMap, HeaderValue};
use axum::response::*;
use axum_helpers::*;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::*;
use utoipa::IntoParams;

pub(crate) mod openapi {
    use super::axum_helpers;
    use crate::endpoints as guard;
    use axum::response::*;
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(
        paths(
            guard::handle_rules_list,
            guard::handle_rules_create,
            guard::handle_rules_update,
            guard::handle_rules_delete,
            guard::handle_visitor,
        ),
        components(schemas(axum_helpers::HttpErrMessage,))
    )]
    pub struct ApiDoc;

    /// returns OpenAPI documentation builder, to be used as string or server JSON response
    pub fn openapi() -> utoipa::openapi::OpenApi {
        ApiDoc::openapi()
    }

    /// */openapi.json endpoint
    pub async fn handle() -> impl IntoResponse {
        Json(openapi())
    }
}

#[derive(Clone, Deserialize, IntoParams)]
pub struct RulesListOptions {
    #[param(example = "blacklist")]
    tags: Option<String>,
}

impl RulesListOptions {
    pub fn tags(&self) -> TagMap {
        match &self.tags {
            Some(t) => TagMap::from_query(t),
            None => TagMap::new(),
        }
    }
}

mod axum_helpers {
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
}

pub(crate) mod metrics {
    use super::*;
    use lazy_static::lazy_static;
    use prometheus::{opts, register_int_gauge};
    #[allow(unused_imports)]
    use prometheus::{Encoder, Gauge, IntGauge, Opts, Registry, TextEncoder};

    lazy_static! {
        pub static ref UP: IntGauge =
            register_int_gauge!(opts!("up", "Whether the server is running")).unwrap();
    }

    pub fn to_string() -> String {
        let encoder = TextEncoder::new();
        // let labels = HashMap::new();
        // let sr = Registry::new_custom(Some("api".to_string()), Some(labels)).unwrap();
        let sr = Registry::new();
        sr.register(Box::new(UP.clone())).unwrap();
        UP.set(1i64);

        let mut buffer = Vec::<u8>::new();
        encoder.encode(&sr.gather(), &mut buffer).unwrap();
        String::from_utf8(buffer.clone()).unwrap()
    }

    pub async fn handle() -> impl IntoResponse {
        metrics::to_string()
    }
}

/// guard/{nsg}
#[utoipa::path(
    get,
    path = "/guard/{nsg}",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
    ),
    responses(
        (status = 200, description = "validate the visitor geography and put the reaction as headers", content_type = "text/plain"),
    ),
)]
#[instrument(skip(state, headers))]
pub async fn handle_visitor(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    headers: HeaderMap,
    insecure_ip: axum_client_ip::InsecureClientIp,
    secure_ip: axum_client_ip::SecureClientIp,
) -> impl IntoResponse {
    let default_uri = HeaderValue::from_static("/");
    let uri = headers
        .get("x-forwarded-uri")
        .unwrap_or(&default_uri)
        .to_str()
        .unwrap_or("/");
    let ip: Ipv4Addr = match real_ip(insecure_ip, secure_ip) {
        Some(ip) => ip,
        None => return err400("ip address detection failed").into_response(),
    };
    let state = state.lock().unwrap();
    let visitor = match state.mm_reader.visit(ip, uri) {
        Ok(v) => v,
        Err(e) => return err500(&e.to_string()).into_response(),
    };
    warn!("visitor {:?}", visitor);
    match state.svc.react(&nsg, &visitor) {
        Ok(reaction) => {
            warn!("reaction {:?}", reaction);

            let hv_ip = HeaderValue::from_str(&visitor.ip().to_string()).unwrap();
            let mut builder = Response::builder()
                .header("x-real-ip", hv_ip)
                .header("x-uri", uri);
            if let Some(country) = visitor.country() {
                builder =
                    builder.header("x-country-code", HeaderValue::from_str(&country).unwrap());
            }
            if let Some(city) = visitor.city() {
                builder = builder.header("x-city-en-name", HeaderValue::from_str(&city).unwrap());
            }
            builder = match reaction {
                Reaction::PermanentRedirect(to) => builder
                    .status(301)
                    .header("Location", HeaderValue::from_str(&to).unwrap()),
                Reaction::TemporaryRedirect(to) => builder
                    .status(302)
                    .header("Location", HeaderValue::from_str(&to).unwrap()),
                Reaction::HttpStatus(code) => builder.status(code),
            };

            builder.body(Full::from("")).unwrap().into_response()
        }
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    get,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    responses(
        (status = 200, description = "retrieve rules for the security group in plain text, one rule per line", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_list(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state.svc.list_rules(&nsg, &tm) {
        Ok(out) => out.join("\n").into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    post,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
    ),
    request_body(content = String, description = "rules in plain text, one rule per line", content_type = "text/plain"),
    responses(
        (status = 200, description = "returns total amount of rules in the security group, plain text", content_type = "text/plain"),
    )
)]
pub async fn handle_rules_create(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    body: String,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    match state.svc.create_rule(&nsg, &body) {
        Ok(out) => out.to_string().into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    put,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    request_body(content = String, description = "rule in plain text, one line is required", content_type = "text/plain"),
    responses(
        (status = 200, description = "delete rules for the security group by given tags", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_update(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    body: String,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state
        .svc
        .update_rule(&nsg, &crate::state::RuleRef::Tag(tm), &body)
    {
        Ok(_) => "OK".into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    delete,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    responses(
        (status = 200, description = "delete rules for the security group by given tags", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_delete(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>, // can be extended to RulesRefOptions
    Extension(state): Extension<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state.svc.delete_rule(&nsg, &crate::state::RuleRef::Tag(tm)) {
        Ok(_) => "OK".into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

// TODO: security layer, secret token to manage rules
// TODO: differentiate 400 on the service layer somehow
// TODO: configure client IP source from cli args
