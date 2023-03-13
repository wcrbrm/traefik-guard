use super::*;
use crate::proto::Reaction;
use axum::http::header::{HeaderMap, HeaderValue};
use axum_client_ip::{InsecureClientIp, SecureClientIp};

fn get_traefik_auth_root(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|x| x.to_str().ok())?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("http");
    Some(format!("{}://{}", proto, host))
}

fn get_location_header(to: &str, headers: &HeaderMap) -> HeaderValue {
    if to.contains("://") {
        // if it is already a full URL, just return it
        return HeaderValue::from_str(to).unwrap();
    }
    // for the case the URL is relative, we need to add the root
    let mut to = to.to_string();
    if let Some(tar) = get_traefik_auth_root(headers) {
        to = format!("{}/{}", tar, to.trim_start_matches('/'));
    }
    HeaderValue::from_str(&to).unwrap()
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
#[instrument(skip(state, headers), level = "info")]
pub async fn handle_visitor(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    headers: HeaderMap,
    insecure_ip: InsecureClientIp,
    secure_ip: SecureClientIp,
) -> impl IntoResponse {
    let default_uri = HeaderValue::from_static("/");
    let uri = headers
        .get("x-forwarded-uri")
        .unwrap_or(&default_uri)
        .to_str()
        .unwrap_or("/");
    let mut builder = Response::builder().header("x-uri", uri);
    let ip: Ipv4Addr = match real_ip(insecure_ip, secure_ip) {
        Some(ip) => {
            let hv_ip = HeaderValue::from_str(&ip.to_string()).unwrap();
            builder = builder.header("x-real-ip", hv_ip);
            ip
        }
        None => {
            builder = builder.header("x-local-ip", "1");
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };

    let state = state.lock().unwrap();
    let mm_reader = match crate::visitor::MmReader::new(&state.maxmind_path) {
        Ok(x) => x,
        Err(e) => {
            warn!("maxmind error {}", e);
            return builder
                .header("x-maxmind-error", "1")
                .status(200)
                .body(Full::from(""))
                .unwrap()
                .into_response();
        }
    };

    let visitor = match mm_reader.visit(ip, uri) {
        Ok(v) => v,
        Err(_) => crate::visitor::Visit::no_ip(uri),
    };

    match state.svc.react(&nsg, &visitor) {
        Ok(reaction) => {
            debug!("reaction {:?}", reaction);
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
                    .header("Location", get_location_header(&to, &headers)),
                Reaction::TemporaryRedirect(to) => builder
                    .status(302)
                    .header("Location", get_location_header(&to, &headers)),
                Reaction::HttpStatus(code) => builder.status(code),
            };
            builder.body(Full::from("")).unwrap().into_response()
        }
        Err(e) => err500(&e.to_string()).into_response(),
    }
}
