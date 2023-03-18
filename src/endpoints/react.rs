use super::*;
use crate::endpoints::client_ip::ClientIp;
use crate::proto::Reaction;
use axum::http::header::{HeaderMap, HeaderValue};
use std::net::{IpAddr, Ipv4Addr};

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
#[instrument(skip(state, headers), level = "debug")]
pub async fn handle_visitor(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> impl IntoResponse {
    let default_uri = HeaderValue::from_static("/");
    let uri = headers
        .get("x-forwarded-uri")
        .unwrap_or(&default_uri)
        .to_str()
        .unwrap_or("/");
    let mut builder = Response::builder().header("x-uri", uri);
    let ipv4: Ipv4Addr = match ip {
        IpAddr::V4(ip4) => {
            if ip4.is_loopback() || ip4.is_private() || ip4.is_link_local() || ip4.is_unspecified()
            {
                builder = builder.header("x-local-ip", "1");
            } else {
                builder = builder.header("x-real-ip", ip.to_string());
            }
            ip4
        }
        _ => {
            builder = builder.header("x-ipv6", "1");
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };

    let state = state.lock().unwrap();
    let Some(mm_reader) = state.mm() else {
        return builder
            .header("x-maxmind-error", "1")
            .status(200)
            .body(Full::from(""))
            .unwrap()
            .into_response();
    };

    let visitor = match mm_reader.visit(ipv4, uri) {
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
