use super::*;
use crate::endpoints::client_ip::ClientIp;
use crate::proto::Reaction;
use crate::visitor::IntoVisitor;
use axum::http::header::{HeaderMap, HeaderValue};
use std::net::{IpAddr, Ipv4Addr};
use tracing::*;

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

#[instrument(skip(headers), level = "TRACE")]
pub fn apache_log(code: u16, access_log: &str, headers: &HeaderMap, real_ip: Ipv4Addr) {
    use std::io::prelude::Write;

    if access_log.len() == 0 || code == 200 {
        // skip if not configured or if guard is not reacting
        return;
    }
    let now = chrono::Local::now();
    let filename = format!("{}/guard.{}.log", access_log, now.format("%Y-%m-%d"));

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("cannot open access log file {} {:?}", filename, e);
            return;
        }
    };

    let default_uri_str = "/";
    let default_uri = HeaderValue::from_static(default_uri_str);
    let uri = headers
        .get("x-forwarded-uri")
        .unwrap_or(&default_uri)
        .to_str()
        .unwrap_or(default_uri_str);

    let default_method_str = "GET";
    let default_method = HeaderValue::from_static(default_method_str);
    let method = headers
        .get("x-forwarded-method")
        .unwrap_or(&default_method)
        .to_str()
        .unwrap_or(default_method_str);

    let default_ua_str = "(no agent)";
    let default_ua = HeaderValue::from_static(default_ua_str);
    let ua = headers
        .get("user-agent")
        .unwrap_or(&default_ua)
        .to_str()
        .unwrap_or(default_ua_str);

    let out = format!(
        "- - - [{}] \"{} {} HTTP/1.1\" {} 0 \"-\" \"{}\" \"{}\"\n",
        now.to_rfc2822(),
        method,
        uri,
        code,
        ua,
        real_ip
    );
    match file.write_all(&out.as_bytes()) {
        Ok(_) => {}
        Err(e) => {
            warn!("cannot write to access log file {} {:?}", filename, e);
        }
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
#[instrument(skip(state, headers), level = "trace")]
pub async fn handle_visitor<MM>(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState<MM>>>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> impl IntoResponse
where
    MM: IntoVisitor,
{
    let default_uri_str = "/";
    let default_uri = HeaderValue::from_static(default_uri_str);
    let uri = headers
        .get("x-forwarded-uri")
        .unwrap_or(&default_uri)
        .to_str()
        .unwrap_or(default_uri_str);
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
    let visitor = match state.mm.visit(ipv4, uri) {
        Ok(v) => v,
        Err(_) => {
            builder = builder.header("x-maxmind-error", "1");
            crate::visitor::Visit::no_ip(uri)
        }
    };

    match state.svc.react(&nsg, &visitor) {
        Ok(reaction) => {
            if let Some(country) = visitor.country() {
                builder =
                    builder.header("x-country-code", HeaderValue::from_str(&country).unwrap());
            }
            if let Some(city) = visitor.city() {
                builder = builder.header("x-city-en-name", HeaderValue::from_str(&city).unwrap());
            }
            builder = match reaction {
                Reaction::PermanentRedirect(to) => {
                    apache_log(301, &state.access_log, &headers, ipv4);
                    builder
                        .status(301)
                        .header("Location", get_location_header(&to, &headers))
                }
                Reaction::TemporaryRedirect(to) => {
                    apache_log(302, &state.access_log, &headers, ipv4);

                    builder
                        .status(302)
                        .header("Location", get_location_header(&to, &headers))
                }
                Reaction::HttpStatus(code) => {
                    apache_log(code, &state.access_log, &headers, ipv4);
                    builder.status(code)
                }
            };
            builder.body(Full::from("")).unwrap().into_response()
        }
        Err(e) => err500(&e.to_string()).into_response(),
    }
}
