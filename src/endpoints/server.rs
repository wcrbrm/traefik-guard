use crate::endpoints;
use crate::visitor::MmKeepInMemory as MR;
use anyhow::Context;
use axum::{
    extract::{DefaultBodyLimit, Extension},
    routing::*,
    Router, Server,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::*;
use tower_http::trace::*;
use tracing::*;

#[allow(unused_imports)]
use axum::ServiceExt;

pub async fn run(
    socket_addr: SocketAddr,
    _secret_token: &str,
    maxmind_path: &str,
    storage_path: &str,
) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let svc = crate::state::SecurityGroupService::from_local_path(storage_path)
        .context("security group load")?;
    let shared_state = Arc::new(Mutex::new(endpoints::AppState {
        svc,
        mm: MR::new(maxmind_path)?,
    }));
    let app = Router::new()
        .route("/openapi.json", get(endpoints::openapi::handle))
        .route("/metrics", get(endpoints::metrics::handle))
        .route("/nsg/:nsg/rules", get(endpoints::handle_rules_list::<MR>))
        .route("/nsg/:nsg/rules", post(endpoints::handle_rules_add::<MR>))
        .route("/nsg/:nsg/rules", put(endpoints::handle_rules_update::<MR>))
        .route("/nsg/:nsg/rules", delete(endpoints::handle_rules_rm::<MR>))
        .route("/guard/:nsg", get(endpoints::react::handle_visitor::<MR>))
        .layer(cors)
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024)) // reason for 429
        .layer(Extension(shared_state))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::DEBUG)
                        .include_headers(false),
                )
                .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .include_headers(true),
                ),
        )
        .route("/", get(|| async { "# Traefik Guard API, v1" }));

    info!("Listening on {}", socket_addr);
    Server::bind(&socket_addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}
