mod cli;
mod endpoints;
mod logging;
mod proto;
mod state;
mod tags;
mod visitor;

// TODO: Dockerfile, push it to dockerhub
// TODO: optimize search by introducing quick search mapping of rules with single IP address or single URL rule

use anyhow::Context;
// use axum::ServiceExt;
use clap::Parser;
use state::*;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tracing::*;

pub struct AppState {
    pub svc: SecurityGroupService,
    pub mm_reader: visitor::MmReader,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    color_eyre::install().unwrap();
    logging::start();

    let args = cli::Opts::parse();
    match args.action {
        cli::Action::Add { rule } => {
            info!("Add {}", rule);
            let mut svc = state::SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            svc.create_rule(&args.nsg, &rule)?;
        }
        cli::Action::List { tags } => {
            let svc = state::SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            let tm = match tags {
                Some(t) => tags::TagMap::from_query(&t),
                None => tags::TagMap::new(),
            };
            for rule in svc.list_rules(&args.nsg, &tm)? {
                println!("{}", rule);
            }
        }
        cli::Action::Update {
            ref_type,
            reference,
            rule,
        } => {
            let r: RuleRef = match ref_type {
                cli::RuleRefType::Index => RuleRef::Index(reference.parse().unwrap()),
                cli::RuleRefType::Tag => RuleRef::Tag(tags::TagMap::from_query(&reference)),
            };
            let mut svc = SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            svc.update_rule(&args.nsg, &r, &rule)?;
        }
        cli::Action::Rm {
            ref_type,
            reference,
        } => {
            let r: RuleRef = match ref_type {
                cli::RuleRefType::Index => RuleRef::Index(reference.parse().unwrap()),
                cli::RuleRefType::Tag => RuleRef::Tag(tags::TagMap::from_query(&reference)),
            };
            let mut svc = SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            svc.delete_rule(&args.nsg, &r)?;
        }

        cli::Action::Check {
            ip,
            uri,
            maxmind_path,
        } => {
            let svc = state::SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            let ipv4 = ip.parse().unwrap();
            let v = visitor::MmReader::new(&maxmind_path)?.visit(ipv4, &uri)?;
            println!("{:?}", svc.react(&args.nsg, &v)?);
        }

        cli::Action::Server {
            listen,
            maxmind_path,
        } => {
            use axum::{extract::Extension, routing::*, Router, Server};
            use tower_http::cors::{Any, CorsLayer};
            use tower_http::trace::*;

            let socket_addr: SocketAddr = listen.parse().expect("invalid network port bind");
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);

            let svc = state::SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            let mm_reader = visitor::MmReader::new(&maxmind_path)?;
            let shared_state = Arc::new(Mutex::new(AppState { svc, mm_reader }));
            let app = Router::new()
                .route("/openapi.json", get(endpoints::openapi::handle))
                .route("/metrics", get(endpoints::metrics::handle))
                .route("/nsg/:nsg/rules", get(endpoints::handle_rules_list))
                .route("/nsg/:nsg/rules", post(endpoints::handle_rules_create))
                .route("/nsg/:nsg/rules", put(endpoints::handle_rules_update))
                .route("/nsg/:nsg/rules", delete(endpoints::handle_rules_delete))
                .route("/guard/:nsg", get(endpoints::handle_visitor))
                .layer(cors)
                .layer(Extension(shared_state))
                .layer(axum_client_ip::SecureClientIpSource::CfConnectingIp.into_extension())
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(DefaultMakeSpan::new().level(Level::TRACE))
                        .on_request(DefaultOnRequest::new().level(Level::TRACE))
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .route("/", get(|| async { "# Traefik Guard API, v1" }));

            info!("Listening on {}", socket_addr);
            Server::bind(&socket_addr)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
    }
    Ok(())
}
