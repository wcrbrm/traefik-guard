mod cli;
mod endpoints;
mod logging;
mod proto;
mod state;
mod tags;
mod visitor;

// NSG: actually check secret token to use it. Token could be in query param request too

use anyhow::Context;
use clap::Parser;
use state::*;
use std::net::SocketAddr;
use tracing::*;
use visitor::*;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    color_eyre::install().unwrap();
    logging::start();

    let args = cli::Opts::parse();
    debug!("{args:?}");
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
            println!("{}", svc.list_rules_as_str(&args.nsg, &tm)?);
        }
        cli::Action::Update {
            ref_type,
            reference,
            rule,
        } => {
            let r: RulesRef = match ref_type {
                cli::RuleRefType::All => RulesRef::All,
                cli::RuleRefType::Index => RulesRef::Index(reference.parse().unwrap()),
                cli::RuleRefType::Tag => RulesRef::Tag(tags::TagMap::from_query(&reference)),
            };
            let mut svc = SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            svc.update_rule(&args.nsg, &r, &rule)?;
        }
        cli::Action::Rm {
            ref_type,
            reference,
        } => {
            let r: RulesRef = match ref_type {
                cli::RuleRefType::All => RulesRef::All,
                cli::RuleRefType::Index => RulesRef::Index(reference.parse().unwrap()),
                cli::RuleRefType::Tag => RulesRef::Tag(tags::TagMap::from_query(&reference)),
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
            let v = MmFromDiskReader::new(&maxmind_path)?.visit(ipv4, &uri)?;
            println!("{:?}", svc.react(&args.nsg, &v)?);
        }

        cli::Action::Server {
            listen,
            maxmind_path,
            secret_token,
            access_log_path,
        } => {
            let socket_addr: SocketAddr = listen.parse().expect("invalid network port bind");
            endpoints::server::run(
                socket_addr,
                &secret_token,
                &maxmind_path,
                &args.storage_path,
                &access_log_path,
            )
            .await?;
        }
    }
    Ok(())
}
