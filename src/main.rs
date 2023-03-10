mod cli;
mod logging;
mod proto;
mod state;
mod tags;
mod visitor;

// TODO: mod http handlers to edit rules under security groups
// TODO: mod auth to allow access to /nsg/ routes
// TODO: Dockerfile, push it to dockerhub
// TODO: optimize search by introducing quick search mapping of rules with single IP address or single URL rule

use anyhow::Context;
use clap::Parser;
use state::*;
use tracing::*;

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

        cli::Action::Check { ip, uri } => {
            let svc = state::SecurityGroupService::from_local_path(&args.storage_path)
                .context("security group load")?;
            let ipv4 = ip.parse().unwrap();
            let v = visitor::MmReader::new(&args.maxmind_path)?.visit(ipv4, &uri)?;
            println!("{:?}", svc.react(&args.nsg, &v)?);
        }
    }
    Ok(())
}
