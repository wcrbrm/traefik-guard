use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum RuleRefType {
    Index,
    Tag,
}

// struct for clap subcommands
#[derive(Debug, Clone, clap::Subcommand)]
pub enum Action {
    /// Add rule to the list of rules in the security group
    Add { rule: String },
    /// List all rules in the security groups
    List { tags: Option<String> },
    /// Delete
    Rm {
        ref_type: RuleRefType,
        reference: String,
    },
    /// Update rules in security group with a specific tag or index
    Update {
        ref_type: RuleRefType,
        reference: String,
        rule: String,
    },
    /// Check IP address
    Check { ip: String, url: Option<String> },
}

// struct for clap CLI args
#[derive(Debug, Parser)]
#[clap(version = "0.1")]
pub struct Opts {
    /// Set storage path
    #[clap(long, default_value = "./data", env = "TRAEFIK_GUARD_STORAGE_PATH")]
    pub storage_path: String,
    /// Name of the security group
    #[clap(long, default_value = "default")]
    pub nsg: String,
    /// Action
    #[command(subcommand)]
    pub action: Action,
    /// Log Level
    #[clap(env = "RUST_LOG")]
    log_level: Option<String>,
}
