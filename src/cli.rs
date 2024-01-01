use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum RuleRefType {
    Index,
    Tag,
    All,
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
    /// Check IP address and show reaction
    Check {
        /// IP address to be checked
        ip: String,
        /// Visiting URI to be checked
        uri: String,
        /// Path to MaxMind database (GeoLite2-City.mmdb)
        #[clap(long, default_value = "./", env = "TRAEFIK_GUARD_MAXMIND_PATH")]
        maxmind_path: String,
    },
    /// Start HTTP server
    Server {
        /// Net listening address of HTTP server in case of "server" command
        #[clap(long, default_value = "0.0.0.0:8000", env = "LISTEN")]
        listen: String,
        /// Path to MaxMind database (GeoLite2-City.mmdb)
        #[clap(long, default_value = "./", env = "TRAEFIK_GUARD_MAXMIND_PATH")]
        maxmind_path: String,
        /// Secret token to manage rules via HTTP API
        #[clap(long, default_value = "", env = "TRAEFIK_GUARD_SECRET_TOKEN")]
        secret_token: String,
        /// Path to a daily access log accumulation directory. Leave empty to disable access logging
        #[clap(long, default_value = "", env = "TRAEFIK_GUARD_ACCESS_LOG_DIR")]
        access_log_path: String,
    },
}

// struct for clap CLI args
#[derive(Debug, Parser)]
#[clap(version = "0.1")]
pub struct Opts {
    /// Storage path, where *.rules.txt files are stored
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
