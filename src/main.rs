pub mod cli;
mod logging;
pub mod proto;
pub mod state;

// TODO: mod validate to validate if http request matches security group
// TODO: mod auth to allow access to /nsg/ routes
// TODO: mod http handlers
use tracing::*;

#[instrument]
fn main() {
    color_eyre::install().unwrap();
    logging::start();

    info!("Hello, world!");
}
