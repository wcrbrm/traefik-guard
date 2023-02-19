use tracing::*;

mod logging {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    pub fn start() {
        let env_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("INFO"));
        let is_tty = atty::is(atty::Stream::Stdout);
        let subscriber = tracing_subscriber::fmt::fmt()
            .with_env_filter(env_filter)
            .with_ansi(is_tty)
            .with_span_events(fmt::format::FmtSpan::CLOSE) // enable durations
            .finish();
        _ = subscriber.with(ErrorLayer::default()).try_init();
    }
}

fn main() {
    color_eyre::install().unwrap();
    logging::start();

    info!("Hello, world!");
}
