#![doc = include_str!("../README.md")]
pub mod config;
pub mod extension;
pub mod host;
pub mod port;

pub use config::read_and_resolve;

/// CLI argument parser.
#[cfg(feature = "bin")]
pub fn command() -> clap::Command {
    use clap::Arg;
    let c = clap::command!();
    c.long_about(
        "Mölla runns the Kvarn web server using plain-text configs.\n\
        See https://kvarn.org/moella/ for more details and how to write the config.\n\
        \n\
        Logging is controlled using the environment variable `KVARN_LOG`.\n\
        See https://docs.rs/env_logger/latest/env_logger/#example for log settings.",
    )
    .arg(
        Arg::new("config")
            .short('c')
            .long("config")
            .num_args(1)
            .required(true)
            .help("Main config file"),
    )
    .arg(
        Arg::new("high_ports")
            .long("high-ports")
            .help("Bind to higher ports (8080, 8443) to avoid permission issues")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("host")
            .short('d')
            .long("host")
            .help("Set the default host to show")
            .num_args(1),
    )
}

/// Sets up logging, starts the server, and returns the handle.
/// Also handles argument parsing.
///
/// Logging is controlled using the environment variable `KVARN_LOG`.
/// See [this page](https://docs.rs/env_logger/latest/env_logger/#example) for log settings.
#[cfg(feature = "bin")]
pub async fn run(
    custom_extensions: &config::CustomExtensions,
) -> std::sync::Arc<kvarn::shutdown::Manager> {
    let env_log = env_logger::Env::new().filter_or("KVARN_LOG", "rustls=off,info");
    env_logger::Builder::from_env(env_log).init();

    let matches = command().get_matches();

    let rc = match config::read_and_resolve(
        matches.get_one::<String>("config").expect("it's required"),
        custom_extensions,
        matches.get_flag("high_ports"),
        matches.get_one::<String>("host").map(String::as_str),
    )
    .await
    {
        Ok(rc) => rc,
        Err(s) => {
            log::error!("{s}");
            std::process::exit(1);
        }
    };
    let sh = rc.execute().await;

    sh
}
