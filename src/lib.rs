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
            .help(
                "Bind to higher ports (8080, 8443) to avoid permission issues. \
                Doesn't modify any other behaviour: \
                this is a good way to test the production environment.",
            )
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("dev")
            .long("dev")
            .help("Enable development environment. Uses high ports & disables all caches.")
            .conflicts_with("high_ports")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("host")
            .short('h')
            .long("host")
            .help("Set the default host to show")
            .num_args(1),
    )
    .arg(
        Arg::new("instance")
            .long("instance-path")
            .long("ctl-socket")
            .short('p')
            .help(
                "The path of the control socket. \
                If you want to start multiple instances of moella, \
                consider this to be an instance name, \
                and make it different for all instances. \
                If you are using kvarnctl, remember to specify this \
                when running the kvarnctl, else it won't find this instance!",
            )
            .default_value("kvarn.sock"),
    )
    .disable_help_flag(true)
    .arg(
        Arg::new("help")
            .long("help")
            .action(clap::ArgAction::Help)
            .help("Print help"),
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
    use self::config::CliOptions;

    let env_log = env_logger::Env::new().filter_or(
        "KVARN_LOG",
        "rustls=off,h3::proto::frame=error,h3::connection=error,info",
    );
    env_logger::Builder::from_env(env_log).init();

    let matches = command().get_matches();

    let opts = CliOptions {
        high_ports: matches.get_flag("high_ports") || matches.get_flag("dev"),
        cache: !matches.get_flag("dev"),
        dev: matches.get_flag("dev"),
        default_host: matches.get_one::<String>("host").map(String::as_str),
    };

    let mut rc = match config::read_and_resolve(
        matches.get_one::<String>("config").expect("it's required"),
        custom_extensions,
        &opts,
    )
    .await
    {
        Ok(rc) => rc,
        Err(s) => {
            log::error!("{s}");
            std::process::exit(1);
        }
    };

    let ctl_path = socket_path().join(
        matches
            .get_one::<String>("instance")
            .expect("we provided a default"),
    );
    rc = rc.set_ctl_path(ctl_path);

    rc.execute().await
}

#[cfg(feature = "bin")]
#[allow(unused_assignments)]
#[cfg_attr(windows, allow(unused_mut))]
pub(crate) fn socket_path() -> std::path::PathBuf {
    use std::path::Path;
    let mut p = Path::new("/run").to_path_buf();
    #[cfg(all(unix, target_os = "macos"))]
    {
        p = std::env::var_os("HOME")
            .map_or_else(|| Path::new("/Library/Caches").to_path_buf(), Into::into);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let user: u32 = unsafe { libc::getuid() };
        if user != 0 {
            p.push("user");
            p.push(user.to_string());
        }
    }
    p
}
