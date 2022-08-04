use kvarn::prelude::*;

pub mod hosts;

#[cfg_attr(feature = "mt", tokio::main)]
#[cfg_attr(not(feature = "mt"), tokio::main(flavor = "current_thread"))]
async fn main() {
    let env_log = env_logger::Env::new().filter_or("KVARN_LOG", "rustls=off,warn");
    env_logger::Builder::from_env(env_log).init();

    let (icelk_host, icelk_se) = hosts::icelk(hosts::icelk_extensions().await).await;
    let icelk_doc_host = hosts::icelk_doc(hosts::icelk_doc_extensions());
    let (kvarn_host, kvarn_se) = hosts::kvarn(hosts::kvarn_extensions()).await;
    let kvarn_doc_host = hosts::kvarn_doc(hosts::kvarn_doc_extensions());
    let agde_host = hosts::agde(hosts::kvarn_extensions());
    let icelk_bitwarden_host = hosts::icelk_bitwarden(hosts::icelk_bitwarden_extensions());

    let host = std::env::args().nth(1);

    let mut hosts = match host.as_deref() {
        Some("--icelk") => HostCollection::builder().default(icelk_host),
        Some("--icelk-doc") => HostCollection::builder().default(icelk_doc_host),
        Some("--kvarn") => HostCollection::builder().default(kvarn_host),
        Some("--kvarn-doc") => HostCollection::builder().default(kvarn_doc_host),
        Some("--agde") => HostCollection::builder().default(agde_host),
        Some("--icelk-bitwarden") => HostCollection::builder().default(icelk_bitwarden_host),
        Some(_) => {
            error!("Unsupported host specifier");
            return;
        }
        _ => HostCollection::builder()
            .insert(icelk_host)
            .insert(icelk_doc_host)
            .insert(kvarn_host)
            .insert(kvarn_doc_host)
            .insert(agde_host)
            .insert(icelk_bitwarden_host),
    };

    // insert HTTP mail hosts, enables Let's Encrypt to validate ownership.
    // All the hosts in the `mail-hosts.txt` file (separated by newlines)
    // are getting data from `$CWD/mail/public/`
    {
        let mail_hosts = hosts::mail_hosts("mail-hosts.txt");
        for host in mail_hosts {
            hosts = hosts.insert(host);
        }
    }

    let hosts = hosts.build();

    let _se_icelk_watcher = if hosts.get_host("icelk.dev").is_some() {
        Some(
            icelk_se
                .watch("icelk.dev", Arc::clone(&hosts))
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let _se_kvarn_watcher = if hosts.get_host("kvarn.org").is_some() {
        Some(
            kvarn_se
                .watch("kvarn.org", Arc::clone(&hosts))
                .await
                .unwrap(),
        )
    } else {
        None
    };

    #[cfg(not(feature = "high_ports"))]
    let http_port = 80;
    #[cfg(all(not(feature = "high_ports"), feature = "https"))]
    let https_port = 443;
    #[cfg(feature = "high_ports")]
    let http_port = 8080;
    #[cfg(all(feature = "high_ports", feature = "https"))]
    let https_port = 8443;

    let mut ports = RunConfig::new();

    ports = ports.bind(kvarn::PortDescriptor::unsecure(
        http_port,
        Arc::clone(&hosts),
    ));

    #[cfg(feature = "https")]
    if hosts.has_secure() {
        ports = ports.bind(kvarn::PortDescriptor::new(https_port, Arc::clone(&hosts)));
    }

    let shutdown_manager = ports.execute().await;

    #[cfg(not(feature = "interactive"))]
    shutdown_manager.wait().await;

    #[cfg(feature = "interactive")]
    {
        let chute = Arc::new(std::sync::Mutex::new(None));
        let chute_handle = Arc::clone(&chute);
        // Start `kvarn-chute`
        static CHUTE_COMMAND: &str = "chute";
        match std::process::Command::new(CHUTE_COMMAND).arg("../").spawn() {
            Ok(child) => {
                println!("Successfully started '{}'.", CHUTE_COMMAND);
                *chute_handle.lock().unwrap() = Some(child);
            }
            Err(_) => {
                eprintln!("Failed to start '{}'.", CHUTE_COMMAND);
            }
        }

        let waiter = shutdown_manager.clone();
        // Exit the application on shutdown.
        tokio::spawn(async move {
            waiter.wait().await;
            info!("Shutdown complete. Exiting binary.");
            if let Some(c) = chute_handle.lock().unwrap().as_mut() {
                drop(c.kill())
            }
            std::process::exit(0);
        });

        shutdown_manager.wait().await;

        drop(_se_icelk_watcher);
        if let Some(c) = chute.lock().unwrap().as_mut() {
            // Check if OK since we might be in between killing of child and std::process::exit
            // as above.
            if c.kill().is_ok() {
                c.wait().unwrap();
            }
        };
    }
}
