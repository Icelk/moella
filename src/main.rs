use kvarn::prelude::*;

#[cfg_attr(feature = "mt", tokio::main)]
#[cfg_attr(not(feature = "mt"), tokio::main(flavor = "current_thread"))]
async fn main() {
    let env_log = env_logger::Env::default().default_filter_or("rustls=off,warn");
    env_logger::Builder::from_env(env_log).init();

    // Mount all extensions to server
    let mut icelk_extensions = kvarn_extensions::new();

    let times_called = Arc::new(threading::atomic::AtomicUsize::new(0));
    icelk_extensions.add_prepare_single(
        "/test".to_string(),
        prepare!(request, _host, _path, _addr, move |times_called| {
            let tc = times_called;
            let tc = tc.fetch_add(1, threading::atomic::Ordering::Relaxed);

            let body = build_bytes!(
                b"<h1>Welcome to my site!</h1> You are calling: ",
                request.uri().path().as_bytes(),
                b" for the ",
                tc.to_string().as_bytes(),
                b" time",
            );

            // It must be OK; we haven't changed the response
            let response = Response::new(body);

            FatResponse::no_cache(response)
        }),
    );
    icelk_extensions.add_prepare_single(
        "/throw_500".to_string(),
        prepare!(_req, host, _path, _addr {
            utility::default_error_response(StatusCode::INTERNAL_SERVER_ERROR, host, None).await
        }),
    );
    icelk_extensions.add_prepare_fn(
        Box::new(|req| req.uri().path().starts_with("/capturing/")),
        prepare!(req, _host, _path, _addr {
            let body = build_bytes!(
                b"!> tmpl standard.html\n\
            [head]\
            [dependencies]\
            [close-head]\
            [navigation]\
            <main style='text-align: center;'><h1>You are visiting: '",
                req.uri().path().as_bytes(),
                b"'.</h1>Well, hope you enjoy <a href='/'>my site</a>!</main>"
            );
            FatResponse::new(Response::new(body), ServerCachePreference::None)
        }),
    );

    #[cfg(feature = "https")]
    let icelk_host = Host::with_http_redirect(
        "icelk.dev",
        "icelk_cert.pem",
        "icelk_pk.pem",
        PathBuf::from("icelk.dev"),
        icelk_extensions,
    );
    let kvarn_extensions = kvarn_extensions::new();

    #[cfg(feature = "https")]
    let kvarn_host = Host::with_http_redirect(
        "kvarn.org",
        "kvarn_cert.pem",
        "kvarn_pk.pem",
        PathBuf::from("kvarn.org"),
        kvarn_extensions,
    );
    #[cfg(not(feature = "https"))]
    let kvarn_host = Host::non_secure("kvarn.org", PathBuf::from("kvarn.org"), kvarn_extensions);

    #[cfg(feature = "https")]
    let hosts = Data::builder(icelk_host).add_host(kvarn_host).build();

    #[cfg(not(feature = "https"))]
    let hosts = Data::builder(kvarn_host).build();

    #[cfg(not(feature = "high_ports"))]
    let http_port = 80;
    #[cfg(all(not(feature = "high_ports"), feature = "https"))]
    let https_port = 443;
    #[cfg(feature = "high_ports")]
    let http_port = 8080;
    #[cfg(all(feature = "high_ports", feature = "https"))]
    let https_port = 8443;

    let mut ports = Vec::with_capacity(2);

    ports.push(kvarn::PortDescriptor::non_secure(
        http_port,
        Arc::clone(&hosts),
    ));

    #[cfg(feature = "https")]
    if hosts.has_secure() {
        ports.push(kvarn::PortDescriptor::new(https_port, Arc::clone(&hosts)));
    }

    let shutdown_manager = run(ports).await;

    #[cfg(not(feature = "interactive"))]
    shutdown_manager.wait().await;

    #[cfg(feature = "interactive")]
    {
        let thread = std::thread::spawn(move || {
            use futures::executor::block_on;
            use std::io::{prelude::*, stdin};

            // Start `kvarn_chute`
            match std::process::Command::new("kvarn_chute").arg(".").spawn() {
                Ok(_child) => println!("Successfully started 'kvarn_chute!'"),
                Err(_) => eprintln!("Failed to start 'kvarn_chute'."),
            }

            // Commands in console
            for line in stdin().lock().lines().flatten() {
                let mut words = line.split(' ');
                if let Some(command) = words.next() {
                    match command {
                        "fcc" => {
                            // File cache clear
                            match block_on(
                                hosts.clear_file_in_cache(&Path::new(words.next().unwrap_or(&""))),
                            ) {
                                true => println!("Removed item from cache!"),
                                false => println!("No item to remove"),
                            }
                        }
                        "rcc" => {
                            // Response cache clear
                            let host = match words.next() {
                                Some(word) => word,
                                None => {
                                    println!("Please enter a host to clear cache in.");
                                    continue;
                                }
                            };
                            let uri = match Uri::builder()
                                .path_and_query(words.next().unwrap_or(&""))
                                .build()
                            {
                                Ok(uri) => uri,
                                Err(..) => {
                                    eprintln!("Failed to format path");
                                    continue;
                                }
                            };
                            let (cleared, found) = block_on(hosts.clear_page(host, &uri));

                            if !found {
                                println!("Did not found host to remove cached item from. Use 'default' or an empty string (e.g. '') for the default host.");
                            } else if !cleared {
                                println!("Did not remove any cached response.");
                            } else {
                                println!("Cleared a cached response.");
                            }
                        }
                        "cfc" => {
                            block_on(hosts.clear_file_caches());
                            println!("Cleared file system cache!");
                        }
                        "crc" => {
                            block_on(hosts.clear_response_caches());
                            println!("Cleared whole response cache.",);
                        }
                        "cc" => {
                            let hosts = hosts.clone();
                            block_on(async move {
                                hosts.clear_response_caches().await;
                                hosts.clear_file_caches().await
                            });
                            println!("Cleared all caches!");
                        }
                        "shutdown" | "sd" => {
                            block_on(async {
                                shutdown_manager.shutdown().await;
                                shutdown_manager.wait().await;
                                info!("Shutdown complete!");
                            });
                            info!("Breaking interactive loop.");
                            break;
                        }
                        _ => {
                            eprintln!("Unknown command!");
                        }
                    }
                }
            }
        });
        thread.join().unwrap();
    }
}
