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
        "/test",
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
        "/throw_500",
        prepare!(_req, host, _path, _addr {
            default_error_response(StatusCode::INTERNAL_SERVER_ERROR, host, None).await
        }),
    );
    icelk_extensions.add_prepare_fn(
        Box::new(|req, _| req.uri().path().starts_with("/capturing/")),
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
        extensions::Id::without_name(0),
    );

    kvarn_extensions::force_cache(
        &mut icelk_extensions,
        &[
            (".png", ClientCachePreference::Changing),
            (".ico", ClientCachePreference::Full),
            (".woff2", ClientCachePreference::Full),
            ("/highlight.js/", ClientCachePreference::Full),
        ],
    );

    let mut icelk_host = host_from_name("icelk.dev", "../icelk.dev/", icelk_extensions);
    icelk_host.disable_client_cache().disable_server_cache();

    let mut kvarn_extensions = kvarn_extensions::new();
    kvarn_extensions::force_cache(
        &mut kvarn_extensions,
        &[
            (".png", ClientCachePreference::Changing),
            (".woff2", ClientCachePreference::Full),
            (".woff", ClientCachePreference::Full),
            (".svg", ClientCachePreference::Changing),
            ("/highlight.js/", ClientCachePreference::Full),
        ],
    );

    let kvarn_cors = Cors::new()
        .add(
            "/logo.svg",
            CorsAllowList::new(time::Duration::from_secs(60 * 60 * 24 * 14))
                .add_origin("https://github.com")
                .add_origin("https://doc.kvarn.org"),
        )
        .add(
            "/favicon.svg",
            CorsAllowList::new(time::Duration::from_secs(60 * 60 * 24 * 14))
                .add_origin("https://doc.kvarn.org"),
        )
        .arc();
    kvarn_extensions.add_cors(kvarn_cors);

    let mut kvarn_host = host_from_name("kvarn.org", "../kvarn.org/", kvarn_extensions);

    kvarn_host.disable_client_cache().disable_server_cache();

    let mut kvarn_doc_extensions = Extensions::new();

    kvarn_extensions::force_cache(
        &mut kvarn_doc_extensions,
        &[("html", ClientCachePreference::None)],
    );

    kvarn_doc_extensions.add_prepare_single("/index.html".to_owned(), prepare!(_req, _host, _path, _addr {
        let response = Response::builder().status(StatusCode::PERMANENT_REDIRECT).header("location", "kvarn/").body(Bytes::new()).expect("we know this is ok.");
        FatResponse::cache(response)
    }));

    let mut kvarn_doc_host = host_from_name(
        "doc.kvarn.org",
        "../kvarn/target/doc/",
        kvarn_doc_extensions,
    );

    kvarn_doc_host.options.set_public_data_dir(".");
    kvarn_doc_host.disable_server_cache();

    let host = std::env::args().nth(1);

    let hosts = match host.as_deref() {
        Some("--kvarn") => Data::builder(kvarn_host).build(),
        Some("--kvarn-doc") => Data::builder(kvarn_doc_host).build(),
        Some(_) => {
            error!("Unsupported host specifier");
            return;
        }
        _ => Data::builder(icelk_host)
            .add_host(kvarn_host)
            .add_host(kvarn_doc_host)
            .build(),
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

    ports = ports.bind(kvarn::PortDescriptor::non_secure(
        http_port,
        Arc::clone(&hosts),
    ));

    #[cfg(feature = "https")]
    if hosts.has_secure() {
        ports = ports.bind(kvarn::PortDescriptor::new(https_port, Arc::clone(&hosts)));
    }

    let shutdown_manager = run(ports).await;

    #[cfg(not(feature = "interactive"))]
    shutdown_manager.wait().await;

    #[cfg(feature = "interactive")]
    {
        let waiter = shutdown_manager.clone();
        // Exit the application on shutdown.
        tokio::spawn(async move {
            waiter.wait().await;
            info!("Shutdown complete. Exiting binary.");
            std::process::exit(0);
        });
        let thread = std::thread::spawn(move || {
            use futures::executor::block_on;
            use std::io::{prelude::*, stdin};

            // Start `kvarn_chute`
            match std::process::Command::new("kvarn_chute").arg("../").spawn() {
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
                                hosts.clear_file_in_cache(&Path::new(words.next().unwrap_or(""))),
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
                                .path_and_query(words.next().unwrap_or(""))
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
                            shutdown_manager.shutdown();
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

fn host_from_name(name: &'static str, path: impl AsRef<Path>, extensions: Extensions) -> Host {
    #[cfg(feature = "https")]
    {
        let cert_base = join(discard_last(name.split('.')), ".");
        Host::with_http_redirect(
            name,
            format!("{}-cert.pem", &cert_base),
            format!("{}-pk.pem", &cert_base),
            path.as_ref().to_path_buf(),
            extensions,
            host::Options::default(),
        )
    }
    #[cfg(not(feature = "https"))]
    {
        Host::non_secure(
            name,
            path.as_ref().to_path_buf(),
            extensions,
            host::Options::default(),
        )
    }
}

#[repr(transparent)]
pub struct DiscardLast<T, I: Iterator<Item = T>> {
    iter: std::iter::Peekable<I>,
}
impl<T: Debug, I: Iterator<Item = T>> Iterator for DiscardLast<T, I> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.peek()?;
        let next = self.iter.next();
        self.iter.peek()?;
        next
    }
}
pub fn discard_last<T, I: Iterator<Item = T>>(iter: I) -> DiscardLast<T, I> {
    DiscardLast {
        iter: iter.peekable(),
    }
}

pub fn join<T: AsRef<str>, I: Iterator<Item = T>>(iter: I, separator: &str) -> String {
    let mut iter = iter.peekable();

    let mut string = String::new();

    while let Some(fragment) = iter.next() {
        let fragment = fragment.as_ref();
        string.push_str(fragment);
        if iter.peek().is_some() {
            string.push_str(separator);
        }
    }
    string
}
