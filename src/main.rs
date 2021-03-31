use kvarn::{
    extensions::Extensions,
    prelude::{threading::*, *},
};
use kvarn_extensions;

#[tokio::main]
async fn main() {
    let env_log = env_logger::Env::default().default_filter_or("rustls=off,warn");
    env_logger::Builder::from_env(env_log).init();

    // let mut bindings = FunctionBindings::new();
    // let times_called = Arc::new(Mutex::new(0_u32));
    // bindings.bind_page("/test", move |buffer, request, _| {
    //     let mut tc = times_called.lock().unwrap();
    //     *tc += 1;

    //     buffer.extend(
    //         format!(
    //             "<h1>Welcome to my site!</h1> You are calling: {} For the {} time.",
    //             request.uri(),
    //             &tc
    //         )
    //         .as_bytes(),
    //     );

    //     (Html, Dynamic)
    // });
    // bindings.bind_page("/throw_500", |mut buffer, _, storage| {
    //     write_error(
    //         &mut buffer,
    //         http::StatusCode::INTERNAL_SERVER_ERROR,
    //         storage,
    //     )
    // });
    // bindings.bind_dir("/capturing/", |buffer, request, _| {
    //     buffer.extend(
    //         &b"!> tmpl standard.html\n\
    //         [head]\
    //         [dependencies]\
    //         [close-head]\
    //         [navigation]\
    //         <main style='text-align: center;'><h1>You are visiting: '"[..],
    //     );
    //     buffer.extend(request.uri().path().as_bytes());
    //     buffer.extend(
    //         &b"'.</h1>Well, hope you enjoy <a href=\"/\">my site</a>!</main>\
    //         [footer]"[..],
    //     );

    //     (Html, Static)
    // });

    // Mount all extensions to server
    let mut extensions = Extensions::new();
    kvarn_extensions::mount_all(&mut extensions);

    let icelk_host = Host::with_http_redirect(
        "icelk_cert.pem",
        "icelk_pk.pem",
        PathBuf::from("icelk.dev"),
        extensions.clone(),
    );
    let kvarn_host = Host::with_http_redirect(
        "kvarn_cert.pem",
        "kvarn_pk.pem",
        PathBuf::from("kvarn.org"),
        extensions,
    );

    let hosts = HostData::builder("icelk.dev".to_string(), icelk_host)
        .add_host("kvarn.org".to_string(), kvarn_host)
        .build();

    #[cfg(not(feature = "high_ports"))]
    let http_port = 80;
    #[cfg(not(feature = "high_ports"))]
    let https_port = 443;
    #[cfg(feature = "high_ports")]
    let http_port = 8080;
    #[cfg(feature = "high_ports")]
    let https_port = 8443;

    let mut ports = Vec::with_capacity(2);

    ports.push(kvarn::HostDescriptor::new(
        http_port,
        Arc::clone(&hosts),
        ConnectionSecurity::http1(),
    ));

    if hosts.has_secure() {
        let mut config = HostData::make_config(&hosts);
        config.alpn_protocols = vec![b"h2".to_vec()];
        let config = Arc::new(config);
        ports.push(kvarn::HostDescriptor::new(
            https_port,
            Arc::clone(&hosts),
            ConnectionSecurity::http1s(config),
        ));
    }

    let server = Config::new(ports);

    #[cfg(feature = "interactive")]
    tokio::spawn(async move { server.run().await });
    #[cfg(not(feature = "interactive"))]
    server.run().await;

    #[cfg(feature = "interactive")]
    {
        use http::uri::Uri;
        use std::io::{prelude::*, stdin};
        // Start `kvarn_chute`
        match std::process::Command::new("kvarn_chute").arg(".").spawn() {
            Ok(_child) => println!("Successfully started 'kvarn_chute!'"),
            Err(_) => eprintln!("Failed to start 'kvarn_chute'."),
        }

        // Commands in console
        for line in stdin().lock().lines() {
            if let Ok(line) = line {
                let mut words = line.split(" ");
                if let Some(command) = words.next() {
                    match command {
                        "fcc" => {
                            // File cache clear
                            match hosts
                                .clear_file_in_cache(&Path::new(words.next().unwrap_or(&"")))
                                .await
                            {
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
                            let (cleared, found) = hosts.clear_page(host, &uri).await;

                            if !found {
                                println!("Did not found host to remove cached item from. Use 'default' or an empty string (e.g. '') for the default host.");
                            } else {
                                if !cleared {
                                    println!("Did not remove any cached response.");
                                } else {
                                    println!("Cleared a cached response.");
                                }
                            }
                        }
                        "cfc" => {
                            hosts.clear_file_caches().await;
                            println!("Cleared file system cache!");
                        }
                        "crc" => {
                            hosts.clear_response_caches().await;
                            println!("Cleared whole response cache.",);
                        }
                        "cc" => {
                            hosts.clear_response_caches().await;
                            hosts.clear_file_caches().await;
                            println!("Cleared all caches!");
                        }
                        _ => {
                            eprintln!("Unknown command!");
                        }
                    }
                }
            };
        }
    }
}
