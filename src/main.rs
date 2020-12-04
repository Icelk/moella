use http::uri::Uri;
use kvarn::prelude::{threading::*, *};
use kvarn_extensions;
use std::io::{prelude::*, stdin};

fn main() {
    // let mut vec = vec![];
    // vec.extend(kvarn::limiting::TOO_MANY_REQUESTS);
    // println!(
    //     "Len: {}",
    //     kvarn::cache::ByteResponse::with_header(vec)
    //         .get_body()
    //         .len()
    // );

    let mut bindings = FunctionBindings::new();
    let times_called = Arc::new(Mutex::new(0));
    bindings.bind_page("/test", move |buffer, request, _| {
        let mut tc = times_called.lock().unwrap();
        *tc += 1;

        buffer.extend(
            format!(
                "<h1>Welcome to my site!</h1> You are calling: {} For the {} time.",
                request.uri(),
                &tc
            )
            .as_bytes(),
        );

        (Html, Dynamic)
    });
    bindings.bind_page("/throw_500", |mut buffer, _, storage| {
        write_error(&mut buffer, 500, storage)
    });
    bindings.bind_dir("/capturing", |buffer, request, _| {
        buffer.extend(
            &b"!> tmpl standard\n\
            [head]\
            [dependencies]\
            [close-head]\
            [navbar]\
            <main style='text-align: center;'><h1>You are visiting: '"[..],
        );
        buffer.extend(request.uri().path().as_bytes());
        buffer.extend(
            &b"'.</h1>Well, hope you enjoy <a href=\"/\">my site</a>!</main>\
            [footer]"[..],
        );

        (Html, Static)
    });

    // The *_cert.pem files are cert1.pem files when using Certbot.

    let icelk_host = match Host::new(
        "icelk_cert.pem",
        "icelk_pk.pem",
        "icelk.dev",
        Some(bindings),
    ) {
        Ok(host) => host,
        Err((err, host_without_cert)) => {
            eprintln!(
                "Failed to get certificate! Not running icelk.dev on HTTPS. {:?}",
                err
            );
            host_without_cert
        }
    };
    let kvarn_host = match Host::new("kvarn_cert.pem", "kvarn_pk.pem", "kvarn.org", None) {
        Ok(host) => host,
        Err((err, host_without_cert)) => {
            eprintln!(
                "Failed to get certificate! Not running arktis.org on HTTPS. {:?}",
                err
            );
            host_without_cert
        }
    };

    let hosts = HostData::builder(icelk_host)
        .add_host("kvarn.org".to_string(), kvarn_host)
        .build();

    let mut ports = Vec::with_capacity(2);
    ports.push((80, ConnectionSecurity::http1(), Arc::clone(&hosts)));
    if hosts.has_secure() {
        let config = Arc::new(HostData::make_config(&hosts));
        ports.push((443, ConnectionSecurity::http1s(config), Arc::clone(&hosts)));
    }
    let mut server = Config::new(ports);
    let mut storage = server.clone_storage();
    kvarn_extensions::mount_all(&mut server);
    thread::spawn(move || server.run());

    // Commands in console
    for line in stdin().lock().lines() {
        if let Ok(line) = line {
            let mut words = line.split(" ");
            if let Some(command) = words.next() {
                match command {
                    "fcc" => {
                        // File cache clear
                        match storage.try_fs() {
                            Some(mut lock) => {
                                let path = PathBuf::from(words.next().unwrap_or(&""));
                                match lock.remove(&path) {
                                    Some(..) => println!("Removed item from cache!"),
                                    None => println!("No item to remove"),
                                };
                            }
                            None => println!("File system cache in use by server!"),
                        }
                    }
                    "rcc" => {
                        // Responds cache clear
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
                        let (cleared, found) = hosts.clear_page(host, &uri);

                        if !found {
                            println!("Did not found host to remove cached item from. Use 'default' or an empty string (e.g. '') for the default host.");
                        } else {
                            if cleared == 0 {
                                println!("Did not remove any cached response.");
                            } else {
                                println!("Cleared a cached response.");
                            }
                        }
                    }
                    "cfc" => match storage.try_fs() {
                        Some(mut lock) => {
                            lock.clear();
                            println!("Cleared file system cache!");
                        }
                        None => println!("File system cache in use by server!"),
                    },
                    "crc" => {
                        let cleared = hosts.clear_all_caches();
                        if cleared == 0 {
                            println!("Did not clear any response cache.");
                        } else {
                            println!(
                                "Cleared {} response cache{}.",
                                cleared,
                                if cleared == 0 { "" } else { "s" }
                            );
                        }
                    }
                    "cc" => {
                        storage.clear();
                        hosts.clear_all_caches();
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
