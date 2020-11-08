use arktis::{Cached::*, Config, ContentType::*, FunctionBindings, *};
use arktis_extensions;
use http::uri::Uri;
use std::io::{prelude::*, stdin};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
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
        println!("Parsed: {:#?}", parse::format_headers(request));

        (Html, Static)
    });
    let server_config = optional_server_config("cert.pem", "private_key.pem");

    let mut ports = Vec::with_capacity(2);
    ports.push((80, ConnectionSecurity::http1()));
    if let Some(config) = server_config {
        ports.push((443, ConnectionSecurity::http1s(config)));
    } else {
        eprintln!("Failed to get certificate! Not running on HTTPS.");
    }
    let mut server = Config::new(bindings, &ports);
    let mut storage = server.clone_storage();
    server.mount_extension(arktis_extensions::php);
    server.mount_extension(arktis_extensions::download);
    server.mount_extension(arktis_extensions::cache);
    server.mount_extension(arktis_extensions::templates);
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
                        match storage.try_response() {
                            Some(mut lock) => {
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
                                match lock.remove(&uri) {
                                    Some(..) => println!("Removed item from cache!"),
                                    None => println!("No item to remove"),
                                };
                            }
                            None => println!("Response cache in use by server!"),
                        }
                    }
                    "cfc" => match storage.try_fs() {
                        Some(mut lock) => {
                            lock.clear();
                            println!("Cleared file system cache!");
                        }
                        None => println!("File system cache in use by server!"),
                    },
                    "crc" => match storage.try_response() {
                        Some(mut lock) => {
                            lock.clear();
                            println!("Cleared response cache!");
                        }
                        None => println!("Response cache in use by server!"),
                    },
                    "cc" => {
                        storage.clear();
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
