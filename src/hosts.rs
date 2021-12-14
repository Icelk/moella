use comprash::ClientCachePreference;
use kvarn::prelude::*;

pub fn icelk_extensions() -> Extensions {
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
            FatResponse::new(Response::new(body), comprash::ServerCachePreference::None)
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

    icelk_extensions.with_csp(
        Csp::new()
            .add(
                "*",
                CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org")),
            )
            .arc(),
    );

    icelk_extensions
}

pub fn icelk(extensions: Extensions) -> Host {
    let mut icelk_host = host_from_name("icelk.dev", "../icelk.dev/", extensions);
    icelk_host.disable_client_cache().disable_server_cache();
    icelk_host
}
pub fn kvarn_extensions() -> Extensions {
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
    kvarn_extensions.with_cors(kvarn_cors);
    kvarn_extensions
}
pub fn kvarn(extensions: Extensions) -> Host {
    let mut kvarn_host = host_from_name("kvarn.org", "../kvarn.org/", extensions);

    kvarn_host.disable_client_cache().disable_server_cache();

    kvarn_host
}

pub fn kvarn_doc_extensions() -> Extensions {
    let mut kvarn_doc_extensions = Extensions::new();

    kvarn_extensions::force_cache(
        &mut kvarn_doc_extensions,
        &[
            (".html", ClientCachePreference::None),
            (".woff2", ClientCachePreference::Full),
            (".woff", ClientCachePreference::Full),
            (".svg", ClientCachePreference::Changing),
            (".js", ClientCachePreference::Changing),
            (".css", ClientCachePreference::Changing),
        ],
    );

    kvarn_doc_extensions.add_prepare_single("/index.html".to_owned(), prepare!(_req, _host, _path, _addr {
        let response = Response::builder().status(StatusCode::PERMANENT_REDIRECT).header("location", "kvarn/").body(Bytes::new()).expect("we know this is ok.");
        FatResponse::cache(response)
    }));

    kvarn_doc_extensions.with_csp(
        Csp::new()
            .add(
                "*",
                CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org")),
            )
            .arc(),
    );
    kvarn_doc_extensions
}
pub fn kvarn_doc(extensions: Extensions) -> Host {
    let mut kvarn_doc_host = host_from_name("doc.kvarn.org", "../kvarn/target/doc/", extensions);

    kvarn_doc_host.options.set_public_data_dir(".");
    kvarn_doc_host.disable_server_cache().disable_client_cache();

    kvarn_doc_host
}
pub fn agde(mut extensions: Extensions) -> Host {
    extensions.add_prepare_fn(
        Box::new(|_, _| true),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", "https://github.com/Icelk/agde/")
                    .body(Bytes::new()).unwrap())
                    .with_server_cache(comprash::ServerCachePreference::Full)
        }
        ),
        Id::new(0, "redirect to GitHub"),
    );

    let mut host = host_from_name("agde.dev", "../agde.dev/", extensions);

    host.disable_client_cache().disable_server_cache();

    host
}

fn host_from_name(name: &'static str, path: impl AsRef<Path>, extensions: Extensions) -> Host {
    #[cfg(feature = "https")]
    {
        let mut iter = name.split('.').rev();
        iter.next();
        let cert_base = utils::join(iter.rev(), ".");
        Host::http_redirect_or_unsecure(
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
