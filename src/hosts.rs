use comprash::ClientCachePreference;
use internals::mime;
use kvarn::prelude::*;

/// Bullshittery with some futures not being Sync.
///
/// Use with care.
///
/// It should not break anything, as we are guaranteed (by the runtime) to only run a
/// task on one thread.
///
/// # Examples
///
/// ```no_compile
/// // Notice the binding to a variable and then awaiting it.
/// let future = UnsafeSendSyncFuture::new(resolver.ipv4_lookup(query));
/// let result = future.await;
/// ```
struct UnsafeSendSyncFuture<F>(F);
impl<F> UnsafeSendSyncFuture<F> {
    fn new(future: F) -> UnsafeSendSyncFuture<Pin<Box<F>>> {
        UnsafeSendSyncFuture(Box::pin(future))
    }
}
// That's the point!
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<F> Send for UnsafeSendSyncFuture<F> {}
unsafe impl<F> Sync for UnsafeSendSyncFuture<F> {}
impl<O, F: Future<Output = O> + Unpin> Future for UnsafeSendSyncFuture<F> {
    type Output = O;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        Future::poll(Pin::new(&mut self.0), ctx)
    }
}

pub fn icelk_extensions() -> Extensions {
    // Mount all extensions to server
    let mut extensions = kvarn_extensions::new();

    let resolver_opts = trust_dns_resolver::config::ResolverOpts {
        cache_size: 0,
        validate: false,
        timeout: time::Duration::from_millis(1000),
        ..Default::default()
    };
    let mut resolver_config = trust_dns_resolver::config::ResolverConfig::new();
    resolver_config.add_name_server(trust_dns_resolver::config::NameServerConfig {
        socket_addr: SocketAddr::V4(net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 53)),
        protocol: trust_dns_resolver::config::Protocol::Udp,
        tls_dns_name: None,
        trust_nx_responses: true,
        tls_config: None,
    });
    let resolver = trust_dns_resolver::AsyncResolver::tokio(resolver_config, resolver_opts)
        .expect("Failed to create a resolver");

    extensions.add_prepare_single(
        "/dns/lookup",
        prepare!(req, host, _path, _addr, move |resolver| {
            let queries = utils::parse::query(req.uri().query().unwrap_or(""));
            let body = if let Some(domain) = queries.get("domain") {
                let mut body = Arc::new(Mutex::new(BytesMut::with_capacity(64)));

                macro_rules! append_body {
                    ($result: expr, $kind: expr, $mod_name: ident, $modification: expr) => {{
                        let body = Arc::clone(&body);
                        let future = async move {
                            let mut future = UnsafeSendSyncFuture::new($result);
                            if let Ok(lookup) = future.await {
                                let mut lock = body.lock().await;
                                for $mod_name in lookup.iter() {
                                    let record = $modification;
                                    lock.extend_from_slice(
                                        format!("{} {}\n", $kind, record).as_bytes(),
                                    );
                                }
                            }
                        };
                        future
                    }};
                    ($result: expr, $kind: expr) => {{
                        append_body!($result, $kind, v, v)
                    }};
                }

                let a = append_body!(resolver.ipv4_lookup(domain.value()), "A");
                let aaaa = append_body!(resolver.ipv6_lookup(domain.value()), "AAAA");
                let cname = append_body!(
                    resolver.lookup(
                        domain.value(),
                        trust_dns_resolver::proto::rr::RecordType::CNAME,
                        trust_dns_resolver::proto::xfer::DnsRequestOptions::default()
                    ),
                    "CNAME"
                );
                let mx = append_body!(resolver.mx_lookup(domain.value()), "MX", mx, mx.exchange());
                let txt = append_body!(resolver.txt_lookup(domain.value()), "TXT");

                futures::join!(a, aaaa, cname, mx, txt);

                let body = std::mem::take(Arc::get_mut(&mut body).unwrap());
                body.into_inner().freeze()
            } else {
                return default_error_response(
                    StatusCode::BAD_REQUEST,
                    host,
                    Some("there must be a `domain` key-value pair in the query"),
                )
                .await;
            };

            if body.is_empty() {
                return default_error_response(
                    StatusCode::NOT_FOUND,
                    host,
                    Some("no DNS entry was found"),
                )
                .await;
            }

            FatResponse::no_cache(Response::new(body))
                .with_compress(comprash::CompressPreference::None)
                .with_content_type(&mime::TEXT_PLAIN)
        }),
    );

    extensions.add_prepare_single(
        "/dns/check-dns-over-tls",
        prepare!(req, host, _path, _addr {
                let queries = utils::parse::query(req.uri().query().unwrap_or(""));

                let result = if let (Some(ip), Some(name)) = (queries.get("ip"), queries.get("name")) {
                    let ip = if let Ok(ip) = ip.value().parse() {
                        ip
                    } else {
                        return default_error_response(StatusCode::BAD_REQUEST, host, Some("the value isn't a valid IP address")).await;
                    };

                    let resolver_config = trust_dns_resolver::config::ResolverConfig::from_parts(
                        None,
                        vec![],
                        trust_dns_resolver::config::NameServerConfigGroup::from_ips_tls(
                            &[ip],
                            853,
                            name.value().into(),
                            false,
                        ),
                    );
                    if let Ok(resolver) = trust_dns_resolver::AsyncResolver::tokio(
                        resolver_config,
                        trust_dns_resolver::config::ResolverOpts {
                            timeout: time::Duration::from_secs_f64(2.0),
                            validate: false,
                            ..Default::default()
                        }
                    ) {
                        let query = queries.get("lookup-name").map(utils::parse::QueryPair::value).unwrap_or("icelk.dev.");
                        let future = UnsafeSendSyncFuture::new(resolver.ipv4_lookup(query));
                        let result = future.await;
                        if result.is_ok() {
                            "supported"
                        } else {
                            "unsupported"
                        }
                    } else {
                        return default_error_response(StatusCode::INTERNAL_SERVER_ERROR, host, Some("Creation of resolver failed.")).await;
                    }
                } else {
                    return default_error_response(
                        StatusCode::BAD_REQUEST,
                        host,
                        Some("there must be a `ip` key with a IP address as the value and a `name` with the corresponding host name as the value.\
                             It can have a `query-name` to specify which host name to test the look up with.")
                    )
                    .await;
                };

                FatResponse::no_cache(Response::new(result.into()))
                    .with_compress(comprash::CompressPreference::None)
                    .with_content_type(&mime::TEXT_PLAIN)
        }),
    );
    extensions.add_prepare_single(
        "/ip",
        prepare!(_req, _host, _path, addr {
            FatResponse::no_cache(Response::new(addr.ip().to_string().into()))
                .with_compress(comprash::CompressPreference::None)
                .with_content_type(&mime::TEXT_PLAIN)
        }),
    );

    kvarn_extensions::force_cache(
        &mut extensions,
        &[
            (".png", ClientCachePreference::Changing),
            (".ico", ClientCachePreference::Full),
            (".woff2", ClientCachePreference::Full),
            ("/highlight.js/", ClientCachePreference::Full),
        ],
    );

    let base_csp = CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org"));
    extensions.with_csp(
        Csp::new()
            .add("*", base_csp.clone())
            .add(
                "/index.html",
                base_csp.script_src(CspValueSet::default().unsafe_inline()),
            )
            .add("/api/*", CspRule::new())
            .add("/ip", CspRule::new())
            .arc(),
    );

    extensions
}
pub async fn icelk(extensions: Extensions) -> (Host, kvarn_search::SearchEngineHandle) {
    let mut host = host_from_name("icelk.dev", "../icelk.dev/", extensions);
    host.disable_client_cache().disable_server_cache();

    let se_options = kvarn_search::Options::default();
    let se_handle = kvarn_search::mount_search(&mut host.extensions, "/search", se_options).await;
    se_handle.index_all(&host).await;

    (host, se_handle)
}

pub fn kvarn_extensions() -> Extensions {
    let mut extensions = kvarn_extensions::new();
    kvarn_extensions::force_cache(
        &mut extensions,
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
    extensions.with_cors(kvarn_cors);
    extensions
}
pub fn kvarn(extensions: Extensions) -> Host {
    let mut host = host_from_name("kvarn.org", "../kvarn.org/", extensions);

    host.disable_client_cache().disable_server_cache();

    host
}

pub fn kvarn_doc_extensions() -> Extensions {
    let mut extensions = Extensions::new();

    kvarn_extensions::force_cache(
        &mut extensions,
        &[
            (".html", ClientCachePreference::None),
            (".woff2", ClientCachePreference::Full),
            (".woff", ClientCachePreference::Full),
            (".svg", ClientCachePreference::Changing),
            (".js", ClientCachePreference::Changing),
            (".css", ClientCachePreference::Changing),
        ],
    );

    extensions.add_prepare_single("/index.html".to_owned(), prepare!(_req, _host, _path, _addr {
        let response = Response::builder().status(StatusCode::PERMANENT_REDIRECT).header("location", "kvarn/").body(Bytes::new()).expect("we know this is ok.");
        FatResponse::cache(response)
    }));

    extensions.with_csp(
        Csp::new()
            .add(
                "*",
                CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org")),
            )
            .arc(),
    );
    extensions
}
pub fn kvarn_doc(extensions: Extensions) -> Host {
    let mut host = host_from_name("doc.kvarn.org", "../kvarn/target/doc/", extensions);

    host.options.set_public_data_dir(".");
    host.disable_server_cache().disable_client_cache();

    host
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

pub fn icelk_bitwarden_extensions() -> Extensions {
    let mut extensions = Extensions::empty();
    let rev_proxy = kvarn_extensions::ReverseProxy::base(
        "/",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(8000),
        )),
        time::Duration::from_secs(15),
    );
    rev_proxy.mount(&mut extensions);
    kvarn_extensions::force_cache(
        &mut extensions,
        &[
            (".html", ClientCachePreference::Changing),
            (".woff2", ClientCachePreference::Full),
            (".woff", ClientCachePreference::Full),
            (".png", ClientCachePreference::Full),
            (".svg", ClientCachePreference::Changing),
            (".js", ClientCachePreference::Changing),
            (".css", ClientCachePreference::Changing),
        ],
    );

    extensions.add_prepare_fn(
        Box::new(|req, _| req.uri().path().starts_with("/.well-known")),
        prepare!(req, host, _path, _addr {
            let path = format!("/usr/share/webapps/vaultwarden-web{}", req.uri().path());
            let file = read::file(&path, host.file_cache.as_ref()).await;
            let file = if let Some(f) = file {
                f
            } else {
                return default_error_response(StatusCode::NOT_FOUND, host, None).await;
            };
            FatResponse::no_cache(Response::new(file))
        }),
        Id::new(1000, "override Let's Encrypt path"),
    );

    extensions.with_csp(Csp::new().arc());

    extensions
}
pub fn icelk_bitwarden(extensions: Extensions) -> Host {
    let mut host = host_from_name(
        "bitwarden.icelk.dev",
        "/usr/share/webapps/vaultwarden-web",
        extensions,
    );
    host.disable_server_cache().disable_client_cache();
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
