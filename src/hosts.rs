use comprash::ClientCachePreference;
use internals::mime;
use kvarn::prelude::bytes::BufMut;
use kvarn::prelude::*;
use kvarn::websocket::{SinkExt, StreamExt};

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

pub async fn icelk_extensions() -> Extensions {
    // Mount all extensions to server
    let mut extensions = kvarn_extensions::new();

    let resolver_opts = trust_dns_resolver::config::ResolverOpts {
        cache_size: 0,
        validate: false,
        timeout: Duration::from_millis(1000),
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
        prepare!(
            req,
            host,
            _path,
            _addr,
            move |resolver: trust_dns_resolver::TokioAsyncResolver| {
                let queries = utils::parse::query(req.uri().query().unwrap_or(""));
                let body = if let Some(domain) = queries.get("domain") {
                    let mut body = Arc::new(Mutex::new(BytesMut::with_capacity(64)));

                    macro_rules! append_body {
                        ($result: expr, $kind: expr, $mod_name: ident, $modification: expr) => {{
                            let body = Arc::clone(&body);
                            let future = async move {
                                let future = UnsafeSendSyncFuture::new($result);
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
                    let mx =
                        append_body!(resolver.mx_lookup(domain.value()), "MX", mx, mx.exchange());
                    let txt = append_body!(resolver.txt_lookup(domain.value()), "TXT");

                    futures_util::join!(a, aaaa, cname, mx, txt);

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
            }
        ),
    );

    extensions.add_prepare_single(
        "/dns/check-dns-over-tls",
        prepare!(req, host, _, _, {
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
                            timeout: Duration::from_secs_f64(2.0),
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
        prepare!(_req, _, _, addr, {
            FatResponse::no_cache(Response::new(addr.ip().to_string().into()))
                .with_compress(comprash::CompressPreference::None)
                .with_content_type(&mime::TEXT_PLAIN)
        }),
    );
    extensions.add_prepare_single(
        "/ws-ping",
        prepare!(req, host, _path, _addr, {
            kvarn::websocket::response(
                req,
                host,
                response_pipe_fut!(response_pipe, _host, {
                    let mut ws = kvarn::websocket::wrap(response_pipe).await;
                    while let Some(Ok(message)) = ws.next().await {
                        let _ = ws.send(message).await;
                    }
                }),
            )
            .await
        }),
    );

    // if you have ulogger installed...
    if tokio::fs::metadata("../ulogger")
        .await
        .map_or(false, |meta| meta.is_dir())
    {
        kvarn_extensions::php::mount_php_with_working_directory(
            &mut extensions,
            kvarn_extensions::Connection::UnixSocket(Path::new("/run/ulogger.sock")),
            "/ulogger/",
            "../ulogger",
        )
        .await
        // UNWRAP: we just checked if it existed
        .unwrap();
    }

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
        Csp::empty()
            .add("*", base_csp.clone())
            .add(
                "/index.html",
                base_csp.script_src(CspValueSet::default().unsafe_inline()),
            )
            .add("/api/*", CspRule::empty())
            .add("/ip", CspRule::empty())
            .add(
                "/ulogger/*",
                CspRule::default()
                    .default_src(
                        CspValueSet::default()
                            .uri("https://maps.googleapis.com")
                            .uri("https://maps.gstatic.com"),
                    )
                    .img_src(
                        CspValueSet::default()
                            .uri("https://*.openstreetmap.org")
                            .uri("https://maps.googleapis.com")
                            .uri("https://maps.gstatic.com")
                            .scheme("data:"),
                    )
                    .script_src(CspValueSet::default().uri("https://maps.googleapis.com")),
            )
            .add(
                "/admin",
                CspRule::default().default_src(CspValueSet::default().unsafe_inline()),
            )
            .add("/organization-game/*", CspRule::empty())
            .add(
                "/quizlet-learn/login.html",
                CspRule::default().script_src(CspValueSet::default().unsafe_inline()),
            )
            .arc(),
    );

    let mut private_ical = kvarn_extensions::ReverseProxy::base(
        "/private-ical/",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(5232),
        )),
        Duration::from_secs(10),
    );
    private_ical = private_ical
        .add_modify_fn(Arc::new(|request, _bytes, _addr| {
            request
                .headers_mut()
                .insert("x-script-name", HeaderValue::from_static("/private-ical"));
        }))
        .add_modify_fn(Arc::new(|req, _, _| {
            if let Some(path) = req.uri().path().strip_suffix("/index.html") {
                let mut parts = req.uri().clone().into_parts();
                let pq = format!(
                    "{path}/{}",
                    parts
                        .path_and_query
                        .as_ref()
                        .map_or("", |pq| pq.query().unwrap_or(""))
                );
                let pq = uri::PathAndQuery::from_maybe_shared(pq.into_bytes()).unwrap();
                parts.path_and_query = Some(pq);
                *req.uri_mut() = Uri::from_parts(parts).unwrap();
            }
        }));
    private_ical.mount(&mut extensions);

    let auth_test_secret = tokio::fs::read("auth-test.secret").await;
    let auth_passwd_file = tokio::fs::read_to_string("auth-test.passwd").await;
    if let (Ok(auth_test_secret), Ok(auth_passwd_file)) = (auth_test_secret, auth_passwd_file) {
        let auth_config = kvarn_auth::Builder::new()
            .with_auth_page_name("/admin/auth")
            .with_cookie_path("/admin")
            .build::<(), _, _>(
                move |user, password, _addr, _req| {
                    let v = if user == "admin"
                        && auth_passwd_file.lines().any(|line| line == password)
                    {
                        kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::None)
                    } else {
                        kvarn_auth::Validation::Unauthorized
                    };
                    core::future::ready(v)
                },
                kvarn_auth::CryptoAlgo::EcdsaP256 {
                    secret: auth_test_secret,
                },
            );
        auth_config.mount(&mut extensions);
        let login_status = auth_config.login_status();
        extensions.add_prepare_single(
            "/admin",
            prepare!(
                req,
                _host,
                _path,
                addr,
                move |login_status: kvarn_auth::LoginStatusClosure<()>| {
                    let status = login_status(req, addr);
                    let response = if let kvarn_auth::Validation::Authorized(_) = status {
                        Response::builder()
                            .header("content-type", "text/plain")
                            .body(Bytes::from_static(
                                "Congratulations, you cracked the login!\n\
                            Please contact <main@icelk.dev> \
                            for public recognition of your performance."
                                    .as_bytes(),
                            ))
                            .unwrap()
                    } else {
                        static LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html>
    <head>
        <meta name="color-scheme" content="dark light">
    </head>
    <body>
        <input id="username" placeholder="Username" />
        <input id="password" placeholder="Password" />
        <button id="login">Log in</button>
        <script>
            let username = document.getElementById("username")
            let password = document.getElementById("password")
            let login = document.getElementById("login")
            login.addEventListener("click", async () => {
                let u = username.value
                let p = password.value
                let response = await fetch("/admin/auth",
                    { method: "PUT", body: `${u.length}\n${u}${p}` })
                if (response.status === 200) {
                    location.reload()
                }
            })
        </script>
    </body>
</html>
"#;

                        Response::new(Bytes::from_static(LOGIN_HTML.as_bytes()))
                    };
                    FatResponse::no_cache(response)
                }
            ),
        );
    }

    let aog_secret = tokio::fs::read("aog.secret").await;
    let aog_passwd_file = tokio::fs::read_to_string("aog.passwd").await;
    if let (Ok(aog_secret), Ok(aog_passwd_file)) = (aog_secret, aog_passwd_file) {
        let accounts: HashMap<String, String> = aog_passwd_file
            .lines()
            .filter_map(|line| {
                let (usr, pas) = line.split_once(' ')?;
                Some((usr.to_owned(), pas.to_owned()))
            })
            .collect();
        let auth_config = kvarn_auth::Builder::new()
            .with_cookie_path("/organization-game/")
            .with_auth_page_name("/organization-game/auth")
            .with_show_auth_page_when_unauthorized("/organization-game/login")
            .build::<(), _, _>(
                move |user, password, _addr, _req| {
                    let v = if accounts.get(user).map_or(false, |pass| pass == password) {
                        kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::None)
                    } else {
                        kvarn_auth::Validation::Unauthorized
                    };
                    core::future::ready(v)
                },
                kvarn_auth::CryptoAlgo::EcdsaP256 { secret: aog_secret },
            );
        auth_config.mount(&mut extensions);
        let login_status = auth_config.login_status();
        extensions.add_prepare_single(
            "/organization-game/login",
            prepare!(
                req,
                _host,
                _path,
                addr,
                move |login_status: kvarn_auth::LoginStatusClosure<()>| {
                    let status = login_status(req, addr);
                    let response = if let kvarn_auth::Validation::Authorized(_) = status {
                        Response::builder()
                            .header("content-type", "text/plain")
                            .body(Bytes::from_static("You are now logged in.".as_bytes()))
                            .unwrap()
                    } else {
                        static LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html>
    <head>
        <meta name="color-scheme" content="dark light">
    </head>
    <body>
        <input id="username" placeholder="Username" />
        <input id="password" placeholder="Password" />
        <button id="login">Log in</button>
        <script>
            let username = document.getElementById("username")
            let password = document.getElementById("password")
            let login = document.getElementById("login")
            login.addEventListener("click", async () => {
                let u = username.value
                let p = password.value
                let response = await fetch("/organization-game/auth",
                    { method: "PUT", body: `${u.length}\n${u}${p}` })
                if (response.status === 200) {
                    location.reload()
                }
            })
        </script>
    </body>
</html>
"#;

                        Response::new(Bytes::from_static(LOGIN_HTML.as_bytes()))
                    };
                    FatResponse::no_cache(response)
                }
            ),
        );
        kvarn_extensions::ReverseProxy::base(
            "/organization-game/",
            kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
                kvarn_extensions::localhost(4040),
            )),
            Duration::from_secs(10),
        )
        .mount(&mut extensions);
    }

    let quizlet_secret = tokio::fs::read("quizlet-learn.secret").await;
    let quizlet_passwd_file = tokio::fs::read_to_string("quizlet-learn.passwd").await;
    if let (Ok(quizlet_secret), Ok(quizlet_passwd_file)) = (quizlet_secret, quizlet_passwd_file) {
        let accounts: HashMap<String, String> = quizlet_passwd_file
            .lines()
            .filter_map(|line| {
                let (usr, pas) = line.split_once(' ')?;
                Some((usr.to_owned(), pas.to_owned()))
            })
            .collect();
        let auth_config = kvarn_auth::Builder::new()
            .with_auth_page_name("/quizlet-learn/auth")
            .with_cookie_path("/quizlet-learn/")
            .with_show_auth_page_when_unauthorized("/quizlet-learn/login.")
            .build::<(), _, _>(
                move |user, password, _addr, _req| {
                    let v = if accounts.get(user).map_or(false, |pass| pass == password) {
                        kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::None)
                    } else {
                        kvarn_auth::Validation::Unauthorized
                    };
                    core::future::ready(v)
                },
                kvarn_auth::CryptoAlgo::EcdsaP256 {
                    secret: quizlet_secret,
                },
            );
        auth_config.mount(&mut extensions);
        let login_status = auth_config.login_status();
        let client = reqwest::Client::new();
        extensions.add_prepare_single(
            "/quizlet-learn/words",
            prepare!(
                req,
                host,
                _path,
                addr,
                move |login_status: kvarn_auth::LoginStatusClosure<()>, client: reqwest::Client| {
                    let status = login_status(req, addr);
                    let response = if let kvarn_auth::Validation::Authorized(_) = status {
                        if let Some(uri) =
                            utils::parse::query(req.uri().query().unwrap_or("")).get("quizlet")
                        {
                            let uri = reqwest::Url::parse(uri.value()).ok().and_then(|uri| {
                                if uri.domain().map_or(false, |domain| domain != "quizlet.com") {
                                    None
                                } else {
                                    Some(uri)
                                }
                            });
                            if let Some(uri) = uri {
                                let mut request = reqwest::Request::new(reqwest::Method::GET, uri);
                                // bypass bot filter xD
                                request.headers_mut().insert(
                                    "user-agent",
                                    HeaderValue::from_static(
                                        "Mozilla/5.0 (Windows NT 10.0; rv:91.0) \
                                        Gecko/20100101 Firefox/91.0",
                                    ),
                                );
                                let body = if let Ok(response) = client.execute(request).await {
                                    response.text().await.ok()
                                } else {
                                    None
                                };
                                let body = if let Some(body) = body {
                                    body
                                } else {
                                    return default_error_response(
                                        StatusCode::BAD_GATEWAY,
                                        host,
                                        None,
                                    )
                                    .await;
                                };

                                let document = select::document::Document::from(body.as_str());
                                let elements = document
                                    .find(select::predicate::Class("SetPageTerm-contentWrapper"));

                                let mut bytes = BytesMut::new();
                                for node in elements {
                                    let (l1, l2) = if let Some(l) =
                                        node.children().next().and_then(|child| {
                                            let mut c = child.children();
                                            Some((c.next()?, c.next()?))
                                        }) {
                                        l
                                    } else {
                                        continue;
                                    };
                                    bytes.extend_from_slice(l1.text().as_bytes());
                                    bytes.put_u8(b'\n');
                                    bytes.extend_from_slice(l2.text().as_bytes());
                                    bytes.put_u8(b'\n');
                                }

                                Response::new(bytes.freeze())
                                // fetch
                            } else {
                                return default_error_response(
                                    StatusCode::BAD_REQUEST,
                                    host,
                                    Some(
                                        "the quizlet query parameter \
                                        couldn't be converted into an URI.",
                                    ),
                                )
                                .await;
                            }
                        } else {
                            return default_error_response(
                                StatusCode::BAD_REQUEST,
                                host,
                                Some("the quizlet query parameter is required"),
                            )
                            .await;
                        }
                    } else {
                        return default_error_response(StatusCode::UNAUTHORIZED, host, None).await;
                    };
                    FatResponse::no_cache(response).with_content_type(&internals::mime::TEXT_PLAIN)
                }
            ),
        );
    }

    extensions
}
pub async fn icelk(extensions: Extensions) -> (Host, kvarn_search::SearchEngineHandle) {
    let mut host = host_from_name("icelk.dev", "../icelk.dev/", extensions);
    host.disable_client_cache().disable_server_cache();

    let se_options = kvarn_search::Options {
        kind: kvarn_search::IndexKind::Lossless,
        ignore_paths: vec![Uri::from_static("/rsync-ignore")],
        ..Default::default()
    };
    let se_handle = kvarn_search::mount_search(&mut host.extensions, "/search", se_options).await;
    se_handle.index_all(&host).await;

    (host, se_handle)
}

pub fn icelk_doc_extensions() -> Extensions {
    let mut extensions = Extensions::new();

    extensions.add_present_internal("tmpl", Box::new(kvarn_extensions::templates_ext));

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

    extensions.with_csp(
        Csp::empty()
            .add(
                "*",
                CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org")),
            )
            .arc(),
    );
    extensions
}
pub fn icelk_doc(extensions: Extensions) -> Host {
    let mut host = host_from_name("doc.icelk.dev", "../icelk.dev/doc/", extensions);

    host.disable_server_cache().disable_client_cache();

    host
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

    let kvarn_cors = Cors::empty()
        .add(
            "/logo.svg",
            CorsAllowList::new(Duration::from_secs(60 * 60 * 24 * 14))
                .add_origin("https://github.com")
                .add_origin("https://doc.kvarn.org"),
        )
        .add(
            "/favicon.svg",
            CorsAllowList::new(Duration::from_secs(60 * 60 * 24 * 14))
                .add_origin("https://doc.kvarn.org"),
        )
        .arc();
    extensions.with_cors(kvarn_cors);
    extensions
}
pub async fn kvarn(extensions: Extensions) -> (Host, kvarn_search::SearchEngineHandle) {
    let mut host = host_from_name("kvarn.org", "../kvarn.org/", extensions);

    host.disable_client_cache().disable_server_cache();

    let se_options = kvarn_search::Options {
        kind: kvarn_search::IndexKind::Lossless,
        ..Default::default()
    };
    let se_handle = kvarn_search::mount_search(&mut host.extensions, "/search", se_options).await;
    se_handle.index_all(&host).await;

    (host, se_handle)
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

    extensions.add_prepare_single(
        "/index.html",
        prepare!(_, _, _, _, {
            let response = Response::builder()
                .status(StatusCode::PERMANENT_REDIRECT)
                .header("location", "kvarn/")
                .body(Bytes::new())
                .expect("we know this is ok.");
            FatResponse::cache(response)
        }),
    );

    extensions.with_csp(
        Csp::empty()
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

async fn handle_ws<
    S: futures_util::Stream<
            Item = agde_tokio::tungstenite::Result<agde_tokio::tungstenite::Message>,
        > + futures_util::Sink<agde_tokio::tungstenite::Message>
        + futures_util::stream::FusedStream
        + Unpin,
>(
    ws_broadcaster: &mut tokio::sync::broadcast::Sender<
        Arc<(Vec<u8>, agde::Uuid, agde::Recipient)>,
    >,
    mut ws: S,
    addr: SocketAddr,
) {
    use futures_util::FutureExt;
    let mut listener = ws_broadcaster.subscribe();
    let mut uuid = None;
    let mut disconnected = false;

    #[allow(unused_assignments)] // invalid lint, the disconnected = true
    // assignments are valid
    loop {
        futures_util::select! {
            msg = listener.recv().fuse() => {
                let msg = msg.expect("ws broadcast got backlogged or unexpectedly closed");
                let (msg, sender, recipient) = &*msg;
                let recipient_matches= *recipient == agde::Recipient::All
                    || if let agde::Recipient::Selected(pier) = recipient {
                        uuid.map_or(false, |uuid| pier.uuid() == uuid)
                    } else {
                        false
                    };

                // don't ping pong message!
                if Some(*sender) == uuid || !recipient_matches {
                    continue;
                }
                let data = (*msg).clone();
                let msg = websocket::tungstenite::Message::Binary(data);
                if ws.send(msg).await.is_err() {
                    if !disconnected {
                        if let Some(uuid) = uuid {
                            ws_broadcaster.send(
                                Arc::new((
                                    agde_tokio::agde_io::to_compressed_bin(&agde::Message::new(
                                        agde::MessageKind::Disconnect,
                                        uuid,
                                        agde::Uuid::new()
                                    )),
                                    uuid,
                                    agde::Recipient::All,
                                ))
                            ).unwrap();
                        }
                        disconnected = true;
                    }
                    break;
                }
            },
            incomming = ws.next() => {
                let incomming = if let Some(Ok(msg)) = incomming {
                    msg
                } else {
                    if !disconnected {
                        if let Some(uuid) = uuid {
                            ws_broadcaster.send(
                                Arc::new((
                                    agde_tokio::agde_io::to_compressed_bin(&agde::Message::new(
                                        agde::MessageKind::Disconnect,
                                        uuid,
                                        agde::Uuid::new()
                                    )),
                                    uuid,
                                    agde::Recipient::All,
                                ))
                            ).unwrap();
                        }
                        disconnected = true;
                    }
                    break;
                };
                let msg = match incomming {
                    websocket::tungstenite::Message::Binary(msg) => msg,
                    websocket::tungstenite::Message::Text(text) => {
                        info!("Agde pier with UUID {uuid:?} send a text message: {text}");
                        continue;
                    }
                    _ => continue,
                };
                // `TODO` change agde protocol to add magic number to Bin
                // format, add version, recipient, sender, and if
                // dsconnecting.
                let agde_msg = if let Ok(msg) = agde_tokio::agde_io::from_compressed_bin(&msg) {
                    msg
                } else {
                    warn!("Received invalid message from UUID {uuid:?} from {addr}");
                    continue;
                };
                if let agde::MessageKind::Hello(cap) = agde_msg.inner() {
                    uuid = Some(cap.uuid());
                }
                if let agde::MessageKind::Disconnect = agde_msg.inner() {
                    disconnected = true;
                }
                if let Some(uuid) = uuid {
                    ws_broadcaster.send(Arc::new((msg, uuid, agde_msg.recipient()))).unwrap();
                }
            }
        };
    }
}

pub async fn agde(
    mut extensions: Extensions,
) -> (
    Host,
    Arc<std::sync::Mutex<Option<agde_tokio::agde_io::StateHandle<agde_tokio::Native>>>>,
) {
    extensions.add_prepare_single(
        "/index.html",
        prepare!(_, _, _, _, {
            FatResponse::no_cache(
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", "https://github.com/Icelk/agde/")
                    .body(Bytes::new())
                    .unwrap(),
            )
            .with_server_cache(comprash::ServerCachePreference::Full)
        }),
    );

    let secret = tokio::fs::read("agde.secret").await.expect(
        "please provide an agde.secret file with a strong secret (preferably 1024-bit entropy)",
    );
    let passwd_file = tokio::fs::read_to_string("agde.passwd").await.expect(
        "please provide an agde.passwd file with users and their passwords \
        (space separated, one account per line)",
    );
    let accounts: HashMap<String, String> = passwd_file
        .lines()
        .filter_map(|line| {
            let (usr, pas) = line.split_once(' ')?;
            Some((usr.to_owned(), pas.to_owned()))
        })
        .collect();
    let auth_config = kvarn_auth::Builder::new()
        .with_cookie_path("/demo/")
        .with_auth_page_name("/demo/auth")
        .with_show_auth_page_when_unauthorized("/demo/login.")
        .build::<(), _, _>(
            move |user, password, _addr, _req| {
                let v = if accounts.get(user).map_or(false, |pass| pass == password) {
                    kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::None)
                } else {
                    kvarn_auth::Validation::Unauthorized
                };
                core::future::ready(v)
            },
            kvarn_auth::CryptoAlgo::EcdsaP256 { secret },
        );
    auth_config.mount(&mut extensions);
    let login_status = auth_config.login_status();

    let agde_handle = Arc::new(std::sync::Mutex::new(None));
    let agde_moved_handle = agde_handle.clone();
    let (dx1, dx2) = tokio::io::duplex(1024 * 64);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let options =
            agde_tokio::options_fs(true, agde_tokio::Compression::Zstd, "agde-data".into())
                .await
                .expect("failed to read file system metadata");
        let options = options
            .with_startup_duration(Duration::from_secs(0))
            .with_sync_interval(Duration::from_secs(30))
            .with_periodic_interval(Duration::from_secs(120))
            .with_no_public_storage();

        let options = options.arc();

        let log_lifetime = Duration::from_secs(60);

        let manager = agde_tokio::agde::Manager::new(true, 0, log_lifetime, 512);

        match agde_tokio::agde_io::run(
            manager,
            options,
            move || async move {
                let connection = agde_tokio::tokio_tungstenite::WebSocketStream::from_raw_socket(
                    dx1,
                    agde_tokio::tungstenite::protocol::Role::Client,
                    None,
                )
                .await;
                let (w, r) = agde_tokio::Io::Duplex(connection).split();
                Ok(agde_tokio::Native(
                    Arc::new(futures_util::lock::Mutex::new(agde_tokio::WriteHalf(w))),
                    Arc::new(futures_util::lock::Mutex::new(agde_tokio::ReadHalf(r))),
                ))
            },
            |_msg| {},
            || {},
        )
        .await
        {
            Ok(handle) => {
                {
                    *agde_moved_handle.lock().unwrap() = Some(handle.state().clone());
                }
                agde_tokio::catch_ctrlc(handle.state().clone()).await;

                let r = handle.wait().await;

                if let Err(err) = r {
                    error!("agde: Got error when running: {err}. Trying to reconnect in 1s.");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                } else {
                    info!("agde-tokio considers itself done.")
                }
            }
            Err(err) => {
                error!("Got error: {err}. Agde will not function from now on.");
            }
        }
    });
    let (ws_broadcaster, _) = tokio::sync::broadcast::channel(1024);
    {
        let mut ws_broadcaster = ws_broadcaster.clone();
        tokio::spawn(async move {
            let connection = agde_tokio::tokio_tungstenite::WebSocketStream::from_raw_socket(
                dx2,
                agde_tokio::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            handle_ws(
                &mut ws_broadcaster,
                connection,
                SocketAddr::new(IpAddr::V6(net::Ipv6Addr::LOCALHOST), 0),
            )
            .await;
        });
    }
    extensions.add_prepare_single(
        "/demo/ws",
        prepare!(
            req,
            host,
            _path,
            addr,
            move |ws_broadcaster: tokio::sync::broadcast::Sender<
                Arc<(Vec<u8>, agde::Uuid, agde::Recipient)>,
            >,
                  login_status: kvarn_auth::LoginStatusClosure<()>| {
                if matches!(
                    login_status(req, addr),
                    kvarn_auth::Validation::Unauthorized
                ) {
                    return default_error_response(
                        StatusCode::UNAUTHORIZED,
                        host,
                        Some("log in at `/demo/login.html`"),
                    )
                    .await;
                }

                let ws_broadcaster = ws_broadcaster.clone();
                websocket::response(
                    req,
                    host,
                    response_pipe_fut!(
                        pipe,
                        _host,
                        move |ws_broadcaster: tokio::sync::broadcast::Sender<
                            Arc<(Vec<u8>, agde::Uuid, agde::Recipient)>,
                        >,
                              addr: SocketAddr| {
                            let ws = websocket::wrap(pipe).await;
                            handle_ws(ws_broadcaster, ws, *addr).await;
                        }
                    ),
                )
                .await
            }
        ),
    );

    extensions.with_csp(
        Csp::default()
            .add(
                "/demo/worker.js",
                CspRule::default()
                    .script_src(CspValueSet::default().unsafe_eval())
                    .connect_src(CspValueSet::default().scheme("wss:")),
            )
            .add(
                "/demo/login.html",
                CspRule::default().script_src(CspValueSet::default().unsafe_inline()),
            )
            .arc(),
    );

    let mut host = host_from_name("agde.dev", "../agde.dev/", extensions);

    host.disable_client_cache().disable_server_cache();

    (host, agde_handle)
}

pub fn icelk_bitwarden_extensions() -> Extensions {
    let mut extensions = Extensions::empty();
    let ws_rev_proxy = kvarn_extensions::ReverseProxy::base(
        "/notifications/hub",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(3012),
        )),
        Duration::from_secs(15),
    )
    .with_priority(-120);
    let rev_proxy = kvarn_extensions::ReverseProxy::base(
        "/",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(8000),
        )),
        Duration::from_secs(15),
    )
    .with_x_real_ip();
    rev_proxy.mount(&mut extensions);
    ws_rev_proxy.mount(&mut extensions);
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
        prepare!(req, host, _, _, {
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

    // Disable, to let reverse proxies' CSP through.
    extensions.with_csp(Csp::empty().arc());

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

pub fn mail_hosts(file: impl AsRef<Path>) -> Vec<Host> {
    let file = match std::fs::read(file.as_ref()) {
        Ok(f) => f,
        Err(err) => {
            warn!(
                "Failed to read mail hosts file '{}': {}",
                file.as_ref().display(),
                err
            );
            return Vec::new();
        }
    };

    let file = String::from_utf8_lossy(&file);
    file.lines()
        .filter_map(|domain| {
            let domain = domain.trim();
            if domain.is_empty() {
                None
            } else {
                info!("Setting up host '{domain}'.");
                Some(Host::unsecure(
                    domain,
                    "mail",
                    Extensions::default(),
                    host::Options::default(),
                ))
            }
        })
        .collect()
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
            path.as_ref(),
            extensions,
            host::Options::default(),
        )
    }
    #[cfg(not(feature = "https"))]
    {
        Host::non_secure(name, path.as_ref(), extensions, host::Options::default())
    }
}
