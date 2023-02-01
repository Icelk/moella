use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{CustomExtensions, Result};
use serde::{Deserialize, Serialize};

pub use kvarn_auth;
pub use kvarn_extensions;
pub use kvarn_search;

/// The available extensions.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Extension {
    If {
        predicate: Predicate,
        extension: Box<Extension>,
    },

    NoDefaults,
    Referrer(Option<String>),
    RedirectIndexHtml,
    RedirectHttpToHttps,
    Nonce,
    Redirect(Filter, String),

    /// kvarn_extension defaults too
    AllDefaults,
    Templates,
    Http2Push {
        push_interval: f64,
        check_every_request: u32,
    },
    Php {
        connection: String,
        capture_route: String,
        working_directory: String,
    },
    ReverseProxy(ReverseProxy),
    ClientCache(HashMap<String, ClientCachePreference>),
    Auth(Auth),
    ViewCounter(ViewCounter),
    Link(Filter, String),

    CorsSafe,
    Cors(HashMap<String, CorsRule>),
    CspSafe,
    CspEmpty,
    Csp(HashMap<String, CspRule>),

    Custom(String, Option<ron::Value>),
}
impl Extension {
    #[allow(clippy::drop_ref)] // we use drop so we don't get &mut Extension in some codepaths
    async fn mount(
        self,
        exts: &mut kvarn::Extensions,
        host: &kvarn::host::Host,
        custom_exts: &CustomExtensions,
        config_dir: &Path,
    ) -> Result<Option<Box<Extension>>> {
        match self {
            Self::If {
                predicate,
                extension,
            } => {
                if predicate.resolve(config_dir) {
                    return Ok(Some(extension));
                }
            }
            Self::NoDefaults => unreachable!(
                "we've handled the NoDefaults case previously. Please report this bug."
            ),
            Self::Referrer(v) => {
                if let Some(v) = v {
                    let v = http::HeaderValue::from_bytes(v.as_bytes()).map_err(|err| {
                        format!("Referrer header value ({v:?}) contains illegal bytes: {err:?}")
                    })?;
                    exts.add_package(
                        kvarn::package!(resp, _, _, _, move |v: http::HeaderValue| {
                            resp.headers_mut().insert("referrer-policy", v.clone());
                        }),
                        kvarn::extensions::Id::new(10, "Add referrer-policy header"),
                    )
                } else {
                    exts.add_package(
                        kvarn::package!(resp, _, _, _, {
                            resp.headers_mut().remove("referrer-policy");
                        }),
                        kvarn::extensions::Id::new(10, "Remove referrer-policy header"),
                    )
                }
            }
            Self::RedirectIndexHtml => drop(exts.with_uri_redirect()),
            Self::RedirectHttpToHttps => drop(exts.with_http_to_https_redirect()),
            Self::Nonce => drop(exts.with_nonce()),
            Self::Redirect(filter, to) => {
                let header_value = http::HeaderValue::from_str(&to)
                    .map_err(|err| format!("Invalid redirect target: {err}"))?;
                let ext = kvarn::prepare!(_, _, _, _, move |header_value: http::HeaderValue| {
                    kvarn::FatResponse::no_cache(
                        http::Response::builder()
                            .status(http::StatusCode::TEMPORARY_REDIRECT)
                            .header("location", header_value)
                            .body(kvarn::prelude::Bytes::new())
                            .unwrap(),
                    )
                    .with_server_cache(kvarn::comprash::ServerCachePreference::Full)
                });
                if let Filter::Exact(path) = filter {
                    exts.add_prepare_single(path, ext);
                } else {
                    exts.add_prepare_fn(
                        Box::new(move |req, _| filter.resolve(req.uri().path())),
                        ext,
                        kvarn::extensions::Id::new(1432, "Redirect").no_override(),
                    )
                }
            }
            Self::AllDefaults => kvarn_extensions::mount_all(exts),
            Self::Templates => {
                exts.add_present_internal("tmpl", Box::new(kvarn_extensions::templates_ext))
            }
            Self::Http2Push {
                push_interval,
                check_every_request,
            } => drop(kvarn_extensions::mount_push(
                exts,
                kvarn_extensions::SmartPush::new(
                    Duration::from_secs_f64(push_interval),
                    check_every_request,
                ),
            )),
            Self::Php {
                connection,
                capture_route,
                working_directory,
            } => kvarn_extensions::php::mount_php_with_working_directory(
                exts,
                parse_connection(&connection)?,
                capture_route,
                config_dir.join(&working_directory),
            )
            .await
            .map_err(|err| {
                format!(
                    "Failed to start PHP: working directory \
                    ({working_directory}) isn't accessible: {err:?}"
                )
            })?,
            Self::ReverseProxy(config) => {
                let mut proxy = kvarn_extensions::ReverseProxy::base(
                    &config.route,
                    kvarn_extensions::reverse_proxy::static_connection(parse_connection(
                        &config.connection,
                    )?),
                    Duration::from_secs_f64(config.timeout.unwrap_or(10.)),
                );
                for option in config.options.into_iter().flatten() {
                    match option {
                        ReverseProxyOption::AddHeader(name, value) => {
                            let name = http::header::HeaderName::from_bytes(name.as_bytes())
                                .map_err(|err| {
                                    format!(
                                        "Tried to add invalid header name \
                                        to reverse proxy: {err:?}"
                                    )
                                })?;
                            let value = http::header::HeaderValue::from_bytes(value.as_bytes())
                                .map_err(|err| {
                                    format!(
                                        "Tried to add invalid header header \
                                        to reverse proxy: {err:?}"
                                    )
                                })?;
                            proxy = proxy.add_modify_fn(Arc::new(move |request, _body, _addr| {
                                request.headers_mut().insert(name.clone(), value.clone());
                            }));
                        }
                        ReverseProxyOption::ForwardIp => proxy = proxy.with_x_real_ip(),
                        ReverseProxyOption::StripIndexHtml { index_html_name } => {
                            let index = format!(
                                "/{}",
                                index_html_name
                                    .unwrap_or_else(|| host.options.get_folder_default().into())
                            );
                            proxy = proxy.add_modify_fn(Arc::new(move |req, _, _| {
                                if let Some(path) = req.uri().path().strip_suffix(&index) {
                                    let mut parts = req.uri().clone().into_parts();
                                    let pq = format!(
                                        "{path}/{}",
                                        parts
                                            .path_and_query
                                            .as_ref()
                                            .map_or("", |pq| pq.query().unwrap_or(""))
                                    );
                                    let pq =
                                        http::uri::PathAndQuery::from_maybe_shared(pq.into_bytes())
                                            .unwrap();
                                    parts.path_and_query = Some(pq);
                                    *req.uri_mut() = http::Uri::from_parts(parts).unwrap();
                                }
                            }));
                        }
                        ReverseProxyOption::DisableUrlRewrite => {
                            proxy = proxy.disable_url_rewrite()
                        }
                    }
                }

                proxy.mount(exts);
            }
            Self::ClientCache(map) => kvarn_extensions::force_cache(
                exts,
                map.into_iter().map(|(k, v)| (k, v.into())).collect(),
            ),

            Self::CorsSafe => drop(exts.with_disallow_cors()),
            Self::Cors(config) => {
                let cors = build_cors(config);
                exts.with_cors(cors.arc());
            }
            Self::CspSafe => drop(exts.with_csp(kvarn::csp::Csp::default().arc())),
            Self::CspEmpty => drop(exts.with_csp(kvarn::csp::Csp::empty().arc())),
            Self::Csp(config) => {
                let mut csp = kvarn::csp::Csp::default();
                for (path, rule) in config {
                    csp.add_mut(path, rule.into_kvarn(&csp)?);
                }
                exts.with_csp(csp.arc());
            }
            Self::Auth(config) => {
                let mut builder = kvarn_auth::Builder::new()
                    .with_auth_page_name(config.auth_api_route)
                    .with_show_auth_page_when_unauthorized(config.unauthorized_route);

                if let Some(refresh) = config.jwt_refresh_interval {
                    builder = builder.with_jwt_validity(Duration::from_secs_f64(refresh))
                }
                if let Some(true) = config.behind_reverse_proxy {
                    builder = builder.with_ip_from_header();
                }
                match config.filter {
                    Filter::StartsWith(cookie_path) => {
                        builder = builder.with_cookie_path(cookie_path)
                    }
                    // also allow always sending it
                    Filter::AcceptAll => {}
                    _ => {
                        return Err(
                            "The filter in the Auth extension only allows `StartsWith` or `All`."
                                .into(),
                        )
                    }
                }
                if let Some(true) = config.lax_samesite {
                    builder = builder.with_lax_samesite();
                }
                if let Some(true) = config.relaxed_httponly {
                    builder = builder.with_relaxed_httponly();
                }
                if let Some(true) = config.force_relog_on_ip_change {
                    builder = builder.with_force_relog_on_ip_change();
                }
                if let Some(name) = config.jwt_cookie_name {
                    builder = builder.with_jwt_cookie_name(name);
                }
                if let Some(name) = config.credentials_cookie_name {
                    builder = builder.with_credentials_cookie_name(name);
                }

                let _ = Auth::resolve(builder, config.secret, config.credentials, exts, config_dir)
                    .await?;
            }
            Self::ViewCounter(config) => drop(
                kvarn_extensions::view_counter::mount(
                    exts,
                    move |req| config.filter.resolve(req.uri().path()),
                    config_dir.join(&config.log_path).display().to_string(),
                    Duration::from_secs_f64(config.commit_interval.unwrap_or(60. * 60.)),
                    Duration::from_secs_f64(config.accept_same_ip_interval.unwrap_or(60. * 60.)),
                )
                .await,
            ),
            Self::Link(filter, target) => {
                use kvarn::prelude::*;

                exts.add_prepare_fn(
                    Box::new(move |req, _| filter.resolve(req.uri().path())),
                    kvarn::prepare!(req, host, _, _, move |target: String| {
                        let path = format!("{}{}", target, req.uri().path());
                        let file = read::file(&path, host.file_cache.as_ref()).await;
                        let file = if let Some(f) = file {
                            f
                        } else {
                            return default_error_response(StatusCode::NOT_FOUND, host, None).await;
                        };
                        FatResponse::no_cache(Response::new(file))
                    }),
                    Id::new(1000, "redirect to other path on file system").no_override(),
                );
            }
            Self::Custom(name, data) => {
                let data = data.unwrap_or(ron::Value::Unit);
                let ext = custom_exts
                    .0
                    .get(&name)
                    .ok_or_else(|| format!("Didn't find a custom extension with name {name}!"))?;
                ext(exts, data, config_dir.to_path_buf()).await?;
            }
        }
        Ok(None)
    }
}

struct IntermediaryExtensions {
    exts: Vec<Extension>,
    defaults: bool,
}
impl IntermediaryExtensions {
    fn new(mut exts: Vec<Extension>) -> Self {
        let mut d = true;
        exts.retain(|ext| {
            if matches!(ext, Extension::NoDefaults) {
                d = false;
                false
            } else {
                true
            }
        });
        Self { exts, defaults: d }
    }
    fn into_parts(self) -> (kvarn::Extensions, Vec<Extension>) {
        if self.defaults {
            (kvarn::Extensions::new(), self.exts)
        } else {
            (kvarn::Extensions::empty(), self.exts)
        }
    }
}

/// Get a [`kvarn::Extensions`] from a list of [`Extension`].
/// `cfg_dir` is the directory of the config file these extensions are read from.
pub async fn build_extensions(
    exts: Vec<Extension>,
    host: &kvarn::host::Host,
    custom_exts: &CustomExtensions,
    cfg_dir: &Path,
) -> Result<kvarn::Extensions> {
    let intermediary = IntermediaryExtensions::new(exts);
    let (mut exts, v) = intermediary.into_parts();

    exts.with_server_header("Kvarn/0.5.0 Moella/0.1.0", true, true);

    for ext in v {
        let mut ext2 = ext.mount(&mut exts, host, custom_exts, cfg_dir).await?;
        while let Some(ext) = ext2.take() {
            ext2 = ext.mount(&mut exts, host, custom_exts, cfg_dir).await?;
        }
    }

    Ok(exts)
}
/// Same as [`build_extensions`], but building on top `extensions`.
pub async fn build_extensions_inherit(
    exts: Vec<Extension>,
    extensions: kvarn::Extensions,
    host: &kvarn::host::Host,
    custom_exts: &CustomExtensions,
    cfg_dir: &Path,
) -> Result<kvarn::Extensions> {
    let intermediary = IntermediaryExtensions::new(exts);
    let (_exts, v) = intermediary.into_parts();
    let mut exts = extensions;

    for ext in v {
        let mut ext2 = ext.mount(&mut exts, host, custom_exts, cfg_dir).await?;
        while let Some(ext) = ext2.take() {
            ext2 = ext.mount(&mut exts, host, custom_exts, cfg_dir).await?;
        }
    }

    Ok(exts)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Predicate {
    Not(Box<Predicate>),
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Exists(String),
}
impl Predicate {
    pub fn resolve(&self, config_dir: &Path) -> bool {
        match self {
            Self::Not(p) => !p.resolve(config_dir),
            Self::And(ps) => ps.iter().all(|p| p.resolve(config_dir)),
            Self::Or(ps) => ps.iter().any(|p| p.resolve(config_dir)),
            Self::Exists(p) => config_dir.join(p).exists(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Filter {
    Not(Box<Filter>),
    And(Vec<Filter>),
    Or(Vec<Filter>),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    Exact(String),
    AcceptAll,
}
impl Filter {
    pub fn resolve(&self, s: &str) -> bool {
        match self {
            Self::Not(p) => !p.resolve(s),
            Self::And(ps) => ps.iter().all(|p| p.resolve(s)),
            Self::Or(ps) => ps.iter().any(|p| p.resolve(s)),
            Self::StartsWith(p) => s.starts_with(p),
            Self::EndsWith(p) => s.ends_with(p),
            Self::Contains(p) => s.contains(p),
            Self::Exact(p) => s == p,
            Self::AcceptAll => true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum ClientCachePreference {
    Ignore,
    None,
    Changing,
    Full,
    MaxAge(f64),
}
impl From<ClientCachePreference> for kvarn::comprash::ClientCachePreference {
    fn from(ccp: ClientCachePreference) -> Self {
        use kvarn::comprash::ClientCachePreference as CCP;
        match ccp {
            ClientCachePreference::Ignore => CCP::Ignore,
            ClientCachePreference::None => CCP::None,
            ClientCachePreference::Changing => CCP::Changing,
            ClientCachePreference::Full => CCP::Full,
            ClientCachePreference::MaxAge(seconds) => CCP::MaxAge(Duration::from_secs_f64(seconds)),
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum CspRule {
    FromDefault(HashMap<CspDirective, Vec<CspSource>>),
    Inherit(String, HashMap<CspDirective, Vec<CspSource>>),
    FromEmpty(HashMap<CspDirective, Vec<CspSource>>),
    Empty,
}
impl CspRule {
    pub fn into_kvarn(self, rule_set: &kvarn::csp::Csp) -> Result<kvarn::csp::Rule> {
        match self {
            CspRule::FromDefault(map) => {
                let mut rule = kvarn::csp::Rule::default();
                for (directive, sources) in map {
                    rule = directive.attach(CspSource::into_kvarn(sources), rule);
                }
                Ok(rule)
            }
            CspRule::Inherit(base, map) => {
                let mut rule = rule_set
                    .get(&base)
                    .ok_or_else(|| format!("the CSP rule you inherit from ({base}) doesn't exist"))?
                    .clone();
                for (directive, sources) in map {
                    rule = directive.attach(CspSource::into_kvarn(sources), rule);
                }
                Ok(rule)
            }
            CspRule::FromEmpty(map) => {
                let mut rule = kvarn::csp::Rule::empty();
                for (directive, sources) in map {
                    rule = directive.attach(CspSource::into_kvarn(sources), rule);
                }
                Ok(rule)
            }
            CspRule::Empty => Ok(kvarn::csp::Rule::empty()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum CspSource {
    Uri(String),
    UnsafeInline,
    UnsafeEval,
    Scheme(String),
}
impl CspSource {
    pub fn into_kvarn(v: Vec<CspSource>) -> kvarn::csp::ValueSet {
        let mut base = kvarn::csp::ValueSet::default();
        for source in v {
            match source {
                CspSource::Uri(uri) => base = base.uri(uri),
                CspSource::UnsafeInline => base = base.unsafe_inline(),
                CspSource::UnsafeEval => base = base.unsafe_eval(),
                CspSource::Scheme(scheme) => base = base.scheme(scheme),
            }
        }
        base
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(deny_unknown_fields)]
#[allow(non_camel_case_types)] // serde names!
pub enum CspDirective {
    child_src,
    connect_src,
    default_src,
    font_src,
    frame_src,
    img_src,
    manifest_src,
    media_src,
    object_src,
    prefetch_src,
    script_src,
    script_src_elem,
    script_src_attr,
    style_src,
    style_src_elem,
    style_src_attr,
    worker_src,
    base_uri,
    sandbox,
    form_action,
    frame_ancestors,
    navigate_to,
    report,
    require_sri_for,
    require_trusted_types_for,
    trusted_types,
    upgrade_insecure_requests,
    raw(String),
}
impl CspDirective {
    pub fn attach(
        self,
        sources: kvarn::csp::ValueSet,
        target: kvarn::csp::Rule,
    ) -> kvarn::csp::Rule {
        match self {
            Self::child_src => target.child_src(sources),
            Self::connect_src => target.connect_src(sources),
            Self::default_src => target.default_src(sources),
            Self::font_src => target.font_src(sources),
            Self::frame_src => target.frame_src(sources),
            Self::img_src => target.img_src(sources),
            Self::manifest_src => target.manifest_src(sources),
            Self::media_src => target.media_src(sources),
            Self::object_src => target.object_src(sources),
            Self::prefetch_src => target.prefetch_src(sources),
            Self::script_src => target.script_src(sources),
            Self::script_src_elem => target.script_src_elem(sources),
            Self::script_src_attr => target.script_src_attr(sources),
            Self::style_src => target.style_src(sources),
            Self::style_src_elem => target.style_src_elem(sources),
            Self::style_src_attr => target.style_src_attr(sources),
            Self::worker_src => target.worker_src(sources),
            Self::base_uri => target.base_uri(sources),
            Self::sandbox => target.sandbox(sources),
            Self::form_action => target.form_action(sources),
            Self::frame_ancestors => target.frame_ancestors(sources),
            Self::navigate_to => target.navigate_to(sources),
            Self::report => target.report(sources),
            Self::require_sri_for => target.require_sri_for(sources),
            Self::require_trusted_types_for => target.require_trusted_types_for(sources),
            Self::trusted_types => target.trusted_types(sources),
            Self::upgrade_insecure_requests => target.upgrade_insecure_requests(sources),
            Self::raw(raw) => target.string(raw, sources),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
#[allow(clippy::upper_case_acronyms)] // serde
enum Method {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    OPTIONS,
    CONNECT,
    PATCH,
    // WEBDAV
    COPY,
    LOCK,
    MKCOL,
    MOVE,
    PROPFIND,
    PROPPATCH,
    UNLOCK,
    // Specials
    ALL,
}
impl From<Method> for http::Method {
    fn from(m: Method) -> Self {
        match m {
            Method::GET => Self::GET,
            Method::HEAD => Self::HEAD,
            Method::POST => Self::POST,
            Method::PUT => Self::PUT,
            Method::DELETE => Self::DELETE,
            Method::TRACE => Self::TRACE,
            Method::OPTIONS => Self::OPTIONS,
            Method::CONNECT => Self::CONNECT,
            Method::PATCH => Self::PATCH,
            Method::COPY => Self::from_bytes(b"COPY").unwrap(),
            Method::LOCK => Self::from_bytes(b"LOCK").unwrap(),
            Method::MKCOL => Self::from_bytes(b"MKCOL").unwrap(),
            Method::MOVE => Self::from_bytes(b"MOVE").unwrap(),
            Method::PROPFIND => Self::from_bytes(b"PROPFIND").unwrap(),
            Method::PROPPATCH => Self::from_bytes(b"PROPPATCH").unwrap(),
            Method::UNLOCK => Self::from_bytes(b"UNLOCK").unwrap(),
            Method::ALL => unreachable!(
                "Tried to convert our special case method to an HTTP method. \
                This should be covered by checks. Please report this bug."
            ),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CorsRule {
    cache: Option<f64>,
    origins: Vec<String>,
    methods: Option<Vec<Method>>,
}
fn build_cors(map: HashMap<String, CorsRule>) -> kvarn::cors::Cors {
    let mut cors = kvarn::cors::Cors::empty();
    for (path, config) in map {
        let mut rule = if let Some(cache) = config.cache {
            kvarn::cors::AllowList::new(Duration::from_secs_f64(cache))
        } else {
            kvarn::cors::AllowList::default()
        };
        for origin in config.origins {
            if origin == "*" {
                rule = rule.allow_all_origins();
            } else {
                rule = rule.add_origin(origin);
            }
        }
        for method in config.methods.into_iter().flatten() {
            if method == Method::ALL {
                rule = rule.allow_all_methods();
            } else {
                rule = rule.add_method(method.into())
            }
        }
        cors.add_mut(path, rule);
    }
    cors
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
enum ReverseProxyOption {
    AddHeader(String, String),
    ForwardIp,
    StripIndexHtml { index_html_name: Option<String> },
    DisableUrlRewrite,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReverseProxy {
    route: String,
    connection: String,
    timeout: Option<f64>,
    options: Option<Vec<ReverseProxyOption>>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub enum AuthCredentials {
    SpaceSepparatedAccoutPerLine(String),
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    credentials: AuthCredentials,
    secret: String,
    auth_api_route: String,
    unauthorized_route: String,
    jwt_refresh_interval: Option<f64>,
    filter: Filter,
    lax_samesite: Option<bool>,
    relaxed_httponly: Option<bool>,
    force_relog_on_ip_change: Option<bool>,
    jwt_cookie_name: Option<String>,
    credentials_cookie_name: Option<String>,
    behind_reverse_proxy: Option<bool>,
}
impl Auth {
    pub async fn resolve(
        builder: kvarn_auth::Builder,
        secret: impl AsRef<str>,
        credentials: AuthCredentials,
        extensions: &mut kvarn::Extensions,
        config_dir: &Path,
    ) -> Result<kvarn_auth::LoginStatusClosure<()>> {
        let path = config_dir.join(secret.as_ref());
        let secret = tokio::fs::read(&path)
            .await
            .map_err(|err| format!("Failed to read auth secret {path:?}: {err:?}"))?;
        let algo = kvarn_auth::CryptoAlgo::EcdsaP256 { secret };
        let auth = match credentials {
            AuthCredentials::SpaceSepparatedAccoutPerLine(file) => {
                let path = config_dir.join(file);
                let passwd_file = tokio::fs::read_to_string(&path).await.map_err(|err| {
                    format!("Failed to read auth password file {path:?}: {err:?}")
                })?;
                let accounts: HashMap<String, String> = passwd_file
                    .lines()
                    .filter_map(|line| {
                        let (usr, pas) = line.split_once(' ')?;
                        Some((usr.to_owned(), pas.to_owned()))
                    })
                    .collect();
                builder.build(
                    move |user, password, _addr, _req| {
                        let v = if accounts.get(user).map_or(false, |pass| pass == password) {
                            kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::<()>::None)
                        } else {
                            kvarn_auth::Validation::Unauthorized
                        };
                        core::future::ready(v)
                    },
                    algo,
                )
            }
        };
        auth.mount(extensions);
        Ok(auth.login_status())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ViewCounter {
    filter: Filter,
    log_path: String,
    commit_interval: Option<f64>,
    accept_same_ip_interval: Option<f64>,
}

fn parse_connection(s: &str) -> Result<kvarn_extensions::Connection> {
    use std::net::{SocketAddr, ToSocketAddrs};

    let select_addr = |mut addrs: std::vec::IntoIter<SocketAddr>| {
        let mut current = addrs.next();
        for addr in addrs {
            if addr.is_ipv4() && current.as_ref().map_or(true, SocketAddr::is_ipv6) {
                current = Some(addr);
            }
        }
        current
    };

    if let Some(socket) = s.strip_prefix("tcp:") {
        let socket = socket.strip_prefix("//").unwrap_or(socket);
        let socket = select_addr(
            socket
                .to_socket_addrs()
                .map_err(|err| format!("Failed to resolve tcp:{socket}: {err:?}"))?,
        )
        .ok_or_else(|| format!("Hostname {socket} didn't resolve any IP adresses"))?;

        Ok(kvarn_extensions::Connection::Tcp(socket))
    } else if let Some(socket) = s.strip_prefix("udp:") {
        let socket = socket.strip_prefix("//").unwrap_or(socket);
        let socket = select_addr(
            socket
                .to_socket_addrs()
                .map_err(|err| format!("Failed to resolve udp:{socket}: {err:?}"))?,
        )
        .ok_or_else(|| format!("Hostname {socket} didn't resolve any IP adresses"))?;

        Ok(kvarn_extensions::Connection::Udp(socket))
    } else if let Some(path) = s.strip_prefix("unix:") {
        let path = path.strip_prefix("//").unwrap_or(path);
        Ok(kvarn_extensions::Connection::UnixSocket(path.into()))
    } else if let Some((protocol, _host)) = s.split_once(':') {
        Err(format!("Protocol {protocol} not recognized"))
    } else {
        Err("Invalid connection address".into())
    }
}
