use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::{CustomExtensions, ExtensionBundles, Result};
use kvarn::prelude::ToCompactString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Limiter {
    max_requests_per_interval: usize,
    interval: f64,
    check_one_in_n_requests: usize,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Limit {
    Limit(Limiter),
    AllowAll,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct HostOptions {
    disable_fs: Option<bool>,
    disable_client_cache: Option<bool>,
    disable_server_cache: Option<bool>,
    disable_response_cache: Option<bool>,
    disable_fs_cache: Option<bool>,
    hsts: Option<bool>,
    brotli_level: Option<u32>,
    gzip_level: Option<u32>,
    zstd_level: Option<i32>,
    brotli_oneshot_level: Option<u32>,
    gzip_oneshot_level: Option<u32>,
    zstd_oneshot_level: Option<i32>,
    folder_default: Option<String>,
    extension_default: Option<String>,
    public_data_directory: Option<String>,
    alternative_names: Option<Vec<String>>,
    limiter: Option<Limit>,
}
impl HostOptions {
    fn resolve(self) -> kvarn::host::Options {
        let mut options = kvarn::host::Options::new();

        if let Some(b) = self.disable_fs {
            options.disable_fs = b;
        }
        if let Some(b) = self.disable_client_cache {
            options.disable_client_cache = b;
        }
        if let Some(d) = self.folder_default {
            options.folder_default = Some(d.to_compact_string());
        }
        if let Some(d) = self.extension_default {
            options.extension_default = Some(d.to_compact_string());
        }
        if let Some(d) = self.public_data_directory {
            options.public_data_dir = Some(d.into());
        }

        options
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum SearchEngineKind {
    Simple,
    Lossless,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum SearchEngineIgnoreExtensions {
    ExtendDefaults(Vec<String>),
    Only(Vec<String>),
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SearchEngineAddon {
    api_route: String,
    kind: SearchEngineKind,
    response_hits_limit: Option<u32>,
    query_max_length: Option<u32>,
    query_max_terms: Option<u32>,
    additional_paths: Option<Vec<String>>,
    ignore_paths: Option<Vec<String>>,
    ignore_extensions: Option<SearchEngineIgnoreExtensions>,
    index_wordpress_sitemap: Option<bool>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AutomaticCertificate {
    contact: Option<String>,
    account_path: Option<String>,
    force_renew_on_start: Option<bool>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum HostAddon {
    SearchEngine(SearchEngineAddon),
    AutomaticCertificate(AutomaticCertificate),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Host {
    Plain {
        cert: String,
        pk: String,
        path: String,
        auto_cert: Option<bool>,
        name: Option<String>,
        extensions: Vec<String>,
        options: Option<HostOptions>,
        addons: Option<Vec<HostAddon>>,
    },
    TryCertificatesOrUnencrypted {
        name: String,
        cert: String,
        pk: String,
        path: String,
        auto_cert: Option<bool>,
        extensions: Vec<String>,
        options: Option<HostOptions>,
        addons: Option<Vec<HostAddon>>,
    },
    Http {
        name: String,
        path: String,
        extensions: Vec<String>,
        options: Option<HostOptions>,
        addons: Option<Vec<HostAddon>>,
    },
}
impl Host {
    async fn resolve_extensions(
        selected: &[String],
        extensions: &ExtensionBundles,
        host: &kvarn::host::Host,
        custom_exts: &CustomExtensions,
        has_auto_cert: bool,
    ) -> Result<kvarn::Extensions> {
        let mut exts = selected.iter();
        if let Some(first) = exts.next() {
            let ext = extensions
                .get(first.as_str())
                .ok_or_else(|| format!("Didn't find an extension bundle with name {first}"))?;
            let mut main = crate::extension::build_extensions(
                ext.0.clone(),
                host,
                custom_exts,
                Path::new(&ext.1)
                    .parent()
                    .expect("config file is in no directory"),
                has_auto_cert,
            )
            .await?;
            for ext in exts {
                let ext = extensions
                    .get(ext.as_str())
                    .ok_or_else(|| format!("Didn't find an extension bundle with name {ext}"))?;
                main = crate::extension::build_extensions_inherit(
                    ext.0.clone(),
                    main,
                    host,
                    custom_exts,
                    Path::new(&ext.1)
                        .parent()
                        .expect("config file is in no directory"),
                )
                .await?;
            }
            Ok(main)
        } else {
            Ok(kvarn::Extensions::new())
        }
    }
    /// `cert_path` have to be relative to $PWD, not the config
    #[allow(clippy::too_many_arguments)]
    async fn assemble(
        mut host: kvarn::host::Host,
        cert_path: Option<(PathBuf, PathBuf)>,
        exts: Vec<String>,
        ext_bundles: &ExtensionBundles,
        options: HostOptions,
        addons: Vec<HostAddon>,
        custom_exts: &CustomExtensions,
        execute_extensions_addons: bool,
        config_dir: &Path,
        root_config_dir: &Path,
        has_auto_cert: bool,
        dev: bool,
    ) -> Result<CloneableHost> {
        let opts_clone = options.clone();
        if let Some(true) = options.disable_fs_cache {
            host.disable_fs_cache();
        }
        if let Some(true) = options.disable_response_cache {
            host.disable_response_cache();
        }
        if let Some(true) = options.disable_server_cache {
            host.disable_server_cache();
        }
        if let Some(level) = options.brotli_level {
            if !(1..=10).contains(&level) {
                return Err("Brotli level has to be in the range 1..=10".into());
            }
            host.set_brotli_level(level);
        }
        if let Some(level) = options.gzip_level {
            if !(1..=10).contains(&level) {
                return Err("GZIP level has to be in the range 1..=10".into());
            }
            host.set_gzip_level(level);
        }
        if let Some(level) = options.zstd_level {
            if !(1..=22).contains(&level) {
                return Err("Zstd level has to be in the range 1..=10".into());
            }
            if (20..=22).contains(&level) {
                log::warn!("Using a very high compression for zstd. This is not recommended.");
            }
            host.set_zstd_level(level);
        }
        if let Some(level) = options.brotli_oneshot_level {
            if !(1..=10).contains(&level) {
                return Err("Brotli level has to be in the range 1..=10".into());
            }
            host.set_brotli_level_oneshot(level);
        }
        if let Some(level) = options.gzip_oneshot_level {
            if !(1..=10).contains(&level) {
                return Err("GZIP level has to be in the range 1..=10".into());
            }
            host.set_gzip_level_oneshot(level);
        }
        if let Some(level) = options.zstd_oneshot_level {
            if !(1..=22).contains(&level) {
                return Err("Zstd level has to be in the range 1..=10".into());
            }
            if (20..=22).contains(&level) {
                log::warn!("Using a very high compression for zstd. This is not recommended.");
            }
            host.set_zstd_level_oneshot(level);
        }
        if let Some(alts) = options.alternative_names {
            for alt in alts {
                host.add_alternative_name(alt);
            }
        }
        if let Some(limiter) = &options.limiter {
            match limiter {
                Limit::Limit(opts) => {
                    host.limiter = kvarn::limiting::Manager::new(
                        opts.max_requests_per_interval,
                        opts.check_one_in_n_requests,
                        opts.interval,
                    );
                }
                Limit::AllowAll => {
                    host.limiter.disable();
                }
            }
        }

        let mut se_handles = Vec::new();
        let mut cert_collection_senders = Vec::new();

        // set extensions
        if execute_extensions_addons {
            let mut extensions =
                Self::resolve_extensions(&exts, ext_bundles, &host, custom_exts, has_auto_cert)
                    .await?;
            for addon in &addons {
                match addon {
                    HostAddon::SearchEngine(config) => {
                        let mut opts = kvarn_search::Options::new();
                        opts.kind = match config.kind {
                            SearchEngineKind::Simple => kvarn_search::IndexKind::Simple,
                            SearchEngineKind::Lossless => kvarn_search::IndexKind::Lossless,
                        };
                        if let Some(i) = config.response_hits_limit {
                            opts.response_hits_limit = i as _;
                        }
                        if let Some(i) = config.query_max_length {
                            opts.query_max_length = i as _;
                        }
                        if let Some(i) = config.query_max_terms {
                            opts.query_max_terms = i as _;
                        }
                        if let Some(b) = config.index_wordpress_sitemap {
                            opts.index_wordpress_sitemap = b;
                        }
                        if let Some(ignored) = &config.ignore_paths {
                            let mut v = Vec::with_capacity(ignored.len());
                            for ignored in ignored {
                                match http::Uri::try_from(ignored) {
                                    Ok(uri) => v.push(uri),
                                    Err(err) => {
                                        return Err(format!(
                                            "Failed to parse ignored path (search engine): {err}"
                                        ))
                                    }
                                }
                            }
                            opts.ignore_paths = v;
                        }
                        match &config.ignore_extensions {
                            Some(SearchEngineIgnoreExtensions::Only(v)) => {
                                opts.ignore_extensions.clone_from(v);
                            }
                            Some(SearchEngineIgnoreExtensions::ExtendDefaults(v)) => {
                                opts.ignore_extensions.extend_from_slice(v);
                            }
                            None => {}
                        }
                        if let Some(v) = &config.additional_paths {
                            let mut paths = Vec::with_capacity(v.len());
                            for path in v {
                                let path = http::Uri::from_maybe_shared(
                                    kvarn::prelude::Bytes::from(path.as_bytes().to_vec()),
                                )
                                .map_err(|err| {
                                    format!(
                                    "Invalid path given to search engine addisional_paths: {err:?}"
                                )
                                })?;
                                paths.push(path);
                            }
                            opts.additional_paths = paths;
                        }

                        let handle = kvarn_search::mount_search(
                            &mut extensions,
                            config.api_route.clone(),
                            opts,
                        )
                        .await;
                        se_handles.push(handle);
                    }
                    HostAddon::AutomaticCertificate(config) => {
                        struct CachedRx<T> {
                            rx: Option<tokio::sync::oneshot::Receiver<T>>,
                            t: Option<T>,
                        }
                        impl<T> CachedRx<T> {
                            fn new(rx: tokio::sync::oneshot::Receiver<T>) -> Self {
                                Self {
                                    rx: Some(rx),
                                    t: None,
                                }
                            }
                            async fn rx(&mut self) -> &T {
                                if let Some(ref t) = self.t {
                                    t
                                } else {
                                    let rx = self.rx.take().unwrap();
                                    let t = rx.await.unwrap();
                                    self.t.insert(t)
                                }
                            }
                        }

                        let email = config
                            .contact
                            .as_ref()
                            .map(|contact| {
                                if let Some(mail) = contact.strip_prefix("mailto:") {
                                    Ok(mail)
                                } else {
                                    Err(format!(
                                        "AutomaticCertificate contact needs to be in the format \
                                        `mailto:you@example.org`. You provided `{}`.",
                                        contact
                                    ))
                                }
                            })
                            .transpose()?;
                        let creds = config.account_path.clone().unwrap_or_else(|| {
                            if let Some(email) = email {
                                format!("lets-encrypt-credentials-{email}.ron")
                            } else {
                                "lets-encrypt-credentials.ron".into()
                            }
                        });

                        let Some((cert_path, pk_path)) = &cert_path else {
                            return Err(
                                "You cannot use `AutomaticCertificate` on an HTTP-only host!"
                                    .to_owned(),
                            );
                        };
                        let has_cert = { host.certificate.read().unwrap().is_some() };
                        let (tx, rx) = tokio::sync::oneshot::channel();

                        cert_collection_senders.push(tx);
                        let host_name = host.name.clone();
                        let rx = Arc::new(tokio::sync::Mutex::new(CachedRx::new(rx)));

                        kvarn_extensions::certificate::mount(
                            move |key| {
                                let rx = rx.clone();
                                let host_name = host_name.clone();
                                async move {
                                    let mut rx = rx.lock().await;
                                    let collection: &Arc<kvarn::host::Collection> = rx.rx().await;
                                    let host = collection
                                        .get_host(&host_name)
                                        .expect("we were created with a host of this name");

                                    log::info!("Set automatic cert on {}!", host.name);
                                    host.live_set_certificate(key);
                                }
                            },
                            &host,
                            &mut extensions,
                            !has_cert || config.force_renew_on_start.unwrap_or(false),
                            config.contact.clone(),
                            root_config_dir.join(creds),
                            cert_path,
                            pk_path,
                            dev,
                        )
                        .await;
                    }
                }
            }
            host.extensions = extensions;
            if let Some(true) = options.hsts {
                host.with_hsts();
            }
            for handle in &se_handles {
                handle.index_all(&host).await;
            }
        }

        Ok(CloneableHost {
            host,
            exts,
            options: opts_clone,
            addons,
            cert_path,

            config_dir: config_dir.to_path_buf(),
            root_config_dir: root_config_dir.to_path_buf(),

            search_engine_handles: se_handles,
            cert_collection_senders,
            has_auto_cert,
        })
    }
    fn add_auto_cert(
        addons: Option<Vec<HostAddon>>,
        auto_cert: Option<bool>,
    ) -> (bool, Vec<HostAddon>) {
        let mut addons = addons.unwrap_or_default();

        let mut contains = addons
            .iter()
            .any(|i| matches!(i, HostAddon::AutomaticCertificate(_)));

        if auto_cert.unwrap_or(false) && !contains {
            addons.push(HostAddon::AutomaticCertificate(AutomaticCertificate {
                contact: None,
                account_path: None,
                force_renew_on_start: None,
            }));
            contains = true;
        }
        (contains, addons)
    }
    pub async fn resolve(
        self,
        ext_bundles: &ExtensionBundles,
        custom_exts: &CustomExtensions,
        config_dir: &Path,
        root_config_dir: &Path,
        dev: bool,
    ) -> Result<CloneableHost> {
        match self {
            Host::Plain {
                cert,
                pk,
                path,
                name: name_override,
                auto_cert,
                extensions,
                options,
                addons,
            } => {
                let (contains_auto_cert, addons) = Self::add_auto_cert(addons, auto_cert);
                let options = options.unwrap_or_default();
                let opts = options.clone().resolve();
                let cert_path = config_dir.join(cert);
                let pk_path = config_dir.join(pk);
                let host = match (name_override, contains_auto_cert) {
                    (Some(name), false) => kvarn::host::Host::try_read_fs(
                        name,
                        cert_path.to_string_lossy(),
                        pk_path.to_string_lossy(),
                        config_dir.join(path).to_string_lossy(),
                        kvarn::Extensions::empty(),
                        opts,
                    )
                    .map_err(|(err, _)| {
                        format!(
                            "Failed when reading certificate \
                            ({cert_path:?})/private key ({pk_path:?}): {err:?}"
                        )
                    })?,
                    (None, false) => kvarn::host::Host::read_fs_name_from_cert(
                        cert_path.to_string_lossy(),
                        pk_path.to_string_lossy(),
                        config_dir.join(path).to_string_lossy(),
                        kvarn::Extensions::empty(),
                        opts,
                    )
                    .map_err(|err| {
                        format!(
                            "Failed when reading certificate \
                            ({cert_path:?})/private key ({pk_path:?}): {err:?}"
                        )
                    })?,
                    (Some(name), true) => kvarn::host::Host::try_read_fs(
                        name,
                        cert_path.to_string_lossy(),
                        pk_path.to_string_lossy(),
                        config_dir.join(path).to_string_lossy(),
                        kvarn::Extensions::empty(),
                        opts,
                    )
                    .unwrap_or_else(|(_, host)| host),
                    (None, true) => {
                        return Err("Tried to create secure host \
                            with automatic certificates but without a domain name. \
                            We can't know which domain it is!"
                            .into());
                    }
                };
                Self::assemble(
                    host,
                    Some((cert_path, pk_path)),
                    extensions,
                    ext_bundles,
                    options,
                    addons,
                    custom_exts,
                    false,
                    config_dir,
                    root_config_dir,
                    contains_auto_cert,
                    dev,
                )
                .await
            }
            Host::TryCertificatesOrUnencrypted {
                name,
                cert,
                pk,
                path,
                auto_cert,
                extensions,
                options,
                addons,
            } => {
                let (contains_auto_cert, addons) = Self::add_auto_cert(addons, auto_cert);
                let cert_path = config_dir.join(cert);
                let pk_path = config_dir.join(pk);
                let options = options.unwrap_or_default();
                let opts = options.clone().resolve();

                let host = kvarn::host::Host::try_read_fs(
                    name,
                    cert_path.to_string_lossy(),
                    pk_path.to_string_lossy(),
                    config_dir.join(path).to_string_lossy(),
                    kvarn::Extensions::empty(),
                    opts,
                );
                let host = if contains_auto_cert {
                    host.unwrap_or_else(|(_, host)| host)
                } else {
                    host
                .unwrap_or_else(|(err, host)| {
                    log::error!("Failed when reading certificate ({cert_path:?})/private key ({pk_path:?}): {err:?}");
                    host
                })
                };
                Self::assemble(
                    host,
                    Some((cert_path, pk_path)),
                    extensions,
                    ext_bundles,
                    options,
                    addons,
                    custom_exts,
                    false,
                    config_dir,
                    root_config_dir,
                    contains_auto_cert,
                    dev,
                )
                .await
            }
            Host::Http {
                name,
                path,
                extensions,
                options,
                addons,
            } => {
                let options = options.unwrap_or_default();
                let opts = options.clone().resolve();
                let host = kvarn::host::Host::unsecure(
                    name,
                    config_dir.join(path).to_string_lossy(),
                    kvarn::Extensions::empty(),
                    opts,
                );
                Self::assemble(
                    host,
                    None,
                    extensions,
                    ext_bundles,
                    options,
                    addons.unwrap_or_default(),
                    custom_exts,
                    false,
                    config_dir,
                    root_config_dir,
                    false,
                    dev,
                )
                .await
            }
        }
    }
}

pub struct CloneableHost {
    pub host: kvarn::host::Host,
    pub exts: Vec<String>,
    pub options: HostOptions,
    pub addons: Vec<HostAddon>,

    pub cert_path: Option<(PathBuf, PathBuf)>,

    pub config_dir: PathBuf,
    pub root_config_dir: PathBuf,

    // addons
    pub search_engine_handles: Vec<kvarn_search::SearchEngineHandle>,
    pub cert_collection_senders: Vec<tokio::sync::oneshot::Sender<Arc<kvarn::host::Collection>>>,
    pub has_auto_cert: bool,
}
impl CloneableHost {
    pub async fn clone_with_extensions(
        &self,
        exts: &ExtensionBundles,
        custom_exts: &CustomExtensions,
        execute_extensions_addons: bool,
        dev: bool,
    ) -> Result<Self> {
        Host::assemble(
            self.host.clone_without_extensions(),
            self.cert_path.clone(),
            self.exts.clone(),
            exts,
            self.options.clone(),
            self.addons.clone(),
            custom_exts,
            execute_extensions_addons,
            &self.config_dir,
            &self.root_config_dir,
            self.has_auto_cert,
            dev,
        )
        .await
    }
}
