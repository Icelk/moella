use std::path::Path;

use crate::config::{CustomExtensions, ExtensionBundles, Result};
use log::error;
use serde::{Deserialize, Serialize};

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
    folder_default: Option<String>,
    extension_default: Option<String>,
    public_data_directory: Option<String>,
    alternative_names: Option<Vec<String>>,
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
            options.folder_default = Some(d);
        }
        if let Some(d) = self.extension_default {
            options.extension_default = Some(d);
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
pub enum HostAddon {
    SearchEngine(SearchEngineAddon),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Host {
    Plain {
        cert: String,
        pk: String,
        path: String,
        name_override: Option<String>,
        extensions: Vec<String>,
        options: Option<HostOptions>,
        addons: Option<Vec<HostAddon>>,
    },
    TryCertificatesOrUnencrypted {
        name: String,
        cert: String,
        pk: String,
        path: String,
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
    ) -> Result<kvarn::Extensions> {
        let mut exts = selected.iter();
        if let Some(first) = exts.next() {
            let ext = extensions
                .get(first)
                .ok_or_else(|| format!("Didn't find an extension bundle with name {first}"))?;
            let mut main = crate::extension::build_extensions(
                ext.0.clone(),
                host,
                custom_exts,
                Path::new(&ext.1)
                    .parent()
                    .expect("config file is in no directory"),
            )
            .await?;
            for ext in exts {
                let ext = extensions
                    .get(ext)
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
    async fn assemble(
        mut host: kvarn::host::Host,
        exts: Vec<String>,
        ext_bundles: &ExtensionBundles,
        options: HostOptions,
        addons: Vec<HostAddon>,
        custom_exts: &CustomExtensions,
        execute_extensions_addons: bool,
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
        if let Some(alts) = options.alternative_names {
            for alt in alts {
                host.add_alternative_name(alt);
            }
        }

        let mut se_handles = Vec::new();
        // set extensions
        if execute_extensions_addons {
            let extensions =
                Self::resolve_extensions(&exts, ext_bundles, &host, custom_exts).await?;
            host.extensions = extensions;
            if let Some(true) = options.hsts {
                host.with_hsts();
            }

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
                                opts.ignore_extensions = v.clone()
                            }
                            Some(SearchEngineIgnoreExtensions::ExtendDefaults(v)) => {
                                opts.ignore_extensions.extend_from_slice(v)
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
                            &mut host.extensions,
                            config.api_route.clone(),
                            opts,
                        )
                        .await;
                        handle.index_all(&host).await;
                        se_handles.push(handle);
                    }
                }
            }
        }

        Ok(CloneableHost {
            host,
            exts,
            options: opts_clone,
            addons,

            search_engine_handles: se_handles,
        })
    }
    pub async fn resolve(
        self,
        ext_bundles: &ExtensionBundles,
        custom_exts: &CustomExtensions,
        config_dir: &Path,
    ) -> Result<CloneableHost> {
        match self {
            Host::Plain {
                cert,
                pk,
                path,
                name_override,
                extensions,
                options,
                addons,
            } => {
                let options = options.unwrap_or_default();
                let opts = options.clone().resolve();
                let host = if let Some(name) = name_override {
                    let cert_path = config_dir.join(cert);
                    let pk_path = config_dir.join(pk);
                    kvarn::host::Host::try_read_fs(
                        name,
                        &cert_path,
                        &pk_path,
                        config_dir.join(path),
                        kvarn::Extensions::empty(),
                        opts,
                    )
                    .map_err(|(err, _)| {
                        format!("Failed when reading certificate ({cert_path:?})/private key ({pk_path:?}): {err:?}")
                    })?
                } else {
                    let cert_path = config_dir.join(cert);
                    let pk_path = config_dir.join(pk);
                    kvarn::host::Host::read_fs_name_from_cert(
                        &cert_path,
                        &pk_path,
                        config_dir.join(path),
                        kvarn::Extensions::empty(),
                        opts,
                    )
                    .map_err(|err| {
                        format!("Failed when reading certificate ({cert_path:?})/private key ({pk_path:?}): {err:?}")
                    })?
                };
                Self::assemble(
                    host,
                    extensions,
                    ext_bundles,
                    options,
                    addons.unwrap_or_default(),
                    custom_exts,
                    false,
                )
                .await
            }
            Host::TryCertificatesOrUnencrypted {
                name,
                cert,
                pk,
                path,
                extensions,
                options,
                addons,
            } => {
                let cert_path = config_dir.join(cert);
                let pk_path = config_dir.join(pk);
                let options = options.unwrap_or_default();
                let opts = options.clone().resolve();
                let host = kvarn::host::Host::try_read_fs(
                    name,
                    &cert_path, &pk_path,
                    config_dir.join(path),
                    kvarn::Extensions::empty(),
                    opts,
                )
                .unwrap_or_else(|(err, host)| {
                    error!("Failed when reading certificate ({cert_path:?})/private key ({pk_path:?}): {err:?}");
                    host
                });
                Self::assemble(
                    host,
                    extensions,
                    ext_bundles,
                    options,
                    addons.unwrap_or_default(),
                    custom_exts,
                    false,
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
                    config_dir.join(path),
                    kvarn::Extensions::empty(),
                    opts,
                );
                Self::assemble(
                    host,
                    extensions,
                    ext_bundles,
                    options,
                    addons.unwrap_or_default(),
                    custom_exts,
                    false,
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

    // addons
    pub search_engine_handles: Vec<kvarn_search::SearchEngineHandle>,
}
impl CloneableHost {
    pub async fn clone_with_extensions(
        &self,
        exts: &ExtensionBundles,
        custom_exts: &CustomExtensions,
    ) -> Result<Self> {
        Host::assemble(
            self.host.clone_without_extensions(),
            self.exts.clone(),
            exts,
            self.options.clone(),
            self.addons.clone(),
            custom_exts,
            true,
        )
        .await
    }
}
