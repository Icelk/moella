use crate::extension::Extension;
use crate::host::Host;
use crate::port::PortsKind;
use log::{info, warn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvarnConfig {
    extensions: HashMap<String, Vec<Extension>>,
    hosts: Vec<Host>,
    host_collections: Option<HashMap<String, Vec<String>>>,
    ports: Option<PortsKind>,
    import: Option<Vec<String>>,
}

#[allow(clippy::or_fun_call)] // it's just as_ref()
async fn read_config(file: impl AsRef<Path>) -> Result<KvarnConfig> {
    let s = file.as_ref();
    let config_file_name = Path::new(s.file_name().unwrap_or(s.as_ref()));
    info!("Read config {}", config_file_name.display());
    let file = tokio::fs::read_to_string(s)
        .await
        .map_err(|err| format!("Failed to read config file {}: {err}", s.display()))?;
    ron::Options::default()
        .with_default_extension(ron::extensions::Extensions::UNWRAP_NEWTYPES)
        .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
        .with_default_extension(ron::extensions::Extensions::UNWRAP_VARIANT_NEWTYPES)
        .from_str(&file)
        .map_err(|err| {
            format!(
                "Parsing config {} failed at {} with message \"{}\"",
                config_file_name.display(),
                err.position,
                err.code
            )
        })
}
pub async fn read_and_resolve(
    file: impl AsRef<str>,
    custom_extensions: &CustomExtensions,
    high_ports: bool,
    mut default_host: Option<&str>,
) -> Result<kvarn::RunConfig> {
    #[derive(Debug)]
    enum Imported {
        File(PathBuf),
        Deserialized(KvarnConfig, PathBuf),
    }

    let file = file.as_ref();

    let mut hosts = HashMap::new();
    let mut ports = None;
    let mut collections: HashMap<String, Vec<String>> = HashMap::new();
    let mut extensions = HashMap::new();

    let mut imports: VecDeque<Imported> = VecDeque::new();
    imports.push_back(Imported::File(file.to_owned().into()));
    let mut imported = HashSet::new();

    while let Some(import) = imports.pop_back() {
        let (mut cfg, import) = match import {
            Imported::File(import) => {
                if imports.is_empty() {
                    (read_config(&import).await?, import)
                } else {
                    match read_config(&import).await {
                        Ok(c) => (c, import),
                        Err(s) => {
                            if s.contains("No such file or directory") {
                                warn!("Skipping config {}: {s}", import.display());
                                continue;
                            } else {
                                return Err(s);
                            }
                        }
                    }
                }
            }
            Imported::Deserialized(cfg, file) => (cfg, file),
        };
        let imports_count = cfg.import.as_ref().map_or(0, Vec::len);
        let config_dir = Path::new(&import)
            .parent()
            .expect("config file is in no directory");
        let descendant_imports = cfg
            .import
            .take()
            .into_iter()
            .flatten()
            .map(|file| config_dir.join(file))
            .filter(|file| imported.insert(file.clone()))
            .map(Imported::File);
        // handle children first
        if imports_count > 0 {
            imports.push_front(Imported::Deserialized(cfg, import.clone()));
            imports.extend(descendant_imports);
            continue;
        } else {
            imports.extend(descendant_imports);
        }

        if let Some(ports_kind) = cfg.ports.take() {
            if let Some((_, first)) = &ports {
                return Err(format!(
                    "Two config files contain a ports parameter. \
                    You must specify exactly 1 per import tree. \
                    First ports parameter in {first:?}, \
                    second ports in {import:?}."
                ));
            }
            ports = Some((ports_kind, import.clone()))
        }
        for (name, ext) in cfg.extensions {
            if let Some((_, file)) = extensions.get(&name) {
                return Err(format!(
                    "Duplicate extension with name {name}. Second occurrence in file {import:?}. \
                    First occurrence in {file:?}.",
                ));
            }
            extensions.insert(name, (ext, import.clone()));
        }
        for host in cfg.hosts {
            let host = host
                .resolve(&extensions, custom_extensions, config_dir)
                .await?;

            info!(
                "Loaded host {} from {} with extensions {:?}.",
                host.host.name,
                import.display(),
                host.exts
            );
            if let Some((_, file)) = hosts.get(&host.host.name) {
                return Err(format!(
                    "Duplicate host with name {}. Second occurrence in file {import:?}. \
                    First occurrence in {file:?}.",
                    host.host.name
                ));
            }
            hosts.insert(host.host.name.clone(), (host, import.clone()));
        }

        if let Some(collection) = cfg.host_collections {
            for (name, mut host_names) in collection {
                let entry = collections.entry(name);
                let entry = entry.or_default();
                host_names.append(entry);
                *entry = host_names;
            }
        }
    }
    let mut built_collections = HashMap::new();
    for (name, host_names) in collections {
        info!("Create host collection \"{name}\" with hosts {host_names:?}");
        let collection = construct_collection(
            host_names,
            &hosts,
            &extensions,
            custom_extensions,
            &mut default_host,
        )
        .await?;
        built_collections.insert(name, collection);
    }
    let mut rc = kvarn::RunConfig::new();
    for descriptor in ports
        .ok_or("Your config must contain a `ports` paramter.")?
        .0
        .resolve(
            &built_collections,
            &hosts,
            &extensions,
            custom_extensions,
            high_ports,
            &mut default_host,
        )
        .await?
    {
        rc = rc.bind(descriptor);
    }

    if let Some(default) = default_host {
        return Err(format!("Your choosen default host {default} wasn't found."));
    }

    Ok(rc)
}

type CustomExtensionFn = Box<
    dyn for<'a> Fn(
        &'a mut kvarn::Extensions,
        ron::Value,
        PathBuf,
    ) -> kvarn::extensions::RetSyncFut<'a, Result<()>>,
>;
type CustomExtensionsInner = HashMap<String, CustomExtensionFn>;
pub struct CustomExtensions(pub(crate) CustomExtensionsInner);
impl CustomExtensions {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
    /// Same as [`Self::insert_without_data`], but without access to the config dir
    /// (for usage with other extensions in Mölla).
    pub fn insert_without_data_or_config_dir(
        &mut self,
        name: impl Into<String>,
        extension: impl Fn(&mut kvarn::Extensions) -> kvarn::extensions::RetSyncFut<Result<()>>
            + Send
            + Sync
            + 'static,
    ) {
        self.insert_without_data(name, move |ext, _| extension(ext))
    }
    /// Same as [`Self::insert`], but without getting any config data specified after the extension
    /// name.
    pub fn insert_without_data(
        &mut self,
        name: impl Into<String>,
        extension: impl Fn(&mut kvarn::Extensions, PathBuf) -> kvarn::extensions::RetSyncFut<Result<()>>
            + Send
            + Sync
            + 'static,
    ) {
        self.insert::<()>(name, move |ext, (), config_dir| extension(ext, config_dir));
    }
    pub fn insert<T: DeserializeOwned + Sync + Send + 'static>(
        &mut self,
        name: impl Into<String>,
        extension: impl Fn(&mut kvarn::Extensions, T, PathBuf) -> kvarn::extensions::RetSyncFut<Result<()>>
            + Send
            + Sync
            + 'static,
    ) {
        let extension = Arc::new(extension);
        let f: CustomExtensionFn = Box::new(move |exts, value: ron::Value, config_dir: PathBuf| {
            let extension = Arc::clone(&extension);
            Box::pin(async move {
                let config = value
                    .into_rust()
                    .map_err(|err| format!("Custom extension data has invalid format: {err}"))?;
                extension(exts, config, config_dir).await?;
                Ok::<(), String>(())
            })
        });
        self.0.insert(name.into(), f);
    }
}
impl Default for CustomExtensions {
    fn default() -> Self {
        Self::empty()
    }
}

pub async fn construct_collection(
    host_names: Vec<String>,
    hosts: &Hosts,
    exts: &ExtensionBundles,
    custom_exts: &CustomExtensions,
    default_host: &mut Option<&str>,
) -> Result<Arc<kvarn::host::Collection>> {
    let mut b = kvarn::host::Collection::builder();
    let mut se = vec![];
    for host in host_names {
        let host = hosts
            .get(&host)
            .ok_or_else(|| format!("Didn't find a host with name {host}."))?
            .0
            .clone_with_extensions(exts, custom_exts)
            .await?;
        for se_handle in host.search_engine_handles {
            se.push((host.host.name.clone(), se_handle))
        }
        if default_host.map_or(false, |default| default == host.host.name) {
            // we can take, because we're guaranteed only 1 host with this name will exist
            default_host.take();
            b = b.default(host.host);
        } else {
            b = b.insert(host.host);
        }
    }
    let collection = b.build();
    for (host, se) in se {
        // assume we'll watch for the rest of time
        core::mem::forget(
            se.watch(&host, collection.clone())
                .await
                .map_err(|err| format!("Failed to start search engine watch: {err:?}"))?,
        );
    }
    Ok(collection)
}

pub type HostCollections = HashMap<String, Arc<kvarn::host::Collection>>;
pub type Hosts = HashMap<String, (crate::host::CloneableHost, PathBuf)>;
pub type ExtensionBundles = HashMap<String, (Vec<crate::extension::Extension>, PathBuf)>;
