use std::collections::HashMap;
use std::fmt::{self, Display};
use std::sync::Arc;

use crate::config::{
    CliOptions, CustomExtensions, ExtensionBundles, HostCollections, Hosts, Result,
};
use kvarn::prelude::{CompactString, ToCompactString};
use log::info;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HostSource {
    Collection(String),
    Hosts(Vec<String>),
    Host(String),
    All,
}
impl HostSource {
    pub async fn resolve(
        self,
        host_collections: &HostCollections,
        hosts: &Hosts,
        exts: &ExtensionBundles,
        custom_exts: &CustomExtensions,
        opts: &CliOptions<'_>,
    ) -> Result<Arc<kvarn::host::Collection>> {
        match self {
            HostSource::Collection(name) => {
                let names = &host_collections
                    .get(name.as_str())
                    .ok_or_else(|| format!("Didn't find a host collection with name {name}."))?
                    .0;
                let collection = crate::config::construct_collection(
                    names,
                    hosts,
                    exts,
                    custom_exts,
                    opts,
                    true,
                )
                .await?;
                Ok(collection)
            }
            HostSource::Hosts(source) => {
                let collection = crate::config::construct_collection(
                    source
                        .into_iter()
                        .map(CompactString::from)
                        .collect::<Vec<_>>(),
                    hosts,
                    exts,
                    custom_exts,
                    opts,
                    true,
                )
                .await?;
                Ok(collection)
            }
            HostSource::Host(source) => {
                let collection = crate::config::construct_collection(
                    vec![source.to_compact_string()],
                    hosts,
                    exts,
                    custom_exts,
                    opts,
                    true,
                )
                .await?;
                Ok(collection)
            }
            HostSource::All => {
                let collection = crate::config::construct_collection(
                    hosts.keys().cloned().collect::<Vec<_>>(),
                    hosts,
                    exts,
                    custom_exts,
                    opts,
                    true,
                )
                .await?;
                Ok(collection)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortMapEntry {
    encrypted: bool,
    source: HostSource,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PortsKind {
    Map(HashMap<u16, PortMapEntry>),
    Standard(HostSource),
    HttpsOnly(HostSource),
    HttpOnly(HostSource),
}
impl PortsKind {
    pub async fn resolve(
        self,
        host_collections: &HostCollections,
        hosts: &Hosts,
        exts: &ExtensionBundles,
        custom_exts: &CustomExtensions,
        opts: &CliOptions<'_>,
    ) -> Result<Vec<kvarn::PortDescriptor>> {
        enum NPorts<'a> {
            One(u16),
            Several(&'a [u16]),
        }
        impl Display for NPorts<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    NPorts::One(port) => write!(f, "port {port}"),

                    NPorts::Several(v) => {
                        write!(f, "ports ")?;
                        for port in v.get(0..v.len() - 1).unwrap_or(&[]) {
                            write!(f, "{port}, ")?;
                        }
                        if let Some(port) = v.last() {
                            write!(f, "{port}")?;
                        }
                        Ok(())
                    }
                }
            }
        }
        let log_bind = |source: &HostSource, port: NPorts| {
            match source {
                HostSource::Collection(name) => {
                    info!("Bind host collection \"{name}\" to {port}")
                }
                HostSource::Hosts(hosts) => info!("Bind hosts {hosts:?} to {port}"),
                HostSource::Host(host) => info!("Bind host collection \"{host}\" to {port}"),
                HostSource::All => info!("Binding all hosts to {port}"),
            };
        };

        match self {
            PortsKind::Map(map) => {
                let mut v = Vec::with_capacity(map.len());
                for (port, entry) in map {
                    log_bind(&entry.source, NPorts::One(port));
                    let descriptor = if entry.encrypted {
                        kvarn::PortDescriptor::new(
                            port,
                            entry
                                .source
                                .resolve(host_collections, hosts, exts, custom_exts, opts)
                                .await?,
                        )
                    } else {
                        kvarn::PortDescriptor::unsecure(
                            port,
                            entry
                                .source
                                .resolve(host_collections, hosts, exts, custom_exts, opts)
                                .await?,
                        )
                    };
                    v.push(descriptor);
                }
                Ok(v)
            }
            PortsKind::Standard(source) => {
                let ports = if opts.high_ports {
                    &[8080, 8443]
                } else {
                    &[80, 443]
                };
                log_bind(&source, NPorts::Several(ports));

                let collection = source
                    .resolve(host_collections, hosts, exts, custom_exts, opts)
                    .await?;
                let v = vec![
                    kvarn::PortDescriptor::unsecure(ports[0], collection.clone()),
                    kvarn::PortDescriptor::new(ports[1], collection),
                ];
                Ok(v)
            }
            PortsKind::HttpsOnly(source) => {
                let port = if opts.high_ports { 8443 } else { 443 };
                log_bind(&source, NPorts::One(port));

                let collection = source
                    .resolve(host_collections, hosts, exts, custom_exts, opts)
                    .await?;
                let v = vec![kvarn::PortDescriptor::new(port, collection)];
                Ok(v)
            }
            PortsKind::HttpOnly(source) => {
                let port = if opts.high_ports { 8080 } else { 80 };
                log_bind(&source, NPorts::One(port));

                let collection = source
                    .resolve(host_collections, hosts, exts, custom_exts, opts)
                    .await?;
                let v = vec![kvarn::PortDescriptor::unsecure(port, collection)];
                Ok(v)
            }
        }
    }
}
