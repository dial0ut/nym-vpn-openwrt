// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_http_api_client::ResolveError;
use nym_vpn_lib_types::{CompleteDnsReport, DnsResolution};
use nym_vpn_network_config::Network;

use hickory_resolver::{
    Resolver, ResolverBuilder,
    config::{CLOUDFLARE, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use std::{
    iter,
    net::IpAddr,
    time::{Duration, Instant},
};

pub struct DnsDiagnostic {
    hostnames: Vec<String>,
}

impl DnsDiagnostic {
    fn system() -> Result<ConfiguredResolver, ResolveError> {
        let nameservers = hickory_resolver::system_conf::read_system_conf()
            .map(|(config, _)| config.name_servers().to_vec())
            .unwrap_or_default();
        Ok(ConfiguredResolver {
            resolver: Self::build_resolver(Resolver::builder_tokio()?)?,
            nameservers,
        })
    }

    fn from_nameservers(
        nameservers: Vec<NameServerConfig>,
    ) -> Result<ConfiguredResolver, ResolveError> {
        let config = ResolverConfig::from_parts(None, Vec::new(), nameservers.clone());
        Ok(ConfiguredResolver {
            resolver: Self::build_resolver(Resolver::builder_with_config(
                config,
                TokioRuntimeProvider::default(),
            ))?,
            nameservers,
        })
    }

    fn build_resolver(
        base: ResolverBuilder<TokioRuntimeProvider>,
    ) -> Result<Resolver<TokioRuntimeProvider>, ResolveError> {
        let mut options = ResolverOpts::default();
        options.attempts = 0;
        options.cache_size = 0;
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
        options.timeout = Duration::from_secs(2);
        Ok(base.with_options(options).build()?)
    }

    pub async fn run_diagnostic(network: &Network) -> CompleteDnsReport {
        tracing::info!("Running DNS diagnostic");

        let many_diagnostic = DnsDiagnostic {
            hostnames: hostnames(network),
        };

        tracing::debug!(
            "Running system DNS diagnostic on: {:?}",
            many_diagnostic.hostnames
        );

        tracing::debug!("System DNS diagnostic");
        let system_resolver = DnsDiagnostic::system();
        let system = match system_resolver {
            Ok(resolver) => Ok(many_diagnostic.resolve(&resolver).await),
            Err(e) => Err(e),
        }
        .into();

        let single_hostname = many_diagnostic.hostnames[0].clone();
        let ns_diagnostic = DnsDiagnostic {
            hostnames: vec![single_hostname],
        };

        tracing::debug!(
            "Running per ns DNS diagnostic on: {:?}",
            many_diagnostic.hostnames
        );

        let mut name_servers: Vec<NameServerConfig> = QUAD9
            .tls()
            .chain(QUAD9.udp_and_tcp())
            .chain(QUAD9.https())
            .chain(CLOUDFLARE.tls())
            .chain(CLOUDFLARE.udp_and_tcp())
            .chain(CLOUDFLARE.https())
            .collect();

        // Also probe the host's actually-configured resolvers (e.g. dnsmasq on
        // 127.0.0.1, or the ISP/upstream resolver), so the per-nameserver report
        // reveals whether the router's own DNS resolves the Nym API/gateway
        // hostnames — a common split-DNS / captive-portal failure mode that the
        // fixed quad9/cloudflare probes can't surface (upstream nym-vpn-client
        // #5267). A missing/unparseable resolv.conf degrades gracefully.
        match hickory_resolver::system_conf::read_system_conf() {
            Ok((system_config, _)) => {
                name_servers.extend(system_config.name_servers().iter().cloned());
            }
            Err(e) => {
                tracing::warn!("Failed to read system DNS configuration for diagnostic: {e}");
            }
        }

        let mut results = Vec::new();
        for nameserver in name_servers {
            tracing::debug!("DNs diagnostic - {nameserver:?}");
            let label = format!("{:?}", [&nameserver]);
            match DnsDiagnostic::from_nameservers(vec![nameserver]) {
                Ok(resolver) => results.append(&mut ns_diagnostic.resolve(&resolver).await),
                // Reported, not dropped: a nameserver the resolver cannot even
                // be built for is a finding of its own.
                Err(err) => results.push(DnsResolution {
                    nameservers: label,
                    hostname: ns_diagnostic.hostnames[0].clone(),
                    resolution: Err::<Vec<IpAddr>, _>(err).into(),
                    resolution_duration_ms: 0,
                }),
            }
        }

        CompleteDnsReport {
            system,
            by_nameserver: results,
        }
    }

    async fn resolve(&self, dns_resolver: &impl DnsResolver) -> Vec<DnsResolution> {
        futures::future::join_all(
            self.hostnames
                .iter()
                .map(|h| Self::dns_resolution(h, dns_resolver)),
        )
        .await
    }

    async fn dns_resolution(hostname: &str, dns_resolver: &impl DnsResolver) -> DnsResolution {
        let now = Instant::now();
        let resolution = dns_resolver.resolve(hostname).await;
        let resolution_duration_ms = now.elapsed().as_millis();

        DnsResolution {
            nameservers: format!("{:?}", dns_resolver.nameservers()),
            hostname: hostname.into(),
            resolution: resolution.into(),
            resolution_duration_ms,
        }
    }
}

pub fn hostnames(network: &Network) -> Vec<String> {
    let api_urls = network
        .nym_api_urls_as_urls()
        .into_iter()
        .chain(network.nym_vpn_api_urls_as_urls())
        .flatten()
        .chain(iter::once(network.nyxd_url.clone()));

    // Convert str urls to hostnames
    api_urls
        .filter_map(|url| match url.host_str() {
            Some(host) => Some(host.to_string()),
            None => {
                tracing::warn!("URL has no host component: {}", url);
                None
            }
        })
        .collect()
}

// QoL trait to accommodate both our custom resolver and hickory ones
#[async_trait::async_trait]
trait DnsResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, ResolveError>;

    fn nameservers(&self) -> Vec<NameServerConfig>;
}

/// A resolver and the nameservers it was built from: hickory no longer
/// exposes a resolver's configuration, and the report names them.
struct ConfiguredResolver {
    resolver: Resolver<TokioRuntimeProvider>,
    nameservers: Vec<NameServerConfig>,
}

#[async_trait::async_trait]
impl DnsResolver for ConfiguredResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Ok(self.resolver.lookup_ip(hostname).await?.iter().collect())
    }

    fn nameservers(&self) -> Vec<NameServerConfig> {
        self.nameservers.clone()
    }
}
