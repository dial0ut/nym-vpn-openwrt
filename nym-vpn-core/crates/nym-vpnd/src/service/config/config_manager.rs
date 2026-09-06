// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::service::{
    config::{
        DEFAULT_CONFIG_FILE_JSON, DEFAULT_CONFIG_FILE_TOML, VpnServiceConfigExt,
        VpnServiceConfigVersion, legacy,
    },
    error::{Error, Result},
    read_json_config_file, read_toml_config_file, write_json_config_file,
};
use nym_common::trace_err_chain;
use nym_registration_client::MixnetClientConfig;
use nym_vpn_api_client::{DEFAULT_FRONT_POLICY, FrontPolicy, set_shared_front_policy};
use nym_vpn_lib::{
    DEFAULT_MIN_GATEWAY_PERFORMANCE, DEFAULT_MIN_MIXNODE_PERFORMANCE,
    tunnel_state_machine::{
        DnsOptions, GatewayPerformanceOptions, MixnetTunnelOptions, TunnelSettings,
        WireguardMultihopMode, WireguardTunnelOptions,
    },
};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{fs, sync::broadcast};

pub struct VpnServiceConfigManager {
    json_config_path: PathBuf,
    config: nym_vpn_lib_types::VpnServiceConfig,

    // Used to send `ConfigChanged` events when the config is updated.
    // It's only optional to simplify testing.
    tunnel_event_tx: Option<broadcast::Sender<nym_vpn_lib_types::TunnelEvent>>,
}

impl VpnServiceConfigManager {
    pub async fn new(
        network_config_dir: &Path,
        tunnel_event_tx: Option<broadcast::Sender<nym_vpn_lib_types::TunnelEvent>>,
    ) -> Result<Self> {
        let toml_config_path = network_config_dir.join(DEFAULT_CONFIG_FILE_TOML);
        let json_config_path = network_config_dir.join(DEFAULT_CONFIG_FILE_JSON);
        let (config, version) =
            match Self::read_from_file(&toml_config_path, &json_config_path).await {
                Ok((config, version)) => (config, version),
                Err(e) => {
                    trace_err_chain!(
                        e,
                        "Failed to read service config file {}; using default",
                        json_config_path.display()
                    );
                    // Stash the unreadable file instead of overwriting it
                    // below: the user's settings stay recoverable and the
                    // corrupt content survives as evidence of what happened.
                    if json_config_path.exists() {
                        let backup_path = json_config_path.with_extension("json.bak");
                        match fs::rename(&json_config_path, &backup_path).await {
                            Ok(()) => tracing::error!(
                                "Preserved unreadable service config as {}",
                                backup_path.display()
                            ),
                            Err(e) => trace_err_chain!(
                                e,
                                "Failed to preserve unreadable service config {}",
                                json_config_path.display()
                            ),
                        }
                    }
                    (nym_vpn_lib_types::VpnServiceConfig::default(), None)
                }
            };

        let config_manager = Self {
            json_config_path,
            config,
            tunnel_event_tx,
        };

        // The fronting policy is process-wide state, not something the tunnel
        // settings carry: put the persisted choice in force before the daemon
        // builds its API clients.
        apply_front_policy(config_manager.config.stealth_api);

        // If we didn't read the latest version then write the config straight back to file
        if version != Some(VpnServiceConfigVersion::latest()) {
            // Failure is already logged; at startup there is no client to report to
            let _ = config_manager.write_to_file().await;
        }

        // If the deprecated TOML file exists then remove it
        if toml_config_path.exists() {
            tracing::info!(
                "Removing deprecated config file {}",
                toml_config_path.display()
            );
            if let Err(e) = fs::remove_file(&toml_config_path).await {
                trace_err_chain!(e, "Failed to remove deprecated config file");
            }
        }

        Ok(config_manager)
    }

    pub fn config(&self) -> &nym_vpn_lib_types::VpnServiceConfig {
        &self.config
    }

    #[cfg(test)]
    pub async fn set_config(&mut self, config: nym_vpn_lib_types::VpnServiceConfig) {
        if self.config != config {
            self.config = config;
            let _ = self.save_config_and_send_event().await;
        }
    }

    pub async fn set_entry_point(
        &mut self,
        entry_point: nym_vpn_lib_types::EntryPoint,
    ) -> Result<(), String> {
        if self.config.entry_point != entry_point {
            self.config.entry_point = entry_point;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_exit_point(
        &mut self,
        exit_point: nym_vpn_lib_types::ExitPoint,
    ) -> Result<(), String> {
        if self.config.exit_point != exit_point {
            self.config.exit_point = exit_point;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_disable_ipv6(&mut self, disable_ipv6: bool) -> Result<(), String> {
        if self.config.disable_ipv6 != disable_ipv6 {
            self.config.disable_ipv6 = disable_ipv6;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_enable_two_hop(&mut self, enable_two_hop: bool) -> Result<(), String> {
        if self.config.enable_two_hop != enable_two_hop {
            self.config.enable_two_hop = enable_two_hop;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_enable_lewes_protocol(
        &mut self,
        enable_lewes_protocol: bool,
    ) -> Result<(), String> {
        if self.config.enable_lewes_protocol != enable_lewes_protocol {
            self.config.enable_lewes_protocol = enable_lewes_protocol;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_netstack(&mut self, netstack: bool) -> Result<(), String> {
        if self.config.netstack != netstack {
            self.config.netstack = netstack;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_allow_lan(&mut self, allow_lan: bool) -> Result<(), String> {
        if self.config.allow_lan != allow_lan {
            self.config.allow_lan = allow_lan;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_enable_bridges(&mut self, enable_bridges: bool) -> Result<(), String> {
        if self.config.enable_bridges != enable_bridges {
            self.config.enable_bridges = enable_bridges;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_residential_exit(&mut self, residential_only: bool) -> Result<(), String> {
        if self.config.residential_exit != residential_only {
            self.config.residential_exit = residential_only;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_enable_ad_blocking(&mut self, enable_ad_blocking: bool) -> Result<(), String> {
        if self.config.enable_ad_blocking != enable_ad_blocking {
            self.config.enable_ad_blocking = enable_ad_blocking;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_killswitch(&mut self, killswitch: bool) -> Result<(), String> {
        if self.config.killswitch != killswitch {
            self.config.killswitch = killswitch;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_legacy_split_tunnel(&mut self, legacy_split_tunnel: bool) -> Result<(), String> {
        if self.config.legacy_split_tunnel != legacy_split_tunnel {
            self.config.legacy_split_tunnel = legacy_split_tunnel;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    /// Stealth API connect: front every Nym API request through the cover
    /// domains (on) or only after a direct request fails (off, the default).
    /// Takes effect on the next API request; the tunnel is not touched.
    pub async fn set_stealth_api(&mut self, stealth_api: bool) -> Result<(), String> {
        if self.config.stealth_api != stealth_api {
            self.config.stealth_api = stealth_api;
            apply_front_policy(stealth_api);
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub async fn set_inbound_exemptions(
        &mut self,
        exemptions: Vec<nym_vpn_lib_types::InboundExemption>,
    ) -> Result<(), String> {
        if self.config.inbound_exemptions != exemptions {
            self.config.inbound_exemptions = exemptions;
            self.save_config_and_send_event().await
        } else {
            Ok(())
        }
    }

    pub fn inbound_exemptions(&self) -> &[nym_vpn_lib_types::InboundExemption] {
        &self.config.inbound_exemptions
    }

    /// Enable or disable custom DNS servers
    ///
    /// Returns true if the setting has changed, otherwise false if it's the same.
    /// An error means the setting changed in memory but could not be persisted.
    pub async fn set_enable_custom_dns(&mut self, enable_custom_dns: bool) -> Result<bool, String> {
        if self.config.enable_custom_dns == enable_custom_dns {
            Ok(false)
        } else {
            self.config.enable_custom_dns = enable_custom_dns;
            self.save_config_and_send_event().await.map(|()| true)
        }
    }

    /// Update custom DNS servers
    ///
    /// Returns true if custom DNS servers have changed, otherwise false if they're the same.
    /// An error means the setting changed in memory but could not be persisted.
    pub async fn set_custom_dns(&mut self, custom_dns: Vec<IpAddr>) -> Result<bool, String> {
        if self.config.custom_dns == custom_dns {
            Ok(false)
        } else {
            self.config.custom_dns = custom_dns;
            self.save_config_and_send_event().await.map(|()| true)
        }
    }

    pub async fn set_mixnet_traffic_config(
        &mut self,
        mixnet_traffic: nym_vpn_lib_types::MixnetTrafficConfig,
    ) -> Result<(), String> {
        mixnet_traffic.validate()?;
        if self.config.mixnet_traffic != mixnet_traffic {
            self.config.mixnet_traffic = mixnet_traffic;
            self.save_config_and_send_event().await?;
        }
        Ok(())
    }

    #[allow(unused)]
    pub async fn set_min_gateway_vpn_performance(
        &mut self,
        min_gateway_vpn_performance: Option<u8>,
    ) {
        if self.config.min_gateway_vpn_performance != min_gateway_vpn_performance {
            self.config.min_gateway_vpn_performance =
                min_gateway_vpn_performance.map(|u| u.min(100));
            let _ = self.save_config_and_send_event().await;
        }
    }

    async fn save_config_and_send_event(&self) -> Result<(), String> {
        // This function already logs
        let write_result = self.write_to_file().await;

        // Notify all clients that the config has changed. Do this even when
        // the write failed: the in-memory config did change and is what the
        // tunnel runs with.
        if let Some(tx) = self.tunnel_event_tx.as_ref() {
            match tx.send(nym_vpn_lib_types::TunnelEvent::ConfigChanged(Box::new(
                self.config.clone(),
            ))) {
                Ok(recv_count) => {
                    tracing::info!("Sent config changed event to {recv_count} receivers");
                }
                Err(e) => {
                    tracing::error!("Failed to send config changed event: {e}");
                }
            }
        }

        write_result.map_err(|e| {
            // Flatten the source chain ("config setup error" alone tells the
            // user nothing; the io error carries the ENOSPC/EROFS detail).
            let mut msg = format!("setting applied but not saved to disk (lost on reboot): {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                msg.push_str(": ");
                msg.push_str(&s.to_string());
                source = s.source();
            }
            msg
        })
    }

    /// Returns the configuration as well as the version read from file.
    async fn read_from_file(
        toml_config_path: &Path,
        json_config_path: &Path,
    ) -> Result<(
        nym_vpn_lib_types::VpnServiceConfig,
        Option<VpnServiceConfigVersion>,
    )> {
        let (config, version) = if json_config_path.exists() {
            let ext_config = read_json_config_file::<VpnServiceConfigExt>(json_config_path)
                .await
                .map_err(Error::ConfigSetup)?;
            let version = ext_config.version();

            tracing::info!(
                "Read service config version {version} from {}",
                json_config_path.display()
            );

            let config = nym_vpn_lib_types::VpnServiceConfig::try_from(ext_config)
                .map_err(Error::ConfigSetup)?;

            (config, Some(version))
        } else if toml_config_path.exists() {
            let legacy_config = read_toml_config_file::<legacy::VpnServiceConfig>(toml_config_path)
                .await
                .map_err(Error::ConfigSetup)?;

            tracing::info!("Read service config from {}", toml_config_path.display());

            let config = nym_vpn_lib_types::VpnServiceConfig::try_from(legacy_config)
                .map_err(Error::ConfigSetup)?;

            (config, None)
        } else {
            tracing::info!("Using default service config");

            (nym_vpn_lib_types::VpnServiceConfig::default(), None)
        };

        Ok((config, version))
    }

    // Only public for unit tests
    pub(crate) async fn write_to_file(&self) -> Result<()> {
        let ext_config = VpnServiceConfigExt::try_from(&self.config)
            .map_err(Error::ConfigSetup)
            .inspect_err(|e| {
                tracing::error!("Failed to convert service config to JSON: {e}");
            })?;
        let version = ext_config.version();

        match write_json_config_file(&self.json_config_path, &ext_config)
            .await
            .map_err(Error::ConfigSetup)
        {
            Ok(_) => {
                tracing::info!(
                    "Writing service config version {version} to {}",
                    self.json_config_path.display()
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    "Failed to write service config version {version} to {}: {e}",
                    self.json_config_path.display()
                );
                Err(e)
            }
        }
    }

    pub fn generate_tunnel_settings(&self) -> TunnelSettings {
        tracing::info!("Using config: {:?}", self.config);

        // `stealth_api` is deliberately absent from TunnelSettings: it is an
        // API-transport switch applied through the shared fronting policy, so
        // changing it must not force a reconnect.

        let gateway_options = GatewayPerformanceOptions {
            mixnet_min_performance: self.config.mixnet_traffic.min_gateway_mixnet_performance,
            vpn_min_performance: self.config.min_gateway_vpn_performance,
        };

        let mixnet_client_config = MixnetClientConfig {
            disable_real_traffic_poisson_process: self.config.mixnet_traffic.disable_poisson_rate,
            disable_background_cover_traffic: self
                .config
                .mixnet_traffic
                .disable_background_cover_traffic,
            min_mixnode_performance: Some(
                self.config
                    .mixnet_traffic
                    .min_mixnode_performance
                    .unwrap_or(DEFAULT_MIN_MIXNODE_PERFORMANCE),
            ),
            min_gateway_performance: Some(
                self.config
                    .mixnet_traffic
                    .min_gateway_mixnet_performance
                    .unwrap_or(DEFAULT_MIN_GATEWAY_PERFORMANCE),
            ),
            loop_cover_traffic_average_delay: self
                .config
                .mixnet_traffic
                .poisson_parameter_for_loop_cover_stream
                .map(|ms| Duration::from_millis(ms.into())),

            average_packet_delay: self
                .config
                .mixnet_traffic
                .average_packet_delay
                .map(|ms| Duration::from_millis(ms.into())),

            message_sending_average_delay: self
                .config
                .mixnet_traffic
                .message_sending_average_delay
                .map(|ms| Duration::from_millis(ms.into())),
        };

        let tunnel_type = if self.config.enable_two_hop {
            nym_vpn_lib_types::TunnelType::Wireguard
        } else {
            nym_vpn_lib_types::TunnelType::Mixnet
        };

        let dns = if self.config.enable_custom_dns && !self.config.custom_dns.is_empty() {
            DnsOptions::Custom(self.config.custom_dns.clone())
        } else {
            DnsOptions::default()
        };

        TunnelSettings {
            enable_ipv6: !self.config.disable_ipv6,
            allow_lan: self.config.allow_lan,
            residential_exit: self.config.residential_exit,
            tunnel_type,
            mixnet_tunnel_options: MixnetTunnelOptions { mtu: None },
            wireguard_tunnel_options: WireguardTunnelOptions {
                // netstack is no longer a separate mode; always use TunTun.
                // The `netstack` config field is preserved for backward compatibility
                // but has no effect.
                multihop_mode: WireguardMultihopMode::TunTun,
                enable_bridges: self.config.enable_bridges,
            },
            gateway_performance_options: gateway_options,
            mixnet_client_config: Some(mixnet_client_config),
            entry_point: Box::new(self.config.entry_point.clone()),
            exit_point: Box::new(self.config.exit_point.clone()),
            dns,
            // Legacy split tunneling and the kill-switch are mutually exclusive:
            // in legacy/PBR mode the daemon must not block non-tunnel WAN egress
            // (that traffic is the whole point), so force the effective kill-switch
            // off regardless of the stored value. The UI also greys out the toggle,
            // but this is the authoritative backstop.
            killswitch: self.config.killswitch && !self.config.legacy_split_tunnel,
            legacy_split_tunnel: self.config.legacy_split_tunnel,
            inbound_exemptions: self
                .config
                .inbound_exemptions
                .iter()
                .map(|e| {
                    let proto = match e.proto {
                        nym_vpn_lib_types::InboundExemptionProtocol::Tcp => {
                            nym_firewall::TransportProtocol::Tcp
                        }
                        nym_vpn_lib_types::InboundExemptionProtocol::Udp => {
                            nym_firewall::TransportProtocol::Udp
                        }
                    };
                    let mut ex = nym_firewall::InboundExemption::new(proto, e.dport);
                    if let Some(label) = &e.label {
                        ex = ex.with_label(label);
                    }
                    ex
                })
                .collect(),
        }
    }
}

/// Map the Stealth API switch onto the shared domain-fronting policy that every
/// fronting-capable API client in this process follows.
fn apply_front_policy(stealth_api: bool) {
    let policy = if stealth_api {
        FrontPolicy::Always
    } else {
        DEFAULT_FRONT_POLICY
    };
    tracing::info!(
        "API domain fronting policy: {policy:?} (stealth API {})",
        if stealth_api { "on" } else { "off" }
    );
    set_shared_front_policy(policy);
}
