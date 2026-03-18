// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::HashSet, fmt, net::IpAddr};

use ipnetwork::IpNetwork;

use nym_common::trace_err_chain;
use nym_routing::{Node, RequiredRoute, RouteManagerHandle};

pub enum RoutingConfig {
    Mixnet {
        tun_name: String,
        tun_mtu: u16,
    },
    Wireguard {
        /// Entry tunnel name
        entry_tun_name: String,

        /// Exit tunnel name
        exit_tun_name: String,

        /// Entry tunnel MTU
        entry_tun_mtu: u16,

        /// Exit tunnel MTU
        exit_tun_mtu: u16,

        /// Private (in-tunnel) gateway IP
        private_entry_gateway_address: IpAddr,

        /// Public exit gateway IP
        exit_gateway_address: IpAddr,
    },
}

#[derive(Debug, Copy, Clone)]
pub struct RoutingParameters {
    /// Routing table id used for routing all traffic through the tunnel.
    pub table_id: u32,

    /// Firewall mark used for marking traffic that should bypass the tunnel.
    pub fwmark: u32,
}

impl Default for RoutingParameters {
    fn default() -> Self {
        Self {
            table_id: crate::TUNNEL_TABLE_ID,
            fwmark: crate::TUNNEL_FWMARK,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteHandler {
    route_manager: RouteManagerHandle,
}

impl RouteHandler {
    pub async fn new(routing_parameters: RoutingParameters) -> Result<Self> {
        let route_manager = RouteManagerHandle::spawn(
            routing_parameters.table_id,
            routing_parameters.fwmark,
        )
        .await?;
        Ok(Self { route_manager })
    }

    pub async fn add_routes(
        &mut self,
        routing_config: RoutingConfig,
        enable_ipv6: bool,
        killswitch: bool,
    ) -> Result<()> {
        let routes = Self::get_routes(routing_config, enable_ipv6, killswitch);

        self.route_manager.create_routing_rules(enable_ipv6).await?;

        self.route_manager.add_routes(routes).await?;

        Ok(())
    }

    pub async fn remove_routes(&mut self) {
        if let Err(e) = self.route_manager.clear_routes() {
            trace_err_chain!(e, "Failed to remove routes");
        }

        if let Err(e) = self.route_manager.clear_routing_rules().await {
            trace_err_chain!(e, "Failed to remove routing rules");
        }
    }

    pub async fn get_mtu_for_route(&mut self, ip_addr: IpAddr) -> Result<u16> {
        Ok(self.route_manager.get_mtu_for_route(ip_addr).await?)
    }

    pub async fn stop(self) {
        self.route_manager.stop().await;
    }

    pub fn inner_handle(&self) -> nym_routing::RouteManagerHandle {
        self.route_manager.clone()
    }

    fn get_routes(
        routing_config: RoutingConfig,
        enable_ipv6: bool,
        killswitch: bool,
    ) -> HashSet<RequiredRoute> {
        let mut routes = HashSet::new();

        match routing_config {
            RoutingConfig::Mixnet {
                tun_name,
                tun_mtu,
            } => {
                if killswitch {
                    routes.extend(Self::get_default_routes(tun_name, tun_mtu, enable_ipv6));
                } else {
                    tracing::info!(
                        "Kill-switch disabled: skipping default routes for PBR compatibility"
                    );
                }
            }
            RoutingConfig::Wireguard {
                entry_tun_name,
                exit_tun_name,
                entry_tun_mtu,
                exit_tun_mtu,
                private_entry_gateway_address,
                exit_gateway_address,
            } => {
                routes.insert(Self::get_in_tunnel_gateway_entry_route(
                    private_entry_gateway_address,
                    entry_tun_name.clone(),
                    entry_tun_mtu,
                ));
                routes.insert(Self::get_multihop_exit_route(
                    exit_gateway_address,
                    entry_tun_name,
                    entry_tun_mtu,
                ));
                if killswitch {
                    routes.extend(Self::get_default_routes(
                        exit_tun_name,
                        exit_tun_mtu,
                        enable_ipv6,
                    ));
                } else {
                    tracing::info!(
                        "Kill-switch disabled: skipping default routes for PBR compatibility"
                    );
                }
            }
        }

        routes
    }

    fn get_in_tunnel_gateway_entry_route(
        in_tunnel_gateway_address: IpAddr,
        iface: String,
        mtu: u16,
    ) -> RequiredRoute {
        RequiredRoute::new(
            IpNetwork::from(in_tunnel_gateway_address),
            Node::device(iface),
        )
        .use_main_table(false)
        .mtu(mtu)
    }

    fn get_multihop_exit_route(ip_addr: IpAddr, iface: String, mtu: u16) -> RequiredRoute {
        RequiredRoute::new(IpNetwork::from(ip_addr), Node::device(iface))
            .use_main_table(false)
            .mtu(mtu)
    }

    fn get_default_routes(iface: String, mtu: u16, enable_ipv6: bool) -> Vec<RequiredRoute> {
        let mut routes = Vec::new();

        routes.push(RequiredRoute::new(
            "0.0.0.0/0".parse().unwrap(),
            Node::device(iface.to_owned()),
        ));

        if enable_ipv6 {
            routes.push(RequiredRoute::new(
                "::0/0".parse().unwrap(),
                Node::device(iface),
            ));
        }

        routes = routes
            .into_iter()
            .map(|r| r.use_main_table(false))
            .collect();

        routes = routes.into_iter().map(|r| r.mtu(mtu)).collect();

        routes
    }
}

#[derive(Debug)]
pub struct Error {
    inner: nym_routing::Error,
}

unsafe impl Send for Error {}
unsafe impl Sync for Error {}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl From<nym_routing::Error> for Error {
    fn from(value: nym_routing::Error) -> Self {
        Self { inner: value }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "routing error: {}", self.inner)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
