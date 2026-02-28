// Copyright 2016-2024 Mullvad VPN AB. All Rights Reserved.
// Copyright 2024 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Manage routing tables on Linux.
#![allow(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]

use ipnetwork::IpNetwork;
use std::{fmt, net::IpAddr};

#[path = "unix/mod.rs"]
mod imp;

use netlink_packet_route::route::RouteHeader;

pub use imp::{Error, RouteManagerHandle};

/// A network route with a specific network node, destination and an optional metric.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct Route {
    node: Node,
    prefix: IpNetwork,
    metric: Option<u32>,
    table_id: u32,
    mtu: Option<u32>,
}

impl Route {
    /// Construct a new Route
    pub fn new(node: Node, prefix: IpNetwork) -> Self {
        Self {
            node,
            prefix,
            metric: None,
            table_id: u32::from(RouteHeader::RT_TABLE_MAIN),
            mtu: None,
        }
    }

    fn table(mut self, new_id: u32) -> Self {
        self.table_id = new_id;
        self
    }

    /// Returns the network node of the route.
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.prefix, self.node)?;
        if let Some(metric) = &self.metric {
            write!(f, " metric {}", *metric)?;
        }
        write!(f, " table {}", self.table_id)?;
        if let Some(mtu) = self.mtu {
            write!(f, " mtu {mtu}")?;
        }
        Ok(())
    }
}

/// A network route that should be applied by the route manager.
/// It can either be routed through a specific network node or it can be routed through the current
/// default route.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct RequiredRoute {
    /// Route's prefix
    pub prefix: IpNetwork,
    node: NetNode,
    /// Specifies whether the route should be added to the main routing table or not.
    main_table: bool,
    /// Specifies route MTU
    mtu: Option<u16>,
}

impl RequiredRoute {
    /// Constructs a new required route.
    pub fn new(prefix: IpNetwork, node: impl Into<NetNode>) -> Self {
        Self {
            node: node.into(),
            prefix,
            main_table: true,
            mtu: None,
        }
    }

    /// Sets the routing table ID of the route.
    pub fn use_main_table(mut self, main_table: bool) -> Self {
        self.main_table = main_table;
        self
    }

    /// Set route MTU to the given value.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
}

/// A NetNode represents a network node - either a real one or a symbolic default one.
/// A route with a symbolic default node will be changed whenever a new default route is created.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum NetNode {
    /// A real node will be used to set a regular route that will remain unchanged for the lifetime
    /// of the route manager
    RealNode(Node),
}

impl From<Node> for NetNode {
    fn from(node: Node) -> NetNode {
        NetNode::RealNode(node)
    }
}

/// Node represents a real network node - it can be identified by a network interface name, an IP
/// address or both.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct Node {
    ip: Option<IpAddr>,
    device: Option<String>,
}

impl Node {
    /// Construct an Node with both an IP address and an interface name.
    pub fn new(address: IpAddr, iface_name: String) -> Self {
        Self {
            ip: Some(address),
            device: Some(iface_name),
        }
    }

    /// Construct an Node from an IP address.
    pub fn address(address: IpAddr) -> Node {
        Self {
            ip: Some(address),
            device: None,
        }
    }

    /// Construct a Node from a network interface name.
    pub fn device(iface_name: String) -> Node {
        Self {
            ip: None,
            device: Some(iface_name),
        }
    }

    /// Retrieve a node's IP address
    pub fn get_address(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Retrieve a node's network interface name
    pub fn get_device(&self) -> Option<&str> {
        self.device.as_ref().map(|s| s.as_ref())
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = &self.ip {
            write!(f, "{ip}")?;
        }
        if let Some(device) = &self.device {
            let extra_space = if self.ip.is_some() { " " } else { "" };
            write!(f, "{extra_space}dev {device}")?;
        }
        Ok(())
    }
}
