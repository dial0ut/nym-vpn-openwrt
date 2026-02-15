// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt firewall integration module.
//!
//! This module provides firewall backends that integrate properly with OpenWrt's
//! firewall system (fw3 for iptables, fw4 for nftables).
//!
//! Key design principles:
//! - Single atomic rule application (no lock contention)
//! - Integration with OpenWrt's include mechanism for cleanup
//! - Support for both fw3 (OpenWrt ≤21.02) and fw4 (OpenWrt ≥22.03)

mod fw3;
mod fw4;
mod detect;
mod common;

pub use detect::{FirewallSystem, detect_system};
pub use fw3::Fw3Firewall;
pub use fw4::Fw4Firewall;

use std::path::Path;

use crate::{FirewallArguments, FirewallPolicy};

pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur with OpenWrt firewall operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to write firewall rules: {0}")]
    WriteError(#[from] std::io::Error),

    #[error("failed to apply firewall rules: {0}")]
    ApplyError(String),

    #[error("failed to detect firewall system")]
    DetectionError,

    #[error("unsupported firewall system")]
    UnsupportedSystem,

    #[error("failed to install include script: {0}")]
    InstallError(String),
}

/// Unified OpenWrt firewall that delegates to the appropriate backend.
pub struct Firewall {
    inner: FirewallInner,
}

enum FirewallInner {
    Fw3(Fw3Firewall),
    Fw4(Fw4Firewall),
}

impl Firewall {
    pub fn from_args(args: FirewallArguments) -> Result<Self> {
        Self::new(args.fwmark)
    }

    pub fn new(_fwmark: u32) -> Result<Self> {
        let system = detect_system();
        tracing::info!("Detected OpenWrt firewall system: {:?}", system);

        // Note: fwmark is not used in the OpenWrt firewall backends.
        // It is used elsewhere (routing, socket marking, WireGuard device config)
        // but the firewall rules don't need it — split tunneling and fwmark-based
        // filtering from the upstream desktop backend are not applicable to routers.
        let inner = match system {
            FirewallSystem::Fw3 => {
                FirewallInner::Fw3(Fw3Firewall::new()?)
            }
            FirewallSystem::Fw4 => {
                FirewallInner::Fw4(Fw4Firewall::new()?)
            }
            FirewallSystem::Unknown => {
                // Fall back to fw3/iptables for unknown OpenWrt systems
                tracing::warn!("Unknown firewall system, falling back to iptables");
                FirewallInner::Fw3(Fw3Firewall::new()?)
            }
        };

        Ok(Firewall { inner })
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        match &mut self.inner {
            FirewallInner::Fw3(fw) => fw.apply_policy(policy),
            FirewallInner::Fw4(fw) => fw.apply_policy(policy),
        }
    }

    pub fn reset_policy(&mut self) -> Result<()> {
        match &mut self.inner {
            FirewallInner::Fw3(fw) => fw.reset_policy(),
            FirewallInner::Fw4(fw) => fw.reset_policy(),
        }
    }

    /// Install the OpenWrt include scripts for proper integration.
    /// This should be called once during package installation.
    pub fn install_include_scripts() -> Result<()> {
        let system = detect_system();
        match system {
            FirewallSystem::Fw3 => fw3::install_include_script(),
            FirewallSystem::Fw4 => fw4::install_include_script(),
            FirewallSystem::Unknown => {
                tracing::warn!("Unknown system, skipping include script installation");
                Ok(())
            }
        }
    }
}

/// Check if we're running on OpenWrt.
pub fn is_openwrt() -> bool {
    Path::new("/etc/openwrt_release").exists()
}
