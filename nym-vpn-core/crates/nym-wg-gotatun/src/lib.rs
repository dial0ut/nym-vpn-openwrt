// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Pure-Rust WireGuard backend for nym-vpn, powered by gotatun.
//!
//! This crate provides the same public API surface as `nym-wg-go` but uses
//! gotatun (a pure-Rust WireGuard implementation) instead of wireguard-go + CGo FFI.

#[cfg(feature = "amnezia")]
pub mod amnezia;
#[cfg(feature = "amnezia")]
pub mod amnezia_udp;
pub mod wireguard_go;

use std::{fmt, net::SocketAddr};

use base64::engine::Engine;
use ipnetwork::IpNetwork;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to start the tunnel: {0}")]
    StartTunnel(String),

    #[error("failed to build gotatun device: {0}")]
    DeviceBuild(String),

    #[error("failed to create TUN device from fd: {0}")]
    TunFromFd(String),

    #[error("failed to update peers: {0}")]
    UpdatePeers(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// WireGuard peer configuration.
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<PresharedKey>,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
}

impl fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "(hidden)"),
            )
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

/// Holds new endpoint for the peer matching by public key.
#[derive(Debug)]
pub struct PeerEndpointUpdate {
    pub public_key: PublicKey,
    pub endpoint: SocketAddr,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(x25519_dalek::StaticSecret);

impl PrivateKey {
    pub fn from_base64(s: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(PrivateKey::from(key))
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }
}

impl From<[u8; 32]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Copy)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    pub fn from_base64(s: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(PublicKey::from(key))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.as_bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_base64())
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(public_key: [u8; 32]) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(public_key))
    }
}

impl<'a> From<&'a x25519_dalek::StaticSecret> for PublicKey {
    fn from(private_key: &'a x25519_dalek::StaticSecret) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(private_key))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PresharedKey([u8; 32]);

impl PresharedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PresharedKey {
    fn from(key: [u8; 32]) -> PresharedKey {
        PresharedKey(key)
    }
}
