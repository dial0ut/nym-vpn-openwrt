//! Integration tests for kernel WireGuard
//!
//! These tests require:
//! - Linux with kernel WireGuard module loaded (modprobe wireguard)
//! - Root privileges or CAP_NET_ADMIN
//!
//! Run with: cargo test -p nym-wg-kernel --test integration -- --ignored

use nym_wg_kernel::tunnel::{Config, InterfaceConfig, PeerConfig, Tunnel};

#[tokio::test]
#[ignore] // Requires root and kernel module
async fn test_tunnel_create_and_destroy() {
    if !nym_wg_kernel::is_available().await {
        eprintln!("SKIP: kernel WireGuard not available");
        return;
    }

    let config = Config {
        interface: InterfaceConfig {
            private_key: [1u8; 32],
            addresses: vec!["10.200.0.2/32".parse().unwrap()],
            listen_port: None,
            mtu: 1420,
            fwmark: None,
        },
        peers: vec![PeerConfig {
            public_key: [2u8; 32],
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            allowed_ips: vec!["10.200.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(25),
        }],
    };

    let tunnel = Tunnel::start("nym-test0", config).await;
    match tunnel {
        Ok(t) => {
            assert_eq!(t.interface_name(), "nym-test0");
            assert!(t.interface_index() > 0);
            t.stop().await.expect("Failed to stop tunnel");
        }
        Err(e) => {
            eprintln!("Expected error if not root: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_kernel_wg_availability() {
    let available = nym_wg_kernel::is_available().await;
    eprintln!("Kernel WireGuard available: {}", available);
    // Just check it doesn't panic
}
