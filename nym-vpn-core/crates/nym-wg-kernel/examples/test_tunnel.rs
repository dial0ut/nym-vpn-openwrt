//! Standalone test for kernel WireGuard tunnel
//!
//! Run with: cargo run --example test_tunnel
//! Requires: root privileges, kernel WireGuard module loaded

use nym_wg_kernel::tunnel::{Config, InterfaceConfig, PeerConfig, Tunnel};

#[tokio::main]
async fn main() {
    // Enable logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("=== Kernel WireGuard Tunnel Test ===\n");

    // Step 1: Check if kernel WireGuard is available
    println!("1. Checking kernel WireGuard availability...");
    if !nym_wg_kernel::is_available().await {
        eprintln!("❌ Kernel WireGuard not available!");
        eprintln!("\nTroubleshooting:");
        eprintln!("  - Load the module: sudo modprobe wireguard");
        eprintln!("  - Check kernel version: uname -r  (need 5.6+)");
        eprintln!("  - Verify module: lsmod | grep wireguard");
        return;
    }
    println!("✅ Kernel WireGuard is available\n");

    // Step 2: Generate dummy keys for testing
    println!("2. Generating test keys...");
    let private_key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let peer_public_key = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    println!("✅ Using dummy keys (not real crypto)\n");

    // Step 3: Configure the tunnel
    println!("3. Configuring tunnel...");
    let config = Config {
        interface: InterfaceConfig {
            private_key,
            addresses: vec!["10.100.0.2/32".parse().expect("Valid IP network")],
            listen_port: Some(51820),
            mtu: 1420,
            fwmark: None,
        },
        peers: vec![PeerConfig {
            public_key: peer_public_key,
            endpoint: "192.0.2.1:51820".parse().expect("Valid socket address"), // TEST-NET-1 (won't actually connect)
            allowed_ips: vec!["0.0.0.0/0".parse().expect("Valid IP network")],
            persistent_keepalive: Some(25),
        }],
    };
    println!("  Interface: wg-test");
    println!("  IP: 10.100.0.2/32");
    println!("  MTU: 1420");
    println!("  Listen port: 51820");
    println!("  Peer endpoint: 192.0.2.1:51820");
    println!("  Allowed IPs: 0.0.0.0/0");
    println!("✅ Configuration ready\n");

    // Step 4: Start the tunnel
    println!("4. Starting tunnel...");
    let mut tunnel = match Tunnel::start("wg-test", config).await {
        Ok(t) => {
            println!("✅ Tunnel started successfully!");
            println!("  Interface name: {}", t.interface_name());
            println!("  Interface index: {}", t.interface_index());
            t
        }
        Err(e) => {
            eprintln!("❌ Failed to start tunnel: {}", e);
            eprintln!("\nPossible causes:");
            eprintln!("  - Not running as root (need: sudo cargo run --example test_tunnel)");
            eprintln!("  - Interface 'wg-test' already exists (cleanup: sudo ip link del wg-test)");
            eprintln!("  - Permission issues (need: CAP_NET_ADMIN)");
            return;
        }
    };
    println!();

    // Step 5: Verify the tunnel
    println!("5. Verifying tunnel state...");
    println!("\n  Run in another terminal to verify:");
    println!("    sudo ip link show wg-test");
    println!("    sudo wg show wg-test");
    println!("    sudo ip addr show wg-test");
    println!();

    match tunnel.get_config().await {
        Ok(device_config) => {
            println!("✅ Retrieved device configuration");
            println!("  Device attributes: {} attributes", device_config.nlas.len());
        }
        Err(e) => {
            eprintln!("⚠️  Warning: failed to get config: {}", e);
        }
    }
    println!();

    // Step 6: Keep tunnel running for inspection
    println!("6. Tunnel is running. Press Ctrl+C to stop...");
    println!("   (Tunnel will auto-cleanup when stopped)\n");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
    println!("\n7. Stopping tunnel...");

    // Step 7: Clean up
    match tunnel.stop().await {
        Ok(_) => println!("✅ Tunnel stopped and cleaned up"),
        Err(e) => eprintln!("⚠️  Warning: cleanup failed: {}", e),
    }

    println!("\n=== Test Complete ===");
    println!("If you saw all ✅ marks, kernel WireGuard is working!");
}
