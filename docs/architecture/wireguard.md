# WireGuard Backend Selection

## The Problem: WireGuard on Embedded Linux

NymVPN needs two simultaneous WireGuard tunnels on devices ranging from x86_64 boxes to 32 MB MIPS routers. The backend must cross-compile for six architectures, link statically against musl, and support AmneziaWG obfuscation to defeat deep packet inspection. These constraints ruled out the approaches used by the upstream project.

## Why Not wireguard-go

The upstream `nym-vpn-client` used wireguard-go, which wraps the Go WireGuard implementation through C FFI. This has a fundamental problem on musl-based systems: Go's `c-archive` buildmode segfaults on musl libc. This is a known, long-standing Go issue tracked in [golang/go#13492](https://github.com/golang/go/issues/13492).

Beyond the segfault, cross-compiling Go for MIPS and other embedded targets requires a separate Go toolchain alongside Rust, plus a CGo bridge between them. Each new target architecture multiplies the build complexity. On Tier 3 targets that already require nightly Rust and `-Z build-std`, adding Go cross-compilation made the build system fragile and difficult to maintain.

## Choosing Gotatun: Pure Rust Userspace WireGuard

The project uses [mullvad/gotatun](https://github.com/mullvad/gotatun), a pure Rust userspace WireGuard implementation. This resolved both the musl compatibility problem and the cross-compilation complexity in one move.

Gotatun only requires `kmod-tun` on the target device, which every OpenWrt build includes. No WireGuard kernel module is needed. The entire VPN stack builds with a single Rust toolchain, from x86_64 down to MIPS.

The `nym-wg-gotatun` crate wraps gotatun and exposes the same API surface that the old wireguard-go crate provided, minimizing integration churn in the rest of the codebase.

## Enabling AmneziaWG Obfuscation

### Why Obfuscation Matters

Standard WireGuard has a distinctive packet fingerprint. The handshake messages use fixed type values, and the packet structure is well-documented. Deep packet inspection systems in censorship-heavy environments can identify and block WireGuard traffic based on these signatures.

AmneziaWG defeats this fingerprinting by remapping message type headers to random values and injecting junk packets during the handshake. To an observer, the traffic no longer matches WireGuard's known patterns.

### Why Userspace Makes It Possible

AmneziaWG obfuscation requires intercepting packets between the WireGuard state machine and the UDP socket. The obfuscation layer must rewrite outgoing packet headers and prepend junk data before the packet hits the network, then reverse the process on incoming packets before the WireGuard state machine sees them.

With a kernel WireGuard implementation, the wire protocol is handled entirely in kernel space. There is no extension point between the WireGuard module and the UDP socket where userspace code could inject obfuscation. A userspace implementation like gotatun exposes this layer, making AmneziaWG integration straightforward.

### Transport Layer Wrapping

Rather than forking gotatun and modifying its internals, the obfuscation is implemented as a wrapper around gotatun's UDP socket factory. The `AmneziaUdpFactory` wraps the standard socket factory to produce obfuscated send and receive halves. The send side remaps headers and injects junk packets. The receive side strips junk and reverses the header remapping.

This design keeps the obfuscation isolated behind a feature flag. When the flag is disabled or the config is set to passthrough, the wrapper adds zero overhead. Gotatun's internals remain unmodified, which simplifies tracking upstream updates.

## Performance Tradeoffs

Userspace WireGuard moves packet processing from kernel space to user space, adding context switches on every packet. Linux provides `sendmmsg` and `recvmmsg` system calls that batch multiple packets per syscall to amortize this cost.

On resource-constrained routers, the userspace approach is an acceptable tradeoff. The benefits of a single toolchain, universal device support, and obfuscation capability outweigh the overhead of context switches.

On 32-bit targets like MIPS, gotatun's `AtomicU64` usage and BLS12-381 field arithmetic require build-time patches: `portable-atomic` for the former, a u32-based multiplication fork for the latter. These are handled by the Tier 3 cross-compilation infrastructure in `docker/tier3-musl/`.
