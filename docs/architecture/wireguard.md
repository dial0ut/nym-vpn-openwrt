# WireGuard Backend

## The constraints

NymVPN needs two simultaneous WireGuard tunnels on hardware ranging from x86_64 boxes down to
MIPS routers with 32 MB of flash. The backend has to cross-compile for eight architectures against
musl, and leave room to add AmneziaWG obfuscation on top.

Between them, those three rule out both the kernel module and wireguard-go.

## Not wireguard-go

Upstream wraps the Go WireGuard implementation through C FFI. Go's `c-archive` buildmode segfaults
on musl libc — a known issue open since 2015, [golang/go#13492](https://github.com/golang/go/issues/13492).

Even without that, it means a Go toolchain alongside Rust and a CGo bridge between them, with the
complexity multiplying per target. Tier 3 targets already need nightly Rust and `-Z build-std`;
adding Go cross-compilation on top made the build fragile enough that adding an architecture
stopped being routine.

## gotatun

[mullvad/gotatun](https://github.com/mullvad/gotatun) is pure-Rust userspace WireGuard. It solves
the musl problem and the toolchain problem at once — one Rust toolchain builds the whole stack,
x86_64 down to MIPS, and the only thing the target needs is `kmod-tun`, which every OpenWrt build
ships.

The `nym-wg-gotatun` crate wraps it behind the same API the old wireguard-go crate exposed, so the
rest of the codebase did not have to change.

## AmneziaWG obfuscation

Standard WireGuard is easy to fingerprint. Handshake messages carry fixed type values and the
packet structure is public, so DPI in censorship-heavy networks can identify and block it on
signature alone. AmneziaWG remaps those message type headers to random values and injects junk
packets during the handshake, so the traffic stops matching the known pattern.

**Userspace is what makes this possible at all.** Obfuscation has to sit between the WireGuard
state machine and the UDP socket — rewriting headers and prepending junk on the way out,
reversing it on the way in. With kernel WireGuard the whole wire protocol lives in kernel space
and there is no seam to insert that. gotatun exposes one.

The implementation wraps gotatun's UDP socket factory rather than forking gotatun.
`AmneziaUdpFactory` produces obfuscated send and receive halves; the send side remaps and injects,
the receive side strips and reverses. gotatun's internals stay untouched, which keeps upstream
updates cheap, and with the feature flag off or the config set to passthrough the wrapper costs
nothing.

## What userspace costs

Packet processing moves out of the kernel, adding context switches per packet. `sendmmsg` and
`recvmmsg` batch multiple packets per syscall to amortise that, which recovers most of it.

On a router the trade is worth it: one toolchain, every device supported, obfuscation possible.

32-bit targets need two build-time patches — `portable-atomic` for gotatun's `AtomicU64` usage,
and a u32-based multiplication fork for BLS12-381 field arithmetic. Both are handled by the Tier 3
infrastructure in `docker/tier3-musl/`.
