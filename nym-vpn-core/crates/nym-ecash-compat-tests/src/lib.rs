//! Tests only; see `tests/ecash_compat.rs`.
//!
//! The pinned `nym-compact-ecash` serialises two key lengths as `usize`, so a
//! 32-bit build writes 4 bytes where a 64-bit gateway expects 8, the spend
//! proof's challenge hash differs, and every ticket fails to verify. The
//! 32-bit builds patch that in place (`docker/tier3-musl/patch-crates.sh`).
//! These tests are what tells a patched build from an unpatched one: run them
//! on the target (`cross test --target armv7-unknown-linux-musleabihf -p
//! nym-ecash-compat-tests`, or under qemu-user), not only on the host.
