//! Tests only; see `tests/ecash_compat.rs`.
//!
//! Before nym #6528, `nym-compact-ecash` serialised two key lengths as
//! `usize`, so a 32-bit build wrote 4 bytes where a 64-bit gateway expects 8,
//! the spend proof's challenge hash differed, and every ticket failed to
//! verify. The nym pin carries the fix; these tests keep a pin without it from
//! shipping. They only mean something on a 32-bit target (CI runs them on
//! i686; armv7 runs under qemu-user), not on the host.
