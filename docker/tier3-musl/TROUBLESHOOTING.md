# Troubleshooting Tier 3 Builds

## "struct takes 3 generic arguments but 2 were supplied"

The autocfg probe failed. Make sure you're running from the repository root with the volume mount correctly set.

## Binary is dynamically linked

Rebuild the Docker image to get the latest GCC wrapper:
```bash
docker build -t nym-musl-cross:mipsel-musl -f Dockerfile.mipsel .
```

## Undefined reference to `_Unwind_*` symbols

The build script should add `-lgcc_eh`. This is handled automatically for MIPS targets.

## Out of memory during build

The build uses thin LTO to reduce memory usage. If still failing, build on a machine with more RAM or add swap space.

## Floating point ABI mismatch (MIPS with lld)

MIPS uses GNU ld, not lld. The musl CRT files are compiled with hard-float but Rust uses soft-float. GNU ld warns but links; lld errors. Don't switch MIPS to lld.

## References

- [Rust Tier 3 targets](https://doc.rust-lang.org/nightly/rustc/platform-support.html)
- [indexmap issue #151](https://github.com/bluss/indexmap/issues/151) - autocfg xattr problem
- [portable-atomic](https://github.com/taiki-e/portable-atomic) - Atomic support for targets without native atomics
