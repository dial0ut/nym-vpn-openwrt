# Nym VPN Core

> This is the OpenWrt/Linux fork of nym-vpn-core. Build support for iOS, Android,
> macOS and Windows has been removed; the only supported target is Linux.

## Clone Git repository

Use the following command to clone repository with submodules:

```sh
git clone --recursive https://github.com/nymtech/nym-vpn-client.git
```

## Prerequisites

Majority of code in this repository is written in Rust which can be installed from https://rustup.rs/

### Linux

1. Install system dependencies:

    ```sh
    sudo apt install libdbus-1-dev libmnl-dev libnftnl-dev
    ```
1. Install the latest protobuf-compiler from https://github.com/protocolbuffers/protobuf/releases
1. Install Go from https://go.dev/dl/

## Code formatting

We use some of nightly features of rustfmt to format the codebase. Please install the nightly rust with rustfmt:

```sh
rustup toolchain install nightly -c rustfmt
```

Format the code using the following command:

```sh
cargo +nightly fmt
```

If you use VSCode and automatic formatting, configure rust-analyzer to use nightly rustfmt:

```json
"rust-analyzer.rustfmt.extraArgs": ["+nightly"],
```

## Build dependencies

Build wireguard-go (**in the repository root**):

```sh
make build-wireguard
```

## Build VPN libraries and executables

```sh
cd nym-vpn-core/

# build only the the vpn daemon
cargo build -p nym-vpnd --release

# build all
cargo build --release
```

For cross-compiling to OpenWrt targets, see the build scripts under `scripts/` and
`docker/tier3-musl/` in the repository root.

## Offline monitoring

- Offline monitoring can be disabled by setting the environment variable `NYM_DISABLE_OFFLINE_MONITOR=0`. When set, the status is always online.

## Firewall logging

Use the following command to print firewall rules: `sudo nft list ruleset`
