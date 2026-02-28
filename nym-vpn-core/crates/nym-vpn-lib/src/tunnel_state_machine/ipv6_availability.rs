// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

pub async fn is_ipv6_enabled_in_os() -> bool {
    // - Use `/proc/sys/net/ipv6/conf/default` instead of `/proc/sys/net/ipv6/conf/default/all`,
    //   because when configuring the kernel with `ipv6.disable_ipv6=1`, `all` would be `0`, however `default` would be `1`.
    //   In such configuration manipulating routing table is not possible anyway due to permission error.
    //   See: https://wiki.archlinux.org/title/IPv6 (paragraph 10.1)
    //
    // - If kernel is configured with `ipv6.disable=1` then `/proc/sys/net/ipv6/*` does not even exist.
    //
    // - When setting `net.ipv6.conf.all.disable_ipv6=1` at runtime, `net.ipv6.conf.default`
    //   is automatically updated to `1` too.
    tokio::fs::read_to_string("/proc/sys/net/ipv6/conf/default/disable_ipv6")
        .await
        .map(|disable_ipv6| disable_ipv6.trim() == "0")
        .unwrap_or(false)
}
