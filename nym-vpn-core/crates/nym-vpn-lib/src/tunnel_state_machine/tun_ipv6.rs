// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{io, net::Ipv6Addr, process::Command};

pub fn set_ipv6_addr(device_name: &str, ipv6_addr: Ipv6Addr) -> io::Result<()> {
    Command::new("ip")
        .args([
            "-6",
            "addr",
            "add",
            &ipv6_addr.to_string(),
            "dev",
            device_name,
        ])
        .output()?;
    Ok(())
}
