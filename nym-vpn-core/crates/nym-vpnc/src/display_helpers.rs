// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

pub fn display_on_off(value: bool) -> &'static str {
    match value {
        true => "on",
        false => "off",
    }
}

/// The tunnel monitor negotiates LP per registration and never consults the
/// stored `enable_lewes_protocol` flag, so the CLI reports "auto".
pub const LEWES_PROTOCOL_STATE: &str = "auto";

/// Shared with the rpcd bridge's `raw_config` reconstruction.
pub const LEWES_PROTOCOL_LINE: &str = "Lewes protocol: auto (used when the gateway supports it)";
