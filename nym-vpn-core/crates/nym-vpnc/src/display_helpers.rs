// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

pub fn display_on_off(value: bool) -> &'static str {
    match value {
        true => "on",
        false => "off",
    }
}

/// Effective Lewes Protocol state. The tunnel monitor requests LP on every
/// registration and uses it whenever the gateway advertises valid LP details;
/// the daemon's stored `enable_lewes_protocol` flag is not consulted, so the
/// CLI reports the negotiated behaviour instead of the flag.
pub const LEWES_PROTOCOL_STATE: &str = "auto";

/// `tunnel get` line for the Lewes Protocol, shared with the rpcd bridge's
/// `raw_config` reconstruction so the two never drift.
pub const LEWES_PROTOCOL_LINE: &str = "Lewes protocol: auto (used when the gateway supports it)";
