// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only
//
// ubus rpcd bridge for the OpenWrt LuCI app, speaking the rpcd "script
// plugin" protocol (`list`; `call <method>` with JSON args on stdin). The
// shell plugin at /usr/libexec/rpcd/nym-vpn is a one-line exec of this.
//
// Replies must be JSON on stdout with exit status 0 even when the daemon is
// unreachable: rpcd turns anything else into an opaque ubus error. The gRPC
// client is created per call so methods keep answering while nym-vpnd is
// down (the UI's daemon-restart flow depends on it).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde_json::{Value, json};

use nym_vpn_lib_types::{
    AccountControllerErrorStateReason, AccountControllerState, AlwaysOnStatus,
    DiagnosticRunParams,
    DnsUpstreamOwner, EntryPoint, ErrorStateReason, ExitPoint, Gateway, GatewayIndependence,
    GatewayType, InboundExemption, InboundExemptionProtocol, ListGatewaysOptions, NodeIdentity,
    StoreAccountRequest, TentativeGateways, TunnelConnectionData, TunnelState, VpnServiceConfig,
};
use nym_vpn_proto::rpc_client::RpcClient;

use crate::display_helpers::{
    LEWES_PROTOCOL_LINE, LEWES_PROTOCOL_STATE, display_on_off, gateway_independence_summary,
};

/// Matches the daemon's own directory cache interval.
const NAME_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Print the ubus method signatures handled by this bridge
    List,

    /// Handle one ubus call: JSON args on stdin, JSON reply on stdout
    Call { method: String },
}

impl Args {
    pub async fn execute(self) -> Result<()> {
        match self.command {
            Command::List => {
                println!("{}", method_signatures());
            }
            Command::Call { method } => {
                let args = if method_takes_args(&method) {
                    read_stdin_args()
                } else {
                    json!({})
                };
                let reply = dispatch(&method, &args).await;
                println!("{}", serde_json::to_string(&reply)?);
            }
        }
        Ok(())
    }
}

/// The `list` answer rpcd sees; the shell plugin just execs this bridge.
fn method_signatures() -> Value {
    json!({
        "init": {},
        "status": {},
        "connect": { "relax_independence": "bool" },
        "disconnect": {},
        "info": {},
        "gateway_get": {},
        "gateway_set": {
            "entry_country": "str", "exit_country": "str", "entry_id": "str", "exit_id": "str",
            "entry_random": "bool", "exit_random": "bool", "residential_exit": "bool"
        },
        "gateway_list_full": { "gateway_type": "str" },
        "gateway_list_countries": { "gateway_type": "str" },
        "gateway_list_by_country": { "gateway_type": "str", "country_code": "str" },
        "tentative_gateways": {},
        "tunnel_get": {},
        "tunnel_set": {
            "ipv6": "str", "two_hop": "str", "killswitch": "str", "legacy_split_tunnel": "str",
            "circumvention": "str", "stealth_api": "str", "gateway_independence": "str",
            "family_reminders": "str", "always_on": "str", "loop_cover_delay": "str", "packet_delay": "str",
            "message_delay": "str", "disable_poisson": "str", "disable_cover": "str"
        },
        "account_get": {},
        "account_set": { "mnemonic": "str", "mode": "str" },
        "account_forget": {},
        "account_rotate_keys": {},
        "network_get": {},
        "network_set": { "network": "str" },
        "lan_get": {},
        "lan_set": { "policy": "str" },
        "inbound_list": {},
        "inbound_add": { "proto": "str", "dport": "int", "label": "str" },
        "inbound_del": { "proto": "str", "dport": "int" },
        "dns_get": {},
        "dns_set": { "enabled": "bool", "servers": "str" },
        "ad_block_get": {},
        "ad_block_set": { "enabled": "bool" },
        "diagnostic_run": { "skip_dns": "bool", "skip_http": "bool", "gateway": "str" },
        "split_list": {},
        "split_add": { "type": "str", "mac": "str", "domain": "str", "label": "str" },
        "split_del": { "id": "str" },
        "split_set_enabled": { "id": "str", "enabled": "int" },
        "split_status": {},
        "clients_list": {},
        "account_reset": {},
        "daemon_status": {},
        "daemon_restart": {},
        "daemon_start": {},
        "daemon_stop": {},
        "logs_get": { "lines": "int" },
    })
}

/// Only these read stdin: rpcd closes the pipe after the argument object, but
/// other callers may leave it open, and a no-arg method must not block on it.
fn method_takes_args(method: &str) -> bool {
    matches!(
        method,
        "connect"
            | "gateway_set"
            | "gateway_list_full"
            | "gateway_list_countries"
            | "gateway_list_by_country"
            | "tunnel_set"
            | "account_set"
            | "network_set"
            | "lan_set"
            | "inbound_add"
            | "inbound_del"
            | "dns_set"
            | "ad_block_set"
            | "diagnostic_run"
            | "logs_get"
            | "split_add"
            | "split_del"
            | "split_set_enabled"
    )
}

fn read_stdin_args() -> Value {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return json!({});
    }
    serde_json::from_str(buf.trim()).unwrap_or_else(|_| json!({}))
}

async fn dispatch(method: &str, args: &Value) -> Value {
    match method {
        "status" => status().await,
        "gateway_get" => gateway_get().await,
        "gateway_set" => gateway_set(args).await,
        "gateway_list_full" => gateway_list_full(args).await,
        "gateway_list_countries" => gateway_list_countries(args).await,
        "gateway_list_by_country" => gateway_list_by_country(args).await,
        "tentative_gateways" => tentative_gateways().await,
        "connect" => connect(args).await,
        "disconnect" => disconnect().await,
        "info" => info().await,
        "tunnel_get" => tunnel_get().await,
        "tunnel_set" => tunnel_set(args).await,
        "account_get" => account_get().await,
        "account_set" => account_set(args).await,
        "account_forget" => account_forget().await,
        "account_rotate_keys" => account_rotate_keys().await,
        "network_get" => network_get().await,
        "network_set" => network_set(args).await,
        "lan_get" => lan_get().await,
        "lan_set" => lan_set(args).await,
        "inbound_list" => inbound_list().await,
        "inbound_add" => inbound_add(args).await,
        "inbound_del" => inbound_del(args).await,
        "dns_get" => dns_get().await,
        "dns_set" => dns_set(args).await,
        "ad_block_get" => ad_block_get().await,
        "ad_block_set" => ad_block_set(args).await,
        "diagnostic_run" => diagnostic_run(args).await,
        "init" => init_batch().await,
        "split_list" => split_list(),
        "split_status" => split_status().await,
        "split_add" => split_add(args),
        "split_del" => split_del(args),
        "split_set_enabled" => split_set_enabled(args),
        "clients_list" => clients_list(),
        "daemon_status" => daemon_status(),
        "daemon_start" => daemon_start(),
        "daemon_stop" => daemon_stop(),
        "daemon_restart" => daemon_restart(),
        "account_reset" => account_reset(),
        "logs_get" => logs_get(args),
        other => fail(format!("Unknown method: {other}")),
    }
}

fn ok_msg(message: impl Into<String>) -> Value {
    json!({ "success": true, "message": message.into() })
}

fn fail(error: impl Into<String>) -> Value {
    json!({ "success": false, "error": error.into() })
}

/// "1"/"true"/true/1 — the shapes jshn and LuCI produce for a set boolean arg.
fn arg_flag(args: &Value, key: &str) -> bool {
    match args.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1" || s == "true",
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// A present-but-false boolean arg ("0"/"false"), distinct from absent.
fn arg_flag_present(args: &Value, key: &str) -> Option<bool> {
    match args.get(key) {
        None | Some(Value::Null) => None,
        _ => Some(arg_flag(args, key)),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// "on"/"off" toggles, the vocabulary the shell validated with `onoff`.
fn arg_onoff(args: &Value, key: &str) -> Option<bool> {
    match arg_str(args, key) {
        Some("on") => Some(true),
        Some("off") => Some(false),
        _ => None,
    }
}

fn arg_u32(args: &Value, key: &str) -> Option<u32> {
    match args.get(key) {
        Some(Value::Number(n)) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

//-------------------------------------------------------------------------------
// Gateway lists
//-------------------------------------------------------------------------------

/// Mirrors the shell's default of `mixnet-exit` for missing/invalid types.
fn parse_gw_type(args: &Value) -> GatewayType {
    match args.get("gateway_type").and_then(Value::as_str) {
        Some("mixnet-entry") => GatewayType::MixnetEntry,
        Some("wg") => GatewayType::Wg,
        _ => GatewayType::MixnetExit,
    }
}

fn gw_type_slug(gw_type: GatewayType) -> &'static str {
    match gw_type {
        GatewayType::MixnetEntry => "mixnet-entry",
        GatewayType::MixnetExit => "mixnet-exit",
        GatewayType::Wg => "wg",
    }
}

async fn fetch_gateways(client: &mut RpcClient, gw_type: GatewayType) -> Result<Vec<Gateway>> {
    Ok(client
        .list_gateways(ListGatewaysOptions {
            gw_type,
            user_agent: None,
        })
        .await?)
}

/// Same string the old table emitted, so the frontend's substring ranking
/// ("High"/"Medium"/"Offline") and quality icons keep working.
fn performance_string(gw: &Gateway, gw_type: GatewayType) -> String {
    gw.performance
        .as_ref()
        .map(|p| {
            let score = match gw_type {
                GatewayType::MixnetEntry | GatewayType::MixnetExit => &p.mixnet_score,
                GatewayType::Wg => &p.score,
            };
            format!(
                "{:?} (load: {:?}, uptime: {}%)",
                score,
                p.load,
                (p.uptime_percentage_last_24_hours * 100f32) as u8,
            )
        })
        .unwrap_or_else(|| "N/A".to_owned())
}

fn location_string(gw: &Gateway) -> String {
    gw.location
        .as_ref()
        .map(|l| {
            if l.city == l.region || l.region.contains(&l.city) {
                format!("{} [{}]", l.city, l.two_letter_iso_country_code)
            } else {
                format!("{}, {} [{}]", l.city, l.region, l.two_letter_iso_country_code)
            }
        })
        .unwrap_or_else(|| "N/A".to_owned())
}

fn gateway_json(gw: &Gateway, gw_type: GatewayType) -> Value {
    json!({
        "id": gw.identity_key,
        "name": gw.name,
        "country": gw.location.as_ref().map(|l| l.two_letter_iso_country_code.clone()),
        "city": gw.location.as_ref().map(|l| l.city.clone()),
        "location": location_string(gw),
        "performance": performance_string(gw, gw_type),
        "bridges": gw.bridge_params.is_some(),
        "family": gw.node_family_name,
    })
}

//-------------------------------------------------------------------------------
// tentative_gateways — the pair a connect would most likely pick
//-------------------------------------------------------------------------------

fn tentative_gateway_json(gw: &Gateway) -> Value {
    json!({
        "id": gw.identity_key,
        "name": gw.name,
        "country": gw.location.as_ref().map(|l| l.two_letter_iso_country_code.clone()),
        "family": gw.node_family_name,
    })
}

/// `status` is "selected", "needs_relaxed" or "none"; entry/exit are present
/// only when selected.
fn tentative_json(tentative: &TentativeGateways) -> Value {
    match tentative {
        TentativeGateways::Selected { entry, exit } => json!({
            "status": "selected",
            "entry": tentative_gateway_json(entry),
            "exit": tentative_gateway_json(exit),
        }),
        TentativeGateways::NeedsRelaxedIndependenceCriteria => json!({ "status": "needs_relaxed" }),
        TentativeGateways::NoGatewaysAvailable => json!({ "status": "none" }),
    }
}

async fn tentative_gateways() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "status": "none", "error": format!("{err:#}") }),
    };
    match client.get_tentative_gateways().await {
        Ok(tentative) => tentative_json(&tentative),
        Err(err) => json!({ "status": "none", "error": format!("{err:#}") }),
    }
}

async fn gateway_list_full(args: &Value) -> Value {
    let gw_type = parse_gw_type(args);
    match connect_and_fetch(gw_type).await {
        Ok(gateways) => json!({
            "gateways": gateways.iter().map(|g| gateway_json(g, gw_type)).collect::<Vec<_>>(),
            "count": gateways.len(),
        }),
        Err(err) => json!({ "gateways": [], "error": format!("{err:#}") }),
    }
}

async fn connect_and_fetch(gw_type: GatewayType) -> Result<Vec<Gateway>> {
    let mut client = RpcClient::new().await?;
    fetch_gateways(&mut client, gw_type).await
}

fn count_countries(gateways: &[Gateway]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for gw in gateways {
        if let Some(location) = &gw.location {
            *counts
                .entry(location.two_letter_iso_country_code.clone())
                .or_insert(0u64) += 1;
        }
    }
    counts
}

async fn gateway_list_countries(args: &Value) -> Value {
    let gw_type = parse_gw_type(args);
    match connect_and_fetch(gw_type).await {
        Ok(gateways) => {
            let countries = count_countries(&gateways)
                .into_iter()
                .map(|(code, count)| json!({ "code": code, "count": count }))
                .collect::<Vec<_>>();
            json!({ "countries": countries })
        }
        // The frontend shows "Failed to load" on empty + error.
        Err(err) => json!({ "countries": [], "error": format!("{err:#}") }),
    }
}

fn valid_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}

async fn gateway_list_by_country(args: &Value) -> Value {
    let gw_type = parse_gw_type(args);
    let Some(country) = args.get("country_code").and_then(Value::as_str) else {
        return fail("Country code required");
    };
    if !valid_country_code(country) {
        return fail("Invalid country code");
    }

    match connect_and_fetch(gw_type).await {
        Ok(gateways) => {
            let filtered = gateways
                .iter()
                .filter(|gw| {
                    gw.location
                        .as_ref()
                        .is_some_and(|l| l.two_letter_iso_country_code == country)
                })
                .map(|gw| gateway_json(gw, gw_type))
                .collect::<Vec<_>>();
            json!({ "gateways": filtered })
        }
        Err(err) => json!({ "gateways": [], "error": format!("{err:#}") }),
    }
}

//-------------------------------------------------------------------------------
// Gateway name resolution (status / gateway_get)
//-------------------------------------------------------------------------------

fn name_cache_path(gw_type: GatewayType) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/nym-vpnc-gw-names-{}.json",
        gw_type_slug(gw_type)
    ))
}

type NameMap = BTreeMap<String, (String, String)>;

fn read_name_cache(path: &PathBuf, max_age: Option<Duration>) -> Option<NameMap> {
    if let Some(max_age) = max_age {
        let modified = std::fs::metadata(path).ok()?.modified().ok()?;
        if modified.elapsed().unwrap_or(Duration::MAX) > max_age {
            return None;
        }
    }
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_name_cache(path: &PathBuf, map: &NameMap) {
    // Rename so a concurrent status poll never sees a half-written file.
    let Ok(serialized) = serde_json::to_string(map) else {
        return;
    };
    let tmp = path.with_extension("json.new");
    if std::fs::write(&tmp, serialized).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// id -> (name, country), cached in /tmp so the 5-second status poll does not
/// pull the full directory each time. Stale cache on daemon failure.
async fn gateway_name_map(client: &mut RpcClient, gw_type: GatewayType) -> Option<NameMap> {
    let path = name_cache_path(gw_type);
    if let Some(map) = read_name_cache(&path, Some(NAME_CACHE_TTL)) {
        return Some(map);
    }
    match fetch_gateways(client, gw_type).await {
        Ok(gateways) => {
            let map: NameMap = gateways
                .into_iter()
                .map(|gw| {
                    let country = gw
                        .location
                        .map(|l| l.two_letter_iso_country_code)
                        .unwrap_or_default();
                    (gw.identity_key, (gw.name, country))
                })
                .collect();
            write_name_cache(&path, &map);
            Some(map)
        }
        Err(_) => read_name_cache(&path, None),
    }
}

//-------------------------------------------------------------------------------
// status
//-------------------------------------------------------------------------------

/// Every degraded shape must carry this: a frontend that cannot tell
/// "unreachable" from a real answer renders "no account configured", which
/// reads as wiped credentials.
fn insert_unavailable(out: &mut serde_json::Map<String, Value>) {
    out.insert("available".into(), json!(false));
    out.insert("daemon_running".into(), json!(initd_running("nym-vpnd")));
    out.insert("daemon_enabled".into(), json!(initd_enabled("nym-vpnd")));
}

fn unknown_status(raw: String) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("state".into(), json!("unknown"));
    out.insert("connected".into(), json!(false));
    out.insert("raw_state".into(), json!(raw));
    insert_unavailable(&mut out);
    Value::Object(out)
}

/// The ident the frontend matches on (e.g. PerformantEntryGatewayUnavailable).
/// Display already equals the variant name for everything except Internal.
fn error_reason_ident(reason: &ErrorStateReason) -> String {
    match reason {
        ErrorStateReason::Internal(_) => "Internal".to_owned(),
        other => other.to_string(),
    }
}

fn insert_account_error(state: AccountControllerState, out: &mut serde_json::Map<String, Value>) {
    let (reason, message): (&str, Option<String>) = match state {
        AccountControllerState::LoggedOut => (
            "logged_out",
            Some("No NymVPN account is configured on this device.".to_owned()),
        ),
        AccountControllerState::Error(err) => match err {
            AccountControllerErrorStateReason::DeviceTimeDesynced => ("device_time_desynced", None),
            AccountControllerErrorStateReason::InactiveSubscription => {
                ("inactive_subscription", None)
            }
            AccountControllerErrorStateReason::MaxDeviceReached => ("max_device_reached", None),
            AccountControllerErrorStateReason::BandwidthExceeded { .. } => {
                ("bandwidth_exceeded", None)
            }
            AccountControllerErrorStateReason::AccountStatusNotActive { status } => {
                ("account_status_not_active", Some(status))
            }
            AccountControllerErrorStateReason::ApiFailure { details, .. }
            | AccountControllerErrorStateReason::Storage { details, .. }
            | AccountControllerErrorStateReason::Internal { details, .. } => {
                ("api_failure", Some(details))
            }
        },
        _ => return,
    };

    out.insert("error_reason".into(), json!(reason));
    if let Some(message) = message {
        out.insert("error_message".into(), json!(message));
    }
}

async fn emit_account_error(client: &mut RpcClient, out: &mut serde_json::Map<String, Value>) {
    if let Ok(state) = client.get_account_state().await {
        insert_account_error(state, out);
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn status() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return unknown_status(format!("Failed to create RPC client: {err:#}")),
    };
    let state = match client.get_tunnel_state().await {
        Ok(state) => state,
        Err(err) => return unknown_status(format!("{err:#}")),
    };

    let mut out = serde_json::Map::new();

    match state {
        TunnelState::Connected { connection_data } => {
            out.insert("state".into(), json!("connected"));
            out.insert("connected".into(), json!(true));

            let connected_since = connection_data.connected_at.unix_timestamp();
            let elapsed = (now_unix() - connected_since).max(0);
            out.insert("connected_since".into(), json!(connected_since.to_string()));
            out.insert("connected_seconds".into(), json!(elapsed));

            let (mode, entry_ip, exit_ip) = match &connection_data.tunnel {
                TunnelConnectionData::Mixnet(data) => (
                    "mixnet",
                    data.entry_ip.to_string(),
                    data.exit_ip.to_string(),
                ),
                TunnelConnectionData::Wireguard(data) => (
                    "wireguard",
                    data.entry.endpoint.ip().to_string(),
                    data.exit.endpoint.ip().to_string(),
                ),
            };
            out.insert("mode".into(), json!(mode));
            out.insert("entry_ip".into(), json!(entry_ip));
            out.insert("exit_ip".into(), json!(exit_ip));

            let entry_id = connection_data.entry_gateway.id.clone();
            let exit_id = connection_data.exit_gateway.id.clone();
            out.insert("entry_id".into(), json!(entry_id));
            out.insert("exit_id".into(), json!(exit_id));

            // List types must match the connection mode: wg/fast gateways are
            // not all present in the mixnet-entry/exit lists.
            let (entry_list, exit_list) = match &connection_data.tunnel {
                TunnelConnectionData::Mixnet(_) => {
                    (GatewayType::MixnetEntry, GatewayType::MixnetExit)
                }
                TunnelConnectionData::Wireguard(_) => (GatewayType::Wg, GatewayType::Wg),
            };
            let entry_map = gateway_name_map(&mut client, entry_list).await;
            let exit_map = if exit_list == entry_list {
                entry_map.clone()
            } else {
                gateway_name_map(&mut client, exit_list).await
            };

            for (side, id, ip, gw_info, map) in [
                (
                    "entry",
                    &entry_id,
                    &entry_ip,
                    &connection_data.entry_gateway,
                    &entry_map,
                ),
                (
                    "exit",
                    &exit_id,
                    &exit_ip,
                    &connection_data.exit_gateway,
                    &exit_map,
                ),
            ] {
                let resolved = map.as_ref().and_then(|m| m.get(id));
                let name = resolved.map(|(name, _)| name.clone()).filter(|n| !n.is_empty());
                let country = gw_info
                    .country_code
                    .clone()
                    .filter(|c| !c.is_empty())
                    .or_else(|| {
                        resolved
                            .map(|(_, country)| country.clone())
                            .filter(|c| !c.is_empty())
                    });

                if let Some(name) = &name {
                    out.insert(format!("{side}_name"), json!(name));
                }
                if let Some(country) = &country {
                    out.insert(format!("{side}_country"), json!(country));
                }
                let display = match &name {
                    Some(name) => name.clone(),
                    None => format!("{ip} [{id}]"),
                };
                out.insert(format!("{side}_gateway"), json!(display));

                // Operator family, straight from the daemon's connection data.
                // Both flat (matching the other per-side keys) and nested.
                let family = gw_info.family_name.clone().filter(|f| !f.is_empty());
                out.insert(format!("{side}_family"), json!(family));
                out.insert(
                    side.to_owned(),
                    json!({
                        "id": id,
                        "name": name,
                        "country": country,
                        "family": family,
                    }),
                );
            }
        }
        TunnelState::Disconnected => {
            out.insert("state".into(), json!("disconnected"));
            out.insert("connected".into(), json!(false));
            emit_account_error(&mut client, &mut out).await;
        }
        state @ TunnelState::Connecting { .. } => {
            out.insert("state".into(), json!("connecting"));
            out.insert("connected".into(), json!(false));
            out.insert("raw_state".into(), json!(format!("State: {state}")));
            emit_account_error(&mut client, &mut out).await;
        }
        TunnelState::Disconnecting { .. } => {
            out.insert("state".into(), json!("disconnecting"));
            out.insert("connected".into(), json!(false));
            emit_account_error(&mut client, &mut out).await;
        }
        TunnelState::Error(reason) => {
            // Tunnel state machine in Error — surfaced as disconnected so the
            // Connect button stays enabled; tunnel_error explains why.
            out.insert("state".into(), json!("disconnected"));
            out.insert("connected".into(), json!(false));
            out.insert(
                "raw_state".into(),
                json!(format!("State: Error state: {reason:?}")),
            );
            out.insert("tunnel_error".into(), json!(error_reason_ident(&reason)));
            emit_account_error(&mut client, &mut out).await;
        }
        state @ TunnelState::Offline { reconnect } => {
            // No default route. With Always On this is a state users see on
            // every WAN drop, so it gets its own name; `reconnect` tells the
            // card "waiting for network" from a plain offline.
            insert_offline(&mut out, reconnect);
            out.insert("raw_state".into(), json!(format!("State: {state}")));
            emit_account_error(&mut client, &mut out).await;
        }
    }

    // The Always On supervisor's view, for the Tunnel Settings status line.
    // Absent when the daemon predates it.
    if let Ok(status) = client.get_always_on_status().await {
        out.insert("always_on".into(), always_on_json(&status));
    }

    Value::Object(out)
}

fn insert_offline(out: &mut serde_json::Map<String, Value>, reconnect: bool) {
    out.insert("state".into(), json!("offline"));
    out.insert("connected".into(), json!(false));
    out.insert("reconnect".into(), json!(reconnect));
}

/// {enabled, active, paused, attempt, next_retry_secs, last_error, latched}:
/// the supervisor snapshot with error reasons as the idents the frontend's
/// copy tables key on.
fn always_on_json(status: &AlwaysOnStatus) -> Value {
    json!({
        "enabled": status.enabled,
        "active": status.active,
        "paused": status.paused,
        "attempt": status.attempt,
        "next_retry_secs": status.next_retry_in.map(|d| d.as_secs()),
        "last_error": status.last_error.as_ref().map(error_reason_ident),
        "latched": status.latched_reason,
    })
}

//-------------------------------------------------------------------------------
// gateway_get
//-------------------------------------------------------------------------------

/// Display strings the frontend parses: bare id, "Random [XX]", "Random".
fn format_entry_point(point: &EntryPoint) -> String {
    match point {
        EntryPoint::Gateway { identity } => identity.to_base58_string(),
        EntryPoint::Country {
            two_letter_iso_country_code,
        } => format!("Random [{two_letter_iso_country_code}]"),
        EntryPoint::Random => "Random".to_owned(),
        other => format!("{other:?}"),
    }
}

fn format_exit_point(point: &ExitPoint) -> String {
    match point {
        ExitPoint::Gateway { identity } => identity.to_base58_string(),
        ExitPoint::Country {
            two_letter_iso_country_code,
        } => format!("Random [{two_letter_iso_country_code}]"),
        ExitPoint::Random => "Random".to_owned(),
        other => format!("{other:?}"),
    }
}

/// (type, pinned id, country) for one side: gateway/country/random/other.
type PointKind = (&'static str, Option<String>, Option<String>);

fn classify_entry_point(point: &EntryPoint) -> PointKind {
    match point {
        EntryPoint::Gateway { identity } => ("gateway", Some(identity.to_base58_string()), None),
        EntryPoint::Country {
            two_letter_iso_country_code,
        } => ("country", None, Some(two_letter_iso_country_code.clone())),
        EntryPoint::Random => ("random", None, None),
        _ => ("other", None, None),
    }
}

fn classify_exit_point(point: &ExitPoint) -> PointKind {
    match point {
        ExitPoint::Gateway { identity } => ("gateway", Some(identity.to_base58_string()), None),
        ExitPoint::Country {
            two_letter_iso_country_code,
        } => ("country", None, Some(two_letter_iso_country_code.clone())),
        ExitPoint::Random => ("random", None, None),
        _ => ("other", None, None),
    }
}

async fn insert_point_fields(
    client: &mut RpcClient,
    out: &mut serde_json::Map<String, Value>,
    side: &str,
    kind: PointKind,
    list_type: GatewayType,
) {
    let (point_type, id, country) = kind;
    out.insert(format!("{side}_type"), json!(point_type));

    if let Some(id) = id {
        out.insert(format!("{side}_id"), json!(id));
        if let Some(map) = gateway_name_map(client, list_type).await
            && let Some((name, country)) = map.get(&id)
        {
            if !country.is_empty() {
                out.insert(format!("{side}_country"), json!(country));
            }
            if !name.is_empty() {
                out.insert(format!("{side}_name"), json!(name));
            }
        }
    } else if let Some(country) = country {
        out.insert(format!("{side}_country"), json!(country));
    }
}

async fn gateway_get() -> Value {
    let degraded = |err: String| {
        json!({
            "entry_point": "",
            "exit_point": "",
            "residential_exit": "",
            "error": err,
        })
    };

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return degraded(format!("{err:#}")),
    };
    let config = match client.get_config().await {
        Ok(config) => config,
        Err(err) => return degraded(format!("{err:#}")),
    };

    let mut out = serde_json::Map::new();
    out.insert("entry_point".into(), json!(format_entry_point(&config.entry_point)));
    out.insert("exit_point".into(), json!(format_exit_point(&config.exit_point)));
    out.insert(
        "residential_exit".into(),
        json!(display_on_off(config.residential_exit)),
    );

    // Always the mixnet lists, matching the dashboard pickers (unlike status,
    // which switches lists on the live connection mode).
    let entry_kind = classify_entry_point(&config.entry_point);
    let exit_kind = classify_exit_point(&config.exit_point);
    insert_point_fields(&mut client, &mut out, "entry", entry_kind, GatewayType::MixnetEntry).await;
    insert_point_fields(&mut client, &mut out, "exit", exit_kind, GatewayType::MixnetExit).await;

    Value::Object(out)
}

//-------------------------------------------------------------------------------
// Tunnel control + info
//-------------------------------------------------------------------------------

async fn connect(args: &Value) -> Value {
    // "Connect anyway": run this session with the gateway independence
    // criteria relaxed; the persisted setting is untouched.
    let relax_independence = arg_flag(args, "relax_independence");
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.connect_tunnel(relax_independence).await {
        Ok(_) if relax_independence => {
            ok_msg("Connection initiated with relaxed gateway independence")
        }
        Ok(_) => ok_msg("Connection initiated"),
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn disconnect() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.disconnect_tunnel().await {
        Ok(_) => ok_msg("Disconnected successfully"),
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn info() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "error": format!("{err:#}") }),
    };
    match client.get_info().await {
        Ok(service_info) => {
            let raw_info = format!(
                "nym-vpnd:\n  version: {}\n  triple: {}\n  platform: {}\n  git_commit: {}\n\nnym_network:\n  network_name: {}",
                service_info.version,
                service_info.triple,
                service_info.platform,
                service_info.git_commit,
                service_info.nym_network.network_name,
            );
            json!({
                "version": service_info.version,
                "network": service_info.nym_network.network_name,
                "raw_info": raw_info,
            })
        }
        Err(err) => json!({ "error": format!("{err:#}") }),
    }
}

//-------------------------------------------------------------------------------
// gateway_set
//-------------------------------------------------------------------------------

/// id takes priority over country; invalid values are silently dropped.
async fn gateway_set(args: &Value) -> Value {
    let entry_point = if let Some(id) = arg_str(args, "entry_id") {
        NodeIdentity::from_base58_string(id)
            .ok()
            .map(|identity| EntryPoint::Gateway { identity })
    } else if let Some(country) = arg_str(args, "entry_country").filter(|c| valid_country_code(c)) {
        Some(EntryPoint::Country {
            two_letter_iso_country_code: country.to_owned(),
        })
    } else if arg_flag(args, "entry_random") {
        Some(EntryPoint::Random)
    } else {
        None
    };

    let exit_point = if let Some(id) = arg_str(args, "exit_id") {
        NodeIdentity::from_base58_string(id)
            .ok()
            .map(|identity| ExitPoint::Gateway { identity })
    } else if let Some(country) = arg_str(args, "exit_country").filter(|c| valid_country_code(c)) {
        Some(ExitPoint::Country {
            two_letter_iso_country_code: country.to_owned(),
        })
    } else if arg_flag(args, "exit_random") {
        Some(ExitPoint::Random)
    } else {
        None
    };

    let residential_exit = arg_onoff(args, "residential_exit");

    if entry_point.is_none() && exit_point.is_none() && residential_exit.is_none() {
        return fail("No gateway parameters specified");
    }

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };

    if let Some(entry_point) = entry_point
        && let Err(err) = client.set_entry_point(entry_point).await
    {
        return fail(format!("{err:#}"));
    }
    if let Some(exit_point) = exit_point
        && let Err(err) = client.set_exit_point(exit_point).await
    {
        return fail(format!("{err:#}"));
    }
    if let Some(residential_exit) = residential_exit
        && let Err(err) = client.set_residential_exit(residential_exit).await
    {
        return fail(format!("{err:#}"));
    }

    ok_msg("Gateway configuration updated")
}

//-------------------------------------------------------------------------------
// tunnel_get / tunnel_set
//-------------------------------------------------------------------------------

fn opt_u32_string(value: Option<u32>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

/// `enabled` is whether any criterion is active; the three criteria and the
/// reminder switch follow individually.
fn gateway_independence_json(gateway_independence: &GatewayIndependence) -> Value {
    json!({
        "enabled": gateway_independence.active(),
        "notifications": gateway_independence.enable_notifications,
        "different_node_family": gateway_independence.different_node_family,
        "different_asn": gateway_independence.different_asn,
        "different_subnet": gateway_independence.different_subnet,
    })
}

/// The core on/off flags shared by tunnel_get and tunnel_set's config echo.
fn tunnel_flags_json(config: &VpnServiceConfig) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    out.insert("ipv6".into(), json!(display_on_off(!config.disable_ipv6)));
    out.insert("two_hop".into(), json!(display_on_off(config.enable_two_hop)));
    out.insert("netstack".into(), json!(display_on_off(config.netstack)));
    out.insert(
        "circumvention_transports".into(),
        json!(display_on_off(config.enable_bridges)),
    );
    out.insert("killswitch".into(), json!(display_on_off(config.killswitch)));
    out.insert(
        "legacy_split_tunnel".into(),
        json!(display_on_off(config.legacy_split_tunnel)),
    );
    out.insert(
        "stealth_api".into(),
        json!(display_on_off(config.stealth_api)),
    );
    out.insert(
        "gateway_independence".into(),
        gateway_independence_json(&config.gateway_independence),
    );
    out.insert("always_on".into(), json!(display_on_off(config.always_on)));
    out
}

fn tunnel_config_json(config: &VpnServiceConfig) -> Value {
    let mut out = tunnel_flags_json(config);
    out.insert("lewes_protocol".into(), json!(LEWES_PROTOCOL_STATE));
    let mt = &config.mixnet_traffic;
    out.insert(
        "loop_cover_delay".into(),
        json!(opt_u32_string(mt.poisson_parameter_for_loop_cover_stream)),
    );
    out.insert(
        "packet_delay".into(),
        json!(opt_u32_string(mt.average_packet_delay)),
    );
    out.insert(
        "message_delay".into(),
        json!(opt_u32_string(mt.message_sending_average_delay)),
    );
    out.insert(
        "disable_poisson".into(),
        json!(mt.disable_poisson_rate.to_string()),
    );
    out.insert(
        "disable_cover".into(),
        json!(mt.disable_background_cover_traffic.to_string()),
    );
    Value::Object(out)
}

fn degraded_tunnel_config(err: String) -> Value {
    json!({
        "ipv6": "", "two_hop": "", "netstack": "", "lewes_protocol": "",
        "circumvention_transports": "", "killswitch": "", "legacy_split_tunnel": "",
        "stealth_api": "", "stealth_api_note": "", "gateway_independence": {},
        "always_on": "", "loop_cover_delay": "", "packet_delay": "", "message_delay": "",
        "disable_poisson": "", "disable_cover": "",
        "raw_config": err,
    })
}

async fn tunnel_get() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return degraded_tunnel_config(format!("{err:#}")),
    };
    let config = match client.get_config().await {
        Ok(config) => config,
        Err(err) => return degraded_tunnel_config(format!("{err:#}")),
    };

    let mut out = match tunnel_config_json(&config) {
        Value::Object(map) => map,
        _ => unreachable!(),
    };

    // Without published cover domains the toggle has nothing to act on.
    let cover_domains = match client.get_info().await {
        Ok(info) => info.has_api_cover_domains(),
        Err(_) => true,
    };
    let stealth_api_note = if cover_domains {
        ""
    } else {
        "no cover domains available"
    };
    out.insert("stealth_api_note".into(), json!(stealth_api_note));

    // `nym-vpnc tunnel get` text, surfaced in diagnostics views only.
    let inbound = if config.inbound_exemptions.is_empty() {
        "none".to_owned()
    } else {
        config
            .inbound_exemptions
            .iter()
            .map(|e| format!("{}/{}", e.proto, e.dport))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let raw_config = format!(
        "IPv6: {}\nTwo-hop: {}\n{}\nNetstack: {}\nCircumvention transports: {}\nKill-switch: {}\nLegacy-split-tunnel: {}\nStealth API connect: {}{}\nGateway independence: {}\nFamily reminders: {}\nAlways on: {}\nInbound exemptions: {}\nMixnet traffic configuration: {}",
        display_on_off(!config.disable_ipv6),
        display_on_off(config.enable_two_hop),
        LEWES_PROTOCOL_LINE,
        display_on_off(config.netstack),
        display_on_off(config.enable_bridges),
        display_on_off(config.killswitch),
        display_on_off(config.legacy_split_tunnel),
        display_on_off(config.stealth_api),
        if cover_domains {
            ""
        } else {
            " (no cover domains available)"
        },
        gateway_independence_summary(&config.gateway_independence),
        display_on_off(config.gateway_independence.enable_notifications),
        display_on_off(config.always_on),
        inbound,
        config.mixnet_traffic,
    );
    out.insert("raw_config".into(), json!(raw_config));

    Value::Object(out)
}

async fn tunnel_set(args: &Value) -> Value {
    let ipv6 = arg_onoff(args, "ipv6");
    let two_hop = arg_onoff(args, "two_hop");
    let killswitch = arg_onoff(args, "killswitch");
    let legacy_split_tunnel = arg_onoff(args, "legacy_split_tunnel");
    let circumvention = arg_onoff(args, "circumvention");
    let stealth_api = arg_onoff(args, "stealth_api");
    let gateway_independence = arg_onoff(args, "gateway_independence");
    let family_reminders = arg_onoff(args, "family_reminders");
    let always_on = arg_onoff(args, "always_on");
    // Numeric ranges mirror the shell (and daemon-side) validation.
    let loop_cover_delay = arg_u32(args, "loop_cover_delay").filter(|v| *v <= 200);
    let packet_delay = arg_u32(args, "packet_delay").filter(|v| *v <= 200);
    let message_delay = arg_u32(args, "message_delay").filter(|v| (5..=50).contains(v));
    let disable_poisson = arg_onoff(args, "disable_poisson");
    let disable_cover = arg_onoff(args, "disable_cover");

    let any_mixnet = loop_cover_delay.is_some()
        || packet_delay.is_some()
        || message_delay.is_some()
        || disable_poisson.is_some()
        || disable_cover.is_some();

    if ipv6.is_none()
        && two_hop.is_none()
        && killswitch.is_none()
        && legacy_split_tunnel.is_none()
        && circumvention.is_none()
        && stealth_api.is_none()
        && gateway_independence.is_none()
        && family_reminders.is_none()
        && always_on.is_none()
        && !any_mixnet
    {
        return fail("No tunnel parameters specified");
    }

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };

    // killswitch before legacy_split_tunnel, like `nym-vpnc tunnel set`, so the
    // daemon-side mutual exclusion sees the same sequence.
    let result: Result<()> = async {
        if let Some(killswitch) = killswitch {
            client.set_killswitch(killswitch).await?;
        }
        if let Some(legacy_split_tunnel) = legacy_split_tunnel {
            client.set_legacy_split_tunnel(legacy_split_tunnel).await?;
        }
        if let Some(two_hop) = two_hop {
            client.set_enable_two_hop(two_hop).await?;
        }
        if let Some(ipv6) = ipv6 {
            client.set_disable_ipv6(!ipv6).await?;
        }
        if let Some(circumvention) = circumvention {
            client.set_enable_bridges(circumvention).await?;
        }
        if let Some(stealth_api) = stealth_api {
            client.set_stealth_api(stealth_api).await?;
        }
        if let Some(enabled) = gateway_independence {
            client.set_enable_gateway_independence(enabled).await?;
        }
        if let Some(enabled) = family_reminders {
            client.set_gateway_independence_notifications(enabled).await?;
        }
        if let Some(enabled) = always_on {
            client.set_always_on(enabled).await?;
        }
        if any_mixnet {
            let mut config = client.get_config().await?;
            if let Some(v) = loop_cover_delay {
                config.mixnet_traffic.poisson_parameter_for_loop_cover_stream = Some(v);
            }
            if let Some(v) = packet_delay {
                config.mixnet_traffic.average_packet_delay = Some(v);
            }
            if let Some(v) = message_delay {
                config.mixnet_traffic.message_sending_average_delay = Some(v);
            }
            if let Some(v) = disable_poisson {
                config.mixnet_traffic.disable_poisson_rate = v;
            }
            if let Some(v) = disable_cover {
                config.mixnet_traffic.disable_background_cover_traffic = v;
            }
            client.set_mixnet_traffic_config(config.mixnet_traffic).await?;
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            let mut out = serde_json::Map::new();
            out.insert("success".into(), json!(true));
            out.insert("message".into(), json!("Tunnel configuration updated"));
            if let Ok(updated) = client.get_config().await {
                out.insert("config".into(), Value::Object(tunnel_flags_json(&updated)));
            }
            Value::Object(out)
        }
        Err(err) => fail(format!("{err:#}")),
    }
}

//-------------------------------------------------------------------------------
// account
//-------------------------------------------------------------------------------

async fn account_get() -> Value {
    let degraded = |err: String| {
        let mut out = serde_json::Map::new();
        out.insert("identity".into(), json!(""));
        out.insert("state".into(), json!(""));
        out.insert("raw_info".into(), json!(err));
        insert_unavailable(&mut out);
        Value::Object(out)
    };
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return degraded(format!("{err:#}")),
    };
    let identity = match client.get_account_identity().await {
        Ok(identity) => identity.unwrap_or_else(|| "unset".to_owned()),
        Err(err) => return degraded(format!("{err:#}")),
    };
    let state = match client.get_account_state().await {
        Ok(state) => format!("{state:?}"),
        Err(err) => return degraded(format!("{err:#}")),
    };
    json!({
        "identity": identity,
        "state": state,
        // An empty state here means "no account", not "could not ask".
        "available": true,
        "raw_info": format!("Account identity: {identity}\nAccount state: {state}"),
    })
}

fn valid_mnemonic(mnemonic: &str) -> bool {
    !mnemonic.is_empty()
        && mnemonic
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b' ')
}

async fn account_set(args: &Value) -> Value {
    let Some(mnemonic) = arg_str(args, "mnemonic") else {
        return fail("Mnemonic required");
    };
    if !valid_mnemonic(mnemonic) {
        return fail("Invalid mnemonic format");
    }
    // Anything but "decentralised" is "api".
    let request = if arg_str(args, "mode") == Some("decentralised") {
        StoreAccountRequest::Decentralised {
            mnemonic: mnemonic.to_owned(),
        }
    } else {
        StoreAccountRequest::Vpn {
            mnemonic: mnemonic.to_owned(),
        }
    };

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.store_account(request).await {
        Ok(response) => match response.error {
            None => ok_msg("Account set successfully"),
            Some(err) => fail(err.to_string()),
        },
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn account_forget() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.forget_account().await {
        Ok(response) => match response.error {
            None => ok_msg("Account forgotten"),
            Some(err) => fail(err.to_string()),
        },
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn account_rotate_keys() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.rotate_keys().await {
        Ok(response) => match response.error {
            None => ok_msg("Keys rotated successfully"),
            Some(err) => fail(err.to_string()),
        },
        Err(err) => fail(format!("{err:#}")),
    }
}

//-------------------------------------------------------------------------------
// network / lan / inbound / dns / ad-block
//-------------------------------------------------------------------------------

async fn network_get() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "network": "", "error": format!("{err:#}") }),
    };
    match client.get_info().await {
        Ok(service_info) => json!({ "network": service_info.nym_network.network_name }),
        Err(err) => json!({ "network": "", "error": format!("{err:#}") }),
    }
}

fn valid_network_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

async fn network_set(args: &Value) -> Value {
    let Some(network) = arg_str(args, "network") else {
        return fail("Network name required");
    };
    if !valid_network_name(network) {
        return fail("Invalid network name");
    }
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.set_network(network.to_owned()).await {
        Ok(_) => ok_msg(format!("Network set to {network}")),
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn lan_get() -> Value {
    // The frontend parses the whole `nym-vpnc lan get` line.
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "policy": format!("{err:#}") }),
    };
    match client.get_config().await {
        Ok(config) => json!({
            "policy": format!(
                "Local network policy: {}",
                if config.allow_lan { "allow" } else { "block" }
            ),
        }),
        Err(err) => json!({ "policy": format!("{err:#}") }),
    }
}

async fn lan_set(args: &Value) -> Value {
    let allow = match arg_str(args, "policy") {
        Some("allow") => true,
        Some("block") => false,
        Some(_) => return fail("Invalid policy (must be allow or block)"),
        None => return fail("Policy required (allow or block)"),
    };
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.set_allow_lan(allow).await {
        Ok(_) => ok_msg(format!(
            "LAN policy set to {}",
            if allow { "allow" } else { "block" }
        )),
        Err(err) => fail(format!("{err:#}")),
    }
}

fn exemptions_json(exemptions: &[InboundExemption]) -> Vec<Value> {
    exemptions
        .iter()
        .map(|e| {
            let mut obj = serde_json::Map::new();
            obj.insert("proto".into(), json!(e.proto.to_string()));
            obj.insert("dport".into(), json!(e.dport));
            if let Some(label) = &e.label {
                obj.insert("label".into(), json!(label));
            }
            Value::Object(obj)
        })
        .collect()
}

async fn inbound_list() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(_) => return json!({ "exemptions": [] }),
    };
    match client.get_inbound_exemptions().await {
        Ok(exemptions) => json!({ "exemptions": exemptions_json(&exemptions) }),
        Err(_) => json!({ "exemptions": [] }),
    }
}

fn parse_inbound_args(args: &Value) -> Result<(InboundExemptionProtocol, u16), Value> {
    let proto = match arg_str(args, "proto") {
        Some("tcp") => InboundExemptionProtocol::Tcp,
        Some("udp") => InboundExemptionProtocol::Udp,
        _ => return Err(fail("Invalid protocol (must be tcp or udp)")),
    };
    let dport = args
        .get("dport")
        .and_then(|v| match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        })
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v >= 1);
    match dport {
        Some(dport) => Ok((proto, dport)),
        None => Err(fail("Invalid port (must be 1-65535)")),
    }
}

fn valid_label(label: &str) -> bool {
    label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._/+:()-".contains(&b))
}

async fn inbound_add(args: &Value) -> Value {
    let (proto, dport) = match parse_inbound_args(args) {
        Ok(parsed) => parsed,
        Err(reply) => return reply,
    };
    let label = match arg_str(args, "label") {
        Some(label) if !valid_label(label) => {
            return fail("Invalid label (max 64 chars, safe chars only)");
        }
        other => other.map(str::to_owned),
    };

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    let mut exemptions = match client.get_inbound_exemptions().await {
        Ok(exemptions) => exemptions,
        Err(err) => return fail(format!("{err:#}")),
    };
    if exemptions.iter().any(|e| e.proto == proto && e.dport == dport) {
        return fail(format!("Exemption {proto}/{dport} already exists"));
    }
    exemptions.push(InboundExemption { proto, dport, label });
    match client.set_inbound_exemptions(exemptions).await {
        Ok(_) => ok_msg(format!("Added {proto}:{dport}")),
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn inbound_del(args: &Value) -> Value {
    let (proto, dport) = match parse_inbound_args(args) {
        Ok(parsed) => parsed,
        Err(reply) => return reply,
    };
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    let mut exemptions = match client.get_inbound_exemptions().await {
        Ok(exemptions) => exemptions,
        Err(err) => return fail(format!("{err:#}")),
    };
    let before = exemptions.len();
    exemptions.retain(|e| !(e.proto == proto && e.dport == dport));
    if exemptions.len() == before {
        return fail(format!("No matching exemption {proto}/{dport}"));
    }
    match client.set_inbound_exemptions(exemptions).await {
        Ok(_) => ok_msg(format!("Removed {proto}:{dport}")),
        Err(err) => fail(format!("{err:#}")),
    }
}

fn dns_json(config: &VpnServiceConfig) -> Value {
    json!({
        "enabled": config.enable_custom_dns,
        "servers": config
            .custom_dns
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(" "),
    })
}

/// `user_managed` is omitted, not set false, when the daemon cannot answer
/// (too old for the call). Nothing is logged: stdout is the reply channel.
async fn dns_json_with_owner(client: &mut RpcClient, config: &VpnServiceConfig) -> Value {
    let mut out = dns_json(config);
    if let (Some(obj), Ok(owner)) = (out.as_object_mut(), client.get_dns_upstream_owner().await) {
        obj.insert("user_managed".into(), json!(owner == DnsUpstreamOwner::User));
    }
    out
}

async fn dns_get() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "enabled": false, "servers": "", "error": format!("{err:#}") }),
    };
    match client.get_config().await {
        Ok(config) => dns_json_with_owner(&mut client, &config).await,
        Err(err) => json!({ "enabled": false, "servers": "", "error": format!("{err:#}") }),
    }
}

async fn dns_set(args: &Value) -> Value {
    let enabled = arg_flag_present(args, "enabled");
    let servers_arg = args.get("servers").and_then(Value::as_str);

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };

    let result: Result<()> = async {
        if let Some(enabled) = enabled {
            client.set_enable_custom_dns(enabled).await?;
        }
        if let Some(servers) = servers_arg {
            // Invalid entries are dropped; an explicitly empty list clears.
            let valid: Vec<std::net::IpAddr> = servers
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !valid.is_empty() {
                client.set_custom_dns(valid).await?;
            } else if servers.trim().is_empty() && enabled.is_some() {
                client.set_custom_dns(vec![]).await?;
            }
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => ok_msg("DNS configuration updated"),
        Err(err) => fail(format!("{err:#}")),
    }
}

async fn ad_block_get() -> Value {
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return json!({ "enabled": false, "raw": format!("{err:#}") }),
    };
    match client.get_config().await {
        Ok(config) => json!({
            "enabled": config.enable_ad_blocking,
            "raw": format!(
                "Ad-blocking: {}",
                if config.enable_ad_blocking { "enabled" } else { "disabled" }
            ),
        }),
        Err(err) => json!({ "enabled": false, "raw": format!("{err:#}") }),
    }
}

async fn ad_block_set(args: &Value) -> Value {
    let enabled = arg_flag(args, "enabled");
    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.set_enable_ad_blocking(enabled).await {
        Ok(_) => ok_msg(format!(
            "Ad-blocking {}",
            if enabled { "enabled" } else { "disabled" }
        )),
        Err(err) => fail(format!("{err:#}")),
    }
}

//-------------------------------------------------------------------------------
// diagnostic_run
//-------------------------------------------------------------------------------

async fn diagnostic_run(args: &Value) -> Value {
    let gateway = arg_str(args, "gateway")
        .filter(|g| g.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_owned);
    let params = DiagnosticRunParams {
        gateway,
        skip_dns: arg_flag(args, "skip_dns"),
        skip_http: arg_flag(args, "skip_http"),
        skip_hybrid_transport: false,
    };

    let mut client = match RpcClient::new().await {
        Ok(client) => client,
        Err(err) => return fail(format!("{err:#}")),
    };
    match client.run_diagnostic(params).await {
        // The report is a JSON string field; the LuCI view parses it itself.
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => json!({ "success": true, "report": text }),
            Err(err) => fail(format!("failed to serialize report: {err}")),
        },
        Err(err) => fail(format!("{err:#}")),
    }
}

//-------------------------------------------------------------------------------
// System reads (uci / init.d / /tmp) — shared by init and their own methods
//-------------------------------------------------------------------------------

fn cmd_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim_end().to_owned())
}

fn uci_get(key: &str) -> Option<String> {
    cmd_stdout("uci", &["-q", "get", key]).filter(|s| !s.is_empty())
}

fn initd_running(service: &str) -> bool {
    cmd_stdout(&format!("/etc/init.d/{service}"), &["status"])
        .map(|s| s.trim() == "running")
        .unwrap_or(false)
}

/// `enabled` answers through the exit status and prints nothing.
fn initd_enabled(service: &str) -> bool {
    std::process::Command::new(format!("/etc/init.d/{service}"))
        .arg("enabled")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn daemon_status() -> Value {
    let running = initd_running("nym-vpnd");
    json!({
        "status": if running { "running" } else { "stopped" },
        "running": running,
        // Running-but-disabled (a failed upgrade) is invisible until the next reboot.
        "enabled": initd_enabled("nym-vpnd"),
    })
}

/// The base dnsmasq build advertises `no-nftset`, so substring matching on
/// "nftset" is not enough.
fn nftset_supported_in(version_output: &str) -> bool {
    let mut has = false;
    for token in version_output.split_whitespace() {
        match token {
            "no-nftset" => return false,
            "nftset" => has = true,
            _ => {}
        }
    }
    has
}

fn nftset_supported() -> bool {
    cmd_stdout("dnsmasq", &["--version"])
        .map(|out| nftset_supported_in(&out))
        .unwrap_or(false)
}

/// Preserves file order; sections without a `type` are skipped.
fn parse_split_exclusions(uci_show: &str) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut options: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for line in uci_show.lines() {
        let Some(rest) = line.strip_prefix("nym-vpn.") else {
            continue;
        };
        let Some((path, value)) = rest.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('\'').to_owned();
        match path.split_once('.') {
            None => {
                if value == "exclusion" {
                    order.push(path.to_owned());
                }
            }
            Some((sid, opt)) => {
                options
                    .entry(sid.to_owned())
                    .or_default()
                    .insert(opt.to_owned(), value);
            }
        }
    }

    order
        .iter()
        .filter_map(|sid| {
            let opts = options.get(sid)?;
            let section_type = opts.get("type").filter(|t| !t.is_empty())?;
            let mut obj = serde_json::Map::new();
            obj.insert("id".into(), json!(sid));
            obj.insert("type".into(), json!(section_type));
            for key in ["mac", "domain", "label"] {
                if let Some(v) = opts.get(key).filter(|v| !v.is_empty()) {
                    obj.insert(key.into(), json!(v));
                }
            }
            let enabled = opts.get("enabled").map(String::as_str).unwrap_or("1");
            obj.insert("enabled".into(), json!(enabled != "0"));
            Some(Value::Object(obj))
        })
        .collect()
}

fn split_exclusions() -> Vec<Value> {
    cmd_stdout("uci", &["-q", "show", "nym-vpn"])
        .map(|out| parse_split_exclusions(&out))
        .unwrap_or_default()
}

fn split_list() -> Value {
    json!({ "exclusions": split_exclusions() })
}

async fn split_status() -> Value {
    let (killswitch, legacy) = match RpcClient::new().await {
        Ok(mut client) => match client.get_config().await {
            Ok(config) => (
                display_on_off(config.killswitch).to_owned(),
                display_on_off(config.legacy_split_tunnel).to_owned(),
            ),
            Err(_) => (String::new(), String::new()),
        },
        Err(_) => (String::new(), String::new()),
    };
    json!({
        "killswitch": killswitch,
        "legacy_split_tunnel": legacy,
        "nftset_supported": nftset_supported(),
    })
}

fn parse_dhcp_leases(leases: &str) -> Vec<Value> {
    leases
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _ts = fields.next()?;
            let mac = fields.next()?;
            let ip = fields.next().unwrap_or_default();
            let host = fields.next().unwrap_or_default();
            let mut obj = serde_json::Map::new();
            obj.insert("mac".into(), json!(mac));
            obj.insert("ip".into(), json!(ip));
            if !host.is_empty() && host != "*" {
                obj.insert("hostname".into(), json!(host));
            }
            Some(Value::Object(obj))
        })
        .collect()
}

fn clients_list() -> Value {
    let clients = std::fs::read_to_string("/tmp/dhcp.leases")
        .map(|leases| parse_dhcp_leases(&leases))
        .unwrap_or_default();
    json!({ "clients": clients })
}

fn strip_ansi(input: &str) -> String {
    // CSI sequences from tracing's color output; LuCI drops raw 0x1b bytes.
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for f in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&f) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn logs_get(args: &Value) -> Value {
    let lines = arg_u32(args, "lines").unwrap_or(200).clamp(10, 2000) as usize;

    // logread's `-l N` clips the scan window, not the filtered output, so
    // filter the full buffer with `-e`, then take the last N filtered lines.
    let output = cmd_stdout("logread", &["-e", "nym-vpn"]).unwrap_or_default();
    let filtered: Vec<&str> = output.lines().collect();
    let tail_start = filtered.len().saturating_sub(lines);
    let logs = strip_ansi(&filtered[tail_start..].join("\n"));

    json!({ "success": true, "logs": logs, "lines": lines })
}

//-------------------------------------------------------------------------------
// Split-tunnel exclusions (UCI `exclusion` sections): an nftables drop-in
// marks matching packets with the bypass fwmark 0x14e, which the priority-90
// ip rule routes out the real WAN. See docs/guide/split-tunneling.md.
//-------------------------------------------------------------------------------

const SPLIT_NFT: &str = "/etc/nftables.d/30-nym-split.nft";
const SPLIT_MARK: &str = "0x14e";

fn uci_run(args: &[&str]) -> bool {
    std::process::Command::new("uci")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn initd_run(service: &str, action: &str) {
    let _ = std::process::Command::new(format!("/etc/init.d/{service}"))
        .arg(action)
        .output();
}

/// Colon-separated EUI-48, normalised to lowercase.
fn valid_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(mac.to_ascii_lowercase())
}

/// RFC-1035-ish hostname: dotted alphanumeric/hyphen labels, max 253, at
/// least two labels, alpha-only TLD of 2+ chars. Normalised to lowercase.
fn valid_domain(domain: &str) -> Option<String> {
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let (tld, hosts) = labels.split_last()?;
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    for label in hosts {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
    }
    Some(domain.to_ascii_lowercase())
}

/// Content-keyed section names: anonymous `cfgXXXX` ids are renumbered by
/// libuci on commit. Domains are md5-hashed to fit UCI's `[A-Za-z0-9_]`;
/// md5sum is shelled out so existing section names survive upgrades.
fn split_section_name(kind: &str, mac: &str, domain: &str) -> Option<String> {
    match kind {
        "client" => Some(format!("cli_{}", mac.replace(':', "").to_ascii_lowercase())),
        "domain" => {
            let mut child = std::process::Command::new("md5sum")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .ok()?;
            use std::io::Write;
            child.stdin.take()?.write_all(domain.as_bytes()).ok()?;
            let output = child.wait_with_output().ok()?;
            let hash = String::from_utf8_lossy(&output.stdout);
            let hex: String = hash.chars().take(16).collect();
            (hex.len() == 16).then(|| format!("dom_{hex}"))
        }
        _ => None,
    }
}

fn render_split_nft(clients: &[String], domains: &[String]) -> String {
    let mut out = String::new();
    out.push_str("# Managed by luci-app-nym-vpn — do not edit by hand.\n");
    out.push_str(&format!(
        "# Marks split-tunnel carve-outs with fwmark {SPLIT_MARK} (priority-90\n"
    ));
    out.push_str("# ip rule routes them out the real WAN). Included into table inet fw4.\n");
    if !domains.is_empty() {
        // Plain sets (dnsmasq adds individual host addresses as it resolves).
        out.push_str("set nym_bypass4 {\n\ttype ipv4_addr\n}\n");
        out.push_str("set nym_bypass6 {\n\ttype ipv6_addr\n}\n");
    }
    out.push_str("chain nym_split {\n");
    out.push_str("\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
    for mac in clients {
        out.push_str(&format!("\tether saddr {mac} meta mark set {SPLIT_MARK}\n"));
    }
    if !domains.is_empty() {
        out.push_str(&format!("\tip daddr @nym_bypass4 meta mark set {SPLIT_MARK}\n"));
        out.push_str(&format!("\tip6 daddr @nym_bypass6 meta mark set {SPLIT_MARK}\n"));
    }
    out.push_str("}\n");
    out
}

/// Idempotent; an empty list tears everything down.
fn regen_split() {
    let mut clients: Vec<String> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    for excl in split_exclusions() {
        if excl["enabled"] != json!(true) {
            continue;
        }
        match excl["type"].as_str() {
            Some("client") => {
                if let Some(mac) = excl["mac"].as_str() {
                    clients.push(mac.to_owned());
                }
            }
            Some("domain") => {
                if let Some(domain) = excl["domain"].as_str() {
                    domains.push(domain.to_owned());
                }
            }
            _ => {}
        }
    }

    // OpenWrt's dnsmasq turns `config ipset` into --nftset directives on fw4.
    uci_run(&["-q", "delete", "dhcp.nym_split_ipset"]);
    if !domains.is_empty() && nftset_supported() {
        uci_run(&["set", "dhcp.nym_split_ipset=ipset"]);
        uci_run(&["add_list", "dhcp.nym_split_ipset.name=nym_bypass4"]);
        uci_run(&["add_list", "dhcp.nym_split_ipset.name=nym_bypass6"]);
        for domain in &domains {
            uci_run(&["add_list", &format!("dhcp.nym_split_ipset.domain={domain}")]);
        }
        uci_run(&["set", "dhcp.nym_split_ipset.table=fw4"]);
        uci_run(&["set", "dhcp.nym_split_ipset.table_family=inet"]);
    }
    uci_run(&["commit", "dhcp"]);

    if clients.is_empty() && domains.is_empty() {
        let _ = std::fs::remove_file(SPLIT_NFT);
    } else {
        let _ = std::fs::write(SPLIT_NFT, render_split_nft(&clients, &domains));
    }

    // Firewall first so the sets exist before dnsmasq references them.
    let fw4_ok = std::process::Command::new("fw4")
        .arg("reload")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !fw4_ok {
        initd_run("firewall", "reload");
    }
    initd_run("dnsmasq", "restart");
}

fn split_dup_exists(field: &str, value: &str) -> bool {
    split_exclusions()
        .iter()
        .any(|excl| excl[field].as_str() == Some(value))
}

fn split_add(args: &Value) -> Value {
    let label = match arg_str(args, "label") {
        Some(label) if !valid_label(label) => {
            return fail("Invalid label (max 64 chars, safe chars only)");
        }
        other => other.map(str::to_owned),
    };

    let (kind, mac, domain) = match arg_str(args, "type") {
        Some("client") => {
            let Some(mac) = arg_str(args, "mac").and_then(valid_mac) else {
                return fail("Invalid MAC address");
            };
            if split_dup_exists("mac", &mac) {
                return fail(format!("{mac} is already excluded"));
            }
            ("client", mac, String::new())
        }
        Some("domain") => {
            let Some(domain) = arg_str(args, "domain").and_then(valid_domain) else {
                return fail("Invalid domain");
            };
            if split_dup_exists("domain", &domain) {
                return fail(format!("{domain} is already excluded"));
            }
            ("domain", String::new(), domain)
        }
        _ => return fail("Invalid type (must be client or domain)"),
    };

    // Ensure the package file exists so `uci set` has somewhere to append.
    if !std::path::Path::new("/etc/config/nym-vpn").exists() {
        let _ = std::fs::write("/etc/config/nym-vpn", "");
    }
    let Some(sid) = split_section_name(kind, &mac, &domain) else {
        return fail("Failed to create exclusion");
    };
    uci_run(&["set", &format!("nym-vpn.{sid}=exclusion")]);
    uci_run(&["set", &format!("nym-vpn.{sid}.type={kind}")]);
    if kind == "client" {
        uci_run(&["set", &format!("nym-vpn.{sid}.mac={mac}")]);
    } else {
        uci_run(&["set", &format!("nym-vpn.{sid}.domain={domain}")]);
    }
    if let Some(label) = &label {
        uci_run(&["set", &format!("nym-vpn.{sid}.label={label}")]);
    }
    uci_run(&["set", &format!("nym-vpn.{sid}.enabled=1")]);
    uci_run(&["commit", "nym-vpn"]);

    regen_split();

    json!({ "success": true, "id": sid, "message": "Added exclusion" })
}

fn valid_section_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn split_section_exists(id: &str) -> bool {
    uci_get(&format!("nym-vpn.{id}")).as_deref() == Some("exclusion")
}

fn split_del(args: &Value) -> Value {
    let Some(id) = arg_str(args, "id").filter(|id| valid_section_id(id)) else {
        return fail("Invalid id");
    };
    if !split_section_exists(id) {
        return fail("No such exclusion");
    }
    uci_run(&["-q", "delete", &format!("nym-vpn.{id}")]);
    uci_run(&["commit", "nym-vpn"]);
    regen_split();
    json!({ "success": true, "message": "Removed exclusion" })
}

fn split_set_enabled(args: &Value) -> Value {
    let Some(id) = arg_str(args, "id").filter(|id| valid_section_id(id)) else {
        return fail("Invalid id");
    };
    let enabled = match args.get("enabled") {
        Some(Value::Number(n)) if n.as_i64() == Some(0) => "0",
        Some(Value::Number(n)) if n.as_i64() == Some(1) => "1",
        Some(Value::String(s)) if s == "0" => "0",
        Some(Value::String(s)) if s == "1" => "1",
        _ => return fail("Invalid enabled flag"),
    };
    if !split_section_exists(id) {
        return fail("No such exclusion");
    }
    uci_run(&["set", &format!("nym-vpn.{id}.enabled={enabled}")]);
    uci_run(&["commit", "nym-vpn"]);
    regen_split();
    json!({ "success": true })
}

//-------------------------------------------------------------------------------
// Daemon lifecycle / account hard-reset
//-------------------------------------------------------------------------------

fn sleep_secs(secs: u64) {
    std::thread::sleep(Duration::from_secs(secs));
}

fn daemon_state_json(running_msg: &str, stopped_err: &str) -> Value {
    let enabled = initd_enabled("nym-vpnd");
    if initd_running("nym-vpnd") {
        json!({ "success": true, "message": running_msg, "status": "running", "enabled": enabled })
    } else {
        json!({ "success": false, "error": stopped_err, "status": "stopped", "enabled": enabled })
    }
}

fn daemon_start() -> Value {
    initd_run("nym-vpnd", "start");
    sleep_secs(2);
    daemon_state_json("Daemon started", "Daemon failed to start")
}

fn daemon_stop() -> Value {
    initd_run("nym-vpnd", "stop");
    sleep_secs(1);
    let enabled = initd_enabled("nym-vpnd");
    if initd_running("nym-vpnd") {
        json!({ "success": false, "error": "Daemon failed to stop", "status": "running", "enabled": enabled })
    } else {
        json!({ "success": true, "message": "Daemon stopped", "status": "stopped", "enabled": enabled })
    }
}

/// One init action, not stop/start: only `restart` keeps the kill-switch
/// armed (init script `keep_killswitch`), and the script's own stop hook
/// waits for the old pid before the new daemon is launched.
fn daemon_restart() -> Value {
    initd_run("nym-vpnd", "restart");
    daemon_state_json("Daemon restarted successfully", "Daemon failed to start")
}

/// Hard recovery when `account forget` is rejected because an account error
/// strands the tunnel outside Disconnected. The init script's `reset_account`
/// action stops the daemon, wipes only /etc/nym/data and starts it again
/// without opening the firewall; UCI settings and the global config stay.
fn account_reset() -> Value {
    initd_run("nym-vpnd", "reset_account");
    daemon_state_json(
        "Account state reset; daemon restarted",
        "Account store wiped but daemon failed to restart",
    )
}

//-------------------------------------------------------------------------------
// init — the dashboard's batch bootstrap call
//-------------------------------------------------------------------------------

/// Everything the dashboard needs on load, from one config fetch. Extra
/// members are additive; missing ones break the UI.
async fn init_batch() -> Value {
    let mut out = serde_json::Map::new();

    out.insert("status".into(), status().await);

    match RpcClient::new().await {
        Ok(mut client) => {
            match client.get_info().await {
                Ok(service_info) => {
                    out.insert(
                        "info".into(),
                        json!({
                            "version": service_info.version,
                            "network": service_info.nym_network.network_name,
                        }),
                    );
                    out.insert(
                        "network".into(),
                        json!({ "network": service_info.nym_network.network_name }),
                    );
                }
                Err(_) => {
                    out.insert("info".into(), json!({}));
                    out.insert("network".into(), json!({ "network": "" }));
                }
            }

            match client.get_config().await {
                Ok(config) => {
                    out.insert(
                        "gateway_config".into(),
                        json!({
                            "entry_point": format_entry_point(&config.entry_point),
                            "exit_point": format_exit_point(&config.exit_point),
                            "residential_exit": display_on_off(config.residential_exit),
                        }),
                    );
                    out.insert("tunnel_config".into(), tunnel_config_json(&config));
                    out.insert(
                        "lan".into(),
                        json!({
                            "policy": format!(
                                "Local network policy: {}",
                                if config.allow_lan { "allow" } else { "block" }
                            ),
                        }),
                    );
                    out.insert(
                        "inbound_exemptions".into(),
                        json!(exemptions_json(&config.inbound_exemptions)),
                    );
                    out.insert(
                        "ad_block".into(),
                        json!({ "enabled": config.enable_ad_blocking }),
                    );
                    out.insert("dns".into(), dns_json_with_owner(&mut client, &config).await);
                }
                Err(err) => insert_degraded_config_members(&mut out, format!("{err:#}")),
            }

            // A failed query must not read as "no account" (see insert_unavailable).
            let identity_res = client.get_account_identity().await;
            let state_res = client.get_account_state().await;
            let mut account = serde_json::Map::new();
            account.insert(
                "identity".into(),
                json!(
                    identity_res
                        .as_ref()
                        .ok()
                        .and_then(|id| id.clone())
                        .unwrap_or_else(|| "unset".to_owned())
                ),
            );
            account.insert(
                "state".into(),
                json!(
                    state_res
                        .as_ref()
                        .map(|state| format!("{state:?}"))
                        .unwrap_or_default()
                ),
            );
            if identity_res.is_err() || state_res.is_err() {
                insert_unavailable(&mut account);
            } else {
                account.insert("available".into(), json!(true));
            }
            out.insert("account".into(), Value::Object(account));
        }
        Err(err) => {
            out.insert("info".into(), json!({}));
            out.insert("network".into(), json!({ "network": "" }));
            let mut account = serde_json::Map::new();
            account.insert("identity".into(), json!(""));
            account.insert("state".into(), json!(""));
            insert_unavailable(&mut account);
            out.insert("account".into(), Value::Object(account));
            insert_degraded_config_members(&mut out, format!("{err:#}"));
        }
    }

    // System-side members work regardless of daemon state.
    out.insert("split_exclusions".into(), json!(split_exclusions()));
    out.insert(
        "split_status".into(),
        json!({ "nftset_supported": nftset_supported() }),
    );
    out.insert("clients".into(), clients_list()["clients"].clone());
    out.insert("daemon".into(), daemon_status());

    Value::Object(out)
}

fn insert_degraded_config_members(out: &mut serde_json::Map<String, Value>, err: String) {
    out.insert(
        "gateway_config".into(),
        json!({ "entry_point": "", "exit_point": "", "residential_exit": "" }),
    );
    out.insert("tunnel_config".into(), degraded_tunnel_config(err));
    out.insert("lan".into(), json!({ "policy": "" }));
    out.insert("inbound_exemptions".into(), json!([]));
    out.insert("ad_block".into(), json!({ "enabled": false }));
    out.insert("dns".into(), json!({ "enabled": false, "servers": "" }));
}

//-------------------------------------------------------------------------------
// Tests
//-------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nym_vpn_lib_types::{Location, Performance, Score};

    fn gateway(id: &str, name: &str, country: Option<&str>, score: Score) -> Gateway {
        Gateway {
            identity_key: id.to_owned(),
            name: name.to_owned(),
            description: None,
            location: country.map(|c| Location {
                two_letter_iso_country_code: c.to_owned(),
                latitude: 0.0,
                longitude: 0.0,
                city: "City".to_owned(),
                region: "Region".to_owned(),
                asn: None,
            }),
            last_probe: None,
            mixnet_performance: None,
            bridge_params: None,
            performance: Some(Performance {
                last_updated_utc: String::new(),
                score,
                mixnet_score: score,
                load: Score::Low,
                uptime_percentage_last_24_hours: 0.995,
            }),
            exit_ipv4s: vec![],
            exit_ipv6s: vec![],
            build_version: None,
            lewes_protocol_details: None,
            node_family_name: None,
        }
    }

    #[test]
    fn gateway_rows_carry_the_family() {
        let mut gw = gateway("id1", "gw1", Some("DE"), Score::High);
        assert_eq!(gateway_json(&gw, GatewayType::Wg)["family"], Value::Null);
        gw.node_family_name = Some("Acme".to_owned());
        assert_eq!(gateway_json(&gw, GatewayType::Wg)["family"], json!("Acme"));
    }

    #[test]
    fn tentative_json_shapes() {
        let mut entry = gateway("e", "entry", Some("DE"), Score::High);
        entry.node_family_name = Some("Acme".to_owned());
        let exit = gateway("x", "exit", None, Score::High);
        let selected = tentative_json(&TentativeGateways::Selected {
            entry: Box::new(entry),
            exit: Box::new(exit),
        });
        assert_eq!(selected["status"], json!("selected"));
        assert_eq!(selected["entry"]["id"], json!("e"));
        assert_eq!(selected["entry"]["country"], json!("DE"));
        assert_eq!(selected["entry"]["family"], json!("Acme"));
        assert_eq!(selected["exit"]["country"], Value::Null);
        assert_eq!(selected["exit"]["family"], Value::Null);

        let relaxed = tentative_json(&TentativeGateways::NeedsRelaxedIndependenceCriteria);
        assert_eq!(relaxed, json!({ "status": "needs_relaxed" }));
        let none = tentative_json(&TentativeGateways::NoGatewaysAvailable);
        assert_eq!(none, json!({ "status": "none" }));
    }

    #[test]
    fn gateway_independence_json_reports_enabled_from_criteria() {
        let on = gateway_independence_json(&GatewayIndependence::default());
        assert_eq!(on["enabled"], json!(true));
        assert_eq!(on["notifications"], json!(true));
        let off = gateway_independence_json(&GatewayIndependence::disabled());
        assert_eq!(off["enabled"], json!(false));
        assert_eq!(off["different_asn"], json!(false));
        assert_eq!(off["notifications"], json!(true));
        let flags = tunnel_flags_json(&VpnServiceConfig::default());
        assert_eq!(flags["gateway_independence"]["enabled"], json!(true));
    }

    #[test]
    fn error_reason_ident_names_the_relax_case() {
        assert_eq!(
            error_reason_ident(&ErrorStateReason::NeedsRelaxedIndependenceCriteria),
            "NeedsRelaxedIndependenceCriteria"
        );
    }

    #[test]
    fn performance_string_matches_legacy_table_format() {
        let gw = gateway("id1", "gw1", Some("DE"), Score::High);
        assert_eq!(
            performance_string(&gw, GatewayType::MixnetEntry),
            "High (load: Low, uptime: 99%)"
        );
        assert_eq!(
            performance_string(&gateway("id2", "gw2", None, Score::Medium), GatewayType::Wg),
            "Medium (load: Low, uptime: 99%)"
        );
    }

    #[test]
    fn performance_string_without_data_is_na() {
        let mut gw = gateway("id1", "gw1", Some("DE"), Score::High);
        gw.performance = None;
        assert_eq!(performance_string(&gw, GatewayType::Wg), "N/A");
    }

    #[test]
    fn location_string_merges_duplicate_city_region() {
        let mut gw = gateway("id1", "gw1", Some("DE"), Score::High);
        assert_eq!(location_string(&gw), "City, Region [DE]");
        if let Some(l) = gw.location.as_mut() {
            l.region = "City".to_owned();
        }
        assert_eq!(location_string(&gw), "City [DE]");
        gw.location = None;
        assert_eq!(location_string(&gw), "N/A");
    }

    #[test]
    fn country_counts_skip_gateways_without_location() {
        let gateways = vec![
            gateway("a", "gw-a", Some("DE"), Score::High),
            gateway("b", "gw-b", Some("DE"), Score::Low),
            gateway("c", "gw-c", Some("US"), Score::High),
            gateway("d", "gw-d", None, Score::High),
        ];
        let counts = count_countries(&gateways);
        assert_eq!(counts.get("DE"), Some(&2));
        assert_eq!(counts.get("US"), Some(&1));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn country_code_validation() {
        assert!(valid_country_code("DE"));
        assert!(!valid_country_code("de"));
        assert!(!valid_country_code("DEU"));
        assert!(!valid_country_code(""));
        assert!(!valid_country_code("D;"));
    }

    #[test]
    fn error_reason_ident_matches_frontend_keys() {
        assert_eq!(
            error_reason_ident(&ErrorStateReason::PerformantEntryGatewayUnavailable),
            "PerformantEntryGatewayUnavailable"
        );
        assert_eq!(
            error_reason_ident(&ErrorStateReason::Internal("boom".to_owned())),
            "Internal"
        );
    }

    #[test]
    fn account_error_mapping_matches_legacy_reasons() {
        let mut out = serde_json::Map::new();
        insert_account_error(AccountControllerState::LoggedOut, &mut out);
        assert_eq!(out.get("error_reason"), Some(&json!("logged_out")));

        let mut out = serde_json::Map::new();
        insert_account_error(
            AccountControllerState::Error(
                AccountControllerErrorStateReason::AccountStatusNotActive {
                    status: "frozen".to_owned(),
                },
            ),
            &mut out,
        );
        assert_eq!(out.get("error_reason"), Some(&json!("account_status_not_active")));
        assert_eq!(out.get("error_message"), Some(&json!("frozen")));

        let mut out = serde_json::Map::new();
        insert_account_error(AccountControllerState::ReadyToConnect, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn mac_and_domain_validation() {
        assert_eq!(
            valid_mac("AA:BB:cc:11:22:33").as_deref(),
            Some("aa:bb:cc:11:22:33")
        );
        assert!(valid_mac("aa:bb:cc:11:22").is_none());
        assert!(valid_mac("aa:bb:cc:11:22:3g").is_none());
        assert!(valid_mac("aabbcc112233").is_none());

        assert_eq!(valid_domain("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(
            valid_domain("a-b.sub.example.org").as_deref(),
            Some("a-b.sub.example.org")
        );
        assert!(valid_domain("nodots").is_none());
        assert!(valid_domain("-bad.example.com").is_none());
        assert!(valid_domain("bad-.example.com").is_none());
        assert!(valid_domain("example.c0m").is_none());
        assert!(valid_domain("example.c").is_none());
    }

    #[test]
    fn split_nft_rendering_matches_shell_output() {
        let clients = vec!["aa:bb:cc:dd:ee:ff".to_owned()];
        assert_eq!(
            render_split_nft(&clients, &[]),
            "# Managed by luci-app-nym-vpn — do not edit by hand.\n\
             # Marks split-tunnel carve-outs with fwmark 0x14e (priority-90\n\
             # ip rule routes them out the real WAN). Included into table inet fw4.\n\
             chain nym_split {\n\
             \ttype filter hook prerouting priority mangle - 1; policy accept;\n\
             \tether saddr aa:bb:cc:dd:ee:ff meta mark set 0x14e\n\
             }\n"
        );

        let domains = vec!["example.com".to_owned()];
        let rendered = render_split_nft(&clients, &domains);
        assert!(rendered.contains("set nym_bypass4 {\n\ttype ipv4_addr\n}\n"));
        assert!(rendered.contains("\tip daddr @nym_bypass4 meta mark set 0x14e\n"));
        assert!(rendered.contains("\tip6 daddr @nym_bypass6 meta mark set 0x14e\n"));
        assert!(rendered.ends_with("}\n"));
    }

    #[test]
    fn split_section_names_match_shell_derivation() {
        assert_eq!(
            split_section_name("client", "aa:bb:cc:dd:ee:ff", "").as_deref(),
            Some("cli_aabbccddeeff")
        );
        // echo -n example.com | md5sum, first 16 hex chars. Needs md5sum on PATH.
        assert_eq!(
            split_section_name("domain", "", "example.com").as_deref(),
            Some("dom_5ababd603b227803")
        );
        assert!(split_section_name("bogus", "", "").is_none());
    }

    #[test]
    fn nftset_detection_handles_negated_token() {
        assert!(nftset_supported_in("Compile time options: IPv6 GNU-getopt nftset auth"));
        assert!(!nftset_supported_in("Compile time options: IPv6 no-nftset auth"));
        assert!(!nftset_supported_in("nftset no-nftset"));
        assert!(!nftset_supported_in("Compile time options: IPv6 auth"));
    }

    #[test]
    fn split_exclusion_parsing_preserves_order_and_skips_typeless() {
        let uci = "\
nym-vpn.settings=settings
nym-vpn.settings.always_on='1'
nym-vpn.cli_aabbccddeeff=exclusion
nym-vpn.cli_aabbccddeeff.type='client'
nym-vpn.cli_aabbccddeeff.mac='aa:bb:cc:dd:ee:ff'
nym-vpn.cli_aabbccddeeff.enabled='0'
nym-vpn.dom_0123456789abcdef=exclusion
nym-vpn.dom_0123456789abcdef.type='domain'
nym-vpn.dom_0123456789abcdef.domain='example.com'
nym-vpn.dom_0123456789abcdef.label='Test site'
nym-vpn.broken=exclusion
nym-vpn.broken.mac='11:22:33:44:55:66'
";
        let parsed = parse_split_exclusions(uci);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["id"], "cli_aabbccddeeff");
        assert_eq!(parsed[0]["type"], "client");
        assert_eq!(parsed[0]["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(parsed[0]["enabled"], false);
        assert_eq!(parsed[1]["id"], "dom_0123456789abcdef");
        assert_eq!(parsed[1]["domain"], "example.com");
        assert_eq!(parsed[1]["label"], "Test site");
        assert_eq!(parsed[1]["enabled"], true);
    }

    #[test]
    fn dhcp_lease_parsing() {
        let leases = "\
1784000000 aa:bb:cc:dd:ee:ff 192.168.1.100 laptop 01:aa:bb:cc:dd:ee:ff
1784000001 11:22:33:44:55:66 192.168.1.101 * *
";
        let parsed = parse_dhcp_leases(leases);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(parsed[0]["hostname"], "laptop");
        assert_eq!(parsed[1]["ip"], "192.168.1.101");
        assert!(parsed[1].get("hostname").is_none());
    }

    #[test]
    fn ansi_stripping() {
        assert_eq!(
            strip_ansi("\u{1b}[2m2026-07-23\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m ready"),
            "2026-07-23  INFO ready"
        );
        assert_eq!(strip_ansi("plain text"), "plain text");
    }

    #[test]
    fn always_on_status_shapes() {
        let off = always_on_json(&AlwaysOnStatus::default());
        assert_eq!(
            off,
            json!({ "enabled": false, "active": false, "paused": false, "attempt": 0,
                    "next_retry_secs": null, "last_error": null, "latched": null })
        );

        let retrying = always_on_json(&AlwaysOnStatus {
            enabled: true,
            active: true,
            paused: false,
            attempt: 3,
            next_retry_in: Some(Duration::from_secs(42)),
            last_error: Some(ErrorStateReason::SetRouting),
            latched_reason: None,
        });
        assert_eq!(retrying["attempt"], 3);
        assert_eq!(retrying["next_retry_secs"], 42);
        assert_eq!(retrying["last_error"], "SetRouting");
        assert!(retrying["latched"].is_null());

        let latched = always_on_json(&AlwaysOnStatus {
            enabled: true,
            active: true,
            paused: false,
            attempt: 0,
            next_retry_in: None,
            last_error: Some(ErrorStateReason::Internal("boom".into())),
            latched_reason: Some("Internal".into()),
        });
        assert_eq!(latched["latched"], "Internal");
        assert_eq!(latched["last_error"], "Internal");

        let paused = always_on_json(&AlwaysOnStatus {
            enabled: true,
            active: false,
            paused: true,
            ..AlwaysOnStatus::default()
        });
        assert_eq!(paused["enabled"], true);
        assert_eq!(paused["active"], false);
        assert_eq!(paused["paused"], true);
    }

    #[test]
    fn offline_state_mapping() {
        let mut out = serde_json::Map::new();
        insert_offline(&mut out, true);
        assert_eq!(out["state"], "offline");
        assert_eq!(out["connected"], false);
        assert_eq!(out["reconnect"], true);
        let mut out = serde_json::Map::new();
        insert_offline(&mut out, false);
        assert_eq!(out["reconnect"], false);
    }

    #[test]
    fn tunnel_flags_carry_always_on() {
        let mut config = VpnServiceConfig::default();
        assert_eq!(tunnel_flags_json(&config)["always_on"], "off");
        config.always_on = true;
        assert_eq!(tunnel_flags_json(&config)["always_on"], "on");
        assert!(degraded_tunnel_config("x".into())["always_on"].is_string());
    }

    #[test]
    fn mnemonic_and_label_validation() {
        assert!(valid_mnemonic("abandon ability able about"));
        assert!(!valid_mnemonic("Abandon ability"));
        assert!(!valid_mnemonic("abandon; rm -rf /"));
        assert!(!valid_mnemonic(""));
        assert!(valid_label("HTTPS reverse proxy (main)"));
        assert!(!valid_label("bad;label"));
    }

    #[test]
    fn arg_helpers_accept_jshn_and_json_shapes() {
        let args = json!({
            "a": true, "b": "1", "c": "true", "d": "0", "e": false,
            "on": "on", "off": "off", "num": "42", "jnum": 7
        });
        assert!(arg_flag(&args, "a"));
        assert!(arg_flag(&args, "b"));
        assert!(arg_flag(&args, "c"));
        assert!(!arg_flag(&args, "d"));
        assert!(!arg_flag(&args, "missing"));
        assert_eq!(arg_flag_present(&args, "e"), Some(false));
        assert_eq!(arg_flag_present(&args, "missing"), None);
        assert_eq!(arg_onoff(&args, "on"), Some(true));
        assert_eq!(arg_onoff(&args, "off"), Some(false));
        assert_eq!(arg_onoff(&args, "num"), None);
        assert_eq!(arg_u32(&args, "num"), Some(42));
        assert_eq!(arg_u32(&args, "jnum"), Some(7));
    }

    #[test]
    fn gateway_json_shape() {
        let gw = gateway("idX", "gw-x", Some("NL"), Score::High);
        let v = gateway_json(&gw, GatewayType::MixnetExit);
        assert_eq!(v["id"], "idX");
        assert_eq!(v["name"], "gw-x");
        assert_eq!(v["country"], "NL");
        assert_eq!(v["bridges"], false);
        assert!(v["performance"].as_str().unwrap().starts_with("High"));
    }
}
