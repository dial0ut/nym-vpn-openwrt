# fw3 restart exposure

Decision record. Status: **recommended, not implemented**. Part of the
[kill-switch contract](killswitch-contract.md).

## The hole

On OpenWrt ≤21.02 the firewall is firewall3 (`fw3`). `/etc/init.d/firewall restart` runs
`fw3 restart`, which in upstream `main.c` is

```c
else if (!strcmp(argv[optind], "restart"))
{
    if (fw3_lock())
    {
        build_state(true);
        stop(true);
        rv = start();
        fw3_unlock();
    }
}
```

`stop(true)` calls `fw3_flush_all` for every table (`defaults.c`):

```c
fw3_flush_all(struct fw3_ipt_handle *handle)
{
    if (handle->table == FW3_TABLE_FILTER)
    {
        fw3_ipt_set_policy(handle, "INPUT",   FW3_FLAG_ACCEPT);
        fw3_ipt_set_policy(handle, "OUTPUT",  FW3_FLAG_ACCEPT);
        fw3_ipt_set_policy(handle, "FORWARD", FW3_FLAG_ACCEPT);
    }
    fw3_ipt_flush(handle);
}
```

`fw3_ipt_flush` (`iptables.c`) flushes and deletes **every** chain in the table, ours included.
`start()` then, per family and table, prints fw3's default chains, zone chains, head rules, UCI
rules, redirects, SNATs, forwards, zone rules and tail rules and commits each table; only after
all families are populated does it run `fw3_set_defaults` and `fw3_run_includes(cfg_state,
false)`. Our include (`fw3-include.sh`) restores the kill-switch from the persisted rules files
at that last step.

So during a restart the router passes through three phases:

1. **Flush → first commit.** Built-in policies are ACCEPT and there are no chains at all.
   Everything is open, both directions. Milliseconds on x86, longer on a MIPS router with many
   zones.
2. **Commits → includes.** fw3's own configuration is in force: zone policies, the user's UCI
   rules, LAN→WAN forwarding *allowed* as on any stock router. The kill-switch is absent. LAN
   clients whose routes point into the tunnel keep going into the tunnel (routing is unaffected
   by the firewall), but anything routed via the WAN — router-originated traffic, dnsmasq's
   upstream lookups, an exempt service's replies, a LAN client with a static route — leaves.
3. **Includes.** Our chains are rebuilt and hooked; back to the contract.

A plain `reload` has none of this: `fw3_flush_rules(reload=true)` skips user chains and touches
only fw3-tagged rules. The measured behaviour (2026-09-07, VM 902, tunnel up) showed the policy
hooked at every one-second sample and zero LAN egress across a restart, which bounds the window
below a second on that box but does not measure it. The exposure is real and inherent to how
fw3 rebuilds; the include cannot run earlier than fw3 lets it.

## Options

### (a) Narrow the guarantee

Document that `firewall reload` is supported and `firewall restart` is not, log a CRITICAL line
from the include when it detects a rebuild (empty `*_rule` chains at entry, which is how the
daemon already detects it in `fw3.rs:apply`), and recommend `reload` in the docs. Zero code
beyond a log line and prose. Honest, but it does not close anything, and users do not choose
between reload and restart — packages and LuCI do, and `restart` is what `/etc/init.d/firewall
restart` gives them.

### (b) A UCI rule "belt" that fw3 rebuilds itself

Express the *coarse* blocking core of the kill-switch as UCI `config rule` sections in
`/etc/config/firewall`, e.g.

```
config rule 'nym_ks_forward'
    option name 'nym-vpn kill-switch (forward)'
    option src 'lan'
    option dest 'wan'
    option proto 'all'
    option family 'any'
    option target 'REJECT'
    option enabled '1'

config rule 'nym_ks_output'
    option name 'nym-vpn kill-switch (output)'
    option dest 'wan'
    option proto 'all'
    option family 'any'
    option target 'REJECT'
    option enabled '1'
```

fw3 emits UCI rules in `fw3_print_rules`, which `start()` runs *inside* the per-table rebuild —
before `fw3_print_forwards` (the zone forwarding policy) and long before the includes. The
`src=lan dest=wan` rule lands in `zone_lan_forward` ahead of the lan→wan accept; the `dest=wan`
rule lands in `zone_wan_output`. Both are committed with the filter table, so phase 2 above
becomes fail-closed and phase 1 shrinks to the flush-to-commit gap of a single table, which is
fw3's own exposure for its own zone policy and cannot be improved from outside fw3.

Interaction with the include-managed chains is benign and is the reason this works at all: our
`NYM_*` chains are reached from `input_rule`/`output_rule`/`forwarding_rule`, which fw3 places
**first** in the built-in chains, and every one of our policies ends in a terminal verdict. Any
packet our policy accepts (WireGuard to the entry gateway, the daemon's root-scoped API/DNS/NTP,
tunnel traffic, LAN if allowed, marked exemption replies) never reaches the belt; any packet we
reject is rejected before the belt. The belt only ever sees traffic while our chains are absent,
which is exactly the window we want closed. fw3's own established-accept in the built-ins precedes
the zone chains, so replies to existing sessions are unaffected during that window.

What the belt cannot express is everything that makes the real policy usable: uid scoping, marks,
rate limits, per-endpoint accepts. That is fine; it is a belt, not the policy. Consequences while
the belt alone is in force (phase 2 of a restart, and boot before the include): the daemon's own
bootstrap is blocked too — the same situation as under the boot block today — and the WireGuard
transport stalls for the window. Both recover when the include hooks our chains.

Ownership: the daemon owns the `enabled` flag. `set_killswitch` / `apply_killswitch_policy`
toggles it and runs `fw3 reload` when the effective kill-switch changes (a reload is cheap and
already what the include expects). The uci-defaults script registers the two sections next to the
include registration; prerm removes them on real removal; the boot guard's decision and the
belt's `enabled` flag are then two views of one setting, both persisted in UCI/JSON, and the
existing string-scan tests can pin that the section names match between Rust and the scripts.

Boot: the belt is active from the moment fw3 starts (S19), before the include even runs, so it
also fronts the boot block. The include's boot block stays; it carries the DHCP, ND and LAN
allowances that make the router usable while blocked. Management is unaffected by the belt
itself: `dest=wan` and `src=lan dest=wan` match neither LAN→router INPUT nor LAN→LAN forwarding.
That must be asserted by rendering the fw3 zone chains on a device, not assumed.

IPv6: `family=any` gives both `iptables` and `ip6tables` rules. If `ip6tables` is unusable fw3
skips v6 entirely, same as today.

Size: about 150 lines of Rust in `fw3.rs`/`common.rs` (a `uci` set/commit helper and the
reload trigger, guarded so it only fires on a change of the effective flag), 20 lines of shell
across `luci-app-nym-vpn/root/etc/uci-defaults/luci-app-nym-vpn` and `scripts/ipk/prerm`, one
string-scan test, one on-device capture across `firewall restart` on the 21.02 VM, and a
CHANGELOG entry. Risks: a user who disables the sections in LuCI silently loses the belt (log it
from the include: the section exists but `enabled=0` while the kill-switch is on); the daemon now
writes UCI, which it has avoided so far (the uci-defaults script already does, so the precedent
exists in the package but not in the daemon).

### (c) Firewall hotplug hooks

fw3 emits `hotplug-call firewall` with `ACTION=remove` from `fw3_hotplug_zones(run_state,
false)` at the top of `stop()` and `reload()`, and `ACTION=add` after the includes. The event is
`fork()`+`execl()` with no wait (`utils.c:fw3_hotplug`), so it is asynchronous and races the
flush; and even a synchronous pre-flush hook could not help, because `fw3_ipt_flush` deletes
every chain regardless of who created it. Nothing survives the flush to be found afterwards, and
`ACTION=add` fires after the includes have already run. Not viable for closing the window; at
most a place to log it.

### (d) Wrapping `/etc/init.d/firewall`

Replacing or shimming the firewall init script to insert our rules between fw3's phases means
owning a copy of another package's init script, breaks on every firewall3 update, confuses
`opkg` conffile handling, and is exactly the kind of "who owns this file" ambiguity the contract
exists to remove. Not acceptable.

## Recommendation

Do (a) now — it is a log line and a sentence, and the contract already states the window — and
implement (b) as the fix. (b) is the only option that puts the blocking rules inside the
transaction fw3 itself rebuilds, which is the same guarantee fw3 gives its own zone policy and
the best available on that firewall. It composes with the existing chains without changing them,
it also fronts the boot window on fw3, and it costs roughly a day including the device capture.
Until (b) lands, the supported statement is: on fw3, `firewall reload` keeps the kill-switch;
`firewall restart` has a sub-second window in which only fw3's own policy applies.
