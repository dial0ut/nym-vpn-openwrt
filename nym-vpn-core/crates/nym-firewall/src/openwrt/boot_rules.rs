// SPDX-License-Identifier: GPL-3.0-only

//! The one definition of the emergency and boot-time kill-switch rule sets,
//! installed by the fw3 backend (transition mode), `fw3-include.sh`
//! (transition after a daemon crash, boot at firewall start) and
//! `fw4-include.sh` (`inet nym_boot` at firewall start). `build.rs` renders
//! [`shell_fragment`] into `scripts/fw-rules.sh` and fails while it is stale.
//!
//! Compiled twice — in the crate and via `#[path]` inside `build.rs` — so it
//! must stay `std`-only with no `super::` imports.
//!
//! Both modes hook the egress path ahead of everything else and end in an
//! unconditional drop; INPUT is never touched. Transition (fw3 only) passes
//! reply-direction packets (fw3 runs `output_rule` before its own
//! established-accept, so management sessions would otherwise die) and IPv6
//! neighbour discovery. Boot adds loopback, DHCP/DHCPv6 both ways, router
//! solicitation, multicast and LAN/link-local/ULA destinations.
//!
//! DNS is rejected before the LAN-destination accepts: a router behind
//! another router has its upstream resolver at 192.168.x.1, and that
//! ordering is what keeps dnsmasq's forwards from leaving in plaintext. The
//! reject follows the loopback and reply accepts so dnsmasq still answers
//! the LAN; reject rather than drop so resolvers fail fast.

/// fw3 user chains in `filter`, preserved on reload and recreated empty on
/// restart; our chains are jumped to from position 1 of these.
pub const FW3_HOOK_INPUT: &str = "input_rule";
pub const FW3_HOOK_OUTPUT: &str = "output_rule";
pub const FW3_HOOK_FORWARD: &str = "forwarding_rule";

/// Fail-closed fw3 chains: installed by the backend and `fw3-include.sh`,
/// lifted as the last step of every apply/reset, torn down by `prerm`.
pub const EMERGENCY_OUTPUT_CHAIN: &str = "NYM_EMERGENCY_OUT";
pub const EMERGENCY_FORWARD_CHAIN: &str = "NYM_EMERGENCY_FWD";

/// fw4 boot-time block table: created by `fw4-include.sh`, deleted as the
/// last step of every apply/reset and on explicit stop and removal.
pub const FW4_BOOT_TABLE: &str = "nym_boot";

/// LAN destinations the daemon's Blocked policy lets through.
pub const LAN_NETS_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
pub const LAN_NETS_V6: &[&str] = &["fe80::/10", "fc00::/7"];
/// Accepted by the boot block only (a router coming up may have just an
/// APIPA neighbour); the Blocked policy does not accept it.
#[allow(dead_code)] // consumed by the tests that check BOOT_LAN_NETS_V4
pub const LINK_LOCAL_V4: &str = "169.254.0.0/16";
/// Multicast is accepted in OUTPUT only, never FORWARD.
pub const MULTICAST_V4: &str = "224.0.0.0/4";
pub const MULTICAST_V6: &str = "ff00::/8";

/// Destinations the boot-time block accepts in both egress chains.
pub const BOOT_LAN_NETS_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];
pub const BOOT_LAN_NETS_V6: &[&str] = LAN_NETS_V6;

/// Address family of an iptables rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn reject_udp(self) -> &'static str {
        match self {
            Family::V4 => "icmp-port-unreachable",
            Family::V6 => "icmp6-port-unreachable",
        }
    }
}

/// Which allowances the emergency block carries; see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Transition,
    Boot,
}

/// `iptables-restore --noflush` script installing the emergency block for one
/// family. Duplicate hook jumps from an earlier crashed attempt are harmless;
/// the fw3 backend removes them exhaustively when it lifts the block.
pub fn iptables_emergency_rules(family: Family, mode: Mode) -> String {
    let out = EMERGENCY_OUTPUT_CHAIN;
    let fwd = EMERGENCY_FORWARD_CHAIN;
    let mut s = String::new();
    let mut line = |l: String| {
        s.push_str(&l);
        s.push('\n');
    };

    line("*filter".into());
    line(format!(":{out} - [0:0]"));
    line(format!(":{fwd} - [0:0]"));
    line(format!("-F {out}"));
    line(format!("-F {fwd}"));
    // Reply-direction packets leave so inbound management sessions survive.
    line(format!(
        "-A {out} -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT"
    ));
    if mode == Mode::Boot {
        line(format!("-A {out} -o lo -j ACCEPT"));
        match family {
            Family::V4 => {
                line(format!("-A {out} -p udp --sport 68 --dport 67 -j ACCEPT"));
                line(format!("-A {out} -p udp --sport 67 --dport 68 -j ACCEPT"));
            }
            Family::V6 => {
                line(format!("-A {out} -p udp --sport 546 --dport 547 -j ACCEPT"));
                line(format!("-A {out} -p udp --sport 547 --dport 546 -j ACCEPT"));
                line(format!(
                    "-A {out} -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT"
                ));
            }
        }
    }
    if family == Family::V6 {
        line(format!(
            "-A {out} -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT"
        ));
        line(format!(
            "-A {out} -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT"
        ));
    }
    if mode == Mode::Boot {
        // DNS first, then the LAN/multicast accepts (see the module doc).
        for chain in [out, fwd] {
            line(format!(
                "-A {chain} -p udp --dport 53 -j REJECT --reject-with {}",
                family.reject_udp()
            ));
            line(format!(
                "-A {chain} -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
            ));
        }
        let (mcast, nets) = match family {
            Family::V4 => (MULTICAST_V4, BOOT_LAN_NETS_V4),
            Family::V6 => (MULTICAST_V6, BOOT_LAN_NETS_V6),
        };
        line(format!("-A {out} -d {mcast} -j ACCEPT"));
        for net in nets {
            line(format!("-A {out} -d {net} -j ACCEPT"));
            line(format!("-A {fwd} -d {net} -j ACCEPT"));
        }
    }
    line(format!("-A {out} -j DROP"));
    line(format!("-A {fwd} -j DROP"));
    line(format!("-I {FW3_HOOK_OUTPUT} 1 -j {out}"));
    line(format!("-I {FW3_HOOK_FORWARD} 1 -j {fwd}"));
    line("COMMIT".into());
    s
}

/// `nft -f` input atomically replacing the `inet nym_boot` table. Hooks at
/// `filter - 20`, ahead of `inet nym` (-10) and `inet fw4`, so "accept" only
/// means "let the next table decide".
#[allow(dead_code)] // rendered by build.rs into scripts/fw-rules.sh
pub fn nft_boot_block() -> String {
    let t = FW4_BOOT_TABLE;
    let set = |nets: &[&str]| nets.join(", ");
    let lan4_out = set(&[BOOT_LAN_NETS_V4, &[MULTICAST_V4]].concat());
    let lan6_out = set(&[BOOT_LAN_NETS_V6, &[MULTICAST_V6]].concat());
    let lan4_fwd = set(BOOT_LAN_NETS_V4);
    let lan6_fwd = set(BOOT_LAN_NETS_V6);
    format!(
        "table inet {t}\n\
         delete table inet {t}\n\
         table inet {t} {{\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority filter - 20; policy accept;\n\
         \x20       oifname \"lo\" accept\n\
         \x20       ct state established,related ct direction reply accept\n\
         \x20       udp sport 68 udp dport 67 accept\n\
         \x20       udp sport 67 udp dport 68 accept\n\
         \x20       udp sport 546 udp dport 547 accept\n\
         \x20       udp sport 547 udp dport 546 accept\n\
         \x20       icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept\n\
         \x20       udp dport 53 reject\n\
         \x20       tcp dport 53 reject\n\
         \x20       ip daddr {{ {lan4_out} }} accept\n\
         \x20       ip6 daddr {{ {lan6_out} }} accept\n\
         \x20       drop\n\
         \x20   }}\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter - 20; policy accept;\n\
         \x20       udp dport 53 reject\n\
         \x20       tcp dport 53 reject\n\
         \x20       ip daddr {{ {lan4_fwd} }} accept\n\
         \x20       ip6 daddr {{ {lan6_fwd} }} accept\n\
         \x20       drop\n\
         \x20   }}\n\
         }}\n"
    )
}

/// `scripts/fw-rules.sh`: the POSIX sh fragment both includes source.
/// Rendered and checked by `build.rs`; never edit the file by hand.
#[allow(dead_code)] // build.rs and the tests are its callers
pub fn shell_fragment() -> String {
    let mut s = String::new();
    s.push_str(
        "#!/bin/sh\n\
         # GENERATED FILE — do not edit. Rendered by nym-firewall/build.rs from\n\
         # src/openwrt/boot_rules.rs, the single definition of the emergency and\n\
         # boot-time kill-switch rule sets shared by the daemon and the includes.\n\
         # Regenerate after changing that file:\n\
         #   NYM_FW_RULES_REGEN=1 cargo build -p nym-firewall\n\
         # and commit the result; the build fails while this file is stale.\n\
         #\n\
         # Sourced (not executed) by fw3-include.sh and fw4-include.sh.\n\
         #\n\
         # SPDX-License-Identifier: GPL-3.0-only\n\n",
    );
    s.push_str(&format!("NYM_EMERGENCY_OUT=\"{EMERGENCY_OUTPUT_CHAIN}\"\n"));
    s.push_str(&format!(
        "NYM_EMERGENCY_FWD=\"{EMERGENCY_FORWARD_CHAIN}\"\n"
    ));
    s.push_str(&format!("NYM_BOOT_TABLE=\"{FW4_BOOT_TABLE}\"\n"));
    s.push_str(&format!(
        "NYM_LAN_NETS_V4=\"{}\"\n",
        BOOT_LAN_NETS_V4.join(" ")
    ));
    s.push_str(&format!(
        "NYM_LAN_NETS_V6=\"{}\"\n",
        BOOT_LAN_NETS_V6.join(" ")
    ));
    s.push_str(&format!("NYM_MCAST_V4=\"{MULTICAST_V4}\"\n"));
    s.push_str(&format!("NYM_MCAST_V6=\"{MULTICAST_V6}\"\n\n"));

    for (family, name) in [(Family::V4, "v4"), (Family::V6, "v6")] {
        s.push_str(&format!(
            "# {name}: iptables-restore script for the emergency OUTPUT/FORWARD block.\n\
             # $1 is \"boot\" (router may come up and stay manageable) or anything\n\
             # else for the transition set. Apply with `--noflush`.\n\
             nym_emergency_rules_{name}() {{\n\
             \x20   case \"$1\" in\n\
             \x20       boot) cat <<'EOF'\n"
        ));
        s.push_str(&iptables_emergency_rules(family, Mode::Boot));
        s.push_str(
            "EOF\n\
             \x20       ;;\n\
             \x20       *) cat <<'EOF'\n",
        );
        s.push_str(&iptables_emergency_rules(family, Mode::Transition));
        s.push_str(
            "EOF\n\
             \x20       ;;\n\
             \x20   esac\n\
             }\n\n",
        );
    }

    s.push_str(
        "# nft -f input installing the fw4 boot-time block as an atomic replace of\n\
         # the inet nym_boot table.\n\
         nym_boot_block_nft() {\n\
         \x20   cat <<'EOF'\n",
    );
    s.push_str(&nft_boot_block());
    s.push_str("EOF\n}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: &str = include_str!("../../scripts/fw-rules.sh");

    fn lines(s: &str) -> Vec<&str> {
        s.lines().map(str::trim).collect()
    }

    fn pos(lines: &[&str], needle: &str) -> usize {
        lines
            .iter()
            .position(|l| l.starts_with(needle))
            .unwrap_or_else(|| panic!("missing rule: {needle}"))
    }

    #[test]
    fn committed_shell_fragment_is_current() {
        assert_eq!(FRAGMENT, shell_fragment(), "regenerate scripts/fw-rules.sh");
    }

    #[test]
    fn boot_lan_set_is_the_policy_lan_set_plus_link_local() {
        let mut expected: Vec<&str> = LAN_NETS_V4.to_vec();
        expected.push(LINK_LOCAL_V4);
        assert_eq!(BOOT_LAN_NETS_V4, expected.as_slice());
        assert_eq!(BOOT_LAN_NETS_V6, LAN_NETS_V6);
    }

    #[test]
    fn every_iptables_set_hooks_egress_only_and_ends_in_drop() {
        for family in [Family::V4, Family::V6] {
            for mode in [Mode::Transition, Mode::Boot] {
                let script = iptables_emergency_rules(family, mode);
                let l = lines(&script);
                assert_eq!(l[0], "*filter");
                assert_eq!(*l.last().unwrap(), "COMMIT");
                assert!(!script.contains(FW3_HOOK_INPUT), "INPUT stays fw3's");
                assert!(script.contains(&format!(
                    "-I {FW3_HOOK_OUTPUT} 1 -j {EMERGENCY_OUTPUT_CHAIN}"
                )));
                assert!(script.contains(&format!(
                    "-I {FW3_HOOK_FORWARD} 1 -j {EMERGENCY_FORWARD_CHAIN}"
                )));
                // The unconditional drops are the last rules of each chain.
                let drop_out = pos(&l, &format!("-A {EMERGENCY_OUTPUT_CHAIN} -j DROP"));
                let drop_fwd = pos(&l, &format!("-A {EMERGENCY_FORWARD_CHAIN} -j DROP"));
                assert!(
                    l.iter()
                        .skip(drop_out + 1)
                        .all(|r| !r.starts_with(&format!("-A {EMERGENCY_OUTPUT_CHAIN}")))
                );
                assert!(
                    l.iter()
                        .skip(drop_fwd + 1)
                        .all(|r| !r.starts_with(&format!("-A {EMERGENCY_FORWARD_CHAIN}")))
                );
                // Reply-direction traffic is the first thing accepted.
                let reply = pos(
                    &l,
                    &format!(
                        "-A {EMERGENCY_OUTPUT_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT"
                    ),
                );
                assert!(l.iter().take(reply).all(|r| !r.starts_with("-A")));
            }
        }
    }

    #[test]
    fn transition_set_only_passes_replies_and_neighbour_discovery() {
        let v4 = iptables_emergency_rules(Family::V4, Mode::Transition);
        let v6 = iptables_emergency_rules(Family::V6, Mode::Transition);
        for script in [&v4, &v6] {
            assert!(
                !script.contains("-o lo"),
                "no loopback allowance in transition mode"
            );
            assert!(!script.contains("--dport 67") && !script.contains("--dport 547"));
            assert!(
                !script.contains(" -d "),
                "no destination accepts in transition mode"
            );
            assert!(
                !script.contains("REJECT"),
                "transition set drops, it has no DNS reject"
            );
        }
        assert!(!v4.contains("icmpv6"));
        assert!(v6.contains("--icmpv6-type neighbour-solicitation"));
        assert!(v6.contains("--icmpv6-type neighbour-advertisement"));
        assert!(
            !v6.contains("router-solicitation"),
            "RS is a boot allowance"
        );
    }

    #[test]
    fn boot_set_keeps_the_router_manageable_and_rejects_dns_before_lan() {
        for family in [Family::V4, Family::V6] {
            let script = iptables_emergency_rules(family, Mode::Boot);
            let l = lines(&script);
            let out = EMERGENCY_OUTPUT_CHAIN;
            let fwd = EMERGENCY_FORWARD_CHAIN;
            let reply = pos(&l, &format!("-A {out} -m conntrack"));
            let lo = pos(&l, &format!("-A {out} -o lo -j ACCEPT"));
            let (dhcp_a, dhcp_b, nets, mcast) = match family {
                Family::V4 => (
                    "--sport 68 --dport 67",
                    "--sport 67 --dport 68",
                    BOOT_LAN_NETS_V4,
                    MULTICAST_V4,
                ),
                Family::V6 => (
                    "--sport 546 --dport 547",
                    "--sport 547 --dport 546",
                    BOOT_LAN_NETS_V6,
                    MULTICAST_V6,
                ),
            };
            assert!(
                script.contains(dhcp_a) && script.contains(dhcp_b),
                "DHCP both ways"
            );
            if family == Family::V6 {
                assert!(script.contains("router-solicitation"));
            }
            for chain in [out, fwd] {
                let udp = pos(
                    &l,
                    &format!(
                        "-A {chain} -p udp --dport 53 -j REJECT --reject-with {}",
                        family.reject_udp()
                    ),
                );
                let tcp = pos(
                    &l,
                    &format!("-A {chain} -p tcp --dport 53 -j REJECT --reject-with tcp-reset"),
                );
                assert!(
                    reply < udp && lo < udp,
                    "reply/loopback accepts precede the DNS reject"
                );
                for net in nets {
                    let accept = pos(&l, &format!("-A {chain} -d {net} -j ACCEPT"));
                    assert!(
                        udp < accept && tcp < accept,
                        "{chain}: DNS reject precedes the {net} accept"
                    );
                }
                let drop = pos(&l, &format!("-A {chain} -j DROP"));
                assert!(tcp < drop);
            }
            let mcast_at = pos(&l, &format!("-A {out} -d {mcast} -j ACCEPT"));
            assert!(pos(&l, &format!("-A {out} -p tcp --dport 53")) < mcast_at);
            assert!(
                !script.contains(&format!("-A {fwd} -d {mcast}")),
                "multicast is router-originated only"
            );
        }
    }

    #[test]
    fn nft_boot_block_mirrors_the_iptables_boot_set() {
        let text = nft_boot_block();
        let l = lines(&text);
        assert_eq!(l[0], format!("table inet {FW4_BOOT_TABLE}"));
        assert_eq!(l[1], format!("delete table inet {FW4_BOOT_TABLE}"));
        let chains: Vec<usize> = l
            .iter()
            .enumerate()
            .filter(|(_, r)| r.starts_with("chain "))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(chains.len(), 2, "output and forward, never input");
        assert!(!text.contains("hook input"));
        assert_eq!(
            l.iter()
                .filter(|r| r.contains("priority filter - 20"))
                .count(),
            2
        );
        assert_eq!(l.iter().filter(|r| **r == "drop").count(), 2);
        for (n, &start) in chains.iter().enumerate() {
            let end = chains.get(n + 1).copied().unwrap_or(l.len());
            let chain = &l[start..end];
            let udp = pos(chain, "udp dport 53 reject");
            let tcp = pos(chain, "tcp dport 53 reject");
            let lan4 = pos(chain, "ip daddr {");
            let lan6 = pos(chain, "ip6 daddr {");
            let drop = pos(chain, "drop");
            assert!(
                udp < lan4 && tcp < lan4 && udp < lan6 && tcp < lan6,
                "{}: DNS reject precedes the LAN accepts",
                chain[0]
            );
            assert!(lan6 < drop);
            for net in BOOT_LAN_NETS_V4 {
                assert!(chain[lan4].contains(net), "{}: {net} accepted", chain[0]);
            }
            if chain[0].starts_with("chain output") {
                assert!(pos(chain, "oifname \"lo\" accept") < udp);
                assert!(
                    pos(
                        chain,
                        "ct state established,related ct direction reply accept"
                    ) < udp
                );
                assert!(chain[lan4].contains(MULTICAST_V4) && chain[lan6].contains(MULTICAST_V6));
                for must in [
                    "udp sport 68 udp dport 67 accept",
                    "udp sport 67 udp dport 68 accept",
                    "udp sport 546 udp dport 547 accept",
                    "udp sport 547 udp dport 546 accept",
                ] {
                    assert!(chain.contains(&must), "{must}");
                }
                assert!(chain.iter().any(|r| r.contains("nd-router-solicit")
                    && r.contains("nd-neighbor-solicit")
                    && r.contains("nd-neighbor-advert")));
            } else {
                assert!(
                    !chain[lan4].contains(MULTICAST_V4),
                    "forward never accepts multicast"
                );
            }
        }
    }

    #[test]
    fn shell_fragment_defines_the_shared_names_and_functions() {
        let l = lines(FRAGMENT);
        for must in [
            format!("NYM_EMERGENCY_OUT=\"{EMERGENCY_OUTPUT_CHAIN}\""),
            format!("NYM_EMERGENCY_FWD=\"{EMERGENCY_FORWARD_CHAIN}\""),
            format!("NYM_BOOT_TABLE=\"{FW4_BOOT_TABLE}\""),
            format!("NYM_LAN_NETS_V4=\"{}\"", BOOT_LAN_NETS_V4.join(" ")),
            format!("NYM_LAN_NETS_V6=\"{}\"", BOOT_LAN_NETS_V6.join(" ")),
            "nym_emergency_rules_v4() {".to_string(),
            "nym_emergency_rules_v6() {".to_string(),
            "nym_boot_block_nft() {".to_string(),
        ] {
            assert!(l.contains(&must.as_str()), "fw-rules.sh must carry: {must}");
        }
        // Every rendered rule set appears verbatim in the fragment.
        for family in [Family::V4, Family::V6] {
            for mode in [Mode::Transition, Mode::Boot] {
                assert!(FRAGMENT.contains(&iptables_emergency_rules(family, mode)));
            }
        }
        assert!(FRAGMENT.contains(&nft_boot_block()));
    }
}
