# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Positive control: an explicit administrative stop opens the firewall by
# design. The LAN probe MUST reach the internet on the router's real address
# and dnsmasq MUST forward to the upstream resolver, or the capture cannot be
# trusted and every later verdict is INCONCLUSIVE.
scenario_expect=leak
scenario_wait=12
scenario_inject() {
    rt '/etc/init.d/nym-vpnd stop; echo "stopped at $(date +%T)"; ls /var/run/nym-firewall/'
}
scenario_post() {
    rt '/etc/init.d/nym-vpnd start'
}
