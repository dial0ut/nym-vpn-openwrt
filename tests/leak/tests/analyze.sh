#!/bin/bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
LEAK_FW=fw4
# shellcheck source=../lib.sh
. "$HERE/lib.sh"
LEAK_HOST_DIR=$(mktemp -d)
trap 'rm -rf "$LEAK_HOST_DIR"' EXIT
LEAK_ROUTER_WAN_IP=192.168.1.252 LEAK_PROBE_IP=203.0.113.10
LEAK_ENTRY=203.0.113.20 LEAK_EXIT=203.0.113.30
# Execute only this test's generated analysis commands locally, without SSH.
px() { bash -o pipefail -c "$1"; }
python3 - "$LEAK_HOST_DIR" <<'PY'
import pathlib, socket, struct, sys
root=pathlib.Path(sys.argv[1])
def packet(dst, port, tcp=False):
    transport=(struct.pack('!HHIIBBHHH',40000,port,0,0,80,2,8192,0,0) if tcp
               else struct.pack('!HHHH',40000,port,8,0))
    return struct.pack('!BBHHHBBH4s4s',69,0,20+len(transport),1,0,64,6 if tcp else 17,0,
                       socket.inet_aton('192.168.1.252'),socket.inet_aton(dst))+transport
header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101)
data=header
for p in [packet('203.0.113.10',443,True), packet('8.8.8.8',53),
          packet('8.8.8.8',53,True), packet('203.0.113.20',51822)]:
    data+=struct.pack('<IIII',1,0,len(p),len(p))+p
(root/'valid.pcap').write_bytes(data)
(root/'truncated.pcap').write_bytes(data[:-5])
PY
analyze valid
[ "$TOTAL" = 4 ] && [ "$LEAK_SYN" = 1 ] && [ "$LEAK_DNS" = 2 ] && [ "$LEAK_WG" = 1 ] || {
    echo "wrong packet counts: total=$TOTAL syn=$LEAK_SYN dns=$LEAK_DNS wg=$LEAK_WG"; exit 1;
}
if analyze truncated; then echo 'truncated capture accepted'; exit 1; fi
if analyze missing; then echo 'missing capture accepted'; exit 1; fi
echo 'Packet classification (including TCP DNS), truncated and missing capture checks passed'
