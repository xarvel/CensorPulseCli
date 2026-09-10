#!/usr/bin/env bash
# Abuse checks against a deployed probe (DOCKER-PROBE.md, "No open
# proxy / reflection"). Every check must print PASS.
#
#   scripts/egress-test.sh <probe-ip> [control-port] [dns-port] [udp-port]
set -u
IP=${1:?probe ip}
CTRL=${2:-8443}
DNS=${3:-53}
UDP=${4:-443}
fail=0
pass() { echo "PASS  $*"; }
flunk() { echo "FAIL  $*"; fail=1; }

# 1. Recursive DNS must be refused for names outside probe.invalid.
if command -v dig >/dev/null; then
  out=$(dig +time=3 +tries=1 @"$IP" -p "$DNS" example.com A 2>&1)
  if echo "$out" | grep -q "status: REFUSED"; then pass "dns: out-of-zone query REFUSED"; else flunk "dns: expected REFUSED, got: $(echo "$out" | grep status)"; fi
  # 2. UDP DNS answer must not exceed the query (amplification <= 1).
  q=$(dig +time=3 +tries=1 +noedns @"$IP" -p "$DNS" aaaaaaaaaaaaaaaa.dns.udp.probe.invalid TXT 2>&1)
  if echo "$q" | grep -qE "flags:.* tc"; then pass "dns: small query gets TC=1 instead of a larger answer"; else
    sz=$(echo "$q" | grep -o "MSG SIZE  rcvd: [0-9]*" | grep -o "[0-9]*$"); [ -n "$sz" ] && [ "$sz" -le 80 ] && pass "dns: answer ${sz}B bounded" || flunk "dns: unbounded answer: $q"; fi
else
  echo "SKIP  dig not installed"
fi

# 3. HTTP CONNECT / absolute-URI proxying must not work.
if command -v curl >/dev/null; then
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -x "http://$IP:80" http://example.com/ 2>/dev/null)
  case "$code" in 200) flunk "http: proxied a request to example.com";; *) pass "http: proxy attempt rejected (code ${code:-none})";; esac
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -k -X CONNECT "https://$IP:$CTRL/" 2>/dev/null)
  case "$code" in 200) flunk "control: CONNECT answered 200";; *) pass "control: CONNECT rejected (code ${code:-none})";; esac
fi

# 4. Unreserved UDP garbage, unreserved WireGuard initiation and unreserved
#    OpenVPN reset must get silence (no reflection without control-plane
#    address validation).
python3 - "$IP" "$UDP" <<'EOF' || fail=1
import socket, sys, os
ip, port = sys.argv[1], int(sys.argv[2])
def probe(name, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    s.sendto(payload, (ip, port))
    try:
        d, _ = s.recvfrom(2048); print(f"FAIL  udp/{port} {name}: got {len(d)} bytes back without reservation"); return False
    except socket.timeout:
        print(f"PASS  udp/{port} {name}: silence"); return True
ok = True
ok &= probe("random 20B", b"\x05" + os.urandom(19))
ok &= probe("openvpn reset", bytes([7 << 3]) + os.urandom(8) + b"\x00" + b"\x00" * 4)
ok &= probe("wireguard-shaped 148B", b"\x01\x00\x00\x00" + os.urandom(144))
ok &= probe("quic initial-shaped", b"\xc0\x00\x00\x00\x01" + os.urandom(1195))
sys.exit(0 if ok else 1)
EOF

[ $fail -eq 0 ] && echo "ALL PASS" || { echo "SOME CHECKS FAILED"; exit 1; }
