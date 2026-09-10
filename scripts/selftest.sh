#!/usr/bin/env bash
# Starts a server on unprivileged loopback ports, scans it, and fails if the
# report contains any verdict. Usage: scripts/selftest.sh [bin/cpprobe]
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo "selftest needs python3" >&2; exit 1; }
BIN=${1:-bin/cpprobe}
TMP=$(mktemp -d)
trap 'kill $SRV 2>/dev/null || true; rm -rf "$TMP"' EXIT
cat > "$TMP/probe.yaml" <<EOF
schema_version: 1
bind: "127.0.0.1"
data_dir: $TMP/data
control_port: 18443
tcp_ports: [10080, 10443, 11194]
udp_ports: [10443, 11194, 15820]
dns_ports: [10053]
dot_port: 10853
quic: true
limits: {sessions_per_minute: 10, attempts_per_10min: 2000, session_ttl_seconds: 600, retention_hours: 1, max_observations: 10000, idle_timeout_seconds: 5}
log: {level: info}
EOF
"$BIN" server --config "$TMP/probe.yaml" >"$TMP/server.log" 2>&1 &
SRV=$!
sleep 1
"$BIN" scan --target 127.0.0.1 --port 18443 --repeat "${REPEAT:-2}" --parallel 4 --timeout 4s --out "$TMP/report.json" --quiet
python3 - "$TMP/report.json" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
cells, verdicts = r.get("cells") or [], r.get("verdicts") or []
bad = [c for c in cells if c["ok"] != c["total"]]
print(f"cells={len(cells)} attempts={len(r.get('attempts') or [])} verdicts={len(verdicts)} failing_cells={len(bad)}")
for c in bad: print("  FAIL", c["test_id"], c["transport"], c["port"], c["variant"], c["outcomes"])
sys.exit(1 if bad or verdicts else 0)
EOF
echo "selftest OK"
