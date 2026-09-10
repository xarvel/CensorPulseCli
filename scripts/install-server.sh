#!/bin/sh
# CensorPulse probe server installer (Linux, run as root or with sudo).
#
#   sudo sh scripts/install-server.sh
#
# 1. installs Docker and git if missing;
# 2. frees TCP/UDP 53 from the systemd-resolved stub listener (Ubuntu/Debian);
# 3. builds and starts the probe with docker compose from this checkout;
# 4. prints the SPKI pin and the ports that must be open in your firewall.
#
# Docker, when absent, is installed with the upstream convenience script
# piped from https://get.docker.com (curl | sh); install it yourself first
# if you do not want that.
#
# Environment:
#   CPPROBE_KEEP_RESOLVED_STUB=1  leave port 53 alone (then remove 53 from
#                                 dns_ports in deploy/probe.yaml first)
#   CPPROBE_FIX_RESOLV=1          allow rewriting /etc/resolv.conf with public
#                                 resolvers (1.1.1.1 / 8.8.8.8) when host DNS
#                                 points at a dead stub and no upstream is known;
#                                 without it only instructions are printed
set -eu

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname -s)" = Linux ] || die "the server installer supports Linux only"
[ "$(id -u)" -eq 0 ] || die "run as root: sudo sh $0"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEPLOY="$SCRIPT_DIR/../deploy"
[ -f "$DEPLOY/docker-compose.yml" ] || die "run this script from a checkout: deploy/docker-compose.yml not found"

# ---- 1. docker + git ------------------------------------------------------
if ! have docker; then
  log "installing Docker"
  if have curl; then curl -fsSL https://get.docker.com | sh
  elif have wget; then wget -qO- https://get.docker.com | sh
  else die "need curl or wget to install Docker"; fi
fi
docker compose version >/dev/null 2>&1 || die "docker compose v2 is missing"
have git || { have apt-get && apt-get install -y -qq git; } || true

# ---- 2. port 53 -----------------------------------------------------------
port53_busy() { ss -Hlun 'sport = :53' 2>/dev/null | grep -q . || ss -Hltn 'sport = :53' 2>/dev/null | grep -q .; }
# A re-run (upgrade) finds the previous probe container on 53; compose replaces it.
port53_holders() { { ss -Hlunp 'sport = :53'; ss -Hltnp 'sport = :53'; } 2>/dev/null; }
port53_ours() { port53_holders | grep -q . && ! port53_holders | grep -v cpprobe | grep -q .; }
# \b is GNU-only; match 53 as a whole number portably.
uses53() { grep -Eq '^dns_ports:.*[^0-9]53([^0-9]|$)' "$DEPLOY/probe.yaml"; }
if uses53 && port53_busy && port53_ours; then
  log "port 53 is held by a previous cpprobe container; it will be replaced"
elif uses53 && port53_busy; then
  if [ "${CPPROBE_KEEP_RESOLVED_STUB:-0}" = 1 ]; then
    die "port 53 is busy and CPPROBE_KEEP_RESOLVED_STUB=1: remove 53 from dns_ports in deploy/probe.yaml"
  fi
  if ss -Hlunp 'sport = :53' 2>/dev/null | grep -q systemd-resolve; then
    log "port 53 is held by systemd-resolved; disabling its stub listener (host DNS keeps working)"
    log "changing: /etc/systemd/resolved.conf.d/cpprobe-no-stub.conf (DNSStubListener=no)"
    log "changing: /etc/resolv.conf -> /run/systemd/resolve/resolv.conf (resolved's upstream list)"
    log "undo: rm /etc/systemd/resolved.conf.d/cpprobe-no-stub.conf; ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf; systemctl restart systemd-resolved"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/cpprobe-no-stub.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    sleep 1
  fi
  port53_busy && die "port 53 is still busy (not systemd-resolved): $(port53_holders)"
fi
# The stub listener may have been disabled by hand earlier while
# /etc/resolv.conf still points at 127.0.0.53: then nothing answers host DNS
# and the docker build cannot even pull the base image. Point resolv.conf at
# systemd-resolved's upstream list; public resolvers only with
# CPPROBE_FIX_RESOLV=1, otherwise say what to do and let the DNS check below
# decide.
if grep -qs '^nameserver 127\.0\.0\.53' /etc/resolv.conf && ! ss -Hlun 'sport = :53' 2>/dev/null | grep -q '127.0.0.53'; then
  if grep -qs '^nameserver' /run/systemd/resolve/resolv.conf; then
    log "host DNS points at the disabled systemd-resolved stub; using its upstream servers instead"
    log "changing: /etc/resolv.conf -> /run/systemd/resolve/resolv.conf (undo: ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf)"
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  elif [ "${CPPROBE_FIX_RESOLV:-0}" = 1 ]; then
    log "host DNS points at the disabled systemd-resolved stub and no upstream is known; CPPROBE_FIX_RESOLV=1: using 1.1.1.1 / 8.8.8.8"
    log "changing: /etc/resolv.conf is replaced by a plain file (backup: /etc/resolv.conf.cpprobe-bak; undo: mv it back)"
    cp -P /etc/resolv.conf /etc/resolv.conf.cpprobe-bak 2>/dev/null || true
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
  else
    warn "host DNS points at the disabled systemd-resolved stub (127.0.0.53) and no upstream is known"
    warn "either set DNS= in /etc/systemd/resolved.conf and restart systemd-resolved, or write"
    warn "  nameserver 1.1.1.1  /  nameserver 8.8.8.8  to /etc/resolv.conf (CPPROBE_FIX_RESOLV=1 does that for you)"
  fi
fi
getent hosts registry-1.docker.io >/dev/null 2>&1 || die "host DNS does not resolve registry-1.docker.io; fix /etc/resolv.conf before building"

# ---- 3. start ---------------------------------------------------------------
cd "$DEPLOY"
log "building and starting the probe (docker compose up -d --build)"
docker compose up -d --build
sleep 3
if ! docker compose ps --status running 2>/dev/null | grep -q cpprobe; then
  docker compose logs --tail 20 probe
  die "the probe container is not running; see the log above"
fi

# ---- 4. summary -------------------------------------------------------------
PIN=$(docker compose exec -T probe cpprobe keys --data-dir /var/lib/cpprobe/data 2>/dev/null | awk '/spki_pin/{print $2}')
ports_line() { grep -E "^$1:" probe.yaml | sed -E 's/.*\[(.*)\].*/\1/'; }
CTRL=$(grep -E '^control_port:' probe.yaml | awk '{print $2}')
DOT=$(grep -E '^dot_port:' probe.yaml | awk '{print $2}')
cat <<EOF

CensorPulse probe is running.

  SPKI pin:  ${PIN:-<see: docker compose logs probe | grep SPKI>}

Open these ports in your firewall / cloud security group:
  TCP: $CTRL (control), $(ports_line tcp_ports), $(ports_line dns_ports), $DOT
  UDP: $(ports_line udp_ports), $(ports_line dns_ports)

Clients scan with:
  cpprobe scan --target <this-host-ip> --pin '$PIN' --out report.json

Manage: cd $DEPLOY && docker compose logs -f probe | stop | up -d --build
EOF
