# CensorPulse Probe

Measure what a network does to your traffic, with evidence from both ends.

`cpprobe` is one static binary. Run it as a **server** on any clean public IP
(Docker, one command) and as a **client** from the network you want to test.
The client only needs the server's IP: it runs a catalog of controlled tests
(TCP, UDP, HTTP, DNS, TLS, QUIC, long flows, VPN and proxy protocol shapes,
Tor, Snowflake-style WebRTC) and reports which protocols, ports and
handshake shapes are passed, blocked or modified on the path.

Every verdict is built from **two halves of evidence**: what the client saw and
what the server saw for the same flow, plus a paired control on the same port.
A client-side timeout alone is never called "blocked".

```
$ cpprobe scan --target 203.0.113.10 --pin 'GG8h46…='

RESULTS  118 cells: ✓ 114 ok, ✗ 3 failed, ~ 1 mixed
coverage: ✓ tcp 20/20  ✓ udp 17/17  ✓ http 9/9  ✓ dns 12/12  ✗ tls 18/20
          ✓ quic 2/2  ✗ wireguard 3/4  ✓ tor 8/8  ✓ obfs4 4/4  ✓ dtls 3/3
ANOMALIES
   TEST             WHERE      VARIANT                  ROLE      OK   DOMINANT (client+server)      SAW
✗  tls.sni          tcp/443    trigger:www.youtube.com  variant   0/3  rst_injected_or_path_reset    0
✗  wireguard.session udp/51820 noise-ik+data            variant   0/3  uplink_drop_after_handshake   3

VERDICTS (2)  behaviour compatible with …, not attribution

  ✗ sni_or_host_blocking_suspected  [high]  tls.sni tcp/443 trigger:www.youtube.com
      · tls.sni tcp/443 trigger:www.youtube.com: 0/3 ok, dominant=rst_injected_or_path_reset, server_saw=0
      · passing baseline: tls.sni tcp/443 benign: 3/3 ok, dominant=ok, server_saw=3

  ✗ wireguard_session_cut_suspected  [high]  wireguard.session udp/51820 noise-ik+data
      · handshake on the same port passed: wireguard.init udp/51820 noise-ik: 3/3 ok
      · data packets answered: median 0 of 12; server saw median 2 data packets: data stopped on the way to the server
```

## Quick start

### 1. Server (a VM with a public IP)

```bash
git clone https://github.com/xarvel/CensorPulseCli.git && cd CensorPulseCli
sudo sh scripts/install-server.sh
```

Installs Docker if needed, frees port 53 from `systemd-resolved`, starts the
probe with `docker compose` and prints the **SPKI pin**. Keep the pin: it is
the only root of trust, no DNS or CA involved.

Ports to open in your firewall / cloud security group (defaults, editable in
`deploy/probe.yaml`):

| Protocol | Ports |
|---|---|
| TCP | 53, 80, 443, 853, 1080, 1194, 4433, 8080, 8388, 9001, 9030, **8443** (control API) |
| UDP | 53, 443, 500, 1194, 1701, 3478, 4433, 4500, 8388, 51820 |

Manual alternative: `cd deploy && docker compose up -d --build`. For a fresh
VM, `deploy/cloud-init.yaml` does the same at first boot (SSH key placeholder,
`CP_REPO` / `CP_BRANCH` for a fork; see [docs/server.md](docs/server.md)).

### 2. Client (the network under test)

```bash
curl -fsSL https://raw.githubusercontent.com/xarvel/CensorPulseCli/main/scripts/install.sh | sh
cpprobe scan --target <server-ip> --pin '<pin>' --out report.json
```

The installer downloads the latest checksum-verified release binary; if no
release exists it falls back to a source build. From a checkout,
`sh scripts/install.sh` deliberately builds that checkout. It installs into
`/usr/local/bin` and may prompt for `sudo` to do so;
`CPPROBE_INSTALL_DIR=$HOME/.local/bin` (any writable directory) avoids that.

Or `make build` and use `bin/cpprobe`. No root needed on the client: it uses
ordinary sockets, exactly what a mobile app can do.

With Docker instead of a Go toolchain (Linux, host network; the image is
rebuilt automatically when the sources change):

```bash
sh scripts/scan-docker.sh --target <server-ip> --pin '<pin>' --out report.json
```

Optional: `cpprobe geoip update` fetches GeoLite2 CSV tables once so that
reports record the scanning network's ASN and country, looked up offline.

The default `full` profile runs the complete catalog in three rounds: the
research mode. `--profile quick` is the country-neutral phone profile: about
forty flows in one round, two more rounds for the ports that failed, covering
the main DPI axes seen across filtered networks (web interception, Host/SNI,
TLS version and fingerprints, DNS injection, QUIC, Snowflake-style
STUN/DTLS, Tor shape, and VPN sessions on their usual ports). `--plan`
connects to the server and shows the exact attempt count without running
tests.

The phone profile measures discrimination visible during its own flows. A
clean result cannot rule out address-list blocking of unrelated endpoints or
delayed active probing (notably used against circumvention servers): those
need distributed destinations and server-side observation after the scan.

`--sites` adds the **real destinations** family to any scan, and
`cpprobe sites` runs it alone, with no server at all: a catalog of sites
(Wikipedia, YouTube, the messengers, the app stores, news, AI services;
`--targets` for your own list) is resolved through the system resolver and
three DoH resolvers, connected to on :443, given a TLS handshake with its
real name, a decoy name and no name on the same address, and, for the
services that gate by region, an HTTP request. That family talks to those
sites and to Cloudflare / Google / Quad9; everything else in the probe talks
to the probe server only. Its evidence is one-sided (no server half), so its
verdicts never exceed `medium`, and the report carries a per-site summary
(`destinations`).
`cpprobe tests` lists profiles and test ids. The terminal summary shows family
coverage and anomalies; add `--verbose` to show every passing cell too. The
JSON always contains all raw evidence.

### 3. Everything on one machine

```bash
make build && make selftest        # loopback server + full scan, must come out clean (needs python3)
make test                          # unit + integration tests (fault injection, anti-abuse)
```

## What it tests

| Family | Tests | Tells apart |
|---|---|---|
| TCP | `tcp.echo`, `tcp.payload.random`, `tcp.rtt` | port reachability, payload modification, spoofed SYN-ACK signal |
| Long flows | `tcp.bulk` (upload / download, plain and TLS, trigger SNI, `--sni-list`) | flows cut or stalled after N kilobytes, per-SNI allow-lists, throughput |
| Packet counts | `tcp.packets` (the echo in 2-byte segments, plain and TLS), `udp.packets` (32 small datagrams) | per-flow packet-count rules (l4-25) as opposed to byte-count rules |
| UDP | `udp.echo`, `udp.payload.random` | UDP / port blocking, "unknown UDP" drops |
| HTTP | `http.host` (benign / trigger / random Host) | block pages, redirects, Host-sensitive filtering |
| DNS | `dns.udp` (A/TXT), `dns.tcp`, `dns.dot`, `dns.doh`, `dns.system` (with a delegated zone) | resolver hijack, spoofed answers, UDP/53, DoT, DoH policy, which recursor really serves you |
| TLS | `tls.version`, `tls.sni` (benign / trigger / absent), `tls.alpn`, `tls.fingerprint` (Chrome, Firefox, Safari, iOS, Edge, Android, Go via uTLS) | SNI filtering, version/ALPN policy, ClientHello fingerprinting and which parrots pass |
| TLS bursts | `tls.burst` (N parallel handshakes to one name, then single handshakes to another name and without SNI) | rate rules that freeze a name after a burst of handshakes, and whether they depend on the parrot |
| QUIC | `quic.v1` (HTTP/3) | QUIC / UDP-443 blocking |
| VPN | `openvpn.reset` (TCP/UDP), `wireguard.init` (real Noise IK handshake) | VPN signature detection at the handshake |
| VPN sessions | `wireguard.session`, `openvpn.session` (handshake + N data/control packets both ways) | stateful blocking: the handshake completes, the data does not |
| IPsec | `ikev2.init`, `ikev2.session` (real X25519 IKE_SA_INIT, IKE_AUTH, ESP-in-UDP on 4500) | IKEv2/IPsec reachability and session cut |
| L2TP | `l2tp.init`, `l2tp.session` (L2TPv2 tunnel/session + PPP data) | plain L2TP reachability and session cut |
| Proxies | `socks5.connect`, `socks5.session` (RFC 1928/1929, server never egresses) | SOCKS5 reachability, auth policy, tunnel cut |
| REALITY | `vless.reality`, `vless.session` (Chrome uTLS, foreign SNI, inner TLS-in-TLS) | VLESS/REALITY SNI-vs-IP and TLS-in-TLS blocking |
| Tor | `tor.handshake` (tor/OpenSSL ClientHello × relay link certificate, four variants), `tor.link` (CREATE_FAST rounds), `tor.dir` (DirPort request) | vanilla Tor blocking and which plaintext feature the rule keys on; stateful cuts after the link handshake |
| obfs4 | `obfs4.handshake`, `obfs4.session` (handshake shape under the server's bridge identity, mirrored frames) | "fully encrypted traffic" rules vs. the 64-byte random control |
| WebRTC / Snowflake | `stun.binding`, `dtls.hello` (pion, Firefox and Chrome DTLS ClientHello fingerprints) | STUN blocking, DTLS fingerprint rules that target Snowflake's client |
| Real destinations | `dest.dns`, `dest.nxdomain`, `dest.tcp`, `dest.tls`, `dest.proto`, `dest.http` (`--sites`, or `cpprobe sites` without a server) | how the network treats the sites people open: system resolver against three DoH resolvers, TCP to the site's address, the SNI differential (real name, decoy name, no name on the same address), the service's own handshake where the address does not speak web TLS (the WhatsApp gateway), HTTP 451; one-sided evidence, verdicts capped at medium |

Each test runs 3 rounds by default, in random order, next to a passing
baseline and a negative control on the same port. Timeouts adapt to the
measured RTT, and the report warns when a VPN or circumvention tool is running
on the client. The full plan list is in
[docs/client.md](docs/client.md); every outcome and verdict a report can
contain is in [docs/report.md](docs/report.md).

## How it works

```
client (cpprobe scan)                              server (cpprobe server)
──────────────────────                             ─────────────────────────
GET  /v1/params          ── pinned TLS :8443 ──▶   pin, keys, ports, tests
POST /v1/session         ──────────────────────▶   session id, token, HMAC key, UDP cookie
tests on the test ports  ──────────────────────▶   responders + one observation per flow
  (native handshakes reserve a correlation window first: POST …/attempt)
GET  /v1/session/…/observations ───────────────▶   the server's half of the evidence
merge + classify ──▶ report.json
```

- **Envelope**: our own payloads carry session, test id, nonce, sequence and an
  HMAC; the reply carries the SHA-256 of what the server received, so
  modification in either direction is visible.
- **UDP cookie** bound to the client IP seen on the control plane: without it
  the UDP responders stay silent and the server cannot be used as a reflector.
- **Reservations** correlate handshakes that cannot carry an envelope
  (TLS ClientHello, QUIC Initial, VPN initiations, obfs4, STUN, DTLS).
- **One port, many protocols**: the TCP dispatcher sniffs the first bytes, the
  UDP dispatcher the datagram shape; QUIC is multiplexed on the same UDP ports.
- **No egress**: DNS answers only the synthetic `probe.invalid` zone, HTTP never
  proxies, VPN and proxy responders stop at the handshake or mirror locally.
- **Classifier**: a merge table (client outcome × server observation) and
  differential verdicts with `high / medium / low` confidence.

## Documentation

| | |
|---|---|
| [docs/server.md](docs/server.md) | deployment, configuration, control API, what the server does with each flow, privacy, anti-abuse |
| [docs/client.md](docs/client.md) | installation, flags, test plans, reading the summary |
| [docs/report.md](docs/report.md) | JSON schema, outcomes, merged results, verdicts |
| [docs/status.md](docs/status.md) | what is implemented, known limits, roadmap |
| [docs/design/](docs/design/README.md) | design notes, specs and prior art the implementation follows (the specs are in Russian) |
| [THIRD_PARTY.md](THIRD_PARTY.md) | borrowed material, licences, research credited |
| [bind/README.md](bind/README.md) | embedding the engine in a mobile app: gomobile build, API, config, platform notes |
| [SECURITY.md](SECURITY.md) | what counts as a security bug in the server, how to report it privately |
| [Releases](https://github.com/xarvel/CensorPulseCli/releases) | binaries, mobile bindings and release notes per tag |
| [LICENSE](LICENSE) | MIT |

## Repository layout

```
cmd/cpprobe/          CLI: server | scan | sites | tests | geoip | keys | classify | config | version
engine/               the scan as a Go API (Config, Hooks, Prepare/Run → report); the CLI is its client
bind/                 gomobile binding of the engine (JSON in, JSON report out) for the mobile app
internal/proto/       envelope, session token, UDP cookie
internal/server/      control API, TCP/UDP dispatchers, protocol responders
internal/client/      scan engine: session, plans, attempts, evidence merge
internal/dest/        real-destinations catalog, DoH resolvers, resolver comparison
internal/classify/    verdicts, confidence, per-site summary
internal/report/      JSON report and styled text summary
internal/geoip/       offline GeoLite2 CSV lookup of the scanning network
internal/wg/          WireGuard Noise_IKpsk2 initiator and responder
internal/ovpn/        OpenVPN hard-reset and control packets
internal/ike/         IKEv2 SA_INIT / AUTH and ESP-in-UDP shapes
internal/l2tp/        L2TPv2 control and PPP data shapes
internal/socks5/      SOCKS5 greeting / auth / CONNECT
internal/vless/       VLESS request inside TLS (REALITY-shaped flows)
internal/tor/         tor ClientHello preset, relay link certificate, link cells
internal/obfs4/       obfs4 handshake shapes with a real mark/MAC
internal/dtlsx/       DTLS 1.2 ClientHello fingerprints, HelloVerify, ServerHello
internal/stun/        STUN Binding request / response
internal/dnsx/        synthetic DNS queries and answers, padding, truncation
internal/httpecho/    deterministic HTTP echo and bulk keystream
internal/tlsx/        raw TLS record helpers
internal/integration/ end-to-end tests with fault injection
lists/                starter SNI allow-list (see THIRD_PARTY.md)
deploy/               docker-compose.yml, probe.yaml, cloud-init.yaml
scripts/              install.sh, install-server.sh, scan-docker.sh, geoip-update.sh, selftest.sh, egress-test.sh
```

## Limits worth knowing

- The `dest.*` family (`--sites`, `cpprobe sites`) is the one part of the
  probe that sends traffic to third parties: the catalog sites, the DoH
  resolvers and the anycast control addresses. Its evidence has no server
  half, so a timeout there is "the site did not answer from here", never
  more than a `medium` verdict next to a control that passed.

- One clean IP measures protocol, port and fingerprint policy and path
  modification. It does **not** prove that a specific third-party domain or
  a real Tor relay is blocked: a failing `trigger:*` SNI on our IP shows the
  middlebox's sensitivity to the string, and a failing `tor.handshake` shows
  its sensitivity to the shape, not the reachability of the real service.
- No raw sockets on the client: TTL, spoofed SYN-ACKs and segmentation are
  inferred only (`tcp.rtt` gives a signal, not a verdict).
- The VPN, proxy, Tor and obfs4 tests reproduce wire **shapes**; the server
  never runs those protocols for real and never forwards anything.
- `tls.burst` and the Tor variants run last and one at a time because a
  triggered rate rule can freeze the probe IP for minutes for everyone behind
  the same client address; a second scan right after may inherit that state.
- Sending VPN-, Tor- or obfs4-shaped traffic is itself visible to a middlebox.
  Run the client only from networks and with endpoints you are allowed to
  test.
- Verdicts are worded "behaviour compatible with …", never as attribution to
  a vendor or an operator.

## Contributing

CI (`.github/workflows/ci.yml`) runs on every push and pull request and
enforces: `gofmt` on `cmd/` and `internal/`, `sh -n scripts/*.sh`,
`go vet ./...`, `go test ./... -p 1`, `make build && REPEAT=1
./scripts/selftest.sh`, an installer smoke test (`scripts/install.sh` into a
temporary `CPPROBE_INSTALL_DIR`) and a `docker build`. Run the same before
opening a pull request. `go test -p 1` is required because the integration
tests bind fixed ports; packages run in parallel would collide.

Security issues in the server go through [SECURITY.md](SECURITY.md), not
the issue tracker.

## Embedding

The scan is a Go API, [`engine`](engine/engine.go): `engine.Run(ctx,
engine.Config{Target: ip, Profile: "quick", Sites: true}, engine.Hooks{…})`
returns the same report `cpprobe scan` writes; `Prepare` first when you
want the plan or the session before running. `Hooks` carry a progress
callback, a logger, advisory notices and the platform's system resolver
(a phone's, which Go cannot see by itself). Zero values in `Config` are the
CLI defaults.

[`bind/`](bind/README.md) is the same engine shaped for gomobile
(`make bind-ios`, `make bind-android`): `NewScan(configJSON, listener,
resolver)`, `Run()` → report JSON, `Cancel()`.

## Requirements

No runtime dependencies for a released client binary. Go 1.26 is needed only
to build from source (the installer fetches it); Docker 24+ is needed for the
server.
Dependencies: [quic-go](https://github.com/quic-go/quic-go),
[uTLS](https://github.com/refraction-networking/utls), `golang.org/x/crypto`,
`golang.org/x/net`, `yaml.v3`. Licence: MIT ([LICENSE](LICENSE)); security
reports: [SECURITY.md](SECURITY.md).
