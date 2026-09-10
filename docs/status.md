# Status

Checked against the definition of done in
[`design/specs/DOCKER-PROBE.md`](design/specs/DOCKER-PROBE.md) and the catalog
in [`design/specs/TEST-CATALOG.md`](design/specs/TEST-CATALOG.md).

## Definition of done

| # | Requirement | Status |
|---|---|---|
| 1 | `docker compose up` on a clean Ubuntu brings up every P0 listener | Yes (verified on arm64; amd64 builds in CI, not yet exercised on a live host) |
| 2 | The CLI runs the whole P0 catalog against one IP and collects client + server evidence | Yes: 37 plans on the default config, every attempt matched to a server observation (`TestCleanPathIsClean`) |
| 3 | Unit tests for envelope / parsers / classifier; integration tests emulate drop, RST, modification, delay | Yes: `internal/proto`, `internal/wg`, `internal/dnsx`, `internal/classify`; `internal/integration` with a fault-injecting proxy |
| 4 | Egress test proves the probe is neither a proxy nor a recursive resolver | Yes: `TestHTTPIsNotAProxy`, `TestDNSNoRecursionNoAmplification`, `scripts/egress-test.sh`; the server has no outbound code path |
| 5 | UDP amplification ≤ 1 before validation, bounded after | Yes: silence without cookie / reservation (`TestNoReflectionWithoutReservation`), DNS truncated to the query size, reply envelopes are always shorter than requests |
| 6 | Two vantage points (clean and censored) against the same server give a matching clean baseline | Not yet run against a public deployment |
| 7 | Versioned, stable JSON report with raw attempts and derived verdicts | Yes, `schema_version: 1` ([report.md](report.md)) |

## Test catalog

| ID | Priority | Status | Note |
|---|---|---|---|
| `tcp.echo`, `tcp.payload.random`, `tcp.rtt` | P0 | done | `tcp.rtt` is a signal, not a verdict |
| `udp.echo` (+ `udp.payload.random` control) | P0 | done | cookie required |
| `http.host` | P0 | done | benign / trigger / random |
| `dns.udp`, `dns.tcp`, `dns.dot` | P0 | done | UDP queries padded with EDNS0 |
| `dns.doh` | P1 | done | on the control port |
| `dns.system` | new | done | needs a delegated `dns_zone`; whoami TXT reveals the recursor |
| `tcp.bulk` (`throughput.bounded` reshaped) | P1 | done | up/down, plain/TLS, trigger SNI and `--sni-list`; cut offset on both ends; per-IP daily quota |
| `tls.version`, `tls.sni`, `tls.alpn`, `tls.fingerprint` | P0 | done | fingerprints: chrome, firefox, safari, ios, edge, android, golang (360, qq selectable); `randomized` disabled (uTLS fails on key share) |
| `tls.burst` | new | done | N parallel handshakes to one name + single handshake to another + empty SNI; chrome and firefox parrots; runs last and alone |
| `tcp.packets`, `udp.packets` | new | done | the echo in 2-byte segments (plain / TLS) and 32 small datagrams: packet-count rules as opposed to the byte count of `tcp.bulk`; partial envelopes attributed on the server |
| `tor.handshake`, `tor.link`, `tor.dir` | new | done | vanilla Tor ORPort shape (tor/OpenSSL ClientHello × relay link certificate, four variants), link cells incl. CREATE_FAST rounds, DirPort request; see [design/tor-blocking-ru.md](design/tor-blocking-ru.md) |
| `obfs4.handshake`, `obfs4.session` | new | done | obfs4 handshake shape under the server's bridge identity (mark/MAC real, ntor/Elligator not), mirrored frames after it |
| `stun.binding`, `dtls.hello` | new | done | WebRTC as Snowflake uses it: STUN binding, DTLS 1.2 ClientHello/HelloVerify/ServerHello with the pion fingerprint and browser captures as controls |
| `quic.v1` | P0 | done | quic-go, HTTP/3 echo, multiplexed on the UDP ports |
| `openvpn.reset` | P0 | done | TCP and UDP, plain and `tls-auth` (HMAC-SHA1 over the replay fields, per-session key from `params.ovpn_tls_auth_key`); `tls-crypt` still open |
| `wireguard.init` | P0 | done | full Noise_IKpsk2 handshake; round trip covered by tests, not yet cross-checked against a kernel/wireguard-go initiator |
| `wireguard.session`, `openvpn.session` | new | done | handshake followed by `--session-packets` data packets both ways; `*_session_cut_suspected` when the handshake passes and the data does not. `openvpn.session` walks the whole real sequence: reset, control channel (ClientHello + records, acked), then the tunnel itself as authenticated `P_DATA_V2` (opcode 9, peer-id, AES-GCM per direction), so the "connects, then no traffic" block is visible; `ctl_recv` / `data_recv` separate the two phases |
| `ikev2.init`, `ikev2.session` | new | done | IKE_SA_INIT (real Curve25519 KE) + IKE_AUTH; UDP 500 and 4500 NAT-T; data phase is ESP-in-UDP (4500) or IKE_AUTH-shaped (500) |
| `l2tp.init`, `l2tp.session` | new | done | L2TPv2 tunnel + session control messages, then PPP data; plain L2TP over UDP 1701, no IPsec |
| `socks5.connect`, `socks5.session` | new | done | RFC 1928/1929 greeting, auth, CONNECT; the server mirrors, never dials out |
| `vless.reality`, `vless.session` | new | done | Chrome-fingerprint TLS 1.3 + foreign SNI + inner VLESS/TLS-in-TLS; `benign` control with a probe SNI isolates the SNI-vs-IP signal |
| `dest.dns`, `dest.nxdomain`, `dest.tcp`, `dest.tls`, `dest.proto`, `dest.http` | new | done | real destinations: the mobile app's original TS suite moved into the engine (`--sites`, `cpprobe sites` without a server). System resolver vs three DoH resolvers with verified disagreement, `.invalid` control, anycast TCP control, TCP :443, SNI differential (real / decoy / absent on one address), `dest.proto` (the WhatsApp gateway's Noise handshake: g.whatsapp.net resets any TLS ClientHello itself, on every network, which made it read as TLS-blocked everywhere until 2026-09-19), HTTP 451; per-site `destinations` summary; `--geoip-online` ASN fallback. One-sided: verdicts capped at `medium` |
| `tcp.segmented`, `http.case_split`, `tls.record_split`, `tls.ech`, `quic.v2`, `quic.shape`, `dtls.12`, `ssh.banner` | P1 | planned | |
| `shadowsocks.2022`, `vless.reality`, `trojan.tls`, `hysteria2` | P1 | planned | need separate worker containers (sing-box / xray) ending in a local nonce service |
| `tuic`, `ikev2.init`, `icmp.echo` | P2 | planned | |

## Borrowed from prior art

From [Runnin4ik/dpi-detector](design/prior-art-dpi-detector.md), reshaped to
be network-agnostic: the long-flow cut test (`tcp.bulk`, both directions, with
server-side byte counts), SNI allow-list search (`--sni-list`), the
`tls_spoof` outcome for non-TLS bytes answering a ClientHello, RTT-adaptive
timeouts, a warning when circumvention software is running, and a whoami TXT
that reveals the recursor actually serving the client (`dns.system`).

From [hyperion-cs/dpi-checkers](design/prior-art-dpi-checkers.md): the TLS
handshake rate rule test (`tls.burst`, after their "siberian" sub-checker),
the packet-count discriminator (`tcp.packets` / `udp.packets`, after their
l4-25 finding that the cut follows packets, not bytes), the "lenient" parrots
(edge, android, 360, qq) as fingerprint controls, the offline GeoLite2 lookup
of the scanning network (`network` in the report, `scripts/geoip-update.sh`),
and their 2025-07 SNI allow-list results as `lists/sni-allowlist-ru-2025-07.txt`.

## Field results

- **2026-09-11, RU mobile (docker client, old build):** every family clean except tcp/80 and tcp/8080, where HTTP passed 9/9 and opaque payloads were dropped 0/12 after the server had answered them, with SYN-ACKs in 2–5 ms against 90–250 ms elsewhere. The classifier of that build called it `port_blocking_suspected`; it is a transparent HTTP proxy, now reported as `transparent_proxy_suspected` + `synack_local_termination_suspected` (`cpprobe classify --in` recomputes old reports). The same report showed `wireguard.init` and `openvpn.reset` passing on a network where those VPNs are known not to work, which is what motivated the session tests: a handshake-only test does not see stateful blocking.

- **2026-09-13, RU, a Russian fixed-line ISP:** the scan called OpenVPN clean on udp/1194, udp/443, tcp/1194 and tcp/443 while a real OpenVPN Connect 3.11.1 on the same network could not pass a byte. The client log shows why: UDP/1194 with `tls-auth`, TLS 1.3 handshake and PUSH_REPLY complete in under a second, the tunnel negotiates `AES-256-GCM` with a peer-id, and then not one `P_DATA_V2` crosses in either direction until `KEEPALIVE_TIMEOUT` at 60 s. The build of that day never left the control channel and only knew the plain 14-byte reset, so the cut was invisible: hence the data phase and the `tls-auth` variants. Re-run pending from the same network (a mobile-operator run below shows the same cut).

- **2026-09-17, RU mobile (a Russian mobile operator), first run with the data phase** (`report-20260917-150103.json`, kept out of the repository like the other reports): OpenVPN is cut on every port and transport (udp/1194, udp/443, tcp/1194, tcp/443, plain and `tls-auth`, 0/24 sessions). The reset and the three acked control packets pass, the first `P_DATA_V2` reaches the server and is answered, the answer never arrives and the next two never reach the server: the rule keys on the first data packet (opcode 9) and then drops the flow in both directions; `tls-auth` changes nothing. In one round the 44-byte `tls-auth` reset on tcp/443 and tcp/1194 was accepted as a connection and never arrived as bytes (now merged as `uplink_drop_or_route_failure`, not `server_silent`). WireGuard on udp/51820 and udp/443: the handshake passes, exactly 6 data packets are answered, the 7th and later never reach the server, in all 6 rounds, the same count as on the fixed-line ISP four days earlier. obfs4 on tcp/443 is cut after 2–3 mirrored frames in 2 of 3 rounds and clean on tcp/8388; the transparent proxy on tcp/80 and tcp/8080 and the local SYN-ACKs on 80/443/8080 are as before; `tls.burst` freezes the chrome parrot ×4 in every round while the firefox parrot ×4 passes; IKEv2 and L2TP never reach the server (the NAT-ALG confound stands, but two operators agree). Two probe faults surfaced by this report are fixed: `server_packets_seen` on `udp.packets` was matched by source port and read 0 on every NAT'd network; a datagram lost in the middle of an answered run was reported as `packets_cut` (the loop stopped three datagrams after the first loss instead of after three unanswered in a row).

- **2026-09-18, RU mobile (a Russian mobile operator), the app 1.1.0 with engine v0.1.0, first field run of the `dest.*` family next to the quick profile:** most of the site verdicts were the probe's own faults, now fixed. (1) Every `dest.*` exchange past the connect ran on the adaptive attempt timeout, 1.5 s on a 100 ms control RTT; on that lossy path even the control point's own handshakes took 0.5–1.4 s, and the control sites, the decoys and the no-SNI handshakes timed out with nothing received: about twenty `tls_stall`-like verdicts. Those exchanges now get at least 4 s. (2) Some 18 s into the scan Android cut the app off the network: `ECONNABORTED` on the open sockets (control-plane POSTs, a handshake to wikipedia.org), `EPERM` on the next UDP send, the platform resolver refusing lookups. Those are now the host's failures (`detail.local_error`, `server_error`), the window they date is flagged as a transient outage, and `server_error` / `skipped` / `inconclusive` attempts are never evidence (`fingerprint_blocking`, `dns_port_blocking`, `protocol_blocking` of `quic.v1` and an OpenVPN cut came out of them). (3) An empty resolution taken during the outage was kept for the whole scan: seven sites had every transport layer `skipped` and two of them read `clear`. It is resolved again after 10 s, and a site whose own handshake measured nothing is `inconclusive`. (4) The trusted view of youtube.com was one AAAA record on a phone without IPv6: the host's instant "unreachable" read as a blackhole. v6 addresses are probed only with a v6 route. (5) github.com's geo-DNS disagreement was called poisoning because the check of the system address timed out: an unfinished check is `inconclusive` now. (6) dw.com, facebook.com, www.linkedin.com and meduza.io were reset 30–50 ms after the ClientHello on a 58–95 ms TCP round trip, while the decoy and no-SNI handshakes on the same addresses only timed out: an injected reset keyed on the name, now `dest_sni_blocking_suspected` with the timing in the evidence. `cpprobe classify` applies the reading of (2), (4), (5) and (6) to the stored report; (1) and (3) need a new run.

## Known limits

- **uTLS `randomized`** is excluded (`tls: CurvePreferences includes unsupported curve` inside uTLS during the TLS 1.3 key share).
- **WireGuard responder** is verified only against this project's initiator.
- **quic-go** runs on a generic `net.PacketConn` (the demultiplexer), so no GSO/ECN optimisations; irrelevant for a probe.
- **Observations** are memory-only; the SQLite option from the design is deferred.
- **No metrics endpoint**; only `/v1/health` and the debug log.
- **Host-level egress firewall** (the design asks for iptables rules) is left to the operator; the container has no code that dials out.

## Roadmap

1. Scan from a clean and a censored vantage point against one public deployment; record the results in `design/specs/EXPERIMENTS.md`.
2. Cross-check the WireGuard responder with a real `wg` initiator; run `wireguard.session` / `openvpn.session` from a network with known VPN blocking and record the cut offset.
3. Record the access type (Wi-Fi / cellular) on the client; ASN and country are done offline via `--geoip-dir`.
4. P1: record split / segmentation, ECH, QUIC v2 and shape, bounded throughput.
4a. Fidelity items from the 2026-09-12 methods review: a tor ClientHello of the OpenSSL 3.5 shape (X25519MLKEM768 first, hybrid key share); an OpenVPN `tls-crypt` / `tls-crypt-v2` reset (`tls-auth` and plain are done); validate the `pion` DTLS body against a live pion/dtls v3 capture; a `tls.sni benign` control on the ORPort; xtls-rprx-vision padding for `vless.session`.
4b. OpenVPN fidelity beyond the data channel: a genuine TLS handshake carried inside the control channel (server certificate burst and Finished, which a DPI waiting for the handshake to finish would key on) and a long `openvpn.session` variant that keeps the tunnel alive for 20–30 s with keepalives, for cuts that arrive late rather than at the first packet.
5. Worker containers for Shadowsocks-2022, REALITY, Trojan, Hysteria2.
6. gomobile wrapper around `internal/client` for the mobile app (the app's
   own TypeScript measurement suite is now the `dest.*` family here; the
   wrapper hands the platform resolver in through `Options.SystemResolver`
   and reads `destinations` for its per-site rows). The probe's module path
   and install URLs already point at its own repository,
   `github.com/xarvel/CensorPulseCli`; CI is `.github/workflows/ci.yml`,
   and a `vX.Y.Z` tag builds the release binaries through
   `.github/workflows/release.yml`.
