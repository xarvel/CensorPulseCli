# Server: the control point

`cpprobe server` runs every responder and the control API in one process.
The supported way to run it is Docker Compose from `deploy/`; the installer
script wraps that.

## 1. Install in one command

On a Linux VM with a public IP:

```bash
git clone https://github.com/xarvel/CensorPulseCli.git && cd CensorPulseCli
sudo sh scripts/install-server.sh
```

The script:

1. installs Docker via `get.docker.com` (`curl | sh`) if it is missing;
2. frees TCP/UDP 53 if `systemd-resolved`'s stub listener holds it
   (`DNSStubListener=no` in a drop-in) and keeps host DNS working by
   symlinking `/etc/resolv.conf` to resolved's upstream list,
   `/run/systemd/resolve/resolv.conf`. Only when no upstream is known
   **and** `CPPROBE_FIX_RESOLV=1` is set does it write public resolvers
   (1.1.1.1 / 8.8.8.8) into `/etc/resolv.conf` instead; without the
   variable it says what to change and stops if host DNS does not resolve;
3. runs `docker compose up -d --build` in `deploy/`;
4. prints the **SPKI pin** and the list of ports to open.

Manual equivalent:

```bash
cd deploy
docker compose up -d --build
docker compose logs probe | grep -E "SPKI pin|WireGuard"
```

First start creates, in the `probe-data` volume:

| File | Purpose |
|---|---|
| `master.key` | HMAC root for tokens, cookies and per-session keys |
| `tls.crt`, `tls.key` | self-signed ECDSA P-256 certificate, 10 years, no SAN: clients trust the pin, not a name; the same certificate serves the control port and every TLS test port |
| `wireguard.key` | static key of the WireGuard responder |
| `obfs4-node.id`, `obfs4.key` | bridge identity of the obfs4 responder (node id + Curve25519 key); the public half is advertised as `obfs4_cert` |

The relay-style link certificate served to Tor-shaped handshakes is not
persisted: like a relay's link key it is regenerated at every start and
pinned through `tor_spki_pin` in `/v1/params`.

Delete the volume and the pin changes; clients scanning with `--pin` must be
updated. `cpprobe keys --data-dir …` prints the pin and the WireGuard public key
at any time (`docker compose exec probe cpprobe keys --data-dir /var/lib/cpprobe/data`).

The container runs as a non-root user, read-only, with every capability dropped
except `NET_BIND_SERVICE` (file capability on the binary for ports below 1024),
`no-new-privileges`, log rotation and a health check on `/v1/params`.

### Ports

Defaults from `deploy/probe.yaml`; all must be reachable from the networks
you want to measure:

| Role | TCP | UDP |
|---|---|---|
| control API (pinned TLS) | 8443 | |
| generic dispatcher: echo, random, HTTP, TLS, OpenVPN, SOCKS5, VLESS-in-TLS, Tor ORPort/DirPort shapes, obfs4 | 80, 443, 1080, 1194, 4433, 8080, 8388, 9001, 9030 | |
| generic dispatcher: echo, random, OpenVPN, WireGuard, IKEv2, L2TP, STUN, DTLS, QUIC/HTTP3 | | 443, 500, 1194, 1701, 3478, 4433, 4500, 8388, 51820 |
| DNS for the probe zone (`dns_zone`, default `probe.invalid`) | 53 | 53 |
| DNS over TLS | 853 | |

A port closed in the cloud security group is indistinguishable from a port
blocked on the path: the client reports `connect_timeout`. Check with
`scripts/egress-test.sh <ip>` and a first scan from a known-clean network.

### Without Docker

```bash
make build
sudo setcap cap_net_bind_service=+ep bin/cpprobe    # bind 53/80/443/853 without root
bin/cpprobe server --config deploy/probe.yaml --data-dir /var/lib/cpprobe
```

A systemd unit:

```ini
[Unit]
Description=CensorPulse probe
After=network-online.target

[Service]
User=cpprobe
ExecStart=/usr/local/bin/cpprobe server --config /etc/cpprobe/probe.yaml --data-dir /var/lib/cpprobe
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/cpprobe
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Fresh VM with cloud-init

`deploy/cloud-init.yaml` bootstraps an Ubuntu 24.04 VM end to end (Docker,
port 53, clone, compose). The only placeholder is the SSH public key; the
repository and branch default to `github.com/xarvel/CensorPulseCli` and
`main` and are overridden through the `CP_REPO` / `CP_BRANCH` environment
variables of the bootstrap script.

## 2. Configuration

One YAML with `schema_version: 1`, fully commented in
[`deploy/probe.yaml`](../deploy/probe.yaml). `cpprobe config` prints the
built-in defaults.

| Field | Meaning |
|---|---|
| `bind` | `""` = all addresses, dual-stack; `0.0.0.0` = IPv4 only; a specific IP avoids clashes with loopback-only services |
| `control_port` | pinned-TLS API; never a test port |
| `tcp_ports`, `udp_ports` | generic dispatchers; a port may not be used by two roles, startup fails otherwise |
| `dns_ports`, `dot_port` | DNS responder for the probe zone; `dot_port: 0` disables DoT |
| `dns_zone` | zone the responder is authoritative for (default `probe.invalid`, which never resolves publicly). Delegate a real subdomain's NS to the probe IP and set it here to enable the client's `dns.system` test through the machine's own resolver; `whoami.*` names answer with the recursor's address |
| `limits.bulk_mb_per_day` | per source IP, bytes served or accepted by `tcp.bulk` (64). `0` does not disable the quota: the server applies the value only when it is above 0 and keeps the 64 MiB default otherwise |
| `quic` | multiplex QUIC/HTTP3 on every `udp_ports` entry |
| `enabled_tests` | empty = every known test; restrict to reduce exposure |
| `limits.sessions_per_minute` | per source IP (10) |
| `limits.attempts_per_10min` | per source IP, counting reservations and echoed envelopes; a full 3-round scan uses about 700 (1200) |
| `limits.session_ttl_seconds` | at most 600 |
| `limits.retention_hours` | how long observations stay in memory (24); sessions themselves are dropped a minute after they expire |
| `limits.max_observations` | size of the in-memory observation ring (100000); once it is full the oldest observation is overwritten, before `retention_hours` has passed |
| `limits.idle_timeout_seconds` | read deadline of the TCP responders (5): a flow that sends nothing for that long (its first bytes, the next envelope, link cell or DNS query) is closed and recorded with `close: timeout`. The 5-minute total lifetime of a flow is fixed |
| `log.level` | `info` or `debug` (one line per flow, never payloads) |

Built-in bounds that do not depend on the address a peer uses: at most 4096
live sessions, 64 concurrent TCP flows per address, 5 minutes per TCP flow,
4 GiB of `tcp.bulk` per day in total; IPv6 clients are rate-limited per /64.
Follow-up packets of a VPN session (WireGuard transport, IKE_AUTH / ESP, L2TP,
OpenVPN control) are only answered to the address the handshake came from,
and a WireGuard initiation is not even decrypted without a pending
reservation. Flows the server cannot attribute to any session are recorded
only when the source address holds a live session (NAT diagnostics), so
strangers cannot evict real evidence from the observation ring.

Startup is **fail-closed**: a port conflict, a bind error or missing key
material aborts the whole server rather than running a partial listener set.

## 3. Control API

JSON over pinned TLS on `control_port`. Types live in
[`internal/model/model.go`](../internal/model/model.go).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/v1/params` | none | pin, WireGuard key, obfs4 identity (`obfs4_cert`), Tor link-cert pin (`tor_spki_pin`), ports, enabled tests, features |
| POST | `/v1/session` | none, rate limited per IP | open a session: `session_id`, `token`, `session_key`, `udp_cookie`, `expires_at` |
| GET | `/v1/health` | Bearer | status of every listener |
| POST | `/v1/session/{id}/attempt` | Bearer | reserve a 15 s correlation window for a native handshake |
| GET | `/v1/session/{id}/observations` | Bearer | everything the server recorded for this session |
| POST | `/dns-query` | none | DNS over HTTPS (RFC 8484) for the probe zone only |

Tokens are signed with `master.key`, bound to one session and its expiry; a
token cannot read another session's observations (403).

## 4. What the server does with a flow

**TCP port from `tcp_ports`.** After accept the first bytes are read (400 ms
window, up to 24 bytes) and the flow is dispatched by prefix:

| Prefix | Responder | Reply |
|---|---|---|
| `CP1\x01` | envelope echo, looped until the client closes. An envelope cut before its MAC is still attributed (`detail.partial=true`, `partial_bytes`) from the session id / test id / nonce it already carried and from the reservation window, so `tcp.packets` can tell "the server got 40 bytes of it" from "nothing arrived" | reply envelope with SHA-256 of the payload and server timestamps |
| `0x16 0x03 xx … 0x01` | TLS terminated with the probe certificate for any SNI; SNI, ALPN, versions, ciphers and a hello fingerprint are recorded; inside the session the dispatcher runs again (envelope / Tor link / VLESS / HTTP / unknown). A Tor-shaped ClientHello (no SNI, tor cipher list, no ALPN, ed448 offered) or a pending `tor.*` reservation whose variant says `tor-cert` gets the relay-style link certificate instead (`detail.cert=tor`, `hello_shape=tor`); the certificate is regenerated at every start and pinned via `tor_spki_pin` | ServerHello + inner echo |
| `00 00 07 …` inside TLS | Tor link handshake: VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO from us; CREATE_FAST answered with CREATED_FAST (`data_in` / `data_out`, capped like VPN sessions) | link cells |
| HTTP `/tor/…` | DirPort-style answer: `HTTP/1.0 200` with a consensus-shaped body, correlated through the reservation | `http_200` |
| random bytes carrying an obfs4 mark | the "unknown" reader looks for the HMAC mark keyed by the bridge identity in `data/obfs4-node.id` + `obfs4.key` (advertised as `obfs4_cert`); found → server response of the obfs4 shape (never longer than the request), then mirror of the frames that follow | `obfs4_response(+echo)` |
| HTTP method | deterministic echo of `/v1/echo/<session>/<test>/<nonce>` | `200`, JSON `{magic, nonce, path, host_sha256}`, `X-CP1-Nonce` |
| HTTP `/v1/bulk/<session>/<test>/<nonce>/up/<seq>` or `…/down/<bytes>` | keep-alive bulk transfer for a granted session: uploads are counted and acknowledged per chunk, downloads stream a keystream derived from the nonce; observation records bytes and last sequence | `200` per chunk / streamed body, within the daily quota |
| OpenVPN, 2-byte length 14 + opcode `0x38` | `P_CONTROL_HARD_RESET_SERVER_V2` | 26 bytes echoing the client session id |
| DNS (on `dns_ports`) | answer for the probe zone | TXT `CP1 <sha256(qname)[:32]>` or an A record from 198.18.0.0/15 |
| anything else | "unknown": read until a 1 s pause, answer with 8 bytes of SHA-256 | `hash_ack`, always smaller than the request |

**UDP port from `udp_ports`.** Dispatched by datagram shape:

| Shape | Answered when | Reply |
|---|---|---|
| `CP1` envelope | MAC valid **and** cookie matches the source IP | reply envelope |
| WireGuard initiation (148 B, type 1) | MAC1 valid, static decrypts **and** a reservation exists for this IP and port | handshake response (92 B) |
| OpenVPN reset (14 B, opcode `0x38`) | reservation | server reset (26 B) |
| QUIC long header | reservation for the first Initial; the peer's further packets pass for 30 s | quic-go + HTTP/3 echo |
| STUN Binding Request | reservation | Binding Success with XOR-MAPPED-ADDRESS |
| DTLS handshake record (`0x16 fe fd/ff`) | reservation for the cookie-less ClientHello; the ClientHello that returns the (stateless HMAC) cookie is attributed to the same attempt | HelloVerifyRequest, then ServerHello + ServerHelloDone; cipher suites, extension ids and a hello fingerprint are recorded |
| DNS (on `dns_ports`) | always, but never more bytes than the query, otherwise `TC=1` | as TCP |
| anything else | reservation | 8 bytes of SHA-256 (`hash_ack`) |

Without a reservation or cookie the server **stays silent**, but still records
the observation (`unmatched: true`), so a client can see "the server received
it but could not attribute it", the signature of a NAT changing addresses
between the control plane and the test.

## 5. Observations and privacy

Each flow yields one `Observation`: transport, ports, first-byte / reply /
close times, byte counts, SHA-256 of the payload, what was parsed, parsed
fields (SNI, ALPN, hello fingerprint, qname, HTTP path and Host hash), what was
answered and how the flow closed (`normal | client_eof | client_reset | timeout
| server_error`). Full payloads are never stored. The client IP lives only in
the in-memory session for correlation and is not exported. Everything is kept
in a memory ring (`max_observations`) with `retention_hours`; a restart clears
it.

## 6. Anti-abuse guarantees

- No egress code path exists: DNS answers only the probe zone (everything
  else is `REFUSED`), HTTP never proxies, SOCKS5 CONNECT "succeeds" to
  0.0.0.0:0, and every VPN / proxy / Tor / obfs4 responder either stops at
  the handshake or mirrors the peer's own bytes back to the peer. Nothing is
  decrypted, forwarded or relayed.
- UDP amplification factor is ≤ 1 before address validation: envelopes need a
  cookie bound to the IP that opened the session, handshakes need a
  reservation, DNS answers are truncated to the query size.
- Per-IP limits on sessions and attempts; tokens expire with the session.

`scripts/egress-test.sh <ip>` checks these from outside;
`internal/integration` checks them in CI.

## 7. After deployment

```bash
cpprobe scan --target <ip> --pin '<pin>' --repeat 1 --out check.json
scripts/egress-test.sh <ip>
```

Expected on a clean path: every cell `ok`, `VERDICTS: none`. A listener marked
`error` in `GET /v1/health` means the port is busy or closed on the host.
