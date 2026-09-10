# Client: `cpprobe scan`

Run it from the network you want to measure. It needs the server's IP and,
ideally, the server's SPKI pin.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/xarvel/CensorPulseCli/main/scripts/install.sh | sh
```

The script downloads the latest release binary for Linux/macOS amd64/arm64,
verifies it against the release's `SHA256SUMS`, and installs it into
`/usr/local/bin`, prompting for `sudo` when that directory is not writable
(without sudo it falls back to `~/.local/bin`).
`CPPROBE_INSTALL_DIR=$HOME/.local/bin` (or any writable directory on `PATH`)
picks the target explicitly and avoids the sudo prompt. It needs no Go
toolchain.

If no release is available it falls back to a source build. When run from a
checkout (`sh scripts/install.sh`, or `make install`) it deliberately builds
that checkout. `CPPROBE_BUILD=1` forces the source path; for a private fork set
`CPPROBE_GIT_URL` to an SSH URL. A missing Go toolchain is installed under
`~/.cpprobe/go` only on this path.

Other ways: `make build` → `bin/cpprobe`; `make cross` → `dist/` for
linux/darwin × amd64/arm64 and windows-amd64.

No root is required: the client uses ordinary TCP/UDP sockets only.

### Run from Docker

If the client machine has Docker but no Go toolchain:

```bash
sh scripts/scan-docker.sh --target 203.0.113.10 --pin '<pin>' --out report.json
```

The script builds the image from the checkout on first use (same image as the
server) and rebuilds it whenever the Go sources, `go.mod`/`go.sum` or the
`Dockerfile` changed since (a checksum is kept as an image label;
`CPPROBE_REBUILD=1` forces it). The container is throwaway (`--rm`), so there
is nothing to recreate by hand. It then runs `cpprobe scan` with `--network host`, the current directory
mounted at `/out` as the working directory (so `--out report.json` lands next
to you) and your own uid, so the file is yours. Every argument goes to
`cpprobe scan` unchanged; `make docker-scan ARGS="…"` is the same thing.

Raw `docker run` equivalent:

```bash
docker build -t censorpulse-probe:local .
docker run --rm -it --network host -u "$(id -u):$(id -g)" -v "$PWD:/out" -w /out \
  censorpulse-probe:local scan --target 203.0.113.10 --pin '<pin>' --out report.json
```

Host networking matters: it gives the scan the machine's real source ports and
RTTs. On Docker Desktop (macOS/Windows) it is an opt-in feature; without it the
script falls back to a bridge network, which adds a NAT hop (the scan still
works, timings are less precise). On Linux with Docker Engine it is native.

## Run

```bash
cpprobe scan --target 203.0.113.10 --pin 'GG8h46W5lmeX7LTeusJFlMEmVDr5SQ0Dbl2AYuopoyo=' --out report.json
```

| Flag | Default | Meaning |
|---|---|---|
| `--target` | | server IP (required; a host name is resolved once, prefer an IP) |
| `--port` | 8443 | control port |
| `--pin` | empty | expected SPKI pin. Without it the client trusts the pin it sees on first use, cross-checks it with `/v1/params` and marks the report `pin_enforced=false` |
| `--profile` | `full` | `full` runs the complete catalog, 3 rounds. `quick` is the country-neutral phone profile: about forty flows in one round, then two more rounds for the ports that had a failure. It covers opaque echo vs HTTP on 80/8080/443; Host/SNI; TLS 1.2/1.3 and Chrome/Firefox/Android fingerprints; direct and system DNS; QUIC; Snowflake-style STUN plus browser/Pion DTLS; vanilla Tor TLS/link shape on 443; and VPN sessions with handshake controls (OpenVPN `tls-auth`, WireGuard, obfs4 and VLESS-Reality). `cpprobe tests` marks the tests it draws from; `--plan` shows the exact cells |
| `--tests` | | comma-separated test ids, e.g. `tcp.echo,tls.sni,quic.v1`; overrides the profile, and unknown ids are rejected |
| `--repeat` | 3 (`quick`: 1) | rounds every plan runs; `high` confidence needs 3 samples of the failing cell and of its control |
| `--retry` | 0 (`quick`: 2) | extra rounds for the port groups (transport/port) that had a failure in the first rounds: a failing cell and the controls on its port reach the samples a confident verdict needs while a clean port stays at one attempt |
| `--parallel` | 4 | concurrent attempts |
| `--timeout` | 6s | per attempt (connect and reply) |
| `--trigger-host` | `www.youtube.com` | Host/SNI used by the `trigger:*` variants of `http.host` and `tls.sni` |
| `--local-addr` | | bind every socket to this local IP (interface selection on multi-homed hosts) |
| `--sni-list` | | file with one SNI per line (`#` comments and trailing notes are ignored); each is added as a `tls.sni` variant and as a TLS bulk upload (allow-list search: which names get more than N KB through). `lists/sni-allowlist-ru-2025-07.txt` is a starting point |
| `--sni-sample` | 0 | use only N randomly chosen entries of `--sni-list` (a 266-name list × ports × rounds is a long scan) |
| `--bulk-kb` | 64 | size of each `tcp.bulk` transfer |
| `--burst-n` | 4 | parallel handshakes per `tls.burst` attempt |
| `--geoip-dir` | `~/.cpprobe/geoip` (or `$CPPROBE_GEOIP_DIR`) | GeoLite2 CSV tables from `cpprobe geoip update`; when present the report's `network` field carries the scanning network's ASN, organisation and country, looked up offline from the address the server saw |
| `--session-packets` | 12 | data packets exchanged after the handshake in every `*.session` test |
| `--reality-sni` | www.microsoft.com | foreign SNI carried by the `vless.reality` ClientHello (a name that does not belong to the probe IP) |
| `--adaptive-timeout` | true | per-attempt timeout = 6 × control RTT + 0.5 s, clamped to 1.5 s … `--timeout` |
| `--sites` | false | also run the real-destinations family `dest.*` (below): DNS system-vs-DoH, TCP, the SNI differential and HTTP 451 against real sites. The only tests that send traffic somewhere other than the probe server |
| `--targets` | | with `--sites`: a file with one site per line instead of the built-in catalog (format under `cpprobe sites`) |
| `--geoip-online` | false | when the offline tables are absent, ask a public geo-ASN API (ipwho.is, then ipapi.co) for the network's ASN, organisation and country; `network.source` names it. The address the API returns is discarded |
| `--bypass-check` | true | warn in the report when a known VPN / circumvention process is running |
| `--color` | auto | `auto` colours the progress line and the text report on a terminal (`NO_COLOR` disables), `always` / `never` force it; JSON is never coloured |
| `--verbose` | false | show every result cell; the default summary shows family coverage and anomalous cells only |
| `--plan` | false | connect, print the selected tests and exact attempt count, then exit without running tests or writing a report |
| `--out` | `report-<UTC>.json` | JSON report path |
| `--json` | | print the JSON report to stdout instead of the text summary |
| `--quiet` | | no progress on stderr |

`quick` detects DPI behavior visible during the scan. It cannot by itself
exclude address-list blocking of other endpoints or delayed active probing;
those require distributed destinations and post-scan server observation.
`quick` is a filter over what the server offers: a server without one of
its test ids runs the profile without that cell (or with the fallback cell
of the same family) instead of refusing the scan.

Exit code 0: the scan ran (even if it found blocking). Exit code 1: the
server was unreachable (`probe_unreachable`) or an I/O error.

Run `cpprobe tests` to list both profiles and every valid test id. Numeric
flags are bounded before the client contacts the server, and a malformed pin
or local address fails with an actionable error instead of starting a scan.

## What a scan does

1. `GET /v1/params` over pinned TLS: ports, enabled tests, WireGuard key. A pin
   mismatch aborts the scan as `probe_unreachable`, never as "blocked".
2. `POST /v1/session`: per-session HMAC key, bearer token, UDP cookie.
3. `GET /v1/health`: the server's listener snapshot goes into the report so a
   broken listener is not mistaken for censorship.
4. Plans are built from the server's ports (table below) and run `--repeat`
   times in random order with 250–1250 ms jitter and fresh source ports;
   with `--retry`, the port groups that had a failure run that many rounds
   more before the serial tail.
5. Native handshakes (TLS, QUIC, OpenVPN, WireGuard, random payload) reserve
   an `attempt_id` first; envelope tests correlate by nonce; DNS by the
   query name `<nonce>.<session>.<test>.probe.invalid`; HTTP by the path.
6. `GET /v1/session/{id}/observations`, merge with the client's attempts,
   classify, write the report.

## Plans

Ports come from `/v1/params`. Families with conventional ports use the
intersection with what the server offers, otherwise the first offered port.

| Test | Where | Variants (role) | Success |
|---|---|---|---|
| `tcp.echo` | every TCP port | `cp1-64` (baseline) | reply envelope with the right nonce and SHA-256 |
| `tcp.payload.random` | every TCP port | `random-64` (control) | 8-byte SHA-256 ack after the quiet period |
| `tcp.rtt` | 443 or first | `x5` | 5× connect+echo; records connect vs payload RTT, `synack_suspect` when the ratio is below 0.5. Every TCP attempt also records its own `connect` duration (measured from the dial, after the control-plane reservation), so the classifier can compare SYN-ACK times across ports |
| `udp.echo` | every UDP port | `cp1-64` (baseline) | reply envelope (cookie required) |
| `udp.payload.random` | every UDP port | `random-64` (control) | `hash_ack` |
| `http.host` | 80 / 8080 / 443 | `benign` (baseline), `trigger:<host>`, `random` (control) | 200, deterministic body, `X-CP1-Nonce` |
| `dns.udp` | DNS ports | `TXT` (baseline), `A`, `trigger:<host>`; queries padded with EDNS0 to 300 B | expected TXT/A for probe-zone names; a second, different answer to the same query is `dns_injected_race` even when the genuine one came first. `trigger:<host>` asks the probe for the trigger name, which is outside its zone: the genuine answer is `REFUSED` with no records, so any record (`detail.injected_a`) or a second answer came from the path |
| `dns.tcp`, `dns.dot`, `dns.doh` | 53 / 853 / control port | `TXT` | as above |
| `dns.system` | system resolver | `whoami` | only when the server serves a real delegated zone (`dns_zone`); the TXT answer must match and carries `recursor=<ip>`, the resolver that really served the client |
| `tcp.bulk` | 80 / 8080 and 443 / 8443 / 4433 | `up-plain` (baseline), `down-plain`, `up-tls` (baseline), `down-tls`, `up-tls:trigger:<host>`, `up-tls:list:<sni>` | `--bulk-kb` moved over one keep-alive HTTP/1.1 connection in 4 KB chunks (POST) or one verified GET; a reset or stall records the exact byte offset on both ends |
| `tls.version` | 443 / 8443 / 4433 | `1.3` (baseline), `1.2` | handshake + envelope echo inside |
| `tls.sni` | same | `benign`, `trigger:<host>`, `absent` (control); Go's TLS stack so only the SNI varies | as above |
| `tls.alpn` | same | `http/1.1` (baseline), `h2`, `cp1`, `none` | as above |
| `tls.fingerprint` | same | `chrome` (baseline), `firefox`, `safari`, `ios`, `edge`, `android`, `golang` via uTLS (`360`, `qq` selectable in code) | as above; the ALPN on the wire is the parrot's own (`h2, http/1.1`), not the probe's. Rules seen in the field act on the chrome/safari/ios parrots and let edge/android/firefox through: when the chrome baseline itself fails, the classifier takes any passing parrot as the control, so the passing set names the axis |
| `tls.burst` | 443 or first TCP port; **runs last, serially** | `chrome-x4` (variant), `firefox-x4` (control) | `--burst-n` handshakes to one random SNI fired together, then one handshake to another SNI, then one without SNI, every one with the envelope echo inside. `burst_freeze` = some parallel handshakes failed and the single one passed; the detail carries `alpha_ok`, `beta_outcome`, `gamma_outcome`, `burst_spread_ms` (how far apart the ClientHellos left), `server_alpha_seen` / `server_alpha_hello`. The rate rule it targets freezes a name for minutes, hence last and alone |
| `tcp.packets` | 80 / 8080 (plain) and 443 (TLS) | `plain-2B`, `tls-2B` | the `tcp.echo` envelope written in 2-byte segments 20 ms apart (Go sets `TCP_NODELAY`, so one segment per write, about 65 of them). `packets_cut` with `packets_sent` when the echo never comes: a per-flow packet counter, as opposed to the byte counter `tcp.bulk` measures. Control: `tcp.echo` on the same port |
| `udp.packets` | 443 or first UDP port | `cp1-32x32` | 32 cookie-bearing envelopes of 32 B on one socket, each awaiting its echo; stops after three unanswered in a row. `packets_acked`, `first_loss`, `server_packets_seen` (observations on that source port) |
| `tor.handshake` | 9001 (all variants, **serial tail**) and 443 (`tor-hello+tor-cert@1.3`) | `go-hello+probe-cert` (baseline), `go-hello+tor-cert`, `tor-hello+probe-cert`, `tor-hello+tor-cert`, `tor-hello+tor-cert@1.3` | a vanilla Tor connection to an ORPort: the tor/OpenSSL 3.0 ClientHello (no SNI, Firefox cipher list plus the SCSV, no ALPN, no session ticket, ed448 in signature_algorithms) and/or the relay link certificate (RSA-2048 link key certified by a 1024-bit identity key, `www.<random>.com` issued by `www.<random>.net`), then VERSIONS both ways and CERTS / AUTH_CHALLENGE / NETINFO from the server, NETINFO from us. The four unsuffixed variants are **TLS 1.2**, the only version in which the certificate is on the wire, and vary the two plaintext features independently; the verdict says which one the rule keys on. `@1.3` is the shape a current tor produces against a current relay (certificate encrypted; only the ClientHello is visible). A variant that does not negotiate its intended version fails as `server_error`, never as blocking. Details: `server_cert`, `negotiated_version`, `cells_recv`, `link_version`, `netinfo_my_addr` |
| `tor.link` | 9001 (tail) | `tor-hello+tor-cert` | the same, then `--session-packets` CREATE_FAST cells each answered with CREATED_FAST: stateful blocking after the link handshake. Control: `tor.handshake` |
| `tor.dir` | 9030 / 80 | `consensus-microdesc` | `GET /tor/status-vote/current/consensus-microdesc.z HTTP/1.0` as a client asks a DirPort; the probe answers 200 with a consensus-shaped body |
| `obfs4.handshake` | 8388 / 443 | `ntor-shaped` | an obfs4 client request under the server's bridge identity (`obfs4_cert` in params): random representative, 85–8128 B of random padding, HMAC mark and MAC; the server finds the mark and answers with the response shape (never longer than the request). No ntor/Elligator: the wire is random bytes either way. Controls on the same port: `tcp.payload.random random-64` (one small segment) and `random-2048` (a handshake-sized opaque payload), so a rule on length or segment count is told from one on "fully encrypted" first packets |
| `obfs4.session` | same | `ntor-shaped` | then `--session-packets` framed random "frames" mirrored by the server. Control: `obfs4.handshake` |
| `stun.binding` | UDP 3478 / 443 | `rfc5389` | STUN Binding Request, success response with XOR-MAPPED-ADDRESS (`mapped_addr`; `mapped_addr_differs` when it is not the address the control plane saw) |
| `dtls.hello` | UDP 3478 / 443 | `firefox-138` (baseline), `pion`, `chrome-136` | WebRTC DTLS 1.2: ClientHello → HelloVerifyRequest → ClientHello with cookie → ServerHello. `pion` is the pion/dtls v3 shape Snowflake's client sends (the fingerprint Russia filtered in 2021 and since 2026-03-30); the browser bodies are captures from covert-dtls. Stages `hello_verify`, `handshake` |
| `quic.v1` | every UDP port with QUIC | `h3` | HTTP/3 GET of the echo |
| `openvpn.reset` | TCP 1194/443, UDP 1194/443 | `tcp`, `udp` | `HARD_RESET_SERVER_V2` echoing our session id |
| `wireguard.init` | UDP 51820/443 | `noise-ik` | cryptographically valid handshake response |
| `wireguard.session` | UDP 51820/443 | `noise-ik+data` | the same handshake, then `--session-packets` authenticated transport packets (type 4, 64–1024 B plaintext, both directions) on the same 5-tuple; the outcome records how many came back and where the first loss was |
| `openvpn.session` | TCP 1194/443, UDP 1194/443 | `tcp+control`, `udp+control` | reset exchange, then the control channel: `P_ACK_V1` and `--session-packets` × `P_CONTROL_V1` (the first carries a real TLS ClientHello), each answered by ack + control |
| `ikev2.init` | UDP 500, 4500 | `plain`, `nat-t` | IKE_SA_INIT with a real Curve25519 KE payload; the response echoes SA/KE/Nonce. NAT-T framing (non-ESP marker) on 4500 |
| `ikev2.session` | UDP 500, 4500 | `plain`, `nat-t` | the SA_INIT, then IKE_AUTH; on 4500 the data phase is ESP-in-UDP echoed by the server, on 500 it is further IKE_AUTH-shaped exchanges (raw ESP needs a kernel SA an unprivileged client cannot make) |
| `l2tp.init` | UDP 1701 | `v2` | L2TPv2 SCCRQ; the server answers SCCRP with an assigned tunnel id |
| `l2tp.session` | UDP 1701 | `v2` | tunnel and session setup (SCCCN, ICRQ/ICRP, ICCN), then PPP data messages (first is an LCP Configure-Request) echoed by the server |
| `socks5.connect` | TCP 1080 | `noauth`, `userpass` | greeting, optional RFC 1929 username/password, CONNECT to a probe name; the server never dials out, CONNECT "succeeds" to 0.0.0.0:0 |
| `socks5.session` | TCP 1080 | `noauth` | after CONNECT, TLS-shaped bytes are pushed through the tunnel and mirrored back |
| `vless.reality` | TCP 443, 4433 | `reality:<sni>`, `benign` | a Chrome-fingerprint TLS 1.3 handshake with a foreign SNI (`--reality-sni`, default www.microsoft.com), then a VLESS request carrying an inner TLS ClientHello (TLS-in-TLS). `benign` is the same with a probe SNI |
| `vless.session` | TCP 443, 4433 | `reality:<sni>`, `benign` | the same, then application-data-shaped records mirrored by the server |

### Real destinations (`dest.*`)

Every other test talks to the probe server. This family talks to real sites:
it answers "what does this network do to the sites people open", the
question the mobile app asks first. It rides along with any scan
(`--sites`) or runs alone, without a server:

```bash
cpprobe sites                                   # the built-in catalog, one round, two retry rounds for the sites that failed
cpprobe sites --targets my-sites.txt --geoip-online --out sites.json
cpprobe scan --target IP --pin PIN --profile quick --sites   # phone profile plus the sites
```

The `sites` command takes `--repeat` (1), `--retry` (2), `--parallel`,
`--timeout`, `--deadline` (2 minutes for the whole run, so that a
blackholed network cannot hang the caller; sites not reached are noted as
missing, not clear), `--local-addr`, `--geoip-online`, `--out`, `--json`,
`--quiet`, `--color`, `--verbose`, `--plan` and `--tests` (dest ids only).

`--targets` is one site per line, `#` comments, options after the domain:
`category=news`, `label="Meduza"`, `ip=1.2.3.4,5.6.7.8` (probed ahead of
the resolved addresses), `sni=name`, `dns=name`, `tcp-only` (no TLS: an
address that speaks something other than web TLS), `no-dns` (only `ip=`),
`http` (add the application-layer check). The built-in catalog is in
`internal/dest/dest.go`: two control sites that should be clear anywhere
(Wikipedia, example.com), then YouTube, the social networks, the messengers
(including the Telegram data-centre addresses, TCP only), the app stores,
video conferencing, streaming, Steam, GitHub, news sites and the AI services
with the HTTP check.

| Test | Where | Variants (role) | What it does |
|---|---|---|---|
| `dest.nxdomain` | system resolver, DoH | `invalid` (control) | a fresh `cp-nxd-<nonce>.invalid` name must be NXDOMAIN everywhere (RFC 6761); an address from the system resolver is `dns_answer_mismatch` with `detail.hijack=system` |
| `dest.tcp` | tcp/443 | `anycast` (control) | the first of 1.1.1.1, 1.0.0.1, 9.9.9.9 that connects: the transport control of the family. When it fails, nothing below gets a verdict |
| `dest.dns` | system resolver, DoH | `<domain>` (baseline for control sites, else variant) | A/AAAA from the system resolver and from Cloudflare, Google and Quad9 (wire POST, then GET, then the JSON API; the domain endpoint, then the IP-literal one). Sinkhole addresses on the system side with public ones on the trusted side, system addresses for a name the trusted side says does not exist, or NXDOMAIN from the system resolver for a name the trusted side resolves, are `dns_answer_mismatch` (`detail.tamper` = `bogon`, `hijack`, `nxdomain`). Disjoint answer sets are **verified**: the system address and the trusted address (same address family) are each connected to and handshaken with the real name (`detail.verify_system`, `verify_trusted`); the system address serves only if its certificate verifies for the name (a chain that fails on the trusted address too is the host's root store, not a sinkhole); only when it does not serve while the trusted address does is it poisoning (`system_address_fails`), otherwise it is CDN geo-DNS and the cell passes. SERVFAIL/REFUSED from every trusted resolver is `inconclusive`. `detail.system_ips`, `trusted_ips`, `trusted_rcode`, `resolvers`, `probe_source` (which answers the other layers use: trusted, else the public system ones, else `ip=`) |
| `dest.tcp` | tcp/443 | `<domain>` | connect to the site's addresses in priority order (public IPv4 first) until one accepts; `detail.endpoint`, `tried` |
| `dest.tls` | tcp/443 | `<domain>` (variant), `decoy:<domain>` (control), `absent:<domain>` (control) | three handshakes on the **same address**: the real name, a random decoy name (www.microsoft.com, www.apple.com, …) and no name. A TLS alert from the server counts as an answer (the ClientHello got through; `detail.alert` keeps it), except `decode_error` / `illegal_parameter`. `negotiated_version`, `cipher`, `cert_subject`, `cert_issuer`, `cert_verified` (against the system roots and the name) |
| `dest.http` | tcp/443 | `<domain>` | for `http` targets: `GET https://<domain>/` with a browser User-Agent on the same address, real certificate verification, up to 5 redirects. `451` is `http_legal_block`; `403` is noted and passes (a bot wall as often as a country gate) |

Plans are grouped per site (`dest/<domain>`, controls in `dest/control`),
so a retry round re-runs a whole site. There is no reservation and no
server observation: `merged` is the outcome itself, and the classifier
(`dest_*` verdicts in [report.md](report.md)) only ever pairs a failing cell
with a control measured the same way: the decoy handshake on the same
address, the anycast connect, a control site's resolution. Confidence is
capped at `medium`. The report's `destinations` array is the per-site view:
each layer's result and the verdict that covers the site (`clear`,
`nxdomain`, a `dest_*` kind, `degraded`, `inconclusive`); the text summary
prints the sites that are not clear.

Embedding note: the system-resolver half needs the platform's resolver.
Where Go's `net.DefaultResolver` cannot see it (a phone), the embedder
passes `Options.SystemResolver`, a function that returns the platform's
addresses for a name, and the comparison is unchanged.

The `*.session` tests exist because a handshake-only test cannot see
stateful blocking: on networks where "the handshake completes but no traffic
flows", `wireguard.init` passes and only `wireguard.session` fails. The
handshake test on the same port is the session test's control.

## Reading the summary

```
RESULTS  87 cells: ✓ 85 ok, ✗ 1 failed, ~ 1 mixed
   TEST      WHERE     VARIANT                  ROLE      OK   DOMINANT (client+server)    SAW
✗  tls.sni   tcp/443   trigger:www.youtube.com  variant   0/3  rst_injected_or_path_reset  0
✓  tls.sni   tcp/443   benign                   baseline  3/3  ok                          3

VERDICTS (1)  behaviour compatible with …, not attribution

  ✗ sni_or_host_blocking_suspected  [high]  tls.sni tcp/443 trigger:www.youtube.com
      · tls.sni tcp/443 trigger:...: 0/3 ok, dominant=rst_injected_or_path_reset, server_saw=0
      · passing baseline: tls.sni tcp/443 benign: 3/3 ok, dominant=ok, server_saw=3
```

By default the terminal prints a compact family-coverage line and only
anomalous cells. `--verbose` adds every passing cell. The JSON report always
contains every raw attempt and cell. Glyphs and the OK / DOMINANT columns are
coloured (green pass, red fail, yellow mixed; confidence red/yellow/dim), and
the progress line is redrawn in place with failed attempts left standing.
`--color never` or `NO_COLOR=1` gives the plain form.

- `OK`: successful attempts out of all attempts of that cell.
- `DOMINANT`: the most frequent client+server merge result (full list in
  [report.md](report.md)).
- `SERVER SAW`: attempts the server could attribute to this cell. `0` next to
  a client timeout means the traffic never reached the server (uplink drop);
  `3` next to a timeout means the server answered and the reply was lost
  (downlink drop).
- Every verdict cites the control that passed. Without a passing control there
  is no verdict, only `control_failed_inconclusive`.

## Recipes

```bash
# what works on this network, in about a minute (the phone profile)
cpprobe scan --target IP --pin PIN --profile quick

# is the server alive?
cpprobe scan --target IP --pin PIN --tests tcp.echo,udp.echo,http.host --repeat 1

# inspect the exact full plan without running it
cpprobe scan --target IP --pin PIN --plan

# do long flows survive, and which SNI values get more than 64 KB through?
cpprobe scan --target IP --pin PIN --tests tcp.echo,tcp.bulk --sni-list my-snis.txt --bulk-kb 128

# is the limit counted in bytes or in packets? (tcp.bulk vs tcp.packets on the same port)
cpprobe scan --target IP --pin PIN --tests tcp.echo,udp.echo,tcp.bulk,tcp.packets,udp.packets

# does a burst of parallel handshakes to one name freeze it, and does the browser parrot matter?
cpprobe scan --target IP --pin PIN --tests tls.sni,tls.fingerprint,tls.burst --burst-n 4

# is Tor blocked here, and by which feature? (vanilla ORPort shape, obfs4 shape, Snowflake's DTLS fingerprint)
cpprobe scan --target IP --pin PIN --tests tcp.echo,tcp.payload.random,tls.sni,tor.handshake,tor.link,tor.dir,obfs4.handshake,obfs4.session,stun.binding,dtls.hello

# record the scanning network's ASN/country in the report (tables are fetched once, read offline)
cpprobe geoip update && cpprobe scan --target IP --pin PIN

# TLS policy only, with a different trigger
cpprobe scan --target IP --pin PIN --tests tls.sni,tls.fingerprint,tls.alpn --trigger-host rutracker.org

# from a specific interface on a multi-homed machine
cpprobe scan --target IP --pin PIN --local-addr 10.20.30.40

# does a VPN flow survive past the handshake? (needs a server with the "vpn-session" feature)
cpprobe scan --target IP --pin PIN --tests udp.echo,wireguard.init,wireguard.session,openvpn.reset,openvpn.session --session-packets 24

# every VPN/proxy protocol, handshake and session, against a fully-featured server
cpprobe scan --target IP --pin PIN --tests wireguard.init,wireguard.session,openvpn.reset,openvpn.session,ikev2.init,ikev2.session,l2tp.init,l2tp.session,socks5.connect,socks5.session,vless.reality,vless.session --reality-sni www.microsoft.com

# machine-readable
cpprobe scan --target IP --pin PIN --quiet --json > report.json

# re-derive cells and verdicts of an old report with this build's classifier
cpprobe classify --in report.json --out report.reclassified.json --verbose
```

## What the scan reveals about you

- Every test talks to the probe IP only, with one family excepted. The
  trigger host (`--trigger-host`) and the REALITY name (`--reality-sni`) are
  sent as strings in SNI / Host / DNS queries to that IP; nothing is sent to
  those hosts.
- The exception is `dest.*` (`--sites`, `cpprobe sites`): it connects to the
  catalog sites on :443, sends their names (and decoy names) as SNI to their
  own addresses, queries Cloudflare, Google and Quad9 over DoH, resolves the
  names through the system resolver, and connects to 1.1.1.1 / 1.0.0.1 /
  9.9.9.9. Those endpoints see the client as an ordinary visitor.
  `--geoip-online` additionally asks ipwho.is or ipapi.co about the client's
  own address; the answer's address field is discarded.
- `dns.system` puts the session id into a query name that travels through
  the machine's own resolver chain (that is the point of the test).
- The report names circumvention tools found running on the client
  (`warnings`) and, with `--geoip-dir`, the network's ASN and country. It
  never contains the client's IP address beyond `client_public_addr`, which
  the server saw anyway.
- Sending VPN-, Tor-, obfs4- or Snowflake-shaped traffic is visible to a
  middlebox; the tests reproduce shapes, not the services, but a network that
  reacts to shapes reacts to these too.

## Limits

- No raw sockets: TTL of injected packets, spoofed SYN-ACKs and segmentation
  can only be inferred (`tcp.rtt` yields a signal, not a verdict).
- One server IP does not prove that a third-party domain is blocked;
  `trigger:*` measures the middlebox's sensitivity to the string.
- A NAT that changes the source address between the control plane and UDP
  tests produces `cookie_mismatch_nat_or_multipath`: a network diagnostic, not
  censorship.
- Interface selection on phones (Wi-Fi vs cellular) belongs to the mobile
  integration; `--local-addr` covers desktops.
