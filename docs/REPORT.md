# Report: JSON schema and vocabulary

`schema_version: 1`. The report always keeps the **raw attempts**; cells and
verdicts are derived from them and can be recomputed.

```jsonc
{
  "schema_version": 1,
  "client_version": "v0.1.0",
  "target": "203.0.113.10", "control_port": 8443,
  "started_at": "...", "finished_at": "...",
  "probe_reachable": true,
  "bootstrap_error": "",                 // set when probe_unreachable
  "observed_spki_pin": "…=", "pin_enforced": true,
  "params": { ... },                     // /v1/params as received
  "session_id": "hex",
  "client_public_addr": "198.51.100.7",  // as seen by the server
  "network": { "asn": 64500, "org": "Example Mobile", "country": "RS", "prefix": "198.51.100.0/22",
               "source": "GeoLite2 CSV (...)", "tables_at": "2026-09-01T03:00:00Z" },  // offline lookup, when --geoip-dir has tables
  "control_rtt_ms": 42.1, "attempt_timeout_ms": 1500,
  "warnings": ["circumvention/VPN software is running (xray/v2ray): ..."],
  "health": { "listeners": { "tcp/443": "ok", ... } },
  "attempts": [ Attempt, ... ],
  "cells":    [ Cell, ... ],
  "verdicts": [ Verdict, ... ],
  "summary":  "clean: ..." | "kind×n, ...",
  "notes":    [ "..." ],
  "destinations": [ Destination, ... ]
}
```

`mode` is `"sites"` for a report written by `cpprobe sites` (no server:
`probe_reachable` is false, `target`, `session_id`, `params` and `health`
are absent) and empty for a scan. `network.source` says whether the ASN
came from the offline tables or from an online lookup (`online: ipwho.is`).

## Destination

Per site of the `dest.*` family, in catalog order:

```json
{ "domain": "youtube.com", "category": "dpi", "label": "YouTube",
  "verdict": "dest_sni_blocking_suspected", "confidence": "medium",
  "layers": { "dns": "ok", "tcp": "ok", "tls": "midstream_reset", "decoy": "ok", "absent": "ok" } }
```

`layers` maps `dns`, `tcp`, `tls`, `decoy`, `absent`, `http` to `ok`,
`skipped`, the dominant outcome of a failing cell, or `mixed:<outcome>`.
`verdict` is the highest-ranked `dest_*` verdict on the site, else
`clear` (every layer ok), `nxdomain` (the trusted resolvers say the name
does not exist), `inconclusive` (a layer could not be assessed) or
`degraded` (a layer failed without a verdict, typically because the family's
control failed too). A failing decoy or no-SNI control on its own never
marks the site.

## Attempt

| Field | Meaning |
|---|---|
| `test_id`, `group`, `role`, `variant` | the plan; `role` ∈ `baseline`, `variant`, `control` |
| `transport`, `dst_port`, `src_port`, `round` | addressing and round number |
| `stages_ms` | milliseconds since start: `first_write`, `handshake` (TLS / VPN reset), `first_byte`, `data_first_write`, `data_first_byte`, `done`. `connect` is the TCP connect **duration** measured from the dial. `reserve` is the control-plane reservation that preceded a native handshake; the attempt clock restarts after it, so stages are comparable across tests |
| `outcome` | client-side outcome (below) |
| `error` | Go error text |
| `bytes_out`, `bytes_in` | application bytes |
| `nonce`, `attempt_id` | correlation keys |
| `detail` | test specific: `sni`, `fingerprint`, `negotiated_version`, `negotiated_alpn`, `cipher`, `status`, `location`, `body_prefix`, `response_prefix` (hex of the first bytes of an unexpected reply), `qtype`, `rcode`, `second_answer`, `connect_min_ms`, `payload_min_ms`, `synack_suspect`, `data_sent`, `data_recv`, `data_first_loss`, `data_close`, `server_data_seen`, `ctl_sent`, `ctl_recv`, `server_ctl_seen` (session tests), … |
| `server` | the matching `Observation`, when the server could attribute the flow |
| `merged` | client + server merge result |

### `outcome` (client)

| Value | When |
|---|---|
| `ok` | expected nonce / hash / answer confirmed |
| `connect_timeout` | SYN unanswered before the deadline |
| `connect_refused` | ECONNREFUSED / ICMP port unreachable |
| `connect_reset` | RST before the first write |
| `payload_timeout` | connected, payload sent, no reply |
| `midstream_reset` | RST after the write |
| `midstream_eof` | FIN after the write without a reply |
| `tls_alert` | a TLS alert was received |
| `tls_parse_failure` | reply is not the expected TLS |
| `tls_spoof` | non-TLS bytes came back to the ClientHello (first bytes in `detail.response_prefix`) |
| `bulk_stall` | a long transfer stopped making progress (`detail.bulk_cut_kb`) |
| `bulk_reset` | a long transfer was reset or closed by the path (`detail.bulk_cut_kb`) |
| `session_cut` | VPN handshake completed but the data packets stopped being answered, i.e. the exchange ended in three unanswered in a row (`detail.data_recv` of `data_sent`, `data_first_loss`). Sporadic loss with the exchange still answered at the end is `ok` with `data_lost`. A stream torn down while not one data packet had come back is a cut as well, with `detail.data_close` holding the form the flow ended in (`midstream_eof`, `midstream_reset`): on TCP a path that swallows the tunnel packets leaves the peer idle until it hangs up |
| `packets_cut` | a flow of small packets stopped being answered, i.e. ended in three unanswered in a row: `tcp.packets` (`detail.packets_sent` counts kernel-accepted writes; `server_packets_seen` is how far the server got) or `udp.packets` (`packets_acked`, `first_loss`, `server_packets_seen`). Sporadic loss in an otherwise answered run is `ok` with `packets_lost` |
| `burst_freeze` | `tls.burst`: at least half of the parallel handshakes to one name failed while the single handshake to another name right after passed (`detail.alpha_ok` of `burst_n`, `alpha_outcomes`, `beta_outcome`, `gamma_outcome`, `burst_spread_ms`, `server_alpha_seen`, `server_alpha_hello`). Fewer failures are loss: `ok` with `alpha_lost` |
| `cert_mismatch` | certificate arrived but the pin differs; for `dest.http`, the site's certificate does not verify against the system roots and the name (`detail.cert_error`) |
| `http_legal_block` | `dest.http`: HTTP 451 after a clean handshake, the service refuses the region |
| `modified` | envelope MAC / body / handshake does not verify |
| `unexpected_response` | bytes arrived that are not the expected reply (block page, foreign protocol) |
| `dns_timeout`, `dns_rcode`, `dns_answer_mismatch`, `dns_injected_race` | DNS specific |
| `quic_no_response`, `quic_handshake_failure` | QUIC |
| `server_error` | the client could not even prepare the attempt (reservation refused, limits) |
| `inconclusive` | not enough data (e.g. `tcp.rtt` with no successful sample; `dest.dns` when every trusted resolver failed or the system resolver errored) |
| `skipped` | a layer that had nothing to work with (`dest.tcp` / `dest.tls` of a site that resolved to nothing) |

### `merged` (client + server)

| Client | Server | `merged` |
|---|---|---|
| ok | any | `ok` (or `uplink_modified` when the server flagged an invalid MAC) |
| timeout class | did not see it | `uplink_drop_or_route_failure` |
| connect_timeout | accepted an empty connection from the client's address in the reservation window | `connect_diverged_middlebox_or_misattributed`: the client never completed the handshake, so the server cannot have stayed silent on it; a middlebox completed the handshake upstream, or the empty flow is another attempt's (reservations carry no source port behind NAT) |
| timeout class | cookie mismatch | `cookie_mismatch_nat_or_multipath` |
| timeout class | first saw the flow after the client had given up (`detail.server_delay_ms` > `done` + 1 s) | `uplink_delayed_past_deadline`: the first transmissions were lost and a retransmission got through, or the path held the flow; nothing was dropped on the way back |
| timeout class | saw it and sent bytes back (a reply, or a ServerHello whose answer never came) | `downlink_drop` |
| timeout class | saw part of it and timed out / got EOF waiting for the rest, nothing sent | `uplink_drop_or_route_failure` |
| timeout class | saw it, server error of its own | `server_error` |
| timeout class (TCP) | accepted the connection and not one byte of the request arrived (`parse: empty`) | `uplink_drop_or_route_failure`: the SYN got through, the payload did not (behind NAT the empty flow could be another attempt's; the reservation window makes that unlikely) |
| timeout class | saw it, stayed silent / refused | `server_silent` |
| quic_handshake_failure by deadline | did not see it / saw the Initial | `uplink_drop_or_route_failure` / `stalled_after_server_saw_it` (the forwarder counts only what came in: the direction that lost the later packets is unknown) |
| reset | server also got a RST | `rst_injected_bidirectional` |
| reset | otherwise | `rst_injected_or_path_reset` |
| midstream_eof | did not see it | `path_closed_before_server` |
| midstream_eof | saw it | `server_closed` |
| refused | did not see it | `refused_by_path_or_port_closed` |
| tls_spoof | did not see it | `injected` |
| tls_spoof | saw it, handshake failed / replied | `server_rejected_handshake` / `downlink_modified` |
| bulk_stall / bulk_reset | did not see it | `uplink_drop_or_route_failure` |
| bulk_reset | server also got a RST | `rst_injected_bidirectional` |
| bulk_reset | otherwise | `rst_injected_or_path_reset` |
| bulk_stall | saw it, download | `downlink_drop` |
| session_cut | server saw fewer data packets than were sent | `uplink_drop_after_handshake` |
| session_cut | server saw and answered every data packet | `downlink_drop_after_handshake` |
| packets_cut | did not see it, or saw a partial envelope / fewer datagrams than were sent | `uplink_drop_or_route_failure` |
| packets_cut | echoed everything it saw | `downlink_drop` |
| burst_freeze | saw fewer ClientHellos than were sent | `uplink_drop_or_route_failure` |
| burst_freeze | sent a ServerHello to at least one, none arrived (`detail.server_alpha_answered`) | `downlink_drop` |
| burst_freeze | every ClientHello arrived cut and the server timed out waiting for the rest (`detail.server_alpha_partial`) | `uplink_drop_or_route_failure` |
| burst_freeze | saw every ClientHello whole, answered none | `server_rejected_handshake` |
| tls_alert / parse / quic handshake error | did not see it | `injected` |
| tls_alert / parse | handshake_failed, SNI differs from what was sent | `uplink_modified` |
| tls_alert / parse | handshake_failed, SNI matches | `server_rejected_handshake` |
| unexpected / modified / dns mismatch | did not see it | `injected` |
| unexpected / modified | saw it and replied | `downlink_modified` |
| cert_mismatch | | `tls_mitm_or_wrong_server` |

The `dest.*` family has no server half: its `merged` is the client outcome
itself, and `server_saw` is always 0.

Every attempt the server could attribute also carries
`detail.server_delay_ms`: how long after the client's first write the server
first saw the flow, in the client's clock (the skew between the two clocks is
estimated from `params.server_time` at bootstrap).

## Cell

Aggregate per test × transport × port × variant: `total`, `ok`, `outcomes{}`,
`merged{}`, `server_saw`. A cell "passes" when `ok` is a majority and "fails"
when `ok == 0`.

Attempts flagged `detail.transient = "true"` are left out of the cells: a
burst of failures (≥ 6 attempts on ≥ 3 ports inside 20 s) in cells that pass
in the other rounds is an outage of the scan, not a rule of the path. The
window is described in `notes` (`transient outage: …`). Failures in cells that
fail consistently are never flagged.

## Verdict

```json
{ "kind": "sni_or_host_blocking_suspected", "subject": "tls.sni tcp/443 trigger:www.youtube.com",
  "confidence": "high", "evidence": ["<failing cell>", "passing baseline: <passing cell>"] }
```

| `kind` | Condition |
|---|---|
| `probe_unreachable` | control API unreachable or pin mismatch; no protocol conclusion possible |
| `endpoint_blocking_suspected` | control plane alive but every `tcp.echo` and `udp.echo` failed |
| `port_blocking_suspected` | echo fails on one port but passes on another port of the same transport, and nothing else passes on the failing port either |
| `transparent_proxy_suspected` | echo (and the random control) fail on a port where a recognised protocol (HTTP, TLS, DNS) passes; when the server answered the opaque payload and the answer never arrived, the path relays only traffic it can parse (HTTP proxy / protocol allow-list) |
| `udp_blocking_suspected` | every UDP echo fails while TCP echo passes |
| `protocol_blocking_suspected` | a native protocol family fails on a port where echo and random pass; one verdict per family and port, and a `*.session` test whose handshake test also fails is covered by the handshake's verdict. For `ikev2.*` / `l2tp.*` the evidence notes that consumer NAT passthrough ALGs are a known confound, and when the server saw the client's flows from a rewritten source port (a NAT is in the path) the verdict is capped at `medium` |
| `control_failed_inconclusive` | the native protocol failed but so did the random control on that port |
| `sni_or_host_blocking_suspected` | `trigger:*` fails while `benign` passes on the same port |
| `sni_or_host_policy_suspected` | another SNI/Host variant (e.g. `absent`) fails with a passing baseline |
| `fingerprint_blocking_suspected` | one ClientHello fingerprint fails while `chrome` passes |
| `alpn_policy_suspected`, `tls_version_policy_suspected`, `dns_qtype_policy_suspected` | same pattern for ALPN / version / record type |
| `dns_manipulation_suspected` | a DNS answer did not match the authoritative nonce answer |
| `system_resolver_manipulation_suspected` | the machine's own resolver returned a different answer for the probe zone |
| `bulk_transfer_cut_suspected` | a long transfer fails while short exchanges pass on the same port; evidence carries the median cut offset |
| `sni_bulk_cut_suspected` | same, for a specific SNI (trigger or `--sni-list`): the name is allowed to handshake but not to carry more than N KB |
| `packet_count_cut_suspected` | `tcp.packets` / `udp.packets` fail while the one-packet echo passes on the same port: a per-flow packet counter. Evidence carries the median packets before the cut and whether `tcp.bulk` on the same port was cut too (packet rule) or passed (only many small packets trip it) |
| `tls_burst_freeze_suspected` | `tls.burst` reports `burst_freeze` in a majority of rounds: N parallel handshakes to one name are dropped while a single handshake to another name passes. Confidence from the `tls.sni benign` baseline on the port; evidence says how many hellos the server saw, answered and got cut mid-hello, and whether the same burst with the other parrot passed (fingerprint-dependent rule) or failed too. A lasting freeze of the address is only noted when the single handshakes after a burst failed as well |
| `tor_handshake_blocking_suspected` | a `tor.handshake` variant fails while `go-hello+probe-cert` passes on the same port; evidence names the feature (the tor ClientHello, the relay certificate, or only both together) from the two single-feature variants |
| `tor_session_cut_suspected`, `obfs4_session_cut_suspected` | the link / obfs4 handshake passes but the data phase does not (rule 5c, like the VPN sessions) |
| `dtls_fingerprint_blocking_suspected` | a `dtls.hello` fingerprint (`pion`, `chrome-136`) fails while the `firefox-138` baseline passes on the same UDP port |
| `protocol_blocking_suspected` (tor.dir, obfs4.handshake, stun.binding) | the whole family fails on a port where echo and the random control pass |
| `dns_udp_blocking_suspected` | `dns.udp` fails, `dns.tcp` passes |
| `dns_port_blocking_suspected` | a `dns.*` family fails on a port that carries no echo test, while an echo of the same transport passes elsewhere (a blanket block of 53 or 853) |
| `uplink_modified`, `downlink_modified`, `injected`, `rst_injected_or_path_reset`, `rst_injected_bidirectional`, `tls_mitm_or_wrong_server` | the corresponding `merged` result occurred in a cell that no differential verdict names; at most `medium`, there being no control. When a differential verdict already names the cell, the merged result is attached to it as a `mechanism: …` evidence line instead |
| `synack_local_termination_suspected` | the median TCP connect on a port is under a quarter of the median on the other ports (and ≥ 20 ms shorter): the SYN-ACK comes from a middlebox. `medium` when `tcp.rtt` on the same port agrees or `transparent_proxy_suspected` names the same port, otherwise `low` |
| `synack_spoof_signal` | `tcp.rtt` alone: connect materially faster than the payload round trip, without cross-port confirmation; a signal only |
| `wireguard_session_cut_suspected`, `openvpn_session_cut_suspected`, `ikev2_session_cut_suspected`, `l2tp_session_cut_suspected`, `socks5_session_cut_suspected`, `vless_session_cut_suspected` | the handshake / connect test passes on a port but the session test fails there; evidence carries the median data packets answered, sent and seen by the server, and the direction of the loss. OpenVPN has a control channel between the reset and the tunnel, so its evidence names which of the two was cut: "control channel passed …, data channel cut: not one data packet came back" is the signature of a path that lets the TLS handshake and PUSH_REPLY through and kills the tunnel, which is what a real client reports as `KEEPALIVE_TIMEOUT` after a clean connect |
| `sni_ip_mismatch_blocking_suspected` | `vless.reality` with a foreign SNI fails while the same handshake with a probe SNI (`benign` control) passes: the path acts on the SNI-does-not-match-IP relation that REALITY relies on |
| `socks5_auth_policy_suspected` | one SOCKS5 auth method fails while another passes on the same port |

Real destinations (`dest.*`, one-sided evidence, never above `medium`; the
control is always something measured the same way from the same vantage
point):

| `kind` | Rule |
|---|---|
| `nxdomain_hijack_suspected` | `dest.nxdomain`: a fresh `.invalid` name was answered with an address |
| `system_resolver_unreachable_suspected` | at least half of the `dest.dns` cells timed out on the system resolver while the DoH resolvers answered: one verdict for the family |
| `dest_dns_poisoning_suspected` | `dest.dns` of a site is `dns_answer_mismatch` (sinkhole addresses, addresses for a name the trusted side says does not exist, NXDOMAIN for a name the trusted side resolves, or a system address that does not serve the name with a verifying certificate while the trusted address does). `medium` with a control site that resolved cleanly, `low` without one |
| `dest_tcp_blackhole_suspected`, `dest_tcp_reset_suspected`, `dest_tcp_blocking_suspected` | `dest.tcp` of a site fails (SYN unanswered / RST or refused / other) while the anycast control connects. Also `dest_tcp_blackhole_suspected` at `low` when `dest.tls` cannot connect to the site's first address while `dest.tcp` connected to another one (no ClientHello was sent: the address, not the name). Without a passing anycast control the family gets one `control_failed_inconclusive` and no transport verdicts |
| `dest_sni_blocking_suspected` | the real-name handshake, sent on a connected socket, fails on an address where the decoy-name handshake completes: the rule keys on the SNI. Evidence adds the no-SNI cell and notes an injected block page (`tls_spoof`) |
| `dest_tls_blocking_suspected` | the real name and the decoy fail on the same address after connecting while TCP connects: address- or handshake-level, not the name alone |
| `dest_legal_block_suspected` | `dest.http` got 451 after a clean handshake: the service refuses the region, not the network |
| `dest_tls_interception_suspected` | `dest.http` fails certificate verification while the handshake itself completes (`low`) |

### `confidence`

- `high`: 3/3 failed and 3/3 of the control passed;
- `medium`: ≥ 2 attempts, ≤ 1/3 succeeded, control passes by majority;
- `low`: everything else (single round, unstable network).

`summary` counts the `high` and `medium` verdicts; `low` ones are listed
after `low confidence:` so that one unexplained timeout does not read like a
rule that fired three times.

## Observation (server)

Fields are defined in [`internal/model/model.go`](../internal/model/model.go).
Most useful when reading a report: `parse` (what the server recognised),
`response` (what it answered), `close` (`client_reset` on the server side next
to `midstream_reset` on the client means a bidirectional RST injection),
`detail.sni` (compare with what was sent), `detail.mac` / `detail.cookie` =
`invalid`, `unmatched: true` (flow not attributable to any session).
