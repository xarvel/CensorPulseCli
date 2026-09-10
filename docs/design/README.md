# Design notes

The specification phase the implementation follows, plus the prior-art
reviews that shaped later tests. The specs are in Russian and kept as
written; the English docs in `docs/` describe what is actually built. The
per-protocol literature review that preceded the specs (TCP/IP middleboxes,
TLS, HTTP/DNS, UDP/QUIC/WireGuard, VPN protocols) lives in the parent
CensorPulse repository under `docs/research/`, not here.

- `specs/TEST-CATALOG.md`: normative test catalog (P0 implemented, P1/P2 roadmap).
- `specs/WIRE-PROTOCOL.md`: sessions, envelope, reservations, observations.
- `specs/CLASSIFICATION.md`: outcomes, client+server merge table, verdicts, confidence.
- `specs/DOCKER-PROBE.md`: control point requirements and anti-abuse rules
  (the numbers there are the original targets; `deploy/probe.yaml` has the
  current defaults).
- `specs/EXPERIMENTS.md`: measurements that motivated the design.
- `prior-art-dpi-detector.md`, `prior-art-dpi-checkers.md`: what was taken
  from the two open-source DPI checkers for Russia and what was not.
- `tor-blocking-ru.md`: how Tor, obfs4 and Snowflake are blocked in Russia
  (2021–2026, with sources) and which probe test covers which mechanism.
