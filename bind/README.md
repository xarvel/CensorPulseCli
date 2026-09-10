# Mobile binding

`bind/` is the probe engine shaped for [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile):
strings and JSON in, a JSON report out, two interfaces for what only the
platform can do (report progress, resolve names the way the user's apps do).
The Go API itself is the `engine` package one directory up; the CLI uses
the same engine, so a scan from the app and a scan from `cpprobe` produce
the same report.

## Build

```bash
make bind-ios        # dist/Cpprobe.xcframework  (needs Xcode; iOS 15+, device + simulator)
make bind-android    # dist/cpprobe.aar + cpprobe-sources.jar (needs the NDK: ANDROID_NDK_HOME,
                     #   or the newest under $ANDROID_HOME/ndk; arm64-v8a, armeabi-v7a, x86_64)
make bind-check      # gobind only: fails if bind/ exports something gomobile cannot bind
sh scripts/check-16k.sh dist/cpprobe.aar   # every ABI's libgojni.so is 16 KB page-aligned
```

gomobile and gobind are tool dependencies of `go.mod` (`go tool gomobile`),
so nothing is installed globally and a laptop builds with the same pinned
version as CI. Every `vX.Y.Z` tag publishes the same artifacts on the
GitHub release (`.github/workflows/bind.yml`): `Cpprobe.xcframework.zip`,
`cpprobe.aar`, `cpprobe-sources.jar` and `SHA256SUMS.bind`; `Version()`
returns the tag. The Android build links with `-z max-page-size=16384`:
Google Play requires 16 KB page-size support of apps targeting Android
15+, and the NDK before r28 aligned segments to 4 KB; CI checks the AAR
(`scripts/check-16k.sh`) before it uploads it.

The generated class is `Cpprobe` (Swift/Objective-C) / `cpprobe.Cpprobe`
(Kotlin/Java). Expect 15–25 MB per architecture: the engine carries uTLS
and quic-go.

## API

| Go | Purpose |
|---|---|
| `NewScan(configJSON string, l Listener, r Resolver) (*Scan, error)` | validates the config and returns a scan; `l` and `r` may be nil |
| `(*Scan).Run() (string, error)` | runs the scan and returns the report JSON ([docs/report.md](../docs/report.md)); blocks for the whole scan, call it off the main thread; once per Scan |
| `(*Scan).Cancel()` | stops the scan from any thread; `Run` then returns the report of what ran |
| `DefaultConfig() string` | every config field with its default, as JSON: a quick scan with the real-destinations family |
| `ValidateConfig(configJSON string) error` | the checks `NewScan` runs, without a scan |
| `KnownTests() string` | JSON array of the test ids `tests` accepts |
| `Version() string` | engine version recorded in reports |

`Listener`:

```go
OnProgress(done, total int, testID, group, variant, outcome string)  // after each attempt; total grows as failures foretell retry rounds, never shrinks
OnLog(level, message string)                                          // debug | info | warn | error
```

`Resolver` (used by the `dest.*` family for the system-resolver side of the
DNS comparison; Go on a phone cannot see the platform resolver by itself):

```go
Lookup(host string) (string, error)   // "1.2.3.4,2606:4700::1"; error containing "nxdomain" | "timeout" | anything else = failure
```

On Android throw `Exception("nxdomain")`; on Swift throw an `NSError` whose
`localizedDescription` is the word, or a `LocalizedError` (a plain Swift
`Error` reaches Go as "The operation couldn't be completed", which counts
as a failure). Always return: the engine gives up waiting at the attempt
timeout, but a `Lookup` that never returns stays blocked in the app.
Calls to `OnProgress` and `OnLog` come one at a time from the scan's
threads, never on the caller's thread: hop to the main thread yourself
before touching UI.

## Config

`DefaultConfig()` prints every field. The ones an app sets:

| Field | Meaning |
|---|---|
| `target`, `control_port`, `pin` | the control point; empty `target` runs the real-destinations family alone (no server) |
| `profile` | `quick` (the phone profile, about forty flows in one round plus two retry rounds for the ports that failed) or `full` |
| `sites`, `targets` | add the real-destinations family; `targets` is the text of a targets file (`cpprobe help sites`) |
| `repeat`, `retry`, `parallel`, `timeout_ms`, `deadline_ms` | 0 = default; `retry` -1 = none; `deadline_ms` caps the attempts (the bootstrap before them is bounded by its own 15 s) |
| `local_addr` | bind sockets to this interface address (cellular vs Wi-Fi) |
| `geoip_dir`, `geoip_online` | offline GeoLite2 tables in the app sandbox, or a public geo-ASN API |
| `detect_bypass` | leave false on a phone: it looks for VPN processes on the host |

Two outcomes are not errors: an unreachable control point returns the
report (`probe_reachable: false`, `bootstrap_error`, verdict
`probe_unreachable`; with `sites` set the real-destinations family has
run all the same and `destinations` is filled: a network that blocks the
control point's address is where the site results are wanted most) and no
error, because the generated Java and
Objective-C bindings drop the return value whenever an error is set; a
cancelled scan returns the partial report and no error. An error from
`Run` means there is no report.

## Platform notes

- Run scans in the foreground. A quick scan takes one to two minutes; a
  full profile takes ten or more and will not survive iOS background
  limits.
- The VPN-, Tor- and obfs4-shaped flows are visible to a middlebox, like
  any other client of this probe (README, "Limits worth knowing").
- Bind every scan of one session to one interface (`local_addr`): a phone
  that switches between cellular and Wi-Fi mid-scan mixes two networks in
  one report.
- On Android the app must implement `Resolver` with the platform resolver
  (`android.net.DnsResolver` or `InetAddress`); on iOS with `getaddrinfo`
  or `NWResolver`. Without it the `dest.dns` comparison uses Go's resolver,
  which reads `/etc/resolv.conf` and on a phone sees nothing useful.
