package classify

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

// The classifier output is a contract: verdict kinds, subjects, confidence,
// evidence strings, notes, their order and the JSON field names are what the
// reports, the mobile app and `cpprobe classify --in` read. The golden files
// pin all of it byte for byte. Regenerate them only when a rule is meant to
// change:
//
//	go test ./internal/classify/ -run TestGolden -update
var update = flag.Bool("update", false, "rewrite testdata/golden/*.json from the current classifier output")

const goldenDir = "testdata/golden"

// Classifier entry points a scenario can run through.
const (
	modeServer      = "server"      // Classify, control plane reached
	modeUnreachable = "unreachable" // Classify, control plane not reached
	modeStandalone  = "standalone"  // ClassifyStandalone
)

// goldenScenario is one input of the table. verdicts lists "kind:confidence"
// in output order: it states what the scenario is there to pin, so that an
// -update cannot silently bless an input that stopped reaching its rule.
type goldenScenario struct {
	name     string
	mode     string
	attempts func() []*client.Attempt
	verdicts []string
}

// goldenAttempt is the compact form the scenario input is stored in. It holds
// every attempt field the classifier reads and nothing else, so a new field
// on client.Attempt does not churn the golden files.
type goldenAttempt struct {
	Test          string            `json:"test"`
	Role          string            `json:"role"`
	Variant       string            `json:"variant"`
	Transport     string            `json:"transport"`
	Port          int               `json:"port"`
	Outcome       string            `json:"outcome"`
	Merged        string            `json:"merged"`
	Server        bool              `json:"server,omitempty"` // the server recorded an observation
	SrcPort       int               `json:"src_port,omitempty"`
	ServerSrcPort int               `json:"server_src_port,omitempty"`
	Round         int               `json:"round,omitempty"`
	StartedAt     string            `json:"started_at,omitempty"`
	ConnectMs     float64           `json:"connect_ms,omitempty"`
	FirstWriteMs  float64           `json:"first_write_ms,omitempty"` // the reset timing
	DoneMs        float64           `json:"done_ms,omitempty"`        // the reset timing, the span of a local outage
	ReserveMs     float64           `json:"reserve_ms,omitempty"`     // the span of a local outage
	Error         string            `json:"error,omitempty"`          // a failure of the host in a report older than detail.local_error
	Detail        map[string]string `json:"detail,omitempty"`
}

func compactAttempt(a *client.Attempt) goldenAttempt {
	g := goldenAttempt{Test: a.TestID, Role: a.Role, Variant: a.Variant, Transport: a.Transport, Port: a.DstPort,
		Outcome: a.Outcome, Merged: a.Merged, Server: a.Server != nil, SrcPort: a.SrcPort, Round: a.Round, ConnectMs: a.Stages["connect"],
		FirstWriteMs: a.Stages["first_write"], DoneMs: a.Stages["done"], ReserveMs: a.Stages["reserve"], Error: a.Error}
	if a.Server != nil {
		g.ServerSrcPort = a.Server.SrcPort
	}
	if !a.StartedAt.IsZero() {
		g.StartedAt = a.StartedAt.Format(time.RFC3339)
	}
	if len(a.Detail) > 0 {
		g.Detail = map[string]string{}
		for k, v := range a.Detail {
			g.Detail[k] = v
		}
	}
	return g
}

func classifyMode(mode string, attempts []*client.Attempt) Result {
	switch mode {
	case modeUnreachable:
		return Classify(attempts, false)
	case modeStandalone:
		return ClassifyStandalone(attempts)
	}
	return Classify(attempts, true)
}

// goldenJSON encodes v the way the files store it: keys of maps sorted (the
// encoder does that), no HTML escaping so that evidence reads as written.
func goldenJSON(t *testing.T, v any, prefix, indent string) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent(prefix, indent)
	}
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

// renderGolden classifies the scenario and returns the golden file content:
// the input one attempt per line, the full Result, and the indexes of the
// attempts the classifier flagged detail.transient=true (flagTransient
// mutates its input; which attempts it marks is part of the contract).
func renderGolden(t *testing.T, sc goldenScenario, attempts []*client.Attempt) ([]byte, Result) {
	t.Helper()
	in := make([]goldenAttempt, len(attempts))
	for i, a := range attempts {
		in[i] = compactAttempt(a) // before classification: see above
	}
	res := classifyMode(sc.mode, attempts)
	flagged := []int{}
	for i, a := range attempts {
		if a.Detail["transient"] == "true" && in[i].Detail["transient"] != "true" {
			flagged = append(flagged, i)
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "{\n  \"mode\": %q,\n  \"attempts\": [\n", sc.mode)
	for i, g := range in {
		b.WriteString("    ")
		b.Write(goldenJSON(t, g, "", ""))
		if i < len(in)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  ],\n  \"flagged_transient\": ")
	b.Write(goldenJSON(t, flagged, "", ""))
	b.WriteString(",\n  \"want\": ")
	b.Write(goldenJSON(t, res, "  ", "  "))
	b.WriteString("\n}\n")
	return b.Bytes(), res
}

// firstDiff renders the first differing line with a little context.
func firstDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		if i < len(w) && i < len(g) && w[i] == g[i] {
			continue
		}
		var b strings.Builder
		from := i - 3
		if from < 0 {
			from = 0
		}
		for j := from; j < i; j++ {
			fmt.Fprintf(&b, "  %4d   %s\n", j+1, w[j])
		}
		if i < len(w) {
			fmt.Fprintf(&b, "  %4d - %s\n", i+1, w[i])
		}
		if i < len(g) {
			fmt.Fprintf(&b, "  %4d + %s\n", i+1, g[i])
		}
		return b.String()
	}
	return ""
}

func TestGolden(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range goldenScenarios {
		sc := sc
		if seen[sc.name] {
			t.Fatalf("duplicate scenario %s", sc.name)
		}
		seen[sc.name] = true
		t.Run(sc.name, func(t *testing.T) {
			attempts := sc.attempts()
			got, res := renderGolden(t, sc, attempts)

			var have []string
			for _, v := range res.Verdicts {
				have = append(have, v.Kind+":"+v.Confidence)
			}
			if strings.Join(have, "\n") != strings.Join(sc.verdicts, "\n") {
				t.Fatalf("the scenario no longer pins what it was written for\nwant:\n  %s\ngot:\n  %s", strings.Join(sc.verdicts, "\n  "), strings.Join(have, "\n  "))
			}

			path := filepath.Join(goldenDir, sc.name+".json")
			if *update {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("%s differs from the classifier output (- golden, + got):\n%s", path, firstDiff(want, got))
			}

			// Map iteration order must never reach the output: the same input
			// classifies to the same bytes every time.
			for i := 0; i < 10; i++ {
				if again, _ := renderGolden(t, sc, sc.attempts()); !bytes.Equal(got, again) {
					t.Fatalf("run %d of the same input differs (- first, + this):\n%s", i+2, firstDiff(got, again))
				}
			}

			// `cpprobe classify --in report.json` re-runs the classifier on the
			// attempts of a stored report: they went through JSON and already
			// carry detail.transient. The result must be the one the scan got.
			raw, err := json.Marshal(attempts)
			if err != nil {
				t.Fatal(err)
			}
			var stored []*client.Attempt
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Fatal(err)
			}
			first := goldenJSON(t, res, "", "  ")
			if again := goldenJSON(t, classifyMode(sc.mode, stored), "", "  "); !bytes.Equal(first, again) {
				t.Fatalf("re-classifying the stored attempts differs (- scan, + re-run):\n%s", firstDiff(first, again))
			}
		})
	}

	// A golden file without a scenario pins nothing and only looks like coverage.
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if name := strings.TrimSuffix(filepath.Base(f), ".json"); !seen[name] {
			t.Errorf("%s has no scenario", f)
		}
	}
}

// Every verdict kind the classifier can emit, from the add() call sites of
// classify.go and dest.go. The scenarios together must produce each of them.
var allKinds = []string{
	// classify.go
	"probe_unreachable",
	"endpoint_blocking_suspected",
	"port_blocking_suspected",
	"transparent_proxy_suspected",
	"udp_blocking_suspected",
	"control_failed_inconclusive",
	"protocol_blocking_suspected",
	"variant_blocking_suspected",
	"sni_or_host_blocking_suspected",
	"sni_or_host_policy_suspected",
	"fingerprint_blocking_suspected",
	"sni_ip_mismatch_blocking_suspected",
	"alpn_policy_suspected",
	"tls_version_policy_suspected",
	"dns_qtype_policy_suspected",
	"socks5_auth_policy_suspected",
	"tor_handshake_blocking_suspected",
	"dtls_fingerprint_blocking_suspected",
	"bulk_transfer_cut_suspected",
	"sni_bulk_cut_suspected",
	"packet_count_cut_suspected",
	"tls_burst_freeze_suspected",
	"wireguard_session_cut_suspected",
	"openvpn_session_cut_suspected",
	"ikev2_session_cut_suspected",
	"l2tp_session_cut_suspected",
	"socks5_session_cut_suspected",
	"vless_session_cut_suspected",
	"obfs4_session_cut_suspected",
	"tor.link_session_cut_suspected", // sic: the kind is built from the test id, and tor.link has no ".session" suffix to strip
	"dns_manipulation_suspected",
	"system_resolver_manipulation_suspected",
	"dns_udp_blocking_suspected",
	"dns_port_blocking_suspected",
	"uplink_modified",
	"downlink_modified",
	"injected",
	"rst_injected_or_path_reset",
	"rst_injected_bidirectional",
	"tls_mitm_or_wrong_server",
	"synack_local_termination_suspected",
	"synack_spoof_signal",
	// dest.go
	"nxdomain_hijack_suspected",
	"system_resolver_unreachable_suspected",
	"system_resolver_unreliable_suspected",
	"dest_dns_poisoning_suspected",
	"dest_tcp_blackhole_suspected",
	"dest_tcp_reset_suspected",
	"dest_tcp_blocking_suspected",
	"dest_sni_blocking_suspected",
	"dest_tls_blocking_suspected",
	"dest_proto_blocking_suspected",
	"dest_legal_block_suspected",
	"dest_tls_interception_suspected",
}

func TestGoldenScenariosCoverEveryKind(t *testing.T) {
	pinned := map[string]map[string]bool{} // kind → confidences
	for _, sc := range goldenScenarios {
		for _, v := range sc.verdicts {
			kind, conf, _ := strings.Cut(v, ":")
			if pinned[kind] == nil {
				pinned[kind] = map[string]bool{}
			}
			pinned[kind][conf] = true
		}
	}
	known := map[string]bool{}
	for _, k := range allKinds {
		known[k] = true
		if len(pinned[k]) == 0 {
			t.Errorf("no golden scenario produces %s", k)
		}
	}
	var unknown []string
	for k := range pinned {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		t.Errorf("%s is produced by a scenario and missing from allKinds", k)
	}
}

// The confidence ladder at its boundaries. Through Classify the control cell
// always passes (every rule checks that first), so the last rows are only
// reachable here.
func TestConfidenceLadder(t *testing.T) {
	cell := func(ok, total int) Cell { return Cell{OK: ok, Total: total} }
	for _, tc := range []struct {
		failed, passed Cell
		want           string
	}{
		{cell(0, 3), cell(3, 3), "high"},
		{cell(0, 5), cell(4, 4), "high"},
		{cell(0, 3), cell(2, 3), "medium"}, // the control lost a round
		{cell(0, 3), cell(2, 2), "medium"}, // the control ran twice only
		{cell(0, 2), cell(3, 3), "medium"}, // the failure ran twice only
		{cell(1, 3), cell(3, 3), "medium"}, // one round in three passed
		{cell(2, 6), cell(3, 3), "medium"},
		{cell(1, 2), cell(3, 3), "low"}, // half passed
		{cell(2, 5), cell(3, 3), "low"},
		{cell(0, 1), cell(3, 3), "low"}, // a single attempt
		{cell(0, 3), cell(1, 2), "low"}, // the control does not pass
		{cell(0, 3), cell(0, 0), "low"},
	} {
		if got := confidence(tc.failed, tc.passed); got != tc.want {
			t.Errorf("confidence(%d/%d failed, %d/%d passed) = %s, want %s", tc.failed.OK, tc.failed.Total, tc.passed.OK, tc.passed.Total, got, tc.want)
		}
	}
}

// Scenario construction helpers.

const (
	bl = client.RoleBaseline
	vr = client.RoleVariant
	ct = client.RoleControl
)

// okA is an attempt that passed and that the server saw.
func okA(test, role, variant, tr string, port int) *client.Attempt {
	return mk(test, role, variant, tr, port, client.OutcomeOK, "ok", true)
}

// lost is the plainest failure: nothing came back and the server saw nothing.
func lost(test, role, variant, tr string, port int) *client.Attempt {
	return mk(test, role, variant, tr, port, client.OutcomePayloadTimeout, "uplink_drop_or_route_failure", false)
}

// echo is the passing baseline echo of a port.
func echo(tr string, port int) *client.Attempt { return okA(tr+".echo", bl, "cp1-64", tr, port) }

// random is the passing random-payload control of a port.
func random(tr string, port int) *client.Attempt {
	return okA(tr+".payload.random", ct, "random-64", tr, port)
}

// detail sets detail keys from key, value pairs.
func detail(a *client.Attempt, kv ...string) *client.Attempt {
	if a.Detail == nil {
		a.Detail = map[string]string{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		a.Detail[kv[i]] = kv[i+1]
	}
	return a
}

// connect records the TCP connect duration.
func connect(a *client.Attempt, ms float64) *client.Attempt {
	a.Stages = map[string]float64{"connect": ms}
	return a
}

// stages records the connect duration and the first write and end offsets:
// what the reset timing reads.
func stages(a *client.Attempt, connectMs, firstWriteMs, doneMs float64) *client.Attempt {
	a.Stages = map[string]float64{"connect": connectMs, "first_write": firstWriteMs, "done": doneMs}
	return a
}

// span places the attempt in a round, sec seconds into the scan, lasting
// doneMs: what a local outage is dated from.
func span(a *client.Attempt, round, sec int, doneMs float64) *client.Attempt {
	at(a, round, sec)
	if a.Stages == nil {
		a.Stages = map[string]float64{}
	}
	a.Stages["done"] = doneMs
	return a
}

// failWith sets the error text of an attempt.
func failWith(a *client.Attempt, err string) *client.Attempt {
	a.Error = err
	return a
}

var goldenT0 = time.Date(2026, 9, 13, 6, 30, 0, 0, time.UTC)

// at places the attempt in a round, sec seconds into the scan.
func at(a *client.Attempt, round, sec int) *client.Attempt {
	a.Round, a.StartedAt = round, goldenT0.Add(time.Duration(sec)*time.Second)
	return a
}

// x repeats an attempt n times. Every copy is its own attempt: flagTransient
// marks attempts one by one.
func x(n int, a *client.Attempt) []*client.Attempt {
	out := make([]*client.Attempt, 0, n)
	for i := 0; i < n; i++ {
		c := *a
		if a.Server != nil {
			c.Server = &model.Observation{SrcPort: a.Server.SrcPort}
		}
		if a.Detail != nil {
			c.Detail = map[string]string{}
			for k, v := range a.Detail {
				c.Detail[k] = v
			}
		}
		if a.Stages != nil {
			c.Stages = map[string]float64{}
			for k, v := range a.Stages {
				c.Stages[k] = v
			}
		}
		out = append(out, &c)
	}
	return out
}

// all concatenates attempt groups in scan order.
func all(groups ...[]*client.Attempt) []*client.Attempt {
	var out []*client.Attempt
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// one wraps single attempts for all().
func one(a ...*client.Attempt) []*client.Attempt { return a }
