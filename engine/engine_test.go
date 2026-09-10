package engine

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/server"
)

func TestConfigDefaultsAndValidation(t *testing.T) {
	d := Config{Target: "203.0.113.10"}.withDefaults()
	if d.ControlPort != 8443 || d.Repeat != 3 || d.Retry != 0 || d.Parallel != 4 || d.Timeout != 6*time.Second || d.Profile != "full" || d.Sites {
		t.Fatalf("full defaults: %+v", d)
	}
	q := Config{Target: "203.0.113.10", Profile: "quick"}.withDefaults()
	if q.Repeat != 1 || q.Retry != 2 {
		t.Fatalf("quick defaults: repeat %d retry %d", q.Repeat, q.Retry)
	}
	if n := (Config{Target: "203.0.113.10", Profile: "quick", Retry: -1}).withDefaults().Retry; n != 0 {
		t.Fatalf("retry -1 must mean none, got %d", n)
	}
	s := Config{Sites: true}.withDefaults()
	if s.Target != "" || s.Repeat != 1 || s.Retry != 2 || !s.Sites {
		t.Fatalf("sites defaults: %+v", s)
	}
	// dest.* ids imply the family; other ids need a server.
	if d := (Config{Tests: []string{"dest.dns"}}).withDefaults(); !d.Sites {
		t.Fatal("dest.* tests must switch Sites on")
	}
	if err := (Config{Tests: []string{"tcp.echo"}}).Validate(); err == nil || !strings.Contains(err.Error(), "needs a probe server") {
		t.Fatalf("server test without target: %v", err)
	}
	for _, bad := range []Config{
		{},
		{Target: "203.0.113.10", Repeat: 11},
		{Target: "203.0.113.10", Retry: 11},
		{Target: "203.0.113.10", Parallel: 33},
		{Target: "203.0.113.10", Timeout: 100 * time.Millisecond},
		{Target: "203.0.113.10", Profile: "fast"},
		{Target: "203.0.113.10", Tests: []string{"tcp.nope"}},
		{Target: "203.0.113.10", Targets: "example.org"},
		{Target: "203.0.113.10", Deadline: -1},
		{Target: "203.0.113.10", ControlPort: 70000},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("expected a validation error for %+v", bad)
		}
	}
	if err := (Config{Target: "203.0.113.10", Sites: true, Targets: "example.org category=news\n"}).Validate(); err != nil {
		t.Fatalf("targets text: %v", err)
	}
}

func TestParseTests(t *testing.T) {
	got, err := ParseTests(" tcp.echo, tls.sni ,tcp.echo,dest.dns ")
	if err != nil || strings.Join(got, ",") != "tcp.echo,tls.sni,dest.dns" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := ParseTests("tcp.echo,bogus"); err == nil {
		t.Fatal("unknown id accepted")
	}
	if got, err := ParseTests(""); got != nil || err != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	if _, err := ParseTests(" , "); err == nil {
		t.Fatal("blank list accepted")
	}
	known := KnownTests()
	for _, want := range []string{"tcp.echo", "dns.doh", "dest.dns", "dest.http", "tor.link"} {
		if !contains(known, want) {
			t.Errorf("KnownTests lacks %s", want)
		}
	}
}

// A sites-only scan needs no server: Prepare builds the plan offline.
func TestPrepareSitesBuildsPlanWithoutServer(t *testing.T) {
	s, err := Prepare(context.Background(), Config{Sites: true, Targets: "example.org category=news\nexample.net tcp-only\n"}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Reachable() || s.SessionID() != "" || !s.Report().Sites() {
		t.Fatalf("sites scan state: reachable=%v session=%q mode=%q", s.Reachable(), s.SessionID(), s.Report().Mode)
	}
	plans := s.Plans()
	if len(plans) == 0 || s.Attempts() != len(plans)*1 {
		t.Fatalf("plans %d attempts %d", len(plans), s.Attempts())
	}
	seen := map[string]bool{}
	for _, p := range plans {
		seen[p.TestID+" "+p.Variant] = true
	}
	for _, want := range []string{"dest.nxdomain invalid", "dest.tcp anycast", "dest.dns example.org", "dest.tls example.org", "dest.tls decoy:example.org", "dest.tcp example.net"} {
		if !seen[want] {
			t.Errorf("plan lacks %s", want)
		}
	}
	if seen["dest.tls example.net"] {
		t.Error("tcp-only target must have no TLS cell")
	}
}

// An unreachable control point is not a Prepare error: the report carries
// the bootstrap error and the probe_unreachable verdict, Run says so.
func TestUnreachableProbeReportsAndReturnsSentinel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 1, Timeout: 500 * time.Millisecond}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Reachable() {
		t.Fatal("port 1 must not answer")
	}
	rep, err := s.Run(ctx)
	if err != ErrProbeUnreachable {
		t.Fatalf("err %v", err)
	}
	if rep == nil || rep.ProbeReached || rep.BootstrapErr == "" || rep.FinishedAt.IsZero() {
		t.Fatalf("report %+v", rep)
	}
	found := false
	for _, v := range rep.Verdicts {
		if v.Kind == "probe_unreachable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("verdicts %+v", rep.Verdicts)
	}
	if _, err := s.Run(ctx); err == nil {
		t.Fatal("second Run must fail")
	}
}

// The whole thing against a loopback server: prepare, run with progress,
// classify, report. Ports are distinct from the integration package's.
func TestRunAgainstLoopbackServer(t *testing.T) {
	cfg := server.Default()
	cfg.Bind = "127.0.0.1"
	cfg.DataDir = t.TempDir()
	cfg.ControlPort = 29443
	cfg.TCPPorts = []int{29080, 29444}
	cfg.UDPPorts = []int{29054}
	cfg.DNSPorts = []int{29053}
	cfg.DoTPort = 0
	cfg.QUIC = false
	cfg.Limits.IdleTimeoutSeconds = 2
	srv, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var mu sync.Mutex
	var progress []Progress
	var notices []string
	hooks := Hooks{
		Progress: func(p Progress) { mu.Lock(); progress = append(progress, p); mu.Unlock() },
		Notice:   func(m string) { mu.Lock(); notices = append(notices, m); mu.Unlock() },
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 29443, Tests: []string{"tcp.echo", "udp.echo", "dns.udp"}, Repeat: 1, Retry: -1, Timeout: 2 * time.Second, GeoIPDir: t.TempDir()}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Reachable() || s.SessionID() == "" || s.Report().Params == nil {
		t.Fatalf("prepared scan: reachable=%v session=%q", s.Reachable(), s.SessionID())
	}
	if len(s.Plans()) == 0 {
		t.Fatal("no plans")
	}
	rep, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ProbeReached || len(rep.Attempts) != s.Attempts() || len(rep.Cells) == 0 || rep.FinishedAt.IsZero() {
		t.Fatalf("report: reached=%v attempts=%d/%d cells=%d", rep.ProbeReached, len(rep.Attempts), s.Attempts(), len(rep.Cells))
	}
	for _, a := range rep.Attempts {
		if a.Outcome != "ok" {
			t.Errorf("%s %s/%d %s: %s %s", a.TestID, a.Transport, a.DstPort, a.Variant, a.Outcome, a.Error)
		}
	}
	if len(rep.Verdicts) != 0 {
		t.Errorf("loopback must be clean, got %+v", rep.Verdicts)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(progress) != len(rep.Attempts) || progress[len(progress)-1].Done != progress[len(progress)-1].Total {
		t.Fatalf("progress: %d events for %d attempts, last %+v", len(progress), len(rep.Attempts), progress[len(progress)-1])
	}
	// A progress bar only moves forward: Done counts deliveries, Total
	// never shrinks, whatever order the workers finished in.
	for i, p := range progress {
		if p.Done != i+1 || p.Total < p.Done || (i > 0 && p.Total < progress[i-1].Total) {
			t.Fatalf("progress[%d] = %d/%d after %+v", i, p.Done, p.Total, progress[max(i-1, 0)])
		}
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "no GeoLite2 tables") {
		t.Fatalf("notices %v", notices)
	}
	if rep.Sites() || rep.ClientVersion != Version {
		t.Fatalf("mode %q version %q", rep.Mode, rep.ClientVersion)
	}
}

// Cancelling the context stops the scan and still yields a report.
func TestRunHonoursCancellation(t *testing.T) {
	cfg := server.Default()
	cfg.Bind = "127.0.0.1"
	cfg.DataDir = t.TempDir()
	cfg.ControlPort = 29543
	cfg.TCPPorts = []int{29180}
	cfg.UDPPorts = []int{29153}
	cfg.DNSPorts = nil
	cfg.DoTPort = 0
	cfg.QUIC = false
	srv, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	// One worker, so that the attempts after the first are still queued
	// when the cancellation lands.
	s, err := Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 29543, Tests: []string{"tcp.echo"}, Repeat: 6, Retry: -1, Parallel: 1, Timeout: 2 * time.Second}, Hooks{
		Progress: func(p Progress) {
			if p.Done == 1 {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Attempts) == 0 || len(rep.Attempts) >= s.Attempts() {
		t.Fatalf("cancelled run made %d of %d attempts", len(rep.Attempts), s.Attempts())
	}
}

// A network that blocks the control point's address is where the site results
// are wanted most: the real-destinations family needs no server, so it is
// planned and run anyway, and the report stays "probe unreachable".
func TestUnreachableProbeStillPlansTheSites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 1, Timeout: 500 * time.Millisecond, Sites: true,
		Targets: "example.org category=news\n"}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Reachable() {
		t.Fatal("port 1 must not answer")
	}
	if len(s.Plans()) == 0 {
		t.Fatal("no plan for the sites although the family was asked for")
	}
	for _, p := range s.Plans() {
		if !client.IsDestTest(p.TestID) {
			t.Fatalf("plan %s needs the server that did not answer", p.TestID)
		}
	}
	// Run on a stopped context: nothing leaves the machine, the shape of the
	// result is what is under test.
	stopped, stop := context.WithCancel(ctx)
	stop()
	rep, err := s.Run(stopped)
	if err != ErrProbeUnreachable {
		t.Fatalf("err %v", err)
	}
	if rep == nil || rep.ProbeReached || rep.BootstrapErr == "" || rep.FinishedAt.IsZero() || rep.Sites() {
		t.Fatalf("report %+v", rep)
	}

	// Without --sites nothing is planned, as before.
	s, err = Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 1, Timeout: 500 * time.Millisecond}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Plans()) != 0 {
		t.Fatalf("%d plans without the family", len(s.Plans()))
	}
	// Explicit tests that are all server tests do not ask for the family either.
	s, err = Prepare(ctx, Config{Target: "127.0.0.1", ControlPort: 1, Timeout: 500 * time.Millisecond, Sites: true, Tests: []string{"tcp.echo"}}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Plans()) != 0 {
		t.Fatalf("%d plans for --tests tcp.echo", len(s.Plans()))
	}
}

func TestClassifyAttemptsKeepsSitesOfAnUnreachableScan(t *testing.T) {
	site := func(test, variant, outcome string) *client.Attempt {
		tr, port := "tcp", 443
		if test == "dest.dns" {
			tr, port = "udp", 53
		}
		return &client.Attempt{TestID: test, Role: "variant", Variant: variant, Transport: tr, DstPort: port, Outcome: outcome, Merged: outcome,
			Detail: map[string]string{"domain": "example.org", "category": "news"}}
	}
	attempts := []*client.Attempt{site("dest.dns", "example.org", "ok"), site("dest.tcp", "example.org", "ok"), site("dest.tls", "example.org", "ok")}
	res := ClassifyAttempts(attempts, false, false)
	if len(res.Verdicts) == 0 || res.Verdicts[0].Kind != "probe_unreachable" {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
	if len(res.Destinations) != 1 || res.Destinations[0].Domain != "example.org" || len(res.Cells) != 3 {
		t.Fatalf("destinations %+v cells %d", res.Destinations, len(res.Cells))
	}
	if !strings.HasPrefix(res.Summary, "probe_unreachable; sites: ") {
		t.Fatalf("summary %q", res.Summary)
	}
	// No attempts: exactly the old unreachable result.
	if bare := ClassifyAttempts(nil, false, false); bare.Summary != "probe_unreachable" || len(bare.Verdicts) != 1 {
		t.Fatalf("bare %+v", bare)
	}
}
