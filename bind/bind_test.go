package cpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu       sync.Mutex
	progress []string
	logs     []string
}

func (r *recorder) OnProgress(done, total int, testID, group, variant, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.progress = append(r.progress, testID+" "+outcome)
}

func (r *recorder) OnLog(level, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, level+": "+message)
}

type fakeResolver struct{ answers map[string]string }

func (f fakeResolver) Lookup(host string) (string, error) {
	switch v, ok := f.answers[host]; {
	case !ok:
		return "", errors.New("nxdomain")
	case v == "timeout":
		return "", errors.New("timeout")
	case v == "fail":
		return "", errors.New("SERVFAIL from 10.0.0.1")
	default:
		return v, nil
	}
}

func TestDefaultConfigRoundTripsAndValidates(t *testing.T) {
	def := DefaultConfig()
	var c config
	if err := json.Unmarshal([]byte(def), &c); err != nil {
		t.Fatal(err)
	}
	if c.Profile != "quick" || c.Repeat != 1 || c.Retry != 2 || c.TimeoutMs != 6000 || !c.Sites || c.DetectBypass {
		t.Fatalf("defaults %+v", c)
	}
	// The default config is a sites-only scan (no target): valid as is.
	if err := ValidateConfig(def); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(`{"target":"203.0.113.10","repeat":11}`); err == nil {
		t.Fatal("repeat 11 accepted")
	}
	if err := ValidateConfig(`{"target":"203.0.113.10","bogus":1}`); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: %v", err)
	}
	if err := ValidateConfig(`{}`); err == nil {
		t.Fatal("empty config (no target, no sites) accepted")
	}
	var ids []string
	if err := json.Unmarshal([]byte(KnownTests()), &ids); err != nil || len(ids) < 30 {
		t.Fatalf("KnownTests: %v %d", err, len(ids))
	}
	if v := Version(); v == "" {
		t.Fatal("empty version")
	}
}

func TestLookupViaMapsErrors(t *testing.T) {
	r := fakeResolver{answers: map[string]string{"ok.example": "1.2.3.4, 2606:4700::1", "slow.example": "timeout", "bad.example": "fail", "junk.example": "not-an-ip"}}
	ctx := context.Background()
	ips, err := lookupVia(ctx, r, "ok.example")
	if err != nil || len(ips) != 2 || ips[0].String() != "1.2.3.4" {
		t.Fatalf("ok: %v %v", ips, err)
	}
	var dnsErr *net.DNSError
	if _, err := lookupVia(ctx, r, "missing.example"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("nxdomain: %v", err)
	}
	if _, err := lookupVia(ctx, r, "slow.example"); !errors.As(err, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("timeout: %v", err)
	}
	if _, err := lookupVia(ctx, r, "bad.example"); !errors.As(err, &dnsErr) || dnsErr.IsTimeout || dnsErr.IsNotFound {
		t.Fatalf("failure: %v", err)
	}
	if _, err := lookupVia(ctx, r, "junk.example"); err == nil {
		t.Fatal("non-address accepted")
	}
	// A resolver that never answers is bounded by the context.
	stuck := stuckResolver{}
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := lookupVia(cctx, stuck, "x"); !errors.As(err, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("stuck: %v", err)
	}
}

type stuckResolver struct{}

func (stuckResolver) Lookup(string) (string, error) { select {} }

// An unreachable control point returns the report and no error (the
// report says probe_reachable: false); Cancel before Run makes Run return
// at once; Run runs once.
func TestScanUnreachableAndCancel(t *testing.T) {
	rec := &recorder{}
	s, err := NewScan(`{"target":"127.0.0.1","control_port":1,"timeout_ms":500,"tests":["tcp.echo"]}`, rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Run()
	if err != nil {
		t.Fatalf("unreachable run must return the report without an error, got %v", err)
	}
	var rep map[string]any
	if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil {
		t.Fatalf("report json: %v", jerr)
	}
	if rep["probe_reachable"] != false || rep["bootstrap_error"] == "" {
		t.Fatalf("report %v", rep["summary"])
	}
	if _, err := s.Run(); err == nil {
		t.Fatal("second Run must fail")
	}

	s2, err := NewScan(`{"sites":true,"targets":"example.org\n","deadline_ms":30000}`, rec, fakeResolver{})
	if err != nil {
		t.Fatal(err)
	}
	s2.Cancel()
	start := time.Now()
	out, err = s2.Run()
	if err != nil {
		t.Fatalf("cancelled run: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancelled run took %s", time.Since(start))
	}
	if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil || rep["mode"] != "sites" {
		t.Fatalf("cancelled report: %v mode=%v", jerr, rep["mode"])
	}
}

func TestLogWriterSplitsLines(t *testing.T) {
	rec := &recorder{}
	w := &logWriter{l: rec}
	w.Write([]byte("time=1 level=INFO msg=a\ntime=2 level=WARN msg=b\ntime=3 lev"))
	w.Write([]byte("el=ERROR msg=c\n"))
	if len(rec.logs) != 3 || !strings.HasPrefix(rec.logs[0], "info: ") || !strings.HasPrefix(rec.logs[1], "warn: ") || !strings.HasPrefix(rec.logs[2], "error: ") {
		t.Fatalf("logs %v", rec.logs)
	}
}
