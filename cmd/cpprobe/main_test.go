package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/engine"
	"github.com/xarvel/CensorPulseCli/internal/client"
)

func TestCLIRetryMapping(t *testing.T) {
	// --retry unset (-1) is the profile default (engine 0), an explicit 0 is
	// none (engine -1), anything else passes through.
	for flag, want := range map[int]int{-1: 0, 0: -1, 2: 2, 10: 10} {
		if got := cliRetry(flag); got != want {
			t.Errorf("cliRetry(%d) = %d, want %d", flag, got, want)
		}
	}
	if err := validateColor("rainbow"); err == nil {
		t.Error("invalid colour accepted")
	}
}

func TestWritePlanUsesSingularLabels(t *testing.T) {
	var b bytes.Buffer
	writePlan(&b, []engine.Plan{{TestID: "dns.doh"}}, 1, 0, 1, "custom")
	if got := b.String(); !strings.Contains(got, "1 plan × 1 round = 1 attempt") || strings.Contains(got, "1 plans") {
		t.Fatalf("bad plan grammar:\n%s", got)
	}
	b.Reset()
	writePlan(&b, []engine.Plan{{TestID: "dns.doh"}}, 1, 2, 1, "quick")
	if got := b.String(); !strings.Contains(got, "1 round (+2 retry rounds for the ports with a failure) = 1 attempt") {
		t.Fatalf("retry note missing:\n%s", got)
	}
}

func TestQuickProfileOnlyContainsKnownTests(t *testing.T) {
	known := map[string]bool{}
	for _, id := range engine.KnownTests() {
		known[id] = true
	}
	for _, id := range client.QuickTests() {
		if !known[id] {
			t.Errorf("quick profile contains unknown test %q", id)
		}
	}
}

func TestKnownTestsIncludeTheDestFamilyOnce(t *testing.T) {
	seen := map[string]int{}
	for _, id := range engine.KnownTests() {
		seen[id]++
	}
	for _, id := range client.DestTests {
		if seen[id] != 1 {
			t.Errorf("%s listed %d times", id, seen[id])
		}
	}
}

func TestLoadTargetsAndSNIList(t *testing.T) {
	ts, err := loadTargets("")
	if err != nil || ts != "" {
		t.Fatalf("got %q %v", ts, err)
	}
	if _, err := loadTargets("/nonexistent/targets.txt"); err == nil {
		t.Fatal("missing file accepted")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "targets.txt")
	os.WriteFile(p, []byte("# sites\nexample.org category=news\n"), 0o644)
	if ts, err := loadTargets(p); err != nil || !strings.Contains(ts, "example.org") {
		t.Fatalf("targets file: %q %v", ts, err)
	}
	os.WriteFile(p, []byte("example.org bogus-option\n"), 0o644)
	if _, err := loadTargets(p); err == nil {
		t.Fatal("malformed targets accepted")
	}
	s := filepath.Join(dir, "sni.txt")
	os.WriteFile(s, []byte("# list\nexample.org  # note\nexample.net\ttrailing\n\n"), 0o644)
	if snis, err := loadSNIList(s); err != nil || strings.Join(snis, ",") != "example.org,example.net" {
		t.Fatalf("sni list: %v %v", snis, err)
	}
	if snis, err := loadSNIList(""); err != nil || snis != nil {
		t.Fatalf("empty sni list: %v %v", snis, err)
	}
}

func TestCLIRangesRejectZeroAndOutOfRange(t *testing.T) {
	if err := cliRanges(8443, 4, 6*time.Second, 64, 12, 0, 4); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	cases := map[string]error{
		"port":            cliRanges(0, 4, 6*time.Second, 64, 12, 0, 4),
		"parallel":        cliRanges(8443, 0, 6*time.Second, 64, 12, 0, 4),
		"timeout":         cliRanges(8443, 4, 0, 64, 12, 0, 4),
		"bulk-kb":         cliRanges(8443, 4, 6*time.Second, 0, 12, 0, 4),
		"session-packets": cliRanges(8443, 4, 6*time.Second, 64, 0, 0, 4),
		"sni-sample":      cliRanges(8443, 4, 6*time.Second, 64, 12, -1, 4),
		"burst-n":         cliRanges(8443, 4, 6*time.Second, 64, 12, 0, 0),
	}
	for name, err := range cases {
		if err == nil || !strings.Contains(err.Error(), "--"+name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
