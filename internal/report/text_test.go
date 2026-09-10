package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/classify"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

func TestCompactTextHidesPassingRowsButKeepsCoverageAndAnomalies(t *testing.T) {
	now := time.Now()
	r := Report{
		Target:       "203.0.113.10",
		ControlPort:  8443,
		StartedAt:    now,
		FinishedAt:   now.Add(time.Second),
		ProbeReached: true,
		Params:       &model.Params{ServerVersion: "test"},
		Cells: []classify.Cell{
			{TestID: "tcp.echo", Transport: "tcp", Port: 443, Variant: "cp1-64", Role: "baseline", Total: 3, OK: 3, Merged: map[string]int{"ok": 3}, ServerSaw: 3},
			{TestID: "tls.sni", Transport: "tcp", Port: 443, Variant: "trigger:example", Role: "variant", Total: 3, OK: 0, Merged: map[string]int{"downlink_drop": 3}, ServerSaw: 3},
		},
	}
	var compact bytes.Buffer
	r.WriteStyled(&compact, Style{})
	got := compact.String()
	if strings.Contains(got, "cp1-64") {
		t.Fatalf("compact report contains passing row:\n%s", got)
	}
	for _, want := range []string{"coverage:", "tcp 1/1", "tls 0/1", "ANOMALIES", "trigger:example"} {
		if !strings.Contains(got, want) {
			t.Fatalf("compact report missing %q:\n%s", want, got)
		}
	}

	var verbose bytes.Buffer
	r.WriteStyled(&verbose, Style{Verbose: true})
	if !strings.Contains(verbose.String(), "cp1-64") {
		t.Fatalf("verbose report omitted passing row:\n%s", verbose.String())
	}
}

func TestCompactCleanReportSaysAllPassed(t *testing.T) {
	now := time.Now()
	r := Report{Target: "203.0.113.10", ControlPort: 8443, StartedAt: now, FinishedAt: now, ProbeReached: true,
		Params: &model.Params{ServerVersion: "test"}, Cells: []classify.Cell{{TestID: "tcp.echo", Transport: "tcp", Port: 443, Variant: "cp1-64", Total: 1, OK: 1, Merged: map[string]int{"ok": 1}}}}
	var b bytes.Buffer
	r.WriteStyled(&b, Style{})
	if !strings.Contains(b.String(), "All result cells passed.") {
		t.Fatalf("clean compact report lacks confirmation:\n%s", b.String())
	}
}

func TestFormatMillisDoesNotRoundPositiveRTTToZero(t *testing.T) {
	if got := formatMillis(0.4); got != "<1 ms" {
		t.Fatalf("formatMillis(0.4) = %q", got)
	}
}
