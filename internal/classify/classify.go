// Package classify derives differential verdicts from a set of attempts, as
// specified in specs/CLASSIFICATION.md. It never looks at a single failure in
// isolation: every verdict names the control that passed.
package classify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// Verdict is one differential finding.
type Verdict struct {
	Kind       string   `json:"kind"`       // e.g. protocol_blocking_suspected
	Subject    string   `json:"subject"`    // test/port/variant the finding is about
	Confidence string   `json:"confidence"` // high|medium|low
	Evidence   []string `json:"evidence"`
}

// Cell aggregates attempts that share (test, transport, port, variant).
type Cell struct {
	TestID    string         `json:"test_id"`
	Transport string         `json:"transport"`
	Port      int            `json:"port"`
	Variant   string         `json:"variant"`
	Role      string         `json:"role"`
	Total     int            `json:"total"`
	OK        int            `json:"ok"`
	Outcomes  map[string]int `json:"outcomes"`
	Merged    map[string]int `json:"merged"`
	ServerSaw int            `json:"server_saw"`
	// Unmeasured counts the attempts of Total that measured nothing about
	// the path (see unmeasured): they are in Total and the histograms, and
	// they are never evidence. A cell whose attempts all are neither passes
	// nor fails.
	Unmeasured int `json:"unmeasured,omitempty"`

	// measuredMerged is the merged histogram of the measured attempts, what
	// dominant() reads (Aggregate fills it; a cell built by hand falls back
	// to Merged without the unmeasured results).
	measuredMerged map[string]int
}

// Key returns the stable identifier of a cell.
func (c Cell) Key() string { return cellKey(c.TestID, c.Transport, c.Port, c.Variant) }

// cellKey is the one spelling of a cell's identifier, "test transport/port
// variant". Verdict subjects are cell keys, so reports and the mobile app
// parse this format: it must not drift between the places that build it.
func cellKey(test, transport string, port int, variant string) string {
	return familyKey(test, transport, port) + " " + variant
}

// familyKey names a whole test family on a port: a cell key without the variant.
func familyKey(test, transport string, port int) string {
	return test + " " + portKey(transport, port)
}

// portKey names a port the way subjects and evidence do: "tcp/443".
func portKey(transport string, port int) string {
	return fmt.Sprintf("%s/%d", transport, port)
}

// Measured is how many attempts of the cell measured the path: Total
// without the unmeasured ones.
func (c Cell) Measured() int { return c.Total - c.Unmeasured }

func (c Cell) pass() bool { return c.Measured() > 0 && c.OK*2 > c.Measured() } // majority ok
func (c Cell) fail() bool { return c.Measured() > 0 && c.OK == 0 }

// dominant is the commonest merged result of the measured attempts; of a
// cell that measured nothing, the commonest of all (server_error, skipped,
// inconclusive), which is what it shows.
func (c Cell) dominant() string {
	hist := c.measuredMerged
	if hist == nil && c.Measured() > 0 {
		hist = map[string]int{}
		for k, v := range c.Merged {
			if !unmeasuredMerged[k] {
				hist[k] = v
			}
		}
	}
	if c.Measured() == 0 || len(hist) == 0 {
		hist = c.Merged
	}
	best, n := "", -1
	for k, v := range hist {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

// unmeasuredMerged are the merged results that measure nothing about the
// path: a fault of the host or the server, a layer skipped for want of an
// address, a check that could not be assessed.
var unmeasuredMerged = map[string]bool{client.OutcomeServerError: true, client.OutcomeInconclusive: true, client.OutcomeSkipped: true}

// unmeasured reports an attempt that is no evidence either way: its outcome
// or merged result is one of unmeasuredMerged, or it ended on a failure of
// the host itself (Android tearing the scan's sockets down), whatever
// outcome the test made of that.
func unmeasured(a *client.Attempt) bool {
	return unmeasuredMerged[a.Outcome] || unmeasuredMerged[a.Merged] || client.LocalFailure(a) != ""
}

// Result is the classifier output.
type Result struct {
	Cells        []Cell        `json:"cells"`
	Verdicts     []Verdict     `json:"verdicts"`
	Summary      string        `json:"summary"`
	Notes        []string      `json:"notes,omitempty"`        // observations about the scan itself, not findings
	Destinations []Destination `json:"destinations,omitempty"` // per-site summary of the dest.* family
}

// Aggregate builds cells from attempts. Attempts flagged as part of a
// transient outage (detail.transient) are left out: they say nothing about
// the path's policy.
func Aggregate(attempts []*client.Attempt) []Cell {
	m := map[string]*Cell{}
	for _, a := range attempts {
		if a.Detail["transient"] == "true" || a.Detail["cancelled"] == "true" {
			continue
		}
		k := fmt.Sprintf("%s|%s|%d|%s", a.TestID, a.Transport, a.DstPort, a.Variant)
		c, ok := m[k]
		if !ok {
			c = &Cell{TestID: a.TestID, Transport: a.Transport, Port: a.DstPort, Variant: a.Variant, Role: a.Role, Outcomes: map[string]int{}, Merged: map[string]int{}, measuredMerged: map[string]int{}}
			m[k] = c
		}
		c.Total++
		c.Outcomes[a.Outcome]++
		c.Merged[a.Merged]++
		switch {
		case unmeasured(a):
			c.Unmeasured++
		case a.Outcome == client.OutcomeOK:
			c.OK++
			c.measuredMerged[a.Merged]++
		default:
			c.measuredMerged[a.Merged]++
		}
		if a.Server != nil {
			c.ServerSaw++
		}
	}
	out := make([]Cell, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// The confidence ladder of a differential: a cell that failed against the
// control that passed.
const (
	// highMinAttempts is how often both cells must have run for "high": the
	// default three rounds, the one never passing, the other never failing.
	highMinAttempts = 3
	// mediumMinAttempts is how often the failing cell must have run for
	// "medium": a single failure is an anecdote, never more than "low".
	mediumMinAttempts = 2
	// mediumMaxOKShare bounds what a "medium" failing cell may pass: at most
	// one attempt in this many (one round in three).
	mediumMaxOKShare = 3
)

// confidence counts measured attempts only: a round lost to the host's own
// failure is not a round the path failed.
func confidence(failed, passed Cell) string {
	f, p := failed.Measured(), passed.Measured()
	if f >= highMinAttempts && failed.OK == 0 && p >= highMinAttempts && passed.OK == p {
		return "high"
	}
	if f >= mediumMinAttempts && failed.OK*mediumMaxOKShare <= f && passed.pass() {
		return "medium"
	}
	return "low"
}

// Classify derives verdicts.
func Classify(attempts []*client.Attempt, probeReachable bool) Result {
	return classify(attempts, probeReachable, false)
}

// ClassifyStandalone classifies a scan that had no server: the dest.* family
// alone. There is no control plane to be unreachable.
func ClassifyStandalone(attempts []*client.Attempt) Result {
	return classify(attempts, true, true)
}

func classify(attempts []*client.Attempt, probeReachable, standalone bool) Result {
	notes, local := flagLocalOutage(attempts)
	notes = append(notes, flagTransient(attempts, local)...)
	cells := Aggregate(attempts)
	res := Result{Cells: cells, Notes: notes}
	if !probeReachable && !standalone {
		res.Verdicts = append(res.Verdicts, Verdict{Kind: "probe_unreachable", Subject: "control plane", Confidence: "high",
			Evidence: []string{"control API on the pinned TLS port did not answer; no protocol-level conclusion is possible"}})
		res.Summary = "probe_unreachable"
		return res
	}
	rc := newRuleCtx(attempts, cells)
	rc.run()

	// Real destinations: one-sided evidence with its own controls.
	destVerdicts(attempts, cells, rc.add)

	sort.SliceStable(rc.verdicts, func(i, j int) bool {
		if rc.verdicts[i].Kind != rc.verdicts[j].Kind {
			return rc.verdicts[i].Kind < rc.verdicts[j].Kind
		}
		return rc.verdicts[i].Subject < rc.verdicts[j].Subject
	})
	res.Verdicts = rc.verdicts
	// After the sort: of two verdicts of one kind for a site the per-site
	// summary keeps the confidence of the first.
	res.Destinations = Destinations(attempts, cells, res.Verdicts)
	res.Summary = summarize(res.Verdicts)
	return res
}

// summarize is the one-line summary: the verdict kinds with their counts.
func summarize(verdicts []Verdict) string {
	if len(verdicts) == 0 {
		return "clean: every test family passed on every port; no differential observed"
	}
	// Low-confidence findings are listed apart: a single unexplained
	// timeout must not read like a rule that fired three times.
	kinds, low := map[string]int{}, map[string]int{}
	for _, v := range verdicts {
		if v.Confidence == "low" {
			low[v.Kind]++
		} else {
			kinds[v.Kind]++
		}
	}
	join := func(m map[string]int) string {
		var parts []string
		for k, n := range m {
			parts = append(parts, fmt.Sprintf("%s×%d", k, n))
		}
		sort.Strings(parts)
		return strings.Join(parts, ", ")
	}
	switch {
	case len(kinds) == 0:
		return "low confidence only: " + join(low)
	case len(low) == 0:
		return join(kinds)
	}
	return join(kinds) + "; low confidence: " + join(low)
}
