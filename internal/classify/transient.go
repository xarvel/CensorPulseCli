package classify

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// transientWindow is the minimum evidence for a passing outage: this many
// failures, on this many ports, inside transientSpan, in cells that pass in
// the other rounds.
const (
	transientSpan  = 20 * time.Second
	transientMin   = 6
	transientPorts = 3
)

// flagTransient looks for a burst of failures across unrelated ports and
// families whose cells pass in the other rounds: a radio drop, a route flap,
// a NAT rebind. Those attempts are flagged detail.transient=true so that the
// cells are built without them, and a note describes the window. Failures in
// cells that fail consistently are never flagged: an outage does not excuse
// a rule that fires every time. The attempts of a local outage (local, from
// flagLocalOutage) are not counted again; the ones a stored report carries
// flagged from this rule are, so that re-classifying it gives the same note.
func flagTransient(attempts []*client.Attempt, local map[*client.Attempt]bool) []string {
	cells := Aggregate(attempts)
	passing := map[string]bool{}
	for _, c := range cells {
		if c.pass() {
			passing[c.Key()] = true
		}
	}
	var cand []*client.Attempt
	for _, a := range attempts {
		if a.Merged == "ok" || a.Outcome == client.OutcomeOK || a.Outcome == client.OutcomeInconclusive || a.Outcome == client.OutcomeServerError || a.StartedAt.IsZero() || local[a] {
			continue
		}
		if passing[cellKey(a.TestID, a.Transport, a.DstPort, a.Variant)] {
			cand = append(cand, a)
		}
	}
	sort.SliceStable(cand, func(i, j int) bool { return cand[i].StartedAt.Before(cand[j].StartedAt) })
	var notes []string
	flagged := map[*client.Attempt]bool{}
	for i := 0; i < len(cand); {
		// The widest window starting at cand[i].
		j := i
		for j+1 < len(cand) && cand[j+1].StartedAt.Sub(cand[i].StartedAt) <= transientSpan {
			j++
		}
		win := cand[i : j+1]
		ports, tests := map[string]bool{}, map[string]bool{}
		for _, a := range win {
			ports[portKey(a.Transport, a.DstPort)] = true
			tests[a.TestID] = true
		}
		if len(win) < transientMin || len(ports) < transientPorts {
			i++
			continue
		}
		var t0 time.Time
		for _, a := range attempts {
			if t0.IsZero() || (!a.StartedAt.IsZero() && a.StartedAt.Before(t0)) {
				t0 = a.StartedAt
			}
		}
		rounds := map[int]bool{}
		for _, a := range win {
			if a.Detail == nil {
				a.Detail = map[string]string{}
			}
			a.Detail["transient"] = "true"
			flagged[a] = true
			rounds[a.Round] = true
		}
		var rs []string
		for r := range rounds {
			rs = append(rs, strconv.Itoa(r))
		}
		sort.Strings(rs)
		notes = append(notes, fmt.Sprintf("transient outage: %d attempts on %d ports (%d test families) failed between +%.0fs and +%.0fs of the scan (round %s) while the same cells passed in the other rounds; they are flagged detail.transient=true and left out of the cells",
			len(win), len(ports), len(tests), win[0].StartedAt.Sub(t0).Seconds(), win[len(win)-1].StartedAt.Sub(t0).Seconds(), strings.Join(rs, ",")))
		i = j + 1
	}
	return notes
}

// A local outage (flagLocalOutage) is at least localMin failures of the host
// itself, each starting within localGap of the end of the one before. It is
// dated from when the first of them started, but not more than localLead
// before it ended: an attempt that ran long before the host cut it proves
// nothing about that earlier time.
const (
	localMin  = 2
	localGap  = 20 * time.Second
	localLead = 10 * time.Second
)

// attemptSpan is when an attempt was in flight: from its start, the
// control-plane reservation included (restart moved StartedAt past it), to
// its end.
func attemptSpan(a *client.Attempt) (from, to time.Time) {
	ms := func(v float64) time.Duration { return time.Duration(v * float64(time.Millisecond)) }
	from = a.StartedAt.Add(-ms(a.Stages["reserve"]))
	to = a.StartedAt.Add(ms(a.Stages["done"]))
	return from, to
}

// flagLocalOutage dates the windows in which the host itself cut the scan
// off the network, from the attempts that ended on a failure of the host
// (client.LocalFailure: Android destroys an app's sockets and refuses its
// sends and lookups when it blocks the app's network access; the connection
// to the control point typically hangs for seconds before that). Every
// attempt that failed while in flight inside a window is flagged
// detail.transient=true, so that the cells are built without it: what
// failed then says nothing about the path, whatever it failed with.
// Attempts that passed stay, and a single failure of the host dates nothing
// (its attempt is unmeasured on its own account). It returns the notes and
// the attempts it flagged, which flagTransient leaves to it. A stored report
// re-classified gets the same windows: the failures of the host are read
// from the attempts, and the ones flagged then are flagged again.
func flagLocalOutage(attempts []*client.Attempt) ([]string, map[*client.Attempt]bool) {
	type event struct {
		from, to time.Time
		name     string
	}
	var events []event
	var t0 time.Time // the first start, as flagTransient counts
	for _, a := range attempts {
		if a.StartedAt.IsZero() {
			continue
		}
		if t0.IsZero() || a.StartedAt.Before(t0) {
			t0 = a.StartedAt
		}
		// No route to one address (an IPv6 answer on an IPv4-only phone) is
		// the host's routing table, not the host dropping off the network.
		name := client.LocalFailure(a)
		if name == "" || name == client.LocalNoRoute {
			continue
		}
		from, to := attemptSpan(a)
		if to.Sub(from) > localLead {
			from = to.Add(-localLead)
		}
		events = append(events, event{from, to, name})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].from.Before(events[j].from) })
	since := func(t time.Time) float64 { return max(0, t.Sub(t0).Seconds()) }
	var notes []string
	local := map[*client.Attempt]bool{}
	for i := 0; i < len(events); {
		from, to := events[i].from, events[i].to
		names := map[string]int{}
		j := i
		for ; j < len(events) && (j == i || !events[j].from.After(to.Add(localGap))); j++ {
			if events[j].to.After(to) {
				to = events[j].to
			}
			names[events[j].name]++
		}
		n := j - i
		i = j
		if n < localMin {
			continue
		}
		flagged := 0
		for _, a := range attempts {
			if a.StartedAt.IsZero() || a.Outcome == client.OutcomeOK || a.Detail["cancelled"] == "true" || local[a] {
				continue
			}
			af, at := attemptSpan(a)
			if at.Before(from) || af.After(to) {
				continue
			}
			if a.Detail == nil {
				a.Detail = map[string]string{}
			}
			a.Detail["transient"] = "true"
			local[a] = true
			flagged++
		}
		var what []string
		for k, v := range names {
			what = append(what, fmt.Sprintf("%s×%d", k, v))
		}
		sort.Strings(what)
		notes = append(notes, fmt.Sprintf("transient outage: the host itself cut the scan off the network between +%.0fs and +%.0fs of the scan (%d failures of its own: %s); the %d attempts that failed in flight then are flagged detail.transient=true and left out of the cells",
			since(from), since(to), n, strings.Join(what, ", "), flagged))
	}
	return notes, local
}
