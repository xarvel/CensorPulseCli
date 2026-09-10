package server

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

// hexSID is the session id of sid(b) the way observations carry it.
func hexSID(b byte) string {
	id := sid(b)
	return hex.EncodeToString(id[:])
}

func obsAt(sid string, at time.Time, tag string) model.Observation {
	return model.Observation{SessionID: sid, FirstSeenAt: at, TestID: tag}
}

func tags(obs []model.Observation) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.TestID)
	}
	return out
}

func sameTags(got []model.Observation, want ...string) bool {
	g := tags(got)
	if len(g) != len(want) {
		return false
	}
	for i := range want {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

func TestAddObservationAssignsID(t *testing.T) {
	st := testStore()
	liveSession(st, 1, ipA, 10*time.Minute)
	st.addObservationAt(obsAt(hexSID(1), t0, "a"), t0)
	st.addObservationAt(model.Observation{ID: "fixed", SessionID: hexSID(1), FirstSeenAt: t0.Add(time.Second)}, t0)
	got := st.observationsFor(hexSID(1))
	if len(got) != 2 || len(got[0].ID) != 16 || got[1].ID != "fixed" {
		t.Fatalf("rows = %+v: want a generated 16-hex id and the given one", got)
	}
}

// addObservation (the wall-clock entry point the listeners use) stores under
// a session that is live now.
func TestAddObservationWallClock(t *testing.T) {
	st := testStore()
	st.putSession(&session{ID: sid(1), Expires: time.Now().Add(time.Minute), ClientIP: ipA})
	st.putSession(&session{ID: sid(2), Expires: time.Now().Add(-time.Second), ClientIP: ipA})
	if !st.addObservation(obsAt(hexSID(1), time.Now(), "live")) {
		t.Error("row of a live session refused")
	}
	if st.addObservation(obsAt(hexSID(2), time.Now(), "expired")) {
		t.Error("row of an expired session stored")
	}
}

func TestObservationsForIsPerSessionOldestFirst(t *testing.T) {
	st := testStore()
	liveSession(st, 1, ipA, 10*time.Minute)
	liveSession(st, 2, ipB, 10*time.Minute)
	// Arrival order is not start order: a TCP row is stored when the flow
	// ends but carries the time it began.
	st.addObservationAt(obsAt(hexSID(1), t0.Add(3*time.Second), "c"), t0)
	st.addObservationAt(obsAt(hexSID(2), t0.Add(1*time.Second), "x"), t0)
	st.addObservationAt(obsAt(hexSID(1), t0.Add(1*time.Second), "a"), t0)
	st.addObservationAt(obsAt(hexSID(1), t0.Add(2*time.Second), "b1"), t0)
	st.addObservationAt(obsAt(hexSID(1), t0.Add(2*time.Second), "b2"), t0)
	if got := st.observationsFor(hexSID(1)); !sameTags(got, "a", "b1", "b2", "c") {
		t.Errorf("session 1 = %q, want [a b1 b2 c] (oldest first, ties in arrival order)", tags(got))
	}
	if got := st.observationsFor(hexSID(2)); !sameTags(got, "x") {
		t.Errorf("session 2 = %q, want [x]", tags(got))
	}
	for _, unknown := range []string{hexSID(9), "", "nobody", hexSID(1) + "00"} {
		if got := st.observationsFor(unknown); got != nil {
			t.Errorf("observationsFor(%q) = %v, want nil", unknown, got)
		}
	}
	// The result is the caller's: sorting or editing it must not reach the store.
	got := st.observationsFor(hexSID(1))
	got[0].TestID = "edited"
	if again := st.observationsFor(hexSID(1)); again[0].TestID != "a" {
		t.Error("observationsFor hands out the store's own slice")
	}
}

func TestObservationNeedsALiveSession(t *testing.T) {
	st := testStore()
	sess := liveSession(st, 1, ipA, time.Minute)
	liveSession(st, 0xab, ipA, time.Minute) // an id with hex letters, for the spelling case
	for _, tc := range []struct {
		name string
		sid  string
		now  time.Time
		want bool
	}{
		{"live session", hexSID(1), t0, true},
		{"at the expiry instant", hexSID(1), sess.Expires, true},
		{"after expiry, before gc", hexSID(1), sess.Expires.Add(time.Nanosecond), false},
		{"no session id (an unmatched flow)", "", t0, false},
		{"well-formed id of no session", hexSID(7), t0, false},
		{"not hex", strings.Repeat("zz", 16), t0, false},
		{"too short", hexSID(1)[:30], t0, false},
		// observationsFor is asked with the canonical lower-case id, so another
		// spelling could never be read back.
		{"upper-case spelling", strings.ToUpper(hexSID(0xab)), t0, false},
	} {
		if got := st.addObservationAt(obsAt(tc.sid, t0, tc.name), tc.now); got != tc.want {
			t.Errorf("%s: stored = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := st.observationsFor(hexSID(1)); len(got) != 2 {
		t.Errorf("session holds %d rows, want 2", len(got))
	}
	d, held := st.takeDrops()
	if d.noSession != 6 || d.sessionCap != 0 || d.globalCap != 0 || held != 2 {
		t.Errorf("drops = %+v held = %d, want 6 without a live session and 2 held", d, held)
	}
	if d, _ := st.takeDrops(); d.total() != 0 {
		t.Errorf("takeDrops did not reset the counters: %+v", d)
	}
}

// The attack the ring allowed: ~max_observations datagrams that name no live
// session (spoofed sources, bad-MAC envelopes, made-up DNS names) used to
// push every real row out. Now they are refused and the victim keeps its rows.
func TestStrangersCannotEvictObservations(t *testing.T) {
	st := newStore(100, time.Hour, 1, 1)
	liveSession(st, 1, ipA, 10*time.Minute)
	for i := 0; i < 10; i++ {
		st.addObservationAt(obsAt(hexSID(1), t0.Add(time.Duration(i)*time.Second), "real"), t0)
	}
	for i := 0; i < 1000; i++ {
		var forged [16]byte
		forged[0], forged[1], forged[15] = byte(i), byte(i>>8), 0xff
		st.addObservationAt(obsAt(hex.EncodeToString(forged[:]), t0, "forged"), t0)
		st.addObservationAt(model.Observation{Unmatched: true, FirstSeenAt: t0}, t0)
	}
	if got := st.observationsFor(hexSID(1)); len(got) != 10 {
		t.Fatalf("victim holds %d rows after the flood, want 10", len(got))
	}
	if d, held := st.takeDrops(); d.noSession != 2000 || held != 10 {
		t.Errorf("drops = %+v held = %d, want 2000 refused and 10 held", d, held)
	}
	// And the store still has room for the victim's next rows.
	if !st.addObservationAt(obsAt(hexSID(1), t0.Add(time.Minute), "real"), t0) {
		t.Error("the flood used up the global ceiling")
	}
}

func TestSessionObservationCap(t *testing.T) {
	st := newStore(10*maxSessionObservations, time.Hour, 1, 1)
	liveSession(st, 1, ipA, 10*time.Minute)
	liveSession(st, 2, ipB, 10*time.Minute)
	for i := 0; i < maxSessionObservations; i++ {
		if !st.addObservationAt(obsAt(hexSID(1), t0.Add(time.Duration(i)*time.Millisecond), "kept"), t0) {
			t.Fatalf("row %d refused below the cap", i)
		}
	}
	// Over the cap the new row is refused; the oldest rows are the evidence
	// of the scan's first tests and stay.
	for i := 0; i < 5; i++ {
		if st.addObservationAt(obsAt(hexSID(1), t0.Add(time.Hour), "over"), t0) {
			t.Fatal("row stored above the per-session cap")
		}
	}
	got := st.observationsFor(hexSID(1))
	if len(got) != maxSessionObservations || got[0].TestID != "kept" || got[len(got)-1].TestID != "kept" {
		t.Errorf("session 1 holds %d rows (last %q), want the first %d", len(got), got[len(got)-1].TestID, maxSessionObservations)
	}
	// A full session is nobody else's problem.
	if !st.addObservationAt(obsAt(hexSID(2), t0, "other"), t0) {
		t.Error("another session refused because session 1 is full")
	}
	if d, held := st.takeDrops(); d.sessionCap != 5 || d.total() != 5 || held != maxSessionObservations+1 {
		t.Errorf("drops = %+v held = %d", d, held)
	}
}

// max_observations is the ceiling across sessions: at the ceiling new rows
// are refused, whoever they belong to, and nothing stored is evicted.
func TestGlobalObservationCeiling(t *testing.T) {
	st := newStore(5, time.Hour, 1, 1)
	liveSession(st, 1, ipA, time.Minute)
	liveSession(st, 2, ipB, 10*time.Minute)
	for i := 0; i < 3; i++ {
		st.addObservationAt(obsAt(hexSID(1), t0, "one"), t0)
	}
	for i := 0; i < 4; i++ {
		st.addObservationAt(obsAt(hexSID(2), t0, "two"), t0)
	}
	if one, two := st.observationsFor(hexSID(1)), st.observationsFor(hexSID(2)); len(one) != 3 || len(two) != 2 {
		t.Fatalf("rows = %d + %d, want 3 + 2 (the ceiling is 5)", len(one), len(two))
	}
	if d, held := st.takeDrops(); d.globalCap != 2 || d.total() != 2 || held != 5 {
		t.Errorf("drops = %+v held = %d, want 2 refused at the ceiling and 5 held", d, held)
	}
	// Session 1 expires; gc frees its rows and with them room under the ceiling.
	st.gc(t0.Add(2*time.Minute + time.Second))
	if _, held := st.takeDrops(); held != 2 {
		t.Fatalf("held = %d after session 1 was collected, want 2", held)
	}
	for i := 0; i < 4; i++ {
		st.addObservationAt(obsAt(hexSID(2), t0.Add(3*time.Minute), "two"), t0.Add(3*time.Minute))
	}
	if two := st.observationsFor(hexSID(2)); len(two) != 5 {
		t.Errorf("session 2 holds %d rows, want 5 (2 + the 3 that fit)", len(two))
	}
}

func TestObservationsAreFreedWithTheSession(t *testing.T) {
	st := testStore()
	sess := liveSession(st, 1, ipA, time.Minute)
	st.addObservationAt(obsAt(hexSID(1), t0, "a"), t0)
	st.addObservationAt(obsAt(hexSID(1), t0, "b"), t0)
	// Between expiry and gc the rows are still there (the reader is already
	// locked out by the expired token), but nothing new is stored.
	afterExpiry := sess.Expires.Add(30 * time.Second)
	st.gc(afterExpiry)
	if got := st.observationsFor(hexSID(1)); len(got) != 2 {
		t.Errorf("%d rows between expiry and collection, want 2", len(got))
	}
	if st.addObservationAt(obsAt(hexSID(1), afterExpiry, "late"), afterExpiry) {
		t.Error("row stored for an expired session")
	}
	st.gc(sess.Expires.Add(time.Minute + time.Second))
	if got := st.observationsFor(hexSID(1)); got != nil {
		t.Errorf("rows survived their session: %q", tags(got))
	}
	if _, held := st.takeDrops(); held != 0 {
		t.Errorf("held = %d after the only session was collected", held)
	}
}

// retention_hours is an upper bound on a row's age. With the shortest value
// an operator can set (1 h) a session (<= 600 s) always goes first; the bound
// itself is exercised here with a store-level retention below the session's
// life.
func TestGCObservationRetention(t *testing.T) {
	st := newStore(10, 5*time.Minute, 1, 1)
	liveSession(st, 1, ipA, 10*time.Minute)
	st.addObservationAt(obsAt(hexSID(1), t0, "old"), t0)
	st.addObservationAt(obsAt(hexSID(1), t0.Add(3*time.Minute), "young"), t0.Add(3*time.Minute))
	st.gc(t0.Add(5*time.Minute - time.Nanosecond))
	if got := st.observationsFor(hexSID(1)); !sameTags(got, "old", "young") {
		t.Fatalf("before retention = %q, want both rows", tags(got))
	}
	st.gc(t0.Add(5 * time.Minute))
	if got := st.observationsFor(hexSID(1)); !sameTags(got, "young") {
		t.Errorf("after retention = %q, want [young]", tags(got))
	}
	if _, held := st.takeDrops(); held != 1 {
		t.Errorf("held = %d, want 1", held)
	}
	// Rows appended after a gc keep their place: nothing is overwritten.
	st.addObservationAt(obsAt(hexSID(1), t0.Add(6*time.Minute), "next"), t0.Add(6*time.Minute))
	if got := st.observationsFor(hexSID(1)); !sameTags(got, "young", "next") {
		t.Errorf("after gc + append = %q, want [young next]", tags(got))
	}
}

func TestPutSessionAgainKeepsRows(t *testing.T) {
	st := testStore()
	liveSession(st, 1, ipA, time.Minute)
	st.addObservationAt(obsAt(hexSID(1), t0, "a"), t0)
	liveSession(st, 1, ipA, 10*time.Minute) // the same id stored again
	if got := st.observationsFor(hexSID(1)); !sameTags(got, "a") {
		t.Errorf("rows after a second putSession = %q, want [a]", tags(got))
	}
	st.gc(t0.Add(12 * time.Minute))
	if _, held := st.takeDrops(); held != 0 {
		t.Errorf("held = %d after collection: the row count leaked", held)
	}
}
