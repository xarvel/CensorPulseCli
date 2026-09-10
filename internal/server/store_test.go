package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// t0 is the fixed clock of the store tests. Noon, mid-year: neither a day
// nor a year boundary is near unless a test walks up to one.
var t0 = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

var (
	ipA = netip.MustParseAddr("192.0.2.10")
	ipB = netip.MustParseAddr("192.0.2.11")
)

func testStore() *store {
	return newStore(1000, 24*time.Hour, 3, 5)
}

func sid(b byte) (id [proto.SessionIDLen]byte) {
	for i := range id {
		id[i] = b
	}
	return id
}

// liveSession registers a session that expires ttl after t0.
func liveSession(st *store, b byte, ip netip.Addr, ttl time.Duration) *session {
	sess := &session{ID: sid(b), Key: []byte{b}, Created: t0, Expires: t0.Add(ttl), ClientIP: ip, Tests: map[string]bool{"tcp.echo": true}}
	st.putSession(sess)
	return sess
}

func TestRateKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.7", "192.0.2.7"},
		{"::ffff:192.0.2.7", "192.0.2.7"}, // v4-mapped is the IPv4 address
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::"},
		{"2001:db8:1:2::1", "2001:db8:1:2::"},
		{"2001:db8:1:3::1", "2001:db8:1:3::"},
		{"::1", "::"},
	} {
		if got := rateKey(netip.MustParseAddr(tc.in)); got != netip.MustParseAddr(tc.want) {
			t.Errorf("rateKey(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// The zero Addr is the key of the global bulk counter; no real address
	// may map onto it.
	if got := rateKey(netip.MustParseAddr("0.0.0.0")); !got.IsValid() {
		t.Errorf("rateKey(0.0.0.0) is the zero Addr")
	}
}

func TestPrune(t *testing.T) {
	ts := []time.Time{t0, t0.Add(time.Second), t0.Add(2 * time.Second)}
	for _, tc := range []struct {
		name  string
		in    []time.Time
		since time.Time
		want  int
	}{
		{"nil", nil, t0, 0},
		{"all kept", ts, t0.Add(-time.Second), 3},
		{"entry at since is kept", ts, t0.Add(time.Second), 2},
		{"all dropped", ts, t0.Add(time.Hour), 0},
	} {
		if got := prune(tc.in, tc.since); len(got) != tc.want {
			t.Errorf("%s: %d entries left, want %d", tc.name, len(got), tc.want)
		}
	}
	if got := prune(ts, t0.Add(time.Second)); !got[0].Equal(t0.Add(time.Second)) {
		t.Errorf("prune dropped from the wrong end: first = %v", got[0])
	}
}

func TestSessionPutGetExpiry(t *testing.T) {
	st := testStore()
	if st.getSession(sid(1), t0) != nil {
		t.Fatal("unknown session resolved")
	}
	sess := liveSession(st, 1, ipA, 10*time.Minute)
	if got := st.getSession(sid(1), t0); got != sess {
		t.Fatalf("getSession = %v, want the session", got)
	}
	// Expires is inclusive: the session is live at that instant, dead after.
	if st.getSession(sid(1), sess.Expires) == nil {
		t.Error("session dead at its Expires instant")
	}
	if st.getSession(sid(1), sess.Expires.Add(time.Nanosecond)) != nil {
		t.Error("session live after Expires")
	}
	if st.getSession(sid(2), t0) != nil {
		t.Error("another id resolved")
	}
}

func TestSessionByHex(t *testing.T) {
	st := testStore()
	id := sid(0xab)
	// sessionByHex / keyFor use the wall clock, so the session must be live now.
	st.putSession(&session{ID: id, Key: []byte("k"), Expires: time.Now().Add(time.Minute), ClientIP: ipA})
	st.putSession(&session{ID: sid(0xcd), Key: []byte("old"), Expires: time.Now().Add(-time.Second), ClientIP: ipA})
	hexID := "abababababababababababababababab"
	if st.sessionByHex(hexID) == nil || string(st.sessionKeyByHex(hexID)) != "k" || string(st.keyFor(id)) != "k" {
		t.Error("live session not resolved by hex id / keyFor")
	}
	for _, bad := range []string{"", "zz", "abab", hexID + "ab", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"} {
		if st.sessionByHex(bad) != nil || st.sessionKeyByHex(bad) != nil {
			t.Errorf("sessionByHex(%q) resolved", bad)
		}
	}
	if st.keyFor(sid(0xcd)) != nil {
		t.Error("keyFor returned the key of an expired session")
	}
}

func TestGCSessions(t *testing.T) {
	st := testStore()
	liveSession(st, 1, ipA, time.Minute)
	liveSession(st, 2, ipA, 10*time.Minute)
	liveSession(st, 3, ipB, time.Minute)

	// A session outlives its expiry by one minute in the map.
	st.gc(t0.Add(2 * time.Minute))
	if len(st.sessions) != 3 {
		t.Fatalf("gc at expiry+1m dropped sessions: %d left", len(st.sessions))
	}
	st.gc(t0.Add(2*time.Minute + time.Second))
	if len(st.sessions) != 1 || st.sessions[sid(2)] == nil {
		t.Fatalf("gc kept %d sessions, want only the long one", len(st.sessions))
	}
}

func TestAllowSession(t *testing.T) {
	st := testStore() // 3 sessions per minute
	for i := 0; i < 3; i++ {
		if !st.allowSession(ipA, t0.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("session %d refused", i)
		}
	}
	if st.allowSession(ipA, t0.Add(3*time.Second)) {
		t.Error("4th session within the minute allowed")
	}
	// A refusal is not recorded: the window still slides on the 3 grants.
	if len(st.sessRate[ipA]) != 3 {
		t.Errorf("refused call was recorded: %d entries", len(st.sessRate[ipA]))
	}
	if !st.allowSession(ipB, t0.Add(3*time.Second)) {
		t.Error("another address shares the limit")
	}
	// The first grant (t0) leaves the window one minute later.
	if st.allowSession(ipA, t0.Add(time.Minute-time.Nanosecond)) {
		t.Error("allowed before the oldest grant left the window")
	}
	if !st.allowSession(ipA, t0.Add(time.Minute+time.Nanosecond)) {
		t.Error("refused after the oldest grant left the window")
	}
}

func TestAllowSessionIPv6PerSlash64(t *testing.T) {
	st := testStore()
	a := netip.MustParseAddr("2001:db8:0:1::1")
	b := netip.MustParseAddr("2001:db8:0:1:ffff:ffff:ffff:ffff")
	other := netip.MustParseAddr("2001:db8:0:2::1")
	for i, ip := range []netip.Addr{a, b, a} {
		if !st.allowSession(ip, t0) {
			t.Fatalf("session %d refused", i)
		}
	}
	if st.allowSession(b, t0) {
		t.Error("a second address of the same /64 got its own budget")
	}
	if !st.allowSession(other, t0) {
		t.Error("another /64 shares the budget")
	}
}

func TestAllowSessionGlobalCap(t *testing.T) {
	st := newStore(10, time.Hour, 1<<30, 1<<30)
	for i := 0; i < maxLiveSessions; i++ {
		var id [proto.SessionIDLen]byte
		id[0], id[1] = byte(i), byte(i>>8)
		st.sessions[id] = &session{ID: id, Expires: t0.Add(time.Minute), ClientIP: ipA}
	}
	if st.allowSession(ipB, t0) {
		t.Errorf("session allowed with %d live sessions", maxLiveSessions)
	}
	if len(st.sessRate) != 0 {
		t.Error("the global refusal charged the per-IP window")
	}
	delete(st.sessions, [proto.SessionIDLen]byte{})
	if !st.allowSession(ipB, t0) {
		t.Error("session refused below the global cap")
	}
}

func TestAllowAttempt(t *testing.T) {
	st := testStore() // 5 attempts per 10 minutes
	for i := 0; i < 5; i++ {
		if !st.allowAttempt(ipA, t0.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if st.allowAttempt(ipA, t0.Add(5*time.Minute)) {
		t.Error("6th attempt within the window allowed")
	}
	if !st.allowAttempt(netip.MustParseAddr("::ffff:192.0.2.11"), t0) {
		t.Error("another address shares the limit")
	}
	if !st.allowAttempt(ipA, t0.Add(10*time.Minute+time.Second)) {
		t.Error("refused after the oldest attempt left the 10-minute window")
	}
	// v4-mapped and plain form are one client.
	if st.allowAttempt(netip.MustParseAddr("::ffff:192.0.2.10"), t0.Add(10*time.Minute+2*time.Second)) {
		t.Error("the v4-mapped form of the address has a budget of its own")
	}
}

func TestGCRateWindows(t *testing.T) {
	st := testStore()
	st.allowSession(ipA, t0)
	st.allowAttempt(ipA, t0)
	st.allowAttempt(ipB, t0.Add(9*time.Minute))
	st.gc(t0.Add(30 * time.Second))
	if len(st.sessRate) != 1 || len(st.attemptRate) != 2 {
		t.Fatalf("gc dropped live windows: sess=%d attempt=%d", len(st.sessRate), len(st.attemptRate))
	}
	st.gc(t0.Add(11 * time.Minute))
	if len(st.sessRate) != 0 {
		t.Error("session window kept after a minute")
	}
	if _, ok := st.attemptRate[ipA]; ok {
		t.Error("attempt window kept after 10 minutes")
	}
	if _, ok := st.attemptRate[ipB]; !ok {
		t.Error("attempt window dropped while an entry is still inside it")
	}
}

func TestConsumeBulkPerIP(t *testing.T) {
	st := testStore()
	st.bulkPerDay = 100
	if !st.consumeBulk(ipA, 60, t0) || !st.consumeBulk(ipA, 40, t0) {
		t.Fatal("charges within the quota refused")
	}
	if st.consumeBulk(ipA, 1, t0) {
		t.Error("charge above the per-IP quota allowed")
	}
	// A refused charge is not booked, neither per IP nor globally.
	if st.bulkUsed[ipA].bytes != 100 || st.bulkUsed[netip.Addr{}].bytes != 100 {
		t.Errorf("after a refusal: ip=%d global=%d, want 100/100", st.bulkUsed[ipA].bytes, st.bulkUsed[netip.Addr{}].bytes)
	}
	if !st.consumeBulk(ipB, 100, t0) {
		t.Error("another address shares the per-IP quota")
	}
	// IPv6 is charged per /64.
	if !st.consumeBulk(netip.MustParseAddr("2001:db8::1"), 100, t0) {
		t.Fatal("first IPv6 charge refused")
	}
	if st.consumeBulk(netip.MustParseAddr("2001:db8::2"), 1, t0) {
		t.Error("a second address of the same /64 got its own quota")
	}
}

func TestConsumeBulkDayRollover(t *testing.T) {
	st := testStore()
	st.bulkPerDay = 100
	evening := time.Date(2026, 6, 15, 23, 59, 59, 0, time.UTC)
	if !st.consumeBulk(ipA, 100, evening) || st.consumeBulk(ipA, 1, evening) {
		t.Fatal("quota not enforced before midnight")
	}
	morning := evening.Add(2 * time.Second)
	if !st.consumeBulk(ipA, 100, morning) {
		t.Error("quota not reset on the next day")
	}
	if got := st.bulkUsed[netip.Addr{}]; got.bytes != 100 || got.day != morning.YearDay() {
		t.Errorf("global counter after rollover = %+v, want 100 bytes on day %d", got, morning.YearDay())
	}
	// gc forgets the counters of other days, the global one included.
	st.gc(morning.Add(24 * time.Hour))
	if len(st.bulkUsed) != 0 {
		t.Errorf("gc kept %d stale bulk counters", len(st.bulkUsed))
	}
}

func TestConsumeBulkGlobal(t *testing.T) {
	st := testStore()
	st.bulkPerDay = 0 // only New() maps 0 to the default; in the store 0 means "no per-IP quota"
	if !st.consumeBulk(ipA, bulkGlobalPerDay, t0) {
		t.Fatal("charge up to the global quota refused")
	}
	if st.consumeBulk(ipB, 1, t0) {
		t.Error("charge above the global quota allowed")
	}
	if !st.consumeBulk(ipB, 1, t0.Add(24*time.Hour)) {
		t.Error("global quota not reset on the next day")
	}
}

func reservationFor(ip netip.Addr, transport string, port int, kind, test string, exp time.Time) *reservation {
	return &reservation{SessionID: sid(1), Expires: exp, ClientIP: ip, DstPort: port, Transport: transport, Kind: kind, TestID: test, Variant: "v-" + test}
}

func TestReserveAssignsIDs(t *testing.T) {
	st := testStore()
	a := st.reserve(reservationFor(ipA, "udp", 443, "quic", "quic.h3", t0.Add(15*time.Second)))
	b := st.reserve(reservationFor(ipA, "udp", 443, "quic", "quic.h3", t0.Add(15*time.Second)))
	if len(a) != 16 || len(b) != 16 || a == b {
		t.Errorf("reservation ids %q %q: want two distinct 16-hex ids", a, b)
	}
	if st.reservations[0].ID != a || st.reservations[1].ID != b {
		t.Error("reserve did not store the id on the reservation")
	}
}

func TestMatchReservationNewestUnusedWins(t *testing.T) {
	st := testStore()
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "old", t0.Add(10*time.Second)))
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "new", t0.Add(15*time.Second)))
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "mid", t0.Add(12*time.Second)))
	var got []string
	for i := 0; i < 4; i++ {
		r := st.matchReservation(ipA, "udp", 443, "quic", t0)
		if r == nil {
			got = append(got, "")
			continue
		}
		if !r.Used {
			t.Errorf("matched reservation %s not marked used", r.TestID)
		}
		got = append(got, r.TestID)
	}
	want := []string{"new", "mid", "old", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("match order = %q, want %q (latest expiry first, each consumed once)", got, want)
		}
	}
}

func TestMatchReservationSelectors(t *testing.T) {
	exp := t0.Add(15 * time.Second)
	for _, tc := range []struct {
		name      string
		res       *reservation
		ip        netip.Addr
		transport string
		port      int
		kind      string
		now       time.Time
		want      bool
	}{
		{"exact", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 443, "quic", t0, true},
		{"v4-mapped flow address", reservationFor(ipA, "udp", 443, "quic", "t", exp), netip.MustParseAddr("::ffff:192.0.2.10"), "udp", 443, "quic", t0, true},
		{"other address", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipB, "udp", 443, "quic", t0, false},
		{"other transport", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "tcp", 443, "quic", t0, false},
		{"other port", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 444, "quic", t0, false},
		{"other kind", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 443, "stun", t0, false},
		{"reservation without a kind matches any flow", reservationFor(ipA, "udp", 443, "", "t", exp), ipA, "udp", 443, "stun", t0, true},
		{"flow without a kind matches any reservation", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 443, "", t0, true},
		// The port is never a wildcard, on either side: a reservation for
		// port 0 matches nothing a listener can ask for.
		{"reservation for port 0", reservationFor(ipA, "udp", 0, "quic", "t", exp), ipA, "udp", 443, "quic", t0, false},
		{"flow on port 0", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 0, "quic", t0, false},
		{"at expiry", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 443, "quic", exp, true},
		{"after expiry", reservationFor(ipA, "udp", 443, "quic", "t", exp), ipA, "udp", 443, "quic", exp.Add(time.Nanosecond), false},
	} {
		st := testStore()
		st.reserve(tc.res)
		if got := st.matchReservation(tc.ip, tc.transport, tc.port, tc.kind, tc.now) != nil; got != tc.want {
			t.Errorf("%s: matched = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPeekAndAttributeDoNotConsume(t *testing.T) {
	st := testStore()
	st.reserve(reservationFor(ipA, "tcp", 443, "tls_client_hello", "tls.sni", t0.Add(10*time.Second)))
	st.reserve(reservationFor(ipA, "tcp", 443, "tls_client_hello", "tor.link", t0.Add(15*time.Second)))
	for i := 0; i < 3; i++ {
		test, variant := st.peekReservation(ipA, "tcp", 443, "tls_client_hello", t0)
		if test != "tor.link" || variant != "v-tor.link" {
			t.Fatalf("peek %d = %q/%q, want the newest reservation", i, test, variant)
		}
		// attributeReservation ignores the kind: an empty flow has none.
		if r := st.attributeReservation(ipA, "tcp", 443, t0); r == nil || r.TestID != "tor.link" || r.Used {
			t.Fatalf("attribute %d = %+v, want the newest reservation, unconsumed", i, r)
		}
	}
	if test, _ := st.peekReservation(ipA, "tcp", 443, "socks5", t0); test != "" {
		t.Errorf("peek with another kind = %q, want nothing", test)
	}
	if test, _ := st.peekReservation(ipB, "tcp", 443, "tls_client_hello", t0); test != "" {
		t.Errorf("peek from another address = %q, want nothing", test)
	}
	// Consumed reservations are invisible to peek and attribute.
	st.matchReservation(ipA, "tcp", 443, "tls_client_hello", t0)
	if test, _ := st.peekReservation(ipA, "tcp", 443, "tls_client_hello", t0); test != "tls.sni" {
		t.Errorf("peek after a match = %q, want the older reservation", test)
	}
	st.matchReservation(ipA, "tcp", 443, "tls_client_hello", t0)
	if test, _ := st.peekReservation(ipA, "tcp", 443, "tls_client_hello", t0); test != "" {
		t.Errorf("peek with every reservation used = %q", test)
	}
	if st.attributeReservation(ipA, "tcp", 443, t0) != nil {
		t.Error("attribute returned a used reservation")
	}
}

func TestGCReservations(t *testing.T) {
	st := testStore()
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "used", t0.Add(15*time.Second)))
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "expired", t0.Add(-2*time.Minute)))
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "grace", t0.Add(-30*time.Second)))
	st.reserve(reservationFor(ipA, "udp", 443, "quic", "open", t0.Add(10*time.Second)))
	if r := st.matchReservation(ipA, "udp", 443, "quic", t0); r == nil || r.TestID != "used" {
		t.Fatalf("setup: matched %+v", r)
	}
	st.gc(t0)
	var left []string
	for _, r := range st.reservations {
		left = append(left, r.TestID)
	}
	// Used ones go at once, unused ones a minute after they expired.
	if len(left) != 2 || left[0] != "grace" || left[1] != "open" {
		t.Errorf("reservations after gc = %q, want [grace open]", left)
	}
}
