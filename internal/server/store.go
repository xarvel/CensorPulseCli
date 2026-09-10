package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// session is the in-memory state for one client session.
type session struct {
	ID       [proto.SessionIDLen]byte
	Key      []byte
	Expires  time.Time
	Created  time.Time
	ClientIP netip.Addr // kept in memory only, never exported
	Tests    map[string]bool
	// obs is everything recorded for this session, in arrival order. It is
	// guarded by store.mu (the other fields are read-only once the session is
	// stored) and freed together with the session.
	obs []model.Observation
}

// reservation is a pending correlation window for a native handshake.
type reservation struct {
	ID        string
	SessionID [proto.SessionIDLen]byte
	Expires   time.Time
	ClientIP  netip.Addr
	DstPort   int
	Transport string
	Kind      string
	TestID    string
	Variant   string
	Used      bool
}

// store keeps sessions, reservations and observations with TTLs. Everything
// is memory-only by design (see DOCKER-PROBE.md, privacy section).
//
// Observations live in their session (session.obs): the only reader is the
// session's own token, so a row that names no live session has no reader and
// is not kept, and nothing a stranger sends can push another session's rows
// out. Three bounds apply, all of them refusing the new row rather than
// evicting an old one: maxSessionObservations per session, obsMax across
// sessions, and retention as an upper bound on a row's age (a session lives
// at most 600 s, so its expiry normally frees the rows long before).
type store struct {
	mu           sync.Mutex
	sessions     map[[proto.SessionIDLen]byte]*session
	reservations []*reservation
	obsCount     int // rows held across all sessions, never above obsMax
	obsMax       int
	retention    time.Duration
	drops        obsDrops // rows refused since the last takeDrops
	// per-IP rate limiting (IPv6 is keyed by /64)
	sessRate    map[netip.Addr][]time.Time
	attemptRate map[netip.Addr][]time.Time
	sessPerMin  int
	attPer10Min int
	// bulk transfer quota per IP per day
	bulkUsed   map[netip.Addr]bulkUse
	bulkPerDay int64
}

type bulkUse struct {
	day   int
	bytes int64
}

// obsDrops counts observations the store refused, by reason.
type obsDrops struct {
	noSession  uint64 // no session id, or not the id of a live session
	sessionCap uint64 // the session already holds maxSessionObservations
	globalCap  uint64 // the store already holds obsMax rows
}

func (d obsDrops) total() uint64 { return d.noSession + d.sessionCap + d.globalCap }

// Global bounds that do not depend on how many addresses a peer can use.
const (
	maxLiveSessions  = 4096
	bulkGlobalPerDay = 4 << 30
)

// maxSessionObservations bounds the rows of one session. A full 3-round scan
// of the integration layout (3 TCP + 3 UDP ports) makes 264 attempts and
// leaves 666 rows, 2.5 per attempt: every UDP datagram of a VPN session test
// is a row of its own. The default attempt budget (1200 per 10 minutes, the
// longest a session lives) therefore ends near 3000 rows, a documented full
// scan (~700 attempts) near 1800. 8192 leaves an honest session more than
// twice what the rate limit lets it produce, while one session can take at
// most 8 % of the default global ceiling.
const maxSessionObservations = 8192

// rateKey is the address rate limits are keyed by: the address itself for
// IPv4, the /64 for IPv6 (a single subscriber usually holds a whole /64 and
// could otherwise rotate through 2^64 "clients").
func rateKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Masked().Addr()
		}
	}
	return ip
}

// consumeBulk charges n bytes against the per-IP and the global daily bulk
// quotas. The day is taken from now (the caller's clock) so that the rollover
// can be tested.
func (s *store) consumeBulk(ip netip.Addr, n int64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip = rateKey(ip)
	day := now.YearDay()
	u := s.bulkUsed[ip]
	if u.day != day {
		u = bulkUse{day: day}
	}
	g := s.bulkUsed[netip.Addr{}]
	if g.day != day {
		g = bulkUse{day: day}
	}
	if s.bulkPerDay > 0 && u.bytes+n > s.bulkPerDay {
		return false
	}
	if g.bytes+n > bulkGlobalPerDay {
		return false
	}
	u.bytes += n
	g.bytes += n
	s.bulkUsed[ip] = u
	s.bulkUsed[netip.Addr{}] = g
	return true
}

// sessionKeyByHex returns the envelope key of a live session, nil otherwise.
func (s *store) sessionKeyByHex(hexID string) []byte {
	if sess := s.sessionByHex(hexID); sess != nil {
		return sess.Key
	}
	return nil
}

// sessionByHex resolves a hex session id to a live session.
func (s *store) sessionByHex(hexID string) *session {
	id, err := proto.ParseSessionID(hexID)
	if err != nil {
		return nil
	}
	return s.getSession(id, time.Now())
}

func newStore(maxObs int, retention time.Duration, sessPerMin, attPer10Min int) *store {
	return &store{
		sessions:    map[[proto.SessionIDLen]byte]*session{},
		obsMax:      maxObs,
		retention:   retention,
		sessRate:    map[netip.Addr][]time.Time{},
		attemptRate: map[netip.Addr][]time.Time{},
		sessPerMin:  sessPerMin,
		attPer10Min: attPer10Min,
		bulkUsed:    map[netip.Addr]bulkUse{},
		bulkPerDay:  64 << 20,
	}
}

func prune(ts []time.Time, since time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(since) {
		i++
	}
	return ts[i:]
}

// allowSession applies the per-IP session limit and the global cap on live
// sessions.
func (s *store) allowSession(ip netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= maxLiveSessions {
		return false
	}
	ip = rateKey(ip)
	s.sessRate[ip] = prune(s.sessRate[ip], now.Add(-time.Minute))
	if len(s.sessRate[ip]) >= s.sessPerMin {
		return false
	}
	s.sessRate[ip] = append(s.sessRate[ip], now)
	return true
}

// allowAttempt applies the per-IP attempt limit (reservations + envelopes).
func (s *store) allowAttempt(ip netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip = rateKey(ip)
	s.attemptRate[ip] = prune(s.attemptRate[ip], now.Add(-10*time.Minute))
	if len(s.attemptRate[ip]) >= s.attPer10Min {
		return false
	}
	s.attemptRate[ip] = append(s.attemptRate[ip], now)
	return true
}

func (s *store) putSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Ids are 128 random bits, so an id that is already known is the same
	// session stored again: its rows stay with it (and stay counted).
	if old := s.sessions[sess.ID]; old != nil && old != sess {
		sess.obs = old.obs
	}
	s.sessions[sess.ID] = sess
}

// getSession returns a live session or nil.
func (s *store) getSession(id [proto.SessionIDLen]byte, now time.Time) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil || now.After(sess.Expires) {
		return nil
	}
	return sess
}

// keyFor is the callback used by proto.DecodeRequest.
func (s *store) keyFor(id [proto.SessionIDLen]byte) []byte {
	if sess := s.getSession(id, time.Now()); sess != nil {
		return sess.Key
	}
	return nil
}

func (s *store) reserve(r *reservation) string {
	var b [8]byte
	rand.Read(b[:])
	r.ID = hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reservations = append(s.reservations, r)
	return r.ID
}

// peekReservation returns the test id and variant of the newest unused
// reservation for a flow, without consuming it. Responders that must decide
// how to answer before the flow can identify itself (which certificate to
// present to a TLS ClientHello) use it.
func (s *store) peekReservation(ip netip.Addr, transport string, dstPort int, kind string, now time.Time) (testID, variant string) {
	if r := s.findReservation(ip, transport, dstPort, kind, now, false); r != nil {
		return r.TestID, r.Variant
	}
	return "", ""
}

// matchReservation finds the newest unused reservation for a native flow
// and consumes it. An empty kind, on the reservation or on the flow, matches
// any kind; address, transport and port must be equal (a port is never a
// wildcard).
func (s *store) matchReservation(ip netip.Addr, transport string, dstPort int, kind string, now time.Time) *reservation {
	return s.findReservation(ip, transport, dstPort, kind, now, true)
}

// attributeReservation is matchReservation without consuming the window:
// for a flow that carried nothing (an accepted connection whose payload
// never arrived) the newest reservation is the likeliest owner, but the
// window stays open for the flow that does carry the reserved handshake, so
// that an unrelated empty flow cannot steal it.
func (s *store) attributeReservation(ip netip.Addr, transport string, dstPort int, now time.Time) *reservation {
	return s.findReservation(ip, transport, dstPort, "", now, false)
}

// applyReservation attributes an observation to the reservation its flow
// matched.
func applyReservation(obs *model.Observation, r *reservation) {
	obs.SessionID = hex.EncodeToString(r.SessionID[:])
	obs.AttemptID = r.ID
	obs.TestID = r.TestID
	if r.Variant != "" {
		obs.Detail["variant"] = r.Variant
	}
}

func (s *store) findReservation(ip netip.Addr, transport string, dstPort int, kind string, now time.Time, consume bool) *reservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip = ip.Unmap()
	var best *reservation
	for _, r := range s.reservations {
		if r.Used || now.After(r.Expires) || r.ClientIP != ip || r.Transport != transport || r.DstPort != dstPort {
			continue
		}
		if r.Kind != "" && kind != "" && r.Kind != kind {
			continue
		}
		if best == nil || r.Expires.After(best.Expires) {
			best = r
		}
	}
	if best != nil && consume {
		best.Used = true
	}
	return best
}

// addObservation records a row under the session it names and reports
// whether it was kept. See the store comment for what is refused.
func (s *store) addObservation(o model.Observation) bool {
	return s.addObservationAt(o, time.Now())
}

// addObservationAt is addObservation with the clock that decides whether the
// session is still live.
func (s *store) addObservationAt(o model.Observation, now time.Time) bool {
	if o.ID == "" {
		var b [8]byte
		rand.Read(b[:])
		o.ID = hex.EncodeToString(b[:])
	}
	// The session id of a row may be unauthenticated (a bad-MAC or partial
	// envelope, a DNS name, an HTTP echo path): it only counts when it is the
	// id of a live session, spelled the way observationsFor is asked for it.
	id, err := proto.ParseSessionID(o.SessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	var sess *session
	if err == nil && hex.EncodeToString(id[:]) == o.SessionID {
		sess = s.sessions[id]
	}
	switch {
	case sess == nil || now.After(sess.Expires):
		s.drops.noSession++
	case len(sess.obs) >= maxSessionObservations:
		s.drops.sessionCap++
	case s.obsCount >= s.obsMax:
		s.drops.globalCap++
	default:
		sess.obs = append(sess.obs, o)
		s.obsCount++
		return true
	}
	return false
}

// observationsFor returns everything recorded for one session, oldest first.
// Rows are stored when a flow ends but ordered by when it began, hence the
// sort; rows that began at the same instant keep their arrival order.
func (s *store) observationsFor(sid string) []model.Observation {
	id, err := proto.ParseSessionID(sid)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil || len(sess.obs) == 0 {
		return nil
	}
	out := append([]model.Observation(nil), sess.obs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].FirstSeenAt.Before(out[j].FirstSeenAt) })
	return out
}

// takeDrops returns the refused-row counters and resets them, together with
// the number of rows currently held.
func (s *store) takeDrops() (d obsDrops, held int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, s.drops = s.drops, obsDrops{}
	return d, s.obsCount
}

// gc drops expired sessions (with their observations), stale rate-limit
// windows and bulk counters, spent or expired reservations and observations
// past retention.
func (s *store) gc(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A session is useless one minute after it expired (getSession refuses
	// it); its observations go with it. Until then retention bounds the age
	// of a row, which only matters when it is shorter than a session's life.
	for id, sess := range s.sessions {
		if now.After(sess.Expires.Add(time.Minute)) {
			delete(s.sessions, id)
			s.obsCount -= len(sess.obs)
			continue
		}
		keep := sess.obs[:0]
		for _, o := range sess.obs {
			if now.Sub(o.FirstSeenAt) < s.retention {
				keep = append(keep, o)
			}
		}
		s.obsCount -= len(sess.obs) - len(keep)
		clear(sess.obs[len(keep):]) // let go of the dropped rows' maps
		sess.obs = keep
	}
	for k, ts := range s.sessRate {
		if len(prune(ts, now.Add(-time.Minute))) == 0 {
			delete(s.sessRate, k)
		}
	}
	for k, ts := range s.attemptRate {
		if len(prune(ts, now.Add(-10*time.Minute))) == 0 {
			delete(s.attemptRate, k)
		}
	}
	for k, u := range s.bulkUsed {
		if u.day != now.YearDay() {
			delete(s.bulkUsed, k)
		}
	}
	live := s.reservations[:0]
	for _, r := range s.reservations {
		if !r.Used && now.Before(r.Expires.Add(time.Minute)) {
			live = append(live, r)
		}
	}
	s.reservations = live
}
