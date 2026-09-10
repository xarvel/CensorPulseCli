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
	ID        [proto.SessionIDLen]byte
	Key       []byte
	Expires   time.Time
	Created   time.Time
	ClientIP  netip.Addr // kept in memory only, never exported
	Tests     map[string]bool
	attempts  int
	obsCount  int
	closedObs bool
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
type store struct {
	mu           sync.Mutex
	sessions     map[[proto.SessionIDLen]byte]*session
	reservations []*reservation
	obs          []model.Observation // ring
	obsHead      int
	obsMax       int
	retention    time.Duration
	// per-IP rate limiting (IPv6 is keyed by /64)
	sessByIP    map[netip.Addr]int
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

// Global bounds that do not depend on how many addresses a peer can use.
const (
	maxLiveSessions  = 4096
	bulkGlobalPerDay = 4 << 30
)

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
// quotas.
func (s *store) consumeBulk(ip netip.Addr, n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip = rateKey(ip)
	day := time.Now().YearDay()
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

// ipHasSession reports whether the address opened a session that is still live.
func (s *store) ipHasSession(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessByIP[ip.Unmap()] > 0
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
		sessByIP:    map[netip.Addr]int{},
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
	if _, exists := s.sessions[sess.ID]; !exists {
		s.sessByIP[sess.ClientIP.Unmap()]++
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
	if best == nil {
		return "", ""
	}
	return best.TestID, best.Variant
}

// matchReservation finds the newest unused reservation for a native flow
// and consumes it. dstPort==0 or kind=="" act as wildcards for the matching
// side.
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

func (s *store) addObservation(o model.Observation) {
	if o.ID == "" {
		var b [8]byte
		rand.Read(b[:])
		o.ID = hex.EncodeToString(b[:])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.obs) < s.obsMax {
		s.obs = append(s.obs, o)
		return
	}
	s.obs[s.obsHead] = o
	s.obsHead = (s.obsHead + 1) % s.obsMax
}

// updateObservation replaces an observation with the same ID (used when a
// flow closes after the initial record was written).
func (s *store) updateObservation(o model.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.obs {
		if s.obs[i].ID == o.ID {
			s.obs[i] = o
			return
		}
	}
}

// observationsFor returns everything recorded for one session, oldest first.
func (s *store) observationsFor(sid string) []model.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Observation
	for _, o := range s.obs {
		if o.SessionID == sid {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeenAt.Before(out[j].FirstSeenAt) })
	return out
}

// gc drops expired sessions, reservations and old observations.
func (s *store) gc(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A session is useless one minute after it expired (getSession refuses
	// it); its observations live on in the ring with their own retention.
	for id, sess := range s.sessions {
		if now.After(sess.Expires.Add(time.Minute)) {
			delete(s.sessions, id)
			k := sess.ClientIP.Unmap()
			if s.sessByIP[k]--; s.sessByIP[k] <= 0 {
				delete(s.sessByIP, k)
			}
		}
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
	keep := s.obs[:0]
	for _, o := range s.obs {
		if now.Sub(o.FirstSeenAt) < s.retention {
			keep = append(keep, o)
		}
	}
	s.obs = keep
	if s.obsHead >= len(s.obs) {
		s.obsHead = 0
	}
}
