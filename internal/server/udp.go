package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/stun"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// udpListener owns one UDP socket and demultiplexes datagrams between the
// probe's own responders and (optionally) an embedded QUIC/H3 endpoint.
type udpListener struct {
	s     *Server
	port  int
	dns   bool
	conn  *net.UDPConn
	quicC chan packet
	quicT *quic.Transport

	peersMu sync.Mutex
	// quicPeers remembers source addresses whose first Initial was matched to
	// a reservation, so that the rest of the handshake (further long-header
	// packets, then short-header packets) is forwarded without a new
	// reservation and without flooding the observation store.
	quicPeers map[string]time.Time

	// wgSess / ovpnSess keep the post-handshake state of VPN flows that were
	// answered under a reservation, so that a bounded number of follow-up
	// packets (the *.session tests) can be authenticated and echoed without a
	// new reservation. Both are keyed by the identifier the peer puts on the
	// wire (our WireGuard receiver index / the OpenVPN client session id).
	wgSess   map[uint32]*wgSession
	ovpnSess map[[8]byte]*ovpnSession
	// ovpnPeer indexes the same sessions by the peer's address: P_DATA_V2
	// packets carry no session id, only the 5-tuple ties them to a reset.
	ovpnPeer map[string]*ovpnSession
	ikeSess  map[[8]byte]*ikeSession // by initiator SPI
	espSess  map[uint32]*ikeSession  // by ESP SPI (derived from the responder SPI)
	l2tpSess map[uint16]*l2tpSession // by the tunnel id we assigned
	// dtlsFlows remembers peers whose cookie-less ClientHello was answered
	// under a reservation, so that the ClientHello repeated with the cookie
	// is attributed to the same attempt.
	dtlsFlows map[string]*vpnFlow
}

const (
	vpnSessionTTL     = 90 * time.Second
	vpnSessionMaxData = 64 // packets echoed per handshake; bounds amplification and store use
)

type vpnFlow struct {
	sessionID string
	attemptID string
	testID    string
	variant   string
	peer      string
	expires   time.Time
	dataIn    int
	dataOut   int
}

type wgSession struct {
	vpnFlow
	sess *wg.ResponderSession
}

type ovpnSession struct {
	vpnFlow
	serverSID [8]byte
	layout    *ovpn.Layout // control-channel layout the reset arrived in (plain / tls-auth)
	nextPID   uint32       // next control message packet id we send
	ctlIn     int          // control packets received / answered (the data
	ctlOut    int          // channel is counted in vpnFlow.dataIn/dataOut)
	c2s, s2c  *ovpn.DataKey
	dataPID   uint32 // next data packet id we send
}

// ovpnLayout is the server side of a control-channel layout: for tls-auth
// it sends with the server→client key and verifies with the client→server
// one. The replay counter is per flow, so every reset gets its own.
func (s *Server) ovpnLayout(auth ovpn.Auth) *ovpn.Layout {
	if auth != ovpn.AuthTLS {
		return ovpn.Plain()
	}
	c2s, s2c, err := ovpn.TLSAuthDirKeys(s.keys.OVPNTLSAuth)
	if err != nil {
		return ovpn.Plain()
	}
	return ovpn.TLSAuth(s2c, c2s)
}

func (l *udpListener) lookupOVPNPeer(addr string, now time.Time) *ovpnSession {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	s := l.ovpnPeer[addr]
	if s == nil || now.After(s.expires) {
		return nil
	}
	return s
}

type ikeSession struct {
	vpnFlow
	spir  [8]byte
	natt  bool
	esp   uint32
	authd bool
}

type l2tpSession struct {
	vpnFlow
	peerTunnel, tunnel   uint16
	peerSession, session uint16
	ns                   uint16
}

func (l *udpListener) gcVPN(now time.Time) {
	for k, s := range l.wgSess {
		if now.After(s.expires) {
			delete(l.wgSess, k)
		}
	}
	for k, s := range l.ovpnSess {
		if now.After(s.expires) {
			delete(l.ovpnSess, k)
		}
	}
	for k, s := range l.ovpnPeer {
		if now.After(s.expires) {
			delete(l.ovpnPeer, k)
		}
	}
	for k, s := range l.ikeSess {
		if now.After(s.expires) {
			delete(l.ikeSess, k)
			delete(l.espSess, s.esp)
		}
	}
	for k, s := range l.espSess {
		if now.After(s.expires) {
			delete(l.espSess, k)
		}
	}
	for k, s := range l.l2tpSess {
		if now.After(s.expires) {
			delete(l.l2tpSess, k)
		}
	}
}

func (l *udpListener) lookupIKE(spii [8]byte, now time.Time) *ikeSession {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	s := l.ikeSess[spii]
	if s == nil || now.After(s.expires) {
		return nil
	}
	return s
}

func (l *udpListener) lookupESP(spi uint32, now time.Time) *ikeSession {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	s := l.espSess[spi]
	if s == nil || now.After(s.expires) {
		return nil
	}
	return s
}

func (l *udpListener) lookupL2TP(tunnel uint16, now time.Time) *l2tpSession {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	s := l.l2tpSess[tunnel]
	if s == nil || now.After(s.expires) {
		return nil
	}
	return s
}

func (l *udpListener) knownPeer(addr string, now time.Time) bool {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	exp, ok := l.quicPeers[addr]
	if ok && now.Before(exp) {
		return true
	}
	if ok {
		delete(l.quicPeers, addr)
	}
	return false
}

func (l *udpListener) rememberPeer(addr string, now time.Time) {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	if l.quicPeers == nil {
		l.quicPeers = map[string]time.Time{}
	}
	for a, exp := range l.quicPeers {
		if now.After(exp) {
			delete(l.quicPeers, a)
		}
	}
	l.quicPeers[addr] = now.Add(30 * time.Second)
}

type packet struct {
	b    []byte
	addr net.Addr
}

// demuxConn is the net.PacketConn quic-go reads from.
type demuxConn struct {
	l      *udpListener
	closed chan struct{}
	once   sync.Once
}

func (d *demuxConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-d.l.quicC:
		return copy(b, p.b), p.addr, nil
	case <-d.closed:
		return 0, nil, net.ErrClosed
	}
}
func (d *demuxConn) WriteTo(b []byte, a net.Addr) (int, error) { return d.l.conn.WriteTo(b, a) }
func (d *demuxConn) Close() error                              { d.once.Do(func() { close(d.closed) }); return nil }
func (d *demuxConn) LocalAddr() net.Addr                       { return d.l.conn.LocalAddr() }
func (d *demuxConn) SetDeadline(time.Time) error               { return nil }
func (d *demuxConn) SetReadDeadline(time.Time) error           { return nil }
func (d *demuxConn) SetWriteDeadline(time.Time) error          { return nil }

func (s *Server) startUDP(port int, dns bool) error {
	addr, err := net.ResolveUDPAddr("udp", s.bindAddr(port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	l := &udpListener{s: s, port: port, dns: dns, conn: conn}
	name := "udp/" + itoa(port)
	s.setListener(name, "ok")
	s.addCloser(conn.Close)
	if s.cfg.QUIC && !dns {
		l.quicC = make(chan packet, 256)
		dc := &demuxConn{l: l, closed: make(chan struct{})}
		l.quicT = &quic.Transport{Conn: dc}
		ln, err := l.quicT.Listen(s.quicTLSConfig(), &quic.Config{MaxIdleTimeout: 10 * time.Second, Allow0RTT: false})
		if err != nil {
			conn.Close()
			return err
		}
		h3 := &http3.Server{Handler: http.HandlerFunc(s.h3Handler(port))}
		s.addCloser(func() error { _ = ln.Close(); _ = dc.Close(); return h3.Close() })
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := h3.ServeListener(ln); err != nil && !errors.Is(err, quic.ErrServerClosed) && !errors.Is(err, http.ErrServerClosed) && s.ctx.Err() == nil {
				s.setListener("quic/"+itoa(port), "error: "+err.Error())
			}
		}()
		s.setListener("quic/"+itoa(port), "ok")
	}
	s.wg.Add(1)
	go l.loop()
	return nil
}

func (l *udpListener) loop() {
	defer l.s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, raddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if l.s.ctx.Err() != nil {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		l.handle(pkt, raddr)
	}
}

func isQUIC(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0]&0x80 != 0 { // long header
		v := binary.BigEndian.Uint32(b[1:5])
		return v == 1 || v == 0x6b3343cf || v == 0 || (v&0x0f0f0f0f) == 0x0a0a0a0a
	}
	// short header: only accepted for known connections, quic-go decides
	return b[0]&0x40 != 0 && len(b) >= 20
}

// udpFlow is one datagram on its way through the demultiplexer: where it
// came from, when it arrived, its bytes, and the observation the handlers
// fill in. A listener handles its datagrams one at a time, so nothing here is
// shared.
type udpFlow struct {
	l     *udpListener
	raddr *net.UDPAddr
	ip    netip.Addr
	now   time.Time
	b     []byte
	sum   [sha256.Size]byte // SHA-256 of b; its first 8 bytes are the unknown-datagram ack
	obs   model.Observation
	// unrecorded is the "do not record" signal, see dontRecord.
	unrecorded bool
	// Sessions a matcher had to look up to claim the datagram, kept for its
	// handler so that the lookup (and its lock) happens once.
	esp  *ikeSession  // set by matchESP
	l2tp *l2tpSession // set by matchL2TPData
}

// udpProtocol is one entry of the demultiplexer: match claims a datagram by
// its shape (and, where the shape alone is too weak, by a live session),
// serve answers it and fills in the observation.
type udpProtocol struct {
	name  string
	match func(*udpFlow) bool
	serve func(*udpFlow)
}

// udpDispatch is tried top to bottom; the first match serves the datagram.
// The ORDER is part of the measurement: several shapes overlap, and the
// entries above win. What depends on it:
//
//   - envelope is first. "CP1\x01" also passes dnsx.LooksLikeQuery (on a DNS
//     port) and, from a remembered QUIC peer, the QUIC short-header shape
//     (0x43 has the fixed bit set).
//   - dns is only matched on DNS ports, where its loose shape check (12
//     bytes, QR clear, one question) swallows nearly everything below it.
//     Those ports serve nothing else.
//   - stun, dtls and the two WireGuard shapes are told apart from each other
//     by their first bytes and are mutually exclusive; they stand above ike
//     and esp because their fixed prefixes are the stronger evidence (random
//     WireGuard ciphertext can form an IKE header; all four have a non-zero
//     first word, which is all ike.IsESPUDP asks for).
//   - ike is above esp: a bare IKE message starts with a non-zero initiator
//     SPI and so has the ESP shape too. (With NAT-T the marker is a zero SPI,
//     which IsESPUDP excludes.)
//   - esp and l2tp-data have shapes random bytes satisfy, so both only match
//     on a session they know. They stand above the OpenVPN, QUIC and unknown
//     entries because an ESP SPI is random and may begin like any of those,
//     and an OpenVPN P_CONTROL_V1 (0x20) can pass l2tp.IsData.
//   - l2tp-control begins with 0xc8, which has the QUIC long-header bit; only
//     isQUIC's version check keeps the two apart, so it stays above quic.
//   - the three OpenVPN entries are exclusive by opcode. openvpn-data (0x48)
//     must stay above quic: 0x48 has the QUIC fixed bit, and from a
//     remembered QUIC peer it would be forwarded to quic-go.
//   - unknown matches everything and must be last.
var udpDispatch = []udpProtocol{
	{"envelope", (*udpFlow).matchEnvelope, (*udpFlow).serveEnvelope},
	{"dns", (*udpFlow).matchDNS, (*udpFlow).serveDNS},
	{"stun", (*udpFlow).matchSTUN, (*udpFlow).serveSTUN},
	{"dtls", (*udpFlow).matchDTLS, (*udpFlow).serveDTLS},
	{"wireguard-initiation", (*udpFlow).matchWGInitiation, (*udpFlow).serveWGInitiation},
	{"wireguard-transport", (*udpFlow).matchWGTransport, (*udpFlow).serveWGTransport},
	{"ike", (*udpFlow).matchIKE, (*udpFlow).serveIKE},
	{"esp", (*udpFlow).matchESP, (*udpFlow).serveESP},
	{"l2tp-control", (*udpFlow).matchL2TPControl, (*udpFlow).serveL2TPControl},
	{"l2tp-data", (*udpFlow).matchL2TPData, (*udpFlow).serveL2TPData},
	{"openvpn-reset", (*udpFlow).matchOVPNReset, (*udpFlow).serveOVPNReset},
	{"openvpn-control", (*udpFlow).matchOVPNControl, (*udpFlow).serveOVPNControl},
	{"openvpn-data", (*udpFlow).matchOVPNData, (*udpFlow).serveOVPNData},
	{"quic", (*udpFlow).matchQUIC, (*udpFlow).serveQUIC},
	{"unknown", (*udpFlow).matchUnknown, (*udpFlow).serveUnknown},
}

func (l *udpListener) handle(b []byte, raddr *net.UDPAddr) {
	now := time.Now()
	f := &udpFlow{l: l, raddr: raddr, ip: netip.MustParseAddr(raddr.IP.String()).Unmap(), now: now, b: b, sum: sha256.Sum256(b)}
	f.obs = model.Observation{Transport: "udp", DstPort: l.port, SrcPort: raddr.Port, FirstSeenAt: now, Parse: model.ParseUnknown, Response: "silence", Close: "n/a", Detail: map[string]string{}, BytesIn: len(b)}
	f.obs.PayloadSHA = hex.EncodeToString(f.sum[:])
	f.protocol().serve(f)
	if f.unrecorded {
		return
	}
	// Unattributable datagrams are not kept: the store refuses (and counts)
	// a row that names no live session, since nobody could ever read it.
	l.s.store.addObservation(f.obs)
}

// protocol returns the first entry of udpDispatch that claims the datagram;
// the last entry claims everything.
func (f *udpFlow) protocol() *udpProtocol {
	for i := range udpDispatch {
		if p := &udpDispatch[i]; p.match(f) {
			return p
		}
	}
	return &udpDispatch[len(udpDispatch)-1]
}

// dontRecord marks a datagram as not worth an observation: the follow-up
// packets of a flow that already has its row (QUIC after the first Initial)
// and bare acknowledgements (OpenVPN P_ACK_V1, L2TP ZLB). Returning from a
// handler without it always records.
func (f *udpFlow) dontRecord() { f.unrecorded = true }

// reply sends out to the peer and marks the observation as answered.
func (f *udpFlow) reply(out []byte, what string) {
	if len(out) > 0 {
		// A failed send is not a reply: the row keeps Response "silence",
		// or the client would read it as "answered, downlink dropped".
		if _, err := f.l.conn.WriteToUDP(out, f.raddr); err != nil {
			f.obs.ServerError = err.Error()
			f.obs.Close = "server_error"
			return
		}
	}
	f.obs.BytesOut = len(out)
	f.obs.Response = what
	f.obs.RepliedAt = ptrTime(time.Now())
	f.obs.Close = "normal"
}

// correlate consumes the peer's reservation for this port and kind and
// attributes the observation to it. Without one the datagram is unmatched,
// and every handler stays silent.
func (f *udpFlow) correlate(kind string) bool {
	r := f.l.s.store.matchReservation(f.ip, "udp", f.l.port, kind, f.now)
	if r == nil {
		f.obs.Unmatched = true
		return false
	}
	applyReservation(&f.obs, r)
	return true
}

// vpnFlow captures the correlation of the handshake observation for the
// follow-up packets of a VPN session.
func (f *udpFlow) vpnFlow() vpnFlow {
	return vpnFlow{sessionID: f.obs.SessionID, attemptID: f.obs.AttemptID, testID: f.obs.TestID, variant: f.obs.Detail["variant"], peer: f.raddr.String(), expires: f.now.Add(vpnSessionTTL)}
}

// samePeer refuses follow-up packets that do not come from the address the
// handshake came from. Session identifiers (WireGuard receiver index, IKE
// SPIs, L2TP tunnel id, OpenVPN session id) are known to the peer that
// opened the session; without this check that peer could bounce our replies
// to a spoofed source.
func (f *udpFlow) samePeer(v *vpnFlow) bool {
	if v.peer != f.raddr.String() {
		f.obs.Unmatched = true
		f.obs.Detail["session"] = "peer_mismatch"
		return false
	}
	return true
}

// attribute copies the handshake's correlation keys onto a follow-up packet.
func (f *udpFlow) attribute(v *vpnFlow) {
	f.obs.SessionID, f.obs.AttemptID, f.obs.TestID = v.sessionID, v.attemptID, v.testID
	if v.variant != "" {
		f.obs.Detail["variant"] = v.variant
	}
}

// dataObs tags a follow-up packet observation with the handshake's
// correlation keys and the transport stage.
func (f *udpFlow) dataObs(v *vpnFlow, counter string, plainLen int) {
	f.attribute(v)
	f.obs.Detail["stage"] = "transport"
	f.obs.Detail["counter"] = counter
	f.obs.Detail["plain_len"] = itoa(plainLen)
	f.obs.Detail["data_in"] = itoa(v.dataIn)
	f.obs.Detail["data_out"] = itoa(v.dataOut)
}

func (f *udpFlow) matchEnvelope() bool { return proto.IsEnvelope(f.b) }

// serveEnvelope echoes a CP1 envelope whose MAC and address-bound cookie
// verify; the reply has the size of the request.
func (f *udpFlow) serveEnvelope() {
	s, obs := f.l.s, &f.obs
	obs.Parse = model.ParseEnvelope
	req, err := proto.DecodeRequest(f.b, s.store.keyFor)
	if req != nil {
		obs.SessionID = hex.EncodeToString(req.SessionID[:])
		obs.TestID = req.TestID
		obs.Nonce = hex.EncodeToString(req.Nonce[:])
		obs.Seq = req.Seq
		ps := sha256.Sum256(req.Payload)
		obs.PayloadSHA = hex.EncodeToString(ps[:])
	}
	if err != nil {
		obs.Detail["mac"] = "invalid"
		return
	}
	sess := s.store.getSession(req.SessionID, f.now)
	if !proto.VerifyCookie(s.keys.Master, req.SessionID, f.ip, sess.Expires, req.Cookie) {
		obs.Detail["cookie"] = "invalid"
		return
	}
	if !sess.Tests[req.TestID] || !s.store.allowAttempt(sess.ClientIP, f.now) {
		obs.Response = "refused"
		return
	}
	f.reply(proto.EncodeReply(req, f.now, time.Now(), sess.Key), "echo")
}

func (f *udpFlow) matchDNS() bool { return f.l.dns && dnsx.LooksLikeQuery(f.b) }

func (f *udpFlow) serveDNS() {
	obs := &f.obs
	obs.Parse = model.ParseDNS
	q, err := dnsx.ParseQuery(f.b)
	if err != nil {
		return
	}
	obs.Detail["qname"] = q.Name
	obs.Detail["qtype"] = q.Type.String()
	obs.SessionID = sessionFromQName(q.Name)
	if obs.SessionID != "" {
		obs.TestID = testFromQName(q.Name)
	} else {
		// A name outside the probe zone (the trigger variant) cannot name
		// its session; the reservation window does.
		f.correlate(model.ParseDNS)
	}
	ans, err := dnsx.BuildAnswerFrom(q, f.ip.String())
	if err != nil {
		obs.Close = "server_error"
		obs.ServerError = err.Error()
		return
	}
	// Amplification guard: never answer with more bytes than we got.
	if len(ans) > len(f.b) {
		ans = dnsx.Truncated(q, len(f.b))
		obs.Detail["truncated"] = "amplification_guard"
	}
	f.reply(ans, "dns_answer")
}

func (f *udpFlow) matchSTUN() bool { return stun.IsBindingRequest(f.b) }

func (f *udpFlow) serveSTUN() {
	f.obs.Parse = model.ParseSTUN
	if f.correlate(model.ParseSTUN) {
		f.reply(stun.BindingSuccess(stun.TransactionID(f.b), netip.AddrPortFrom(f.ip, uint16(f.raddr.Port))), "stun_binding_success")
	}
}

// matchQUIC claims long-header packets of a version quic-go speaks and, from
// a peer whose Initial was forwarded, short-header ones.
func (f *udpFlow) matchQUIC() bool {
	return f.l.quicC != nil && isQUIC(f.b) && (f.b[0]&0x80 != 0 || f.l.knownPeer(f.raddr.String(), f.now))
}

// serveQUIC hands the datagram to the embedded quic-go endpoint.
func (f *udpFlow) serveQUIC() {
	l, obs := f.l, &f.obs
	obs.Parse = model.ParseQUIC
	// Address validation happens on the control plane: only a source that
	// holds a live reservation gets its first Initial forwarded; the rest
	// of that peer's packets follow for 30 s.
	known := l.knownPeer(f.raddr.String(), f.now)
	if !known {
		if !f.correlate(model.ParseQUIC) {
			return
		}
		l.rememberPeer(f.raddr.String(), f.now)
	}
	select {
	case l.quicC <- packet{b: f.b, addr: f.raddr}:
		obs.Response = "quic_forwarded"
		obs.Close = "normal"
	default:
		obs.Close = "server_error"
		obs.ServerError = "quic queue full"
	}
	if known {
		f.dontRecord() // follow-up packets of a known handshake: don't flood the store
	}
}

func (f *udpFlow) matchUnknown() bool { return true }

// serveUnknown is the UDP random negative control. It is acknowledged only
// when the sender reserved it through the control plane.
func (f *udpFlow) serveUnknown() {
	if f.correlate(model.ParseUnknown) {
		f.reply(f.sum[:8], "hash_ack")
	}
}

func boolStr(b bool) string {
	if b {
		return "valid"
	}
	return "invalid"
}

func (s *Server) quicTLSConfig() *tls.Config {
	c := s.tlsConfig(nil)
	c.NextProtos = []string{"h3"}
	return c
}

// h3Handler serves the same deterministic echo over HTTP/3.
func (s *Server) h3Handler(port int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		_, sport := addrPortOf(strAddr(r.RemoteAddr))
		obs := model.Observation{Transport: "udp", DstPort: port, SrcPort: sport, FirstSeenAt: now, Parse: model.ParseQUIC, Detail: map[string]string{"stage": "h3_request", "path": r.URL.Path}}
		if sid, test, nonce, ok := parseEchoPath(r.URL.Path); ok {
			obs.SessionID, obs.TestID, obs.Nonce = sid, test, nonce
		}
		body := httpEchoBody(r.Host, r.URL.Path, obs.Nonce)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-CP1-Nonce", obs.Nonce)
		w.Write(body)
		obs.BytesOut = len(body)
		obs.Response = "h3_200"
		obs.RepliedAt = ptrTime(time.Now())
		obs.Close = "normal"
		s.store.addObservation(obs)
	}
}
