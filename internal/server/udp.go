package server

import (
	"context"
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
	"github.com/xarvel/CensorPulseCli/internal/dtlsx"
	"github.com/xarvel/CensorPulseCli/internal/ike"
	"github.com/xarvel/CensorPulseCli/internal/l2tp"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/stun"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
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

func (l *udpListener) handle(b []byte, raddr *net.UDPAddr) {
	s := l.s
	now := time.Now()
	ip := netip.MustParseAddr(raddr.IP.String()).Unmap()
	obs := model.Observation{Transport: "udp", DstPort: l.port, SrcPort: raddr.Port, FirstSeenAt: now, Parse: model.ParseUnknown, Response: "silence", Close: "n/a", Detail: map[string]string{}, BytesIn: len(b)}
	sum := sha256.Sum256(b)
	obs.PayloadSHA = hex.EncodeToString(sum[:])

	reply := func(out []byte, what string) {
		if len(out) > 0 {
			if _, err := l.conn.WriteToUDP(out, raddr); err != nil {
				obs.ServerError = err.Error()
				obs.Close = "server_error"
			}
		}
		obs.BytesOut = len(out)
		obs.Response = what
		obs.RepliedAt = ptrTime(time.Now())
		obs.Close = "normal"
	}
	correlate := func(kind string) bool {
		r := s.store.matchReservation(ip, "udp", l.port, kind, now)
		if r == nil {
			obs.Unmatched = true
			return false
		}
		obs.SessionID = hex.EncodeToString(r.SessionID[:])
		obs.AttemptID = r.ID
		obs.TestID = r.TestID
		if r.Variant != "" {
			obs.Detail["variant"] = r.Variant
		}
		return true
	}
	// flowFromObs captures the correlation of the handshake observation for
	// the follow-up packets of a VPN session.
	flowFromObs := func() vpnFlow {
		return vpnFlow{sessionID: obs.SessionID, attemptID: obs.AttemptID, testID: obs.TestID, variant: obs.Detail["variant"], peer: raddr.String(), expires: now.Add(vpnSessionTTL)}
	}
	// samePeer refuses follow-up packets that do not come from the address
	// the handshake came from. Session identifiers (WireGuard receiver
	// index, IKE SPIs, L2TP tunnel id, OpenVPN session id) are known to the
	// peer that opened the session; without this check that peer could
	// bounce our replies to a spoofed source.
	samePeer := func(f *vpnFlow) bool {
		if f.peer != raddr.String() {
			obs.Unmatched = true
			obs.Detail["session"] = "peer_mismatch"
			return false
		}
		return true
	}
	// dataObs tags a follow-up packet observation with the handshake's
	// correlation keys and the transport stage.
	dataObs := func(f *vpnFlow, counter string, plainLen int) {
		obs.SessionID, obs.AttemptID, obs.TestID = f.sessionID, f.attemptID, f.testID
		if f.variant != "" {
			obs.Detail["variant"] = f.variant
		}
		obs.Detail["stage"] = "transport"
		obs.Detail["counter"] = counter
		obs.Detail["plain_len"] = itoa(plainLen)
		obs.Detail["data_in"] = itoa(f.dataIn)
		obs.Detail["data_out"] = itoa(f.dataOut)
	}

	switch {
	case proto.IsEnvelope(b):
		obs.Parse = model.ParseEnvelope
		req, err := proto.DecodeRequest(b, s.store.keyFor)
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
			break
		}
		sess := s.store.getSession(req.SessionID, now)
		if !proto.VerifyCookie(s.keys.Master, req.SessionID, ip, sess.Expires, req.Cookie) {
			obs.Detail["cookie"] = "invalid"
			break
		}
		if !sess.Tests[req.TestID] || !s.store.allowAttempt(sess.ClientIP, now) {
			obs.Response = "refused"
			break
		}
		reply(proto.EncodeReply(req, now, time.Now(), sess.Key), "echo")

	case l.dns && dnsx.LooksLikeQuery(b):
		obs.Parse = model.ParseDNS
		q, err := dnsx.ParseQuery(b)
		if err != nil {
			break
		}
		obs.Detail["qname"] = q.Name
		obs.Detail["qtype"] = q.Type.String()
		obs.SessionID = sessionFromQName(q.Name)
		if obs.SessionID != "" {
			obs.TestID = testFromQName(q.Name)
		} else {
			// A name outside the probe zone (the trigger variant) cannot name
			// its session; the reservation window does.
			correlate(model.ParseDNS)
		}
		ans, err := dnsx.BuildAnswerFrom(q, ip.String())
		if err != nil {
			obs.Close = "server_error"
			obs.ServerError = err.Error()
			break
		}
		// Amplification guard: never answer with more bytes than we got.
		if len(ans) > len(b) {
			ans = dnsx.Truncated(q, len(b))
			obs.Detail["truncated"] = "amplification_guard"
		}
		reply(ans, "dns_answer")

	case stun.IsBindingRequest(b):
		obs.Parse = model.ParseSTUN
		if correlate(model.ParseSTUN) {
			reply(stun.BindingSuccess(stun.TransactionID(b), netip.AddrPortFrom(ip, uint16(raddr.Port))), "stun_binding_success")
		}

	case dtlsx.IsHandshake(b):
		l.handleDTLS(b, raddr, ip, &obs, correlate, reply, now)

	case wg.LooksLikeInitiation(b):
		obs.Parse = model.ParseWireGuard
		// The Noise handshake costs two X25519 operations; a peer without a
		// pending reservation gets neither them nor a reply.
		if test, _ := s.store.peekReservation(ip, "udp", l.port, model.ParseWireGuard, now); test == "" {
			obs.Unmatched = true
			obs.Detail["auth"] = "unreserved"
			break
		}
		info, err := wg.ConsumeInitiation(b, s.keys.WG)
		obs.Detail["mac1"] = boolStr(info != nil && info.MAC1Valid)
		if err != nil {
			obs.Detail["auth"] = "failed"
			correlate(model.ParseWireGuard)
			break
		}
		obs.Detail["peer_static"] = base64Std(info.PeerStatic[:])
		if !correlate(model.ParseWireGuard) {
			break // unreserved: silent
		}
		resp, rs, err := wg.CreateResponse(info, s.keys.WG, [32]byte{})
		if err != nil {
			obs.Close = "server_error"
			obs.ServerError = err.Error()
			break
		}
		reply(resp, "wireguard_response")
		l.peersMu.Lock()
		if l.wgSess == nil {
			l.wgSess = map[uint32]*wgSession{}
		}
		l.gcVPN(now)
		l.wgSess[rs.LocalIdx] = &wgSession{vpnFlow: flowFromObs(), sess: rs}
		l.peersMu.Unlock()

	case wg.LooksLikeTransport(b):
		// Transport data on a session we answered: authenticate, echo the
		// plaintext back under our send key. Unknown receiver index or bad
		// tag → silence (never a reflector for unauthenticated bytes).
		obs.Parse = model.ParseWireGuardData
		l.peersMu.Lock()
		ws := l.wgSess[wg.TransportReceiver(b)]
		l.peersMu.Unlock()
		if ws == nil || now.After(ws.expires) {
			obs.Unmatched = true
			obs.Detail["session"] = "unknown"
			break
		}
		if !samePeer(&ws.vpnFlow) {
			break
		}
		ctr, plain, err := wg.OpenTransport(ws.sess.Keys.Recv, b)
		if err != nil {
			obs.Detail["auth"] = "failed"
			dataObs(&ws.vpnFlow, itoa(int(ctr)), 0)
			break
		}
		ws.dataIn++
		if ws.dataIn > vpnSessionMaxData {
			dataObs(&ws.vpnFlow, itoa(int(ctr)), len(plain))
			obs.Response = "refused"
			break
		}
		ws.dataOut++
		dataObs(&ws.vpnFlow, itoa(int(ctr)), len(plain))
		reply(wg.SealTransport(ws.sess.Keys.Send, ws.sess.PeerIdx, ctr, plain), "wireguard_data")

	case ike.Looks(b) || func() bool { _, natt := ike.StripNATT(b); return natt }():
		// IKEv2: IKE_SA_INIT opens a session under a reservation; IKE_AUTH on
		// a known SPI is answered with an SK-shaped response. NAT-T framing
		// (port 4500) is mirrored on the reply.
		msg, natt := ike.StripNATT(b)
		hdr, _ := ike.ParseHeader(msg)
		obs.Parse = model.ParseIKE
		obs.Detail["exchange"] = itoa(int(hdr.Exchange))
		if natt {
			obs.Detail["natt"] = "true"
		}
		frame := func(out []byte) []byte {
			if natt {
				return ike.AddNATT(out)
			}
			return out
		}
		switch {
		case hdr.Exchange == ike.ExchangeSAInit && hdr.Flags&ike.FlagResponse == 0:
			if !correlate(model.ParseIKE) {
				break
			}
			spir := ike.RandomSPI()
			resp := ike.SAInitResponse(hdr, spir, s.keys.WG.Public)
			reply(frame(resp), "ike_sa_init")
			is := &ikeSession{vpnFlow: flowFromObs(), spir: spir, natt: natt, esp: ike.ESPSPIFor(spir)}
			l.peersMu.Lock()
			if l.ikeSess == nil {
				l.ikeSess, l.espSess = map[[8]byte]*ikeSession{}, map[uint32]*ikeSession{}
			}
			l.gcVPN(now)
			l.ikeSess[hdr.SPIi] = is
			l.espSess[is.esp] = is
			l.peersMu.Unlock()
		case hdr.Exchange == ike.ExchangeAuth && hdr.Flags&ike.FlagResponse == 0:
			is := l.lookupIKE(hdr.SPIi, now)
			if is == nil || hdr.SPIr != is.spir {
				obs.Unmatched = true
				obs.Detail["session"] = "unknown"
				break
			}
			if !samePeer(&is.vpnFlow) {
				break
			}
			is.dataIn++
			if is.dataIn > vpnSessionMaxData {
				dataObs(&is.vpnFlow, itoa(int(hdr.MessageID)), len(msg)-ike.HeaderLen)
				obs.Response = "refused"
				break
			}
			is.dataOut++
			is.authd = true
			dataObs(&is.vpnFlow, itoa(int(hdr.MessageID)), len(msg)-ike.HeaderLen)
			obs.Detail["stage"] = "ike_auth"
			inner := len(msg) - ike.HeaderLen - 4 - 32
			if inner < 32 {
				inner = 32
			}
			reply(frame(ike.Auth(hdr.SPIi, is.spir, hdr.MessageID, inner, true)), "ike_auth")
		default:
			obs.Unmatched = true
		}

	case ike.IsESPUDP(b) && l.lookupESP(ike.ESPSPI(b), now) != nil:
		// ESP-in-UDP on a session that went through IKE_AUTH: echoed back
		// with the same SPI (a real peer would use its own; a DPI cannot
		// tell), same size.
		obs.Parse = model.ParseESP
		is := l.lookupESP(ike.ESPSPI(b), now)
		if !samePeer(&is.vpnFlow) {
			break
		}
		if !is.authd {
			obs.Detail["session"] = "not_authenticated"
			break
		}
		is.dataIn++
		if is.dataIn > vpnSessionMaxData {
			dataObs(&is.vpnFlow, "", len(b)-ike.ESPHeaderLen)
			obs.Response = "refused"
			break
		}
		is.dataOut++
		seq := binary.BigEndian.Uint32(b[4:8])
		dataObs(&is.vpnFlow, itoa(int(seq)), len(b)-ike.ESPHeaderLen)
		reply(ike.ESP(is.esp, seq, b[ike.ESPHeaderLen:]), "esp_echo")

	case l2tp.IsControl(b):
		obs.Parse = model.ParseL2TP
		ctl, err := l2tp.ParseControl(b)
		if err != nil {
			break
		}
		obs.Detail["message_type"] = itoa(int(ctl.MessageType))
		if ctl.MessageType == l2tp.MsgSCCRQ && ctl.TunnelID == 0 {
			if !correlate(model.ParseL2TP) {
				break
			}
			ts := &l2tpSession{vpnFlow: flowFromObs(), peerTunnel: ctl.AssignedTunnel, tunnel: l2tp.RandomID()}
			l.peersMu.Lock()
			if l.l2tpSess == nil {
				l.l2tpSess = map[uint16]*l2tpSession{}
			}
			l.gcVPN(now)
			l.l2tpSess[ts.tunnel] = ts
			l.peersMu.Unlock()
			reply(l2tp.SCCRP(ts.peerTunnel, ts.tunnel, "cpprobe"), "l2tp_sccrp")
			break
		}
		ts := l.lookupL2TP(ctl.TunnelID, now)
		if ts == nil {
			obs.Unmatched = true
			obs.Detail["session"] = "unknown"
			break
		}
		if !samePeer(&ts.vpnFlow) {
			break
		}
		obs.SessionID, obs.AttemptID, obs.TestID = ts.sessionID, ts.attemptID, ts.testID
		switch ctl.MessageType {
		case l2tp.MsgSCCCN, l2tp.MsgICCN, l2tp.MsgStopCCN:
			ts.ns++
			reply(l2tp.ZLB(ts.peerTunnel, ts.peerSession, ts.ns, ctl.Ns+1), "l2tp_zlb")
		case l2tp.MsgICRQ:
			ts.peerSession, ts.session = ctl.AssignedSession, l2tp.RandomID()
			ts.ns++
			reply(l2tp.ICRP(ts.peerTunnel, ts.peerSession, ts.session, ts.ns, ctl.Ns+1), "l2tp_icrp")
		case l2tp.MsgZLB:
			return // acknowledgements are not worth an observation
		default:
			obs.Response = "silence"
		}

	case l2tp.IsData(b) && l.lookupL2TP(l2tp.DataTunnel(b), now) != nil:
		obs.Parse = model.ParseL2TPData
		ts := l.lookupL2TP(l2tp.DataTunnel(b), now)
		if !samePeer(&ts.vpnFlow) {
			break
		}
		ts.dataIn++
		if ts.dataIn > vpnSessionMaxData || ts.session == 0 {
			dataObs(&ts.vpnFlow, "", len(b)-l2tp.DataHeaderLen)
			obs.Response = "refused"
			break
		}
		ts.dataOut++
		dataObs(&ts.vpnFlow, itoa(ts.dataIn), len(b)-l2tp.DataHeaderLen)
		reply(l2tp.Data(ts.peerTunnel, ts.peerSession, l2tp.DataPayload(b)), "l2tp_data_echo")

	case func() bool { _, ok := ovpn.IsClientReset(b); return ok }():
		// Client hard reset, plain (14 bytes) or tls-auth (42 bytes). A
		// tls-auth reset whose HMAC does not verify is dropped silently like
		// a real server does; when it arrived under a reservation the
		// observation says so (detail.mac=invalid → uplink_modified).
		obs.Parse = model.ParseOpenVPN
		auth, _ := ovpn.IsClientReset(b)
		obs.Detail["control_auth"] = auth.String()
		layout := s.ovpnLayout(auth)
		csid, err := layout.ParseClientReset(b)
		if err != nil {
			if errors.Is(err, ovpn.ErrBadHMAC) {
				obs.Detail["mac"] = "invalid"
				correlate(model.ParseOpenVPN)
			}
			break
		}
		obs.Detail["client_session"] = hex.EncodeToString(csid[:])
		if !correlate(model.ParseOpenVPN) {
			break
		}
		resp, ssid := layout.ServerReset(csid)
		reply(resp, "openvpn_reset")
		ov := &ovpnSession{vpnFlow: flowFromObs(), serverSID: ssid, layout: layout, nextPID: 1, dataPID: 1}
		// Data-channel keys: derived from the session key the control plane
		// handed out and the reservation id (see ovpn.DeriveDataKeys).
		if key := s.store.sessionKeyByHex(obs.SessionID); key != nil {
			ov.c2s, ov.s2c = ovpn.DeriveDataKeys(key, obs.AttemptID)
		}
		l.peersMu.Lock()
		if l.ovpnSess == nil {
			l.ovpnSess = map[[8]byte]*ovpnSession{}
			l.ovpnPeer = map[string]*ovpnSession{}
		}
		l.gcVPN(now)
		l.ovpnSess[csid] = ov
		l.ovpnPeer[raddr.String()] = ov
		l.peersMu.Unlock()

	case ovpn.Opcode(b) == ovpn.OpAckV1 || ovpn.Opcode(b) == ovpn.OpControlV1:
		// Control channel after a reset we answered. Acks are counted and
		// stay silent (like a real server); each control packet is answered
		// with a control packet of our own that piggy-backs the ack and
		// never exceeds the request in size.
		obs.Parse = model.ParseOpenVPNControl
		csid, ok := ovpn.SessionOf(b)
		l.peersMu.Lock()
		ov := l.ovpnSess[csid]
		l.peersMu.Unlock()
		if !ok || ov == nil || now.After(ov.expires) {
			obs.Unmatched = true
			obs.Detail["session"] = "unknown"
			break
		}
		if !samePeer(&ov.vpnFlow) {
			break
		}
		obs.Detail["control_auth"] = ov.layout.Auth.String()
		p, err := ov.layout.Parse(b)
		if err != nil {
			dataObs(&ov.vpnFlow, "", 0)
			obs.Detail["stage"] = "control"
			if errors.Is(err, ovpn.ErrBadHMAC) {
				obs.Detail["mac"] = "invalid"
			} else {
				obs.Detail["parse"] = "bad_control"
			}
			break
		}
		if p.Op == ovpn.OpAckV1 {
			obs.Detail["stage"] = "ack"
			obs.SessionID, obs.AttemptID, obs.TestID = ov.sessionID, ov.attemptID, ov.testID
			return // acks are not worth an observation each
		}
		ov.ctlIn++
		dataObs(&ov.vpnFlow, itoa(int(p.PID)), len(p.Payload))
		obs.Detail["stage"] = "control"
		obs.Detail["ctl_in"] = itoa(ov.ctlIn)
		obs.Detail["ctl_out"] = itoa(ov.ctlOut)
		if ov.ctlIn+ov.dataIn > vpnSessionMaxData {
			obs.Response = "refused"
			break
		}
		if ov.ctlIn == 1 && len(p.Payload) >= 6 && p.Payload[0] == 0x16 && p.Payload[5] == 0x01 {
			obs.Detail["control_payload"] = "tls_client_hello"
		}
		if len(p.Acks) > 0 {
			obs.Detail["acks"] = itoa(len(p.Acks))
		}
		// Our control payload: a handshake-shaped TLS record sized so that
		// the control packet (ack included) ≤ what the client sent.
		n := len(b) - ov.layout.HdrLen(1) - 5
		if n < 0 {
			n = 0
		}
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i * 7)
		}
		ctl := ov.layout.Control(ov.serverSID, ov.nextPID, tlsx.Record(body), []uint32{p.PID}, csid)
		ov.nextPID++
		ov.ctlOut++
		obs.Detail["ctl_out"] = itoa(ov.ctlOut)
		reply(ctl, "openvpn_control")

	case ovpn.IsData(b):
		// Data channel (P_DATA_V2) on a flow we answered: no session id on
		// the wire, the peer address is the key. Authenticate under the
		// client→server key, echo the plaintext under the server→client key
		// with the same length. Anything that does not verify is silence,
		// as with a real server.
		obs.Parse = model.ParseOpenVPNData
		ov := l.lookupOVPNPeer(raddr.String(), now)
		if ov == nil || ov.c2s == nil {
			obs.Unmatched = true
			obs.Detail["session"] = "unknown"
			break
		}
		pid, plain, err := ov.c2s.Open(b)
		if err != nil {
			obs.Detail["auth"] = "failed"
			dataObs(&ov.vpnFlow, itoa(int(pid)), 0)
			break
		}
		ov.dataIn++
		if ov.ctlIn+ov.dataIn > vpnSessionMaxData {
			dataObs(&ov.vpnFlow, itoa(int(pid)), len(plain))
			obs.Response = "refused"
			break
		}
		ov.dataOut++
		dataObs(&ov.vpnFlow, itoa(int(pid)), len(plain))
		out := ov.s2c.Seal(0, ov.dataPID, plain)
		ov.dataPID++
		reply(out, "openvpn_data")

	case l.quicC != nil && isQUIC(b) && (b[0]&0x80 != 0 || l.knownPeer(raddr.String(), now)):
		obs.Parse = model.ParseQUIC
		// Address validation happens on the control plane: only a source that
		// holds a live reservation gets its first Initial forwarded; the rest
		// of that peer's packets follow for 30 s.
		known := l.knownPeer(raddr.String(), now)
		if !known {
			if !correlate(model.ParseQUIC) {
				break
			}
			l.rememberPeer(raddr.String(), now)
		}
		select {
		case l.quicC <- packet{b: b, addr: raddr}:
			obs.Response = "quic_forwarded"
			obs.Close = "normal"
		default:
			obs.Close = "server_error"
			obs.ServerError = "quic queue full"
		}
		if known {
			return // follow-up packets of a known handshake: don't flood the store
		}

	default:
		// Unknown datagram (the UDP random negative control). Acknowledge
		// only when the sender reserved it through the control plane.
		if correlate(model.ParseUnknown) {
			reply(sum[:8], "hash_ack")
		}
	}
	// Unattributable datagrams are only worth keeping when the source has a
	// session (a NAT that changed the address between control plane and
	// test); otherwise a flood would evict the evidence of real scans.
	if obs.Unmatched && obs.SessionID == "" && !s.store.ipHasSession(ip) {
		return
	}
	s.store.addObservation(obs)
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

var _ = context.Background
