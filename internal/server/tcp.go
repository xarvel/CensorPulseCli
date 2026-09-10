package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
	"github.com/xarvel/CensorPulseCli/internal/httpecho"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/obfs4"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/proto"
	"github.com/xarvel/CensorPulseCli/internal/socks5"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
	"github.com/xarvel/CensorPulseCli/internal/tor"
	"github.com/xarvel/CensorPulseCli/internal/vless"
)

type tcpRole int

const (
	tcpRoleGeneric tcpRole = iota
	tcpRoleDNS
	tcpRoleDoT
)

const (
	maxUnknownRead = 64 << 10
	sniffWindow    = 400 * time.Millisecond
	// maxConnLife bounds any single TCP flow; bulk transfers re-arm their
	// own per-chunk deadlines within it and are bounded by the quota.
	maxConnLife = 5 * time.Minute
	// maxConnsPerIP bounds concurrent TCP flows from one address.
	maxConnsPerIP = 64
)

func (s *Server) startTCP(port int, role tcpRole) error {
	ln, err := net.Listen("tcp", s.bindAddr(port))
	if err != nil {
		return err
	}
	name := "tcp/" + itoa(port)
	s.setListener(name, "ok")
	s.addCloser(ln.Close)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				s.log.Warn("accept", "listener", name, "err", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			ip, _ := addrPortOf(c.RemoteAddr())
			if !s.acquireConn(ip) {
				c.Close()
				continue
			}
			go func() {
				defer s.releaseConn(ip)
				s.handleTCP(c, port, role)
			}()
		}
	}()
	return nil
}

func (s *Server) acquireConn(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[netip.Addr]int{}
	}
	if s.conns[ip] >= maxConnsPerIP {
		return false
	}
	s.conns[ip]++
	return true
}

func (s *Server) releaseConn(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[ip]--; s.conns[ip] <= 0 {
		delete(s.conns, ip)
	}
}

// peekConn lets the dispatcher read the first bytes of a stream and then hand
// the connection, with those bytes replayed, to a protocol handler.
type peekConn struct {
	net.Conn
	prefix []byte
	in     int // bytes consumed from the wire (for observations)
	out    int
}

func (p *peekConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	n, err := p.Conn.Read(b)
	p.in += n
	return n, err
}

func (p *peekConn) Write(b []byte) (int, error) {
	n, err := p.Conn.Write(b)
	p.out += n
	return n, err
}

// sniff reads until at least min bytes are buffered or the window elapses.
// Bytes already buffered from a previous sniff are kept.
func (p *peekConn) sniff(min int, window time.Duration) ([]byte, error) {
	deadline := time.Now().Add(window)
	buf := append(make([]byte, 0, 4096), p.prefix...)
	p.prefix = nil
	tmp := make([]byte, 4096)
	for len(buf) < min {
		p.Conn.SetReadDeadline(deadline)
		n, err := p.Conn.Read(tmp)
		p.in += n
		buf = append(buf, tmp[:n]...)
		if err != nil {
			p.Conn.SetReadDeadline(time.Time{})
			p.prefix = buf
			return buf, err
		}
	}
	p.Conn.SetReadDeadline(time.Time{})
	p.prefix = buf
	return buf, nil
}

func closeReason(err error) string {
	switch {
	case err == nil:
		return "normal"
	case errors.Is(err, io.EOF):
		return "client_eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "client_reset"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "server_error"
}

func (s *Server) handleTCP(c net.Conn, port int, role tcpRole) {
	defer c.Close()
	life := time.AfterFunc(maxConnLife, func() { c.Close() })
	defer life.Stop()
	now := time.Now()
	ip, sport := addrPortOf(c.RemoteAddr())
	obs := model.Observation{Transport: "tcp", DstPort: port, SrcPort: sport, FirstSeenAt: now, Parse: model.ParseEmpty, Response: "silence", Close: "n/a", Detail: map[string]string{}}
	pc := &peekConn{Conn: c}
	idle := s.idle()

	first, serr := pc.sniff(1, idle)
	if len(first) == 0 {
		obs.Close = closeReason(serr)
		s.finish(&obs, pc, ip, "")
		return
	}
	// Grow the prefix a little for classifiers that need more than one byte.
	if len(first) < 24 {
		pc.sniff(24, sniffWindow)
		first = pc.prefix
	}

	switch {
	case role == tcpRoleDNS:
		s.tcpDNS(pc, &obs, false)
	case role == tcpRoleDoT:
		s.tcpDoT(pc, &obs)
	case proto.IsEnvelope(first):
		s.tcpEnvelope(pc, &obs)
	case isTLSClientHello(first):
		s.tcpTLS(pc, &obs, ip)
	case ovpn.IsClientResetTCP(first):
		s.tcpOpenVPN(pc, &obs)
	case socks5.IsGreeting(first):
		s.tcpSOCKS5(pc, &obs, ip)
	case isHTTPRequest(first):
		s.tcpHTTP(pc, &obs)
	default:
		s.tcpUnknown(pc, &obs)
	}
	s.finish(&obs, pc, ip, obs.Parse)
}

// correlateEarly matches a reservation before the handler answers, for
// protocols that must stay silent towards unreserved peers.
func (s *Server) correlateEarly(obs *model.Observation, ip netip.Addr, kind string) bool {
	r := s.store.matchReservation(ip, "tcp", obs.DstPort, kind, obs.FirstSeenAt)
	if r == nil {
		obs.Unmatched = true
		return false
	}
	applyReservation(obs, r)
	return true
}

// tcpEchoStream echoes every chunk the client sends until it hangs up or
// goes idle, counting chunks as data packets of a session test.
func (s *Server) tcpEchoStream(pc net.Conn, obs *model.Observation, idle time.Duration) {
	buf := make([]byte, 16<<10)
	dataIn, dataOut := 0, 0
	var err error
	for dataIn < vpnSessionMaxData {
		pc.SetReadDeadline(time.Now().Add(idle))
		var n int
		n, err = pc.Read(buf)
		if n > 0 {
			dataIn++
			pc.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := pc.Write(buf[:n]); werr != nil {
				err = werr
				break
			}
			dataOut++
			obs.RepliedAt = ptrTime(time.Now())
		}
		if err != nil {
			break
		}
	}
	if dataIn > 0 {
		obs.Detail["stage"] = "transport"
		obs.Detail["data_in"] = itoa(dataIn)
		obs.Detail["data_out"] = itoa(dataOut)
	}
	obs.Close = closeReason(err)
	if obs.Close == "timeout" || err == nil {
		obs.Close = "normal"
	}
}

// tcpSOCKS5 answers the greeting, an optional username/password
// sub-negotiation and a CONNECT, then echoes. It never connects anywhere:
// CONNECT "succeeds" to 0.0.0.0:0 and the tunnel is a mirror. Unreserved
// peers get "no acceptable methods" and nothing else.
func (s *Server) tcpSOCKS5(pc *peekConn, obs *model.Observation, ip netip.Addr) {
	obs.Parse = model.ParseSOCKS5
	idle := s.idle()
	greet, err := pc.sniff(3, sniffWindow)
	if len(greet) < 3 || !socks5.IsGreeting(greet) {
		obs.Close = closeReason(err)
		return
	}
	n := 2 + int(greet[1])
	methods := socks5.GreetingMethods(greet[:n])
	pc.prefix = greet[n:]
	if !s.correlateEarly(obs, ip, model.ParseSOCKS5) {
		pc.Write(socks5.MethodReply(socks5.MethodNone))
		obs.Response = "refused"
		obs.Close = "normal"
		return
	}
	chosen := byte(socks5.MethodNone)
	for _, m := range methods {
		if m == socks5.MethodUser {
			chosen = m
			break
		}
		if m == socks5.MethodNoAuth {
			chosen = m
		}
	}
	obs.Detail["method"] = itoa(int(chosen))
	if _, err := pc.Write(socks5.MethodReply(chosen)); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "socks5_method"
	obs.RepliedAt = ptrTime(time.Now())
	if chosen == socks5.MethodNone {
		obs.Close = "normal"
		return
	}
	if chosen == socks5.MethodUser {
		up, err := pc.sniff(3, idle)
		if _, _, perr := socks5.ParseUserPass(up); perr != nil {
			if err == nil && len(up) < 3+int(up[1])+1 {
				up, err = pc.sniff(len(up)+1, idle)
			}
			if _, _, perr := socks5.ParseUserPass(up); perr != nil {
				obs.Close = closeReason(err)
				return
			}
		}
		user, _, _ := socks5.ParseUserPass(up)
		ul := 2 + len(user)
		pl := 1 + int(up[ul])
		pc.prefix = up[ul+pl:]
		obs.Detail["user_len"] = itoa(len(user))
		if _, err := pc.Write(socks5.UserPassReply(0)); err != nil {
			obs.Close = closeReason(err)
			return
		}
		obs.Response = "socks5_auth"
	}
	req, err := pc.sniff(7, idle)
	r, perr := socks5.ParseRequest(req)
	for perr != nil && err == nil && len(req) < 262 {
		req, err = pc.sniff(len(req)+1, idle)
		r, perr = socks5.ParseRequest(req)
	}
	if perr != nil {
		obs.Close = closeReason(err)
		return
	}
	pc.prefix = req[r.Len:]
	obs.Detail["cmd"] = itoa(int(r.Cmd))
	obs.Detail["dst_len"] = itoa(len(r.Host))
	obs.Detail["dst_sha256"] = hexSum([]byte(r.Host))
	obs.Detail["dst_port"] = itoa(int(r.Port))
	if r.Cmd != socks5.CmdConnect {
		pc.Write(socks5.Reply(7)) // command not supported
		obs.Response = "socks5_refused"
		obs.Close = "normal"
		return
	}
	if _, err := pc.Write(socks5.Reply(socks5.RepSuccess)); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "socks5_connect"
	obs.RepliedAt = ptrTime(time.Now())
	s.tcpEchoStream(pc, obs, idle)
	if obs.Detail["data_in"] != "" {
		obs.Response = "socks5_connect+echo"
	}
}

// finish stores the observation, correlating native flows with reservations.
func (s *Server) finish(obs *model.Observation, pc *peekConn, ip netip.Addr, kind string) {
	obs.BytesIn = pc.in
	obs.BytesOut = pc.out
	obs.ClosedAt = ptrTime(time.Now())
	// A flow that never authenticated (no envelope, or an envelope cut before
	// its MAC) is attributed through the reservation window it was announced in.
	if obs.SessionID == "" || obs.Detail["partial"] == "true" {
		var r *reservation
		if kind == "" && obs.Parse == model.ParseEmpty {
			// Nothing arrived: attribute the empty flow without consuming
			// the window (it may be another attempt's connection whose
			// payload was dropped; the reserved handshake may still come).
			r = s.store.attributeReservation(ip, "tcp", obs.DstPort, obs.FirstSeenAt)
		} else {
			r = s.store.matchReservation(ip, "tcp", obs.DstPort, kind, obs.FirstSeenAt)
		}
		if r != nil {
			applyReservation(obs, r)
		} else if obs.SessionID == "" {
			obs.Unmatched = true
		}
	}
	// Flows nobody can claim are not kept: observations are only ever served
	// to their session, so the store refuses a row that names no live one
	// (and counts it; see store.addObservation).
	stored := s.store.addObservation(*obs)
	if s.cfg.Log.Level == "debug" {
		s.log.Debug("tcp flow", "port", obs.DstPort, "parse", obs.Parse, "response", obs.Response, "close", obs.Close, "in", obs.BytesIn, "out", obs.BytesOut, "session", obs.SessionID != "", "stored", stored)
	}
}

func isTLSClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04 && b[5] == 0x01
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "PRI ", "CONNECT "}

func isHTTPRequest(b []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// tcpEnvelope echoes every CP1 envelope on the stream until the client closes.
func (s *Server) tcpEnvelope(pc *peekConn, obs *model.Observation) {
	obs.Parse = model.ParseEnvelope
	idle := s.idle()
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 8192)
	for {
		for {
			total, need := proto.RequestLen(buf)
			if total > 0 {
				break
			}
			if need > proto.MaxPayload+512 {
				obs.Close = "server_error"
				obs.ServerError = "envelope too large"
				return
			}
			pc.SetReadDeadline(time.Now().Add(idle))
			n, err := pc.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				obs.Close = closeReason(err)
				// A cut envelope still names its session/test/nonce; record
				// them (unverified) so the client can see how far it got.
				if len(buf) > 0 && obs.SessionID == "" {
					if sid, test, nonce, have := proto.PeekRequest(buf); have > 0 {
						obs.SessionID = hex.EncodeToString(sid[:])
						obs.Detail["partial"] = "true"
						obs.Detail["partial_bytes"] = itoa(len(buf))
						if have >= 2 {
							obs.TestID = test
						}
						if have >= 3 {
							obs.Nonce = hex.EncodeToString(nonce[:])
						}
					}
				}
				return
			}
		}
		total, _ := proto.RequestLen(buf)
		seen := time.Now()
		req, err := proto.DecodeRequest(buf[:total], s.store.keyFor)
		buf = append(buf[:0], buf[total:]...)
		if req != nil {
			obs.SessionID = hex.EncodeToString(req.SessionID[:])
			obs.TestID = req.TestID
			obs.Nonce = hex.EncodeToString(req.Nonce[:])
			obs.Seq = req.Seq
			sum := sha256.Sum256(req.Payload)
			obs.PayloadSHA = hex.EncodeToString(sum[:])
		}
		if err != nil {
			obs.Detail["mac"] = "invalid"
			obs.Response = "silence"
			obs.Close = "server_error"
			obs.ServerError = "envelope mac invalid or session unknown"
			return
		}
		sess := s.store.getSession(req.SessionID, seen)
		if !sess.Tests[req.TestID] || !s.store.allowAttempt(sess.ClientIP, seen) {
			obs.Response = "refused"
			obs.Close = "normal"
			return
		}
		rep := proto.EncodeReply(req, seen, time.Now(), sess.Key)
		pc.SetWriteDeadline(time.Now().Add(idle))
		if _, err := pc.Write(rep); err != nil {
			obs.Close = closeReason(err)
			return
		}
		obs.Response = "echo"
		obs.RepliedAt = ptrTime(time.Now())
		obs.Close = "normal"
	}
}

// tcpUnknown consumes an unrecognised payload (the "random bytes" negative
// control) and acknowledges it with 8 bytes of its hash once the client goes
// quiet. The ack is always smaller than the request.
func (s *Server) tcpUnknown(pc *peekConn, obs *model.Observation) {
	obs.Parse = model.ParseUnknown
	h := sha256.New()
	total := 0
	tmp := make([]byte, 8192)
	var raw []byte // kept up to the obfs4 handshake bound, for the mark search
	var lastErr error
	for total < maxUnknownRead {
		pc.SetReadDeadline(time.Now().Add(time.Second))
		n, err := pc.Read(tmp)
		h.Write(tmp[:n])
		if len(raw) < obfs4.MaxHandshakeLen+obfs4.MaxFrame {
			raw = append(raw, tmp[:n]...)
		}
		total += n
		if err != nil {
			lastErr = err
			break
		}
	}
	sum := h.Sum(nil)
	obs.PayloadSHA = hex.EncodeToString(sum)
	obs.Detail["payload_len"] = itoa(total)
	// An obfs4 client request is random bytes by design; only the mark keyed
	// by our bridge identity tells it apart from the random control.
	if n, ok := obfs4.FindClientRequest(raw, s.keys.Obfs4, time.Now()); ok {
		s.tcpObfs4(pc, obs, raw, n)
		return
	}
	if lastErr != nil && closeReason(lastErr) != "timeout" {
		obs.Close = closeReason(lastErr)
		return
	}
	if _, err := pc.Write(sum[:8]); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "hash_ack"
	obs.RepliedAt = ptrTime(time.Now())
	obs.Close = "normal"
}

// tcpOpenVPN answers a client hard reset (plain or tls-auth) with a server
// hard reset, then serves the control channel and the data channel of an
// openvpn.session flow until the client hangs up.
func (s *Server) tcpOpenVPN(pc *peekConn, obs *model.Observation) {
	obs.Parse = model.ParseOpenVPN
	br := bufio.NewReaderSize(pc, 4096)
	readFrame := func() ([]byte, error) {
		var lenb [2]byte
		if _, err := io.ReadFull(br, lenb[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lenb[:]))
		if n == 0 || n > ovpn.MaxPacketLen {
			return nil, errors.New("bad frame")
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(br, pkt); err != nil {
			return nil, err
		}
		return pkt, nil
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, err := readFrame()
	if err != nil {
		obs.Close = closeReason(err)
		return
	}
	auth, ok := ovpn.IsClientReset(first)
	if !ok {
		obs.Parse = model.ParseUnknown
		obs.Close = "normal"
		return
	}
	obs.Detail["control_auth"] = auth.String()
	layout := s.ovpnLayout(auth)
	csid, err := layout.ParseClientReset(first)
	if err != nil {
		// A tls-auth reset that does not verify: silence, like a real
		// server; the observation says why.
		if errors.Is(err, ovpn.ErrBadHMAC) {
			obs.Detail["mac"] = "invalid"
		}
		obs.Close = "normal"
		return
	}
	obs.Detail["client_session"] = hex.EncodeToString(csid[:])
	sum := sha256.Sum256(first)
	obs.PayloadSHA = hex.EncodeToString(sum[:])
	reply, ssid := layout.ServerReset(csid)
	if _, err := pc.Write(ovpn.FrameTCP(reply)); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "openvpn_reset"
	obs.RepliedAt = ptrTime(time.Now())
	// Data-channel keys need the session; the reset is attributed to its
	// reservation only in finish(), so match it (without consuming) here.
	var c2s, s2c *ovpn.DataKey
	ip, _ := addrPortOf(pc.RemoteAddr())
	if s.correlateEarly(obs, ip, model.ParseOpenVPN) {
		if key := s.store.sessionKeyByHex(obs.SessionID); key != nil {
			c2s, s2c = ovpn.DeriveDataKeys(key, obs.AttemptID)
		}
	}
	// Control channel: every P_CONTROL_V1 is answered with a control packet
	// that piggy-backs the ack and stays ≤ the request; acks from the client
	// are consumed silently. Data channel: every authenticated P_DATA_V2 is
	// echoed with the same plaintext length. A plain openvpn.reset client
	// just hangs up here, which ends the loop.
	ctlIn, ctlOut, dataIn, dataOut := 0, 0, 0, 0
	var nextPID, dataPID uint32 = 1, 1
	for ctlIn+dataIn < vpnSessionMaxData {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		var pkt []byte
		pkt, err = readFrame()
		if err != nil {
			break
		}
		switch {
		case ovpn.IsData(pkt):
			if c2s == nil {
				obs.Detail["session"] = "no_keys"
				continue
			}
			_, plain, perr := c2s.Open(pkt)
			if perr != nil {
				obs.Detail["auth"] = "failed"
				continue // silence, like a real server
			}
			dataIn++
			out := ovpn.FrameTCP(s2c.Seal(0, dataPID, plain))
			dataPID++
			if _, err = pc.Write(out); err != nil {
				break
			}
			dataOut++
			obs.Response = "openvpn_reset+control+data"
			obs.RepliedAt = ptrTime(time.Now())
		case ovpn.IsControlOp(ovpn.Opcode(pkt)):
			p, perr := layout.Parse(pkt)
			if perr != nil {
				if errors.Is(perr, ovpn.ErrBadHMAC) {
					obs.Detail["mac"] = "invalid"
					continue
				}
				err = perr
				break
			}
			if p.Op == ovpn.OpAckV1 {
				continue
			}
			ctlIn++
			if ctlIn == 1 && len(p.Payload) >= 6 && p.Payload[0] == 0x16 && p.Payload[5] == 0x01 {
				obs.Detail["control_payload"] = "tls_client_hello"
			}
			body := make([]byte, max(0, len(pkt)-layout.HdrLen(1)-5))
			for i := range body {
				body[i] = byte(i * 7)
			}
			out := ovpn.FrameTCP(layout.Control(ssid, nextPID, tlsx.Record(body), []uint32{p.PID}, csid))
			nextPID++
			if _, err = pc.Write(out); err != nil {
				break
			}
			ctlOut++
			if dataOut == 0 {
				obs.Response = "openvpn_reset+control"
			}
			obs.RepliedAt = ptrTime(time.Now())
		default:
			err = errors.New("unexpected opcode")
		}
		if err != nil {
			break
		}
	}
	if ctlIn > 0 || dataIn > 0 {
		obs.Detail["stage"] = "transport"
		obs.Detail["ctl_in"] = itoa(ctlIn)
		obs.Detail["ctl_out"] = itoa(ctlOut)
		obs.Detail["data_in"] = itoa(dataIn)
		obs.Detail["data_out"] = itoa(dataOut)
	}
	obs.Close = closeReason(err)
	if obs.Close == "timeout" || err == nil {
		obs.Close = "normal"
	}
}

// tcpHTTP serves the deterministic HTTP echo.
func (s *Server) tcpHTTP(pc *peekConn, obs *model.Observation) {
	obs.Parse = model.ParseHTTP
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(pc, 16<<10)
	req, err := http.ReadRequest(br)
	if err != nil {
		obs.Parse = model.ParseUnknown
		obs.Close = closeReason(err)
		return
	}
	if b, ok := httpecho.ParseBulkPath(req.URL.Path); ok {
		ip, _ := addrPortOf(pc.RemoteAddr())
		s.tcpBulk(pc, br, req, b, obs, ip)
		return
	}
	if strings.HasPrefix(req.URL.Path, "/tor/") {
		s.tcpTorDir(pc, req, obs)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	obs.Detail["method"] = req.Method
	obs.Detail["path"] = req.URL.Path
	hostSum := sha256.Sum256([]byte(req.Host))
	obs.Detail["host_sha256"] = hex.EncodeToString(hostSum[:])
	obs.Detail["host_len"] = itoa(len(req.Host))
	sum := sha256.Sum256(append([]byte(req.Method+" "+req.URL.RequestURI()+" "+req.Host+"\n"), body...))
	obs.PayloadSHA = hex.EncodeToString(sum[:])
	if sid, test, nonce, ok := parseEchoPath(req.URL.Path); ok {
		obs.SessionID, obs.TestID, obs.Nonce = sid, test, nonce
	}
	resp := httpEchoBody(req.Host, req.URL.Path, obs.Nonce)
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\nX-CP1-Nonce: %s\r\n\r\n", len(resp), obs.Nonce)
	b.Write(resp)
	if _, err := pc.Write(b.Bytes()); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "http_200"
	obs.RepliedAt = ptrTime(time.Now())
	obs.Close = "normal"
}

func httpEchoBody(host, path, nonce string) []byte { return httpecho.Body(host, path, nonce) }

func parseEchoPath(p string) (sid, test, nonce string, ok bool) { return httpecho.ParsePath(p) }

// tcpTLS terminates TLS, records the ClientHello and then echoes envelopes
// inside the session.
func (s *Server) tcpTLS(pc *peekConn, obs *model.Observation, ip netip.Addr) {
	obs.Parse = model.ParseTLS
	var hello *tls.ClientHelloInfo
	cfg := s.tlsConfig(nil)
	base := cfg
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		hello = chi
		if s.wantTorCert(chi, ip, obs) {
			c2 := base.Clone()
			c2.GetConfigForClient = nil
			c2.Certificates = []tls.Certificate{s.keys.TorCert}
			c2.NextProtos = nil
			return c2, nil
		}
		return nil, nil
	}
	tc := tls.Server(pc, cfg)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	err := tc.Handshake()
	if hello != nil {
		obs.Detail["sni"] = hello.ServerName
		obs.Detail["sni_sha256"] = hexSum([]byte(hello.ServerName))
		obs.Detail["alpn"] = strings.Join(hello.SupportedProtos, ",")
		obs.Detail["versions"] = fmtVersions(hello.SupportedVersions)
		obs.Detail["cipher_count"] = itoa(len(hello.CipherSuites))
		obs.Detail["hello_fp"] = helloFingerprint(hello)
	}
	if err != nil {
		obs.Response = "handshake_failed"
		obs.ServerError = err.Error()
		obs.Close = closeReason(err)
		if obs.Close == "server_error" {
			obs.Close = "normal"
		}
		return
	}
	cs := tc.ConnectionState()
	obs.Detail["negotiated_version"] = fmtVersions([]uint16{cs.Version})
	obs.Detail["negotiated_alpn"] = cs.NegotiatedProtocol
	obs.Response = "server_hello"
	obs.RepliedAt = ptrTime(time.Now())
	// Inner echo: same loop as plain TCP but over the TLS stream.
	inner := &peekConn{Conn: tc}
	first, err := inner.sniff(1, s.idle())
	if len(first) == 0 {
		obs.Close = closeReason(err)
		return
	}
	// Same as the outer dispatcher: a client that trickles the envelope in
	// tiny records (tcp.packets) must still be recognised as an envelope.
	if len(first) < 24 {
		inner.sniff(24, sniffWindow)
		first = inner.prefix
	}
	switch {
	case proto.IsEnvelope(first):
		sub := model.Observation{Detail: map[string]string{}}
		s.tcpEnvelope(inner, &sub)
		obs.SessionID, obs.TestID, obs.Nonce, obs.Seq = sub.SessionID, sub.TestID, sub.Nonce, sub.Seq
		obs.PayloadSHA = sub.PayloadSHA
		for _, k := range []string{"partial", "partial_bytes", "mac"} {
			if v := sub.Detail[k]; v != "" {
				obs.Detail[k] = v
			}
		}
		if sub.Response == "echo" {
			obs.Response = "server_hello+echo"
		}
		obs.Close = sub.Close
		obs.ServerError = sub.ServerError
	case tor.IsVersionsCell(first):
		s.tcpTorLink(inner, obs)
	case vless.IsRequest(first):
		// VLESS request inside the TLS stream (REALITY-shaped flow): answer
		// the header and mirror what follows. The flow carries its own parse
		// kind so it correlates with a vless reservation, not a bare TLS one.
		r, _ := vless.Parse(first)
		obs.Parse = model.ParseVLESS
		obs.Detail["vless_cmd"] = itoa(int(r.Cmd))
		obs.Detail["vless_dst_len"] = itoa(len(r.Host))
		obs.Detail["vless_dst_sha256"] = hexSum([]byte(r.Host))
		inner.prefix = first[r.Len:]
		if _, err := inner.Write(vless.Response()); err != nil {
			obs.Close = closeReason(err)
			return
		}
		obs.Response = "server_hello+vless"
		obs.RepliedAt = ptrTime(time.Now())
		sub := model.Observation{Detail: map[string]string{}}
		s.tcpEchoStream(inner, &sub, s.idle())
		for k, v := range sub.Detail {
			obs.Detail[k] = v
		}
		if sub.Detail["data_in"] != "" {
			obs.Response = "server_hello+vless+echo"
		}
		obs.Close = sub.Close
	case isHTTPRequest(first):
		sub := model.Observation{Detail: map[string]string{}}
		s.tcpHTTP(inner, &sub)
		obs.SessionID, obs.TestID, obs.Nonce = sub.SessionID, sub.TestID, sub.Nonce
		for k, v := range sub.Detail {
			obs.Detail["http_"+k] = v
		}
		if sub.Response == "http_200" {
			obs.Response = "server_hello+http_200"
		}
		obs.Close = sub.Close
	default:
		sub := model.Observation{Detail: map[string]string{}}
		s.tcpUnknown(inner, &sub)
		obs.Close = sub.Close
	}
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fmtVersions(v []uint16) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		switch x {
		case tls.VersionTLS10:
			parts = append(parts, "1.0")
		case tls.VersionTLS11:
			parts = append(parts, "1.1")
		case tls.VersionTLS12:
			parts = append(parts, "1.2")
		case tls.VersionTLS13:
			parts = append(parts, "1.3")
		default:
			parts = append(parts, fmt.Sprintf("0x%04x", x))
		}
	}
	return strings.Join(parts, ",")
}

// helloFingerprint is a stable, JA3-like digest of the offered surface. It is
// not JA3 (Go does not expose extension order) but is enough to tell the
// client's fingerprint variants apart on the server side.
func helloFingerprint(h *tls.ClientHelloInfo) string {
	var b bytes.Buffer
	for _, v := range h.SupportedVersions {
		binary.Write(&b, binary.BigEndian, v)
	}
	b.WriteByte('|')
	for _, c := range h.CipherSuites {
		binary.Write(&b, binary.BigEndian, c)
	}
	b.WriteByte('|')
	for _, c := range h.SupportedCurves {
		binary.Write(&b, binary.BigEndian, uint16(c))
	}
	b.WriteByte('|')
	for _, p := range h.SupportedPoints {
		b.WriteByte(p)
	}
	b.WriteByte('|')
	for _, s := range h.SignatureSchemes {
		binary.Write(&b, binary.BigEndian, uint16(s))
	}
	b.WriteByte('|')
	b.WriteString(strings.Join(h.SupportedProtos, ","))
	return hexSum(b.Bytes())[:24]
}

// tcpDNS answers DNS over TCP (2-byte length framing).
func (s *Server) tcpDNS(pc *peekConn, obs *model.Observation, viaTLS bool) {
	pc.SetReadDeadline(time.Now().Add(s.idle()))
	obs.Parse = model.ParseDNS
	if viaTLS {
		obs.Detail["via"] = "dot"
	}
	var lenb [2]byte
	if _, err := io.ReadFull(pc, lenb[:]); err != nil {
		obs.Parse = model.ParseUnknown
		obs.Close = closeReason(err)
		return
	}
	n := int(binary.BigEndian.Uint16(lenb[:]))
	if n == 0 || n > 4096 {
		obs.Parse = model.ParseUnknown
		obs.Close = "normal"
		return
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(pc, msg); err != nil {
		obs.Close = closeReason(err)
		return
	}
	q, err := dnsx.ParseQuery(msg)
	if err != nil {
		obs.Parse = model.ParseUnknown
		obs.Close = "normal"
		return
	}
	obs.Detail["qname"] = q.Name
	obs.Detail["qtype"] = q.Type.String()
	obs.PayloadSHA = hexSum(msg)
	obs.SessionID = sessionFromQName(q.Name)
	if obs.SessionID != "" {
		obs.TestID = testFromQName(q.Name)
	}
	srcIP, _ := addrPortOf(pc.RemoteAddr())
	ans, err := dnsx.BuildAnswerFrom(q, srcIP.String())
	if err != nil {
		obs.Close = "server_error"
		obs.ServerError = err.Error()
		return
	}
	out := make([]byte, 2+len(ans))
	binary.BigEndian.PutUint16(out, uint16(len(ans)))
	copy(out[2:], ans)
	if _, err := pc.Write(out); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "dns_answer"
	obs.RepliedAt = ptrTime(time.Now())
	obs.Close = "normal"
}

// tcpDoT terminates TLS and answers one DNS query.
func (s *Server) tcpDoT(pc *peekConn, obs *model.Observation) {
	var hello *tls.ClientHelloInfo
	tc := tls.Server(pc, s.tlsConfig(func(chi *tls.ClientHelloInfo) { hello = chi }))
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		obs.Parse = model.ParseTLS
		obs.Response = "handshake_failed"
		obs.ServerError = err.Error()
		obs.Close = closeReason(err)
		return
	}
	if hello != nil {
		obs.Detail["sni"] = hello.ServerName
	}
	s.tcpDNS(&peekConn{Conn: tc}, obs, true)
}

// testFromQName extracts the test id of <nonce>.<sid>.<test>.<zone>. The
// zone has two labels by default (probe.invalid) but more when an operator
// delegated a real subdomain (dns_zone); a name outside the configured zone
// keeps the two-label guess.
func testFromQName(name string) string {
	name = strings.TrimSuffix(name, ".")
	zoneLabels := 2
	if zone := strings.TrimSuffix(dnsx.Zone, "."); strings.HasSuffix(name, "."+zone) {
		zoneLabels = strings.Count(zone, ".") + 1
	}
	parts := strings.Split(name, ".")
	if len(parts) >= 3+zoneLabels {
		return strings.Join(parts[2:len(parts)-zoneLabels], ".")
	}
	return ""
}
