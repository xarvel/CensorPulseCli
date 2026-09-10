package server

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/xarvel/CensorPulseCli/internal/ike"
	"github.com/xarvel/CensorPulseCli/internal/l2tp"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/tlsx"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// The VPN entries of udpDispatch (see there for the order they are tried
// in). Each handshake is answered under a reservation only; its follow-up
// packets are answered to the handshake's address only (samePeer), at most
// vpnSessionMaxData times, and never with more bytes than they brought.

func (f *udpFlow) matchWGInitiation() bool { return wg.LooksLikeInitiation(f.b) }

func (f *udpFlow) serveWGInitiation() {
	l, s, obs := f.l, f.l.s, &f.obs
	obs.Parse = model.ParseWireGuard
	// The Noise handshake costs two X25519 operations; a peer without a
	// pending reservation gets neither them nor a reply.
	if test, _ := s.store.peekReservation(f.ip, "udp", l.port, model.ParseWireGuard, f.now); test == "" {
		obs.Unmatched = true
		obs.Detail["auth"] = "unreserved"
		return
	}
	info, err := wg.ConsumeInitiation(f.b, s.keys.WG)
	obs.Detail["mac1"] = boolStr(info != nil && info.MAC1Valid)
	if err != nil {
		obs.Detail["auth"] = "failed"
		f.correlate(model.ParseWireGuard)
		return
	}
	obs.Detail["peer_static"] = base64Std(info.PeerStatic[:])
	if !f.correlate(model.ParseWireGuard) {
		return // unreserved: silent
	}
	resp, rs, err := wg.CreateResponse(info, s.keys.WG, [32]byte{})
	if err != nil {
		obs.Close = "server_error"
		obs.ServerError = err.Error()
		return
	}
	f.reply(resp, "wireguard_response")
	l.peersMu.Lock()
	if l.wgSess == nil {
		l.wgSess = map[uint32]*wgSession{}
	}
	l.gcVPN(f.now)
	l.wgSess[rs.LocalIdx] = &wgSession{vpnFlow: f.vpnFlow(), sess: rs}
	l.peersMu.Unlock()
}

func (f *udpFlow) matchWGTransport() bool { return wg.LooksLikeTransport(f.b) }

// serveWGTransport handles transport data on a session we answered:
// authenticate, echo the plaintext back under our send key. Unknown receiver
// index or bad tag → silence (never a reflector for unauthenticated bytes).
func (f *udpFlow) serveWGTransport() {
	l, obs := f.l, &f.obs
	obs.Parse = model.ParseWireGuardData
	l.peersMu.Lock()
	ws := l.wgSess[wg.TransportReceiver(f.b)]
	l.peersMu.Unlock()
	if ws == nil || f.now.After(ws.expires) {
		obs.Unmatched = true
		obs.Detail["session"] = "unknown"
		return
	}
	if !f.samePeer(&ws.vpnFlow) {
		return
	}
	ctr, plain, err := wg.OpenTransport(ws.sess.Keys.Recv, f.b)
	if err != nil {
		obs.Detail["auth"] = "failed"
		f.dataObs(&ws.vpnFlow, itoa(int(ctr)), 0)
		return
	}
	ws.dataIn++
	if ws.dataIn > vpnSessionMaxData {
		f.dataObs(&ws.vpnFlow, itoa(int(ctr)), len(plain))
		obs.Response = "refused"
		return
	}
	ws.dataOut++
	f.dataObs(&ws.vpnFlow, itoa(int(ctr)), len(plain))
	f.reply(wg.SealTransport(ws.sess.Keys.Send, ws.sess.PeerIdx, ctr, plain), "wireguard_data")
}

// matchIKE claims IKEv2 messages, bare (port 500) or behind the NAT-T
// non-ESP marker (port 4500).
func (f *udpFlow) matchIKE() bool {
	if ike.Looks(f.b) {
		return true
	}
	_, natt := ike.StripNATT(f.b)
	return natt
}

// serveIKE: IKE_SA_INIT opens a session under a reservation; IKE_AUTH on a
// known SPI is answered with an SK-shaped response. NAT-T framing (port
// 4500) is mirrored on the reply.
func (f *udpFlow) serveIKE() {
	l, s, obs := f.l, f.l.s, &f.obs
	msg, natt := ike.StripNATT(f.b)
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
		if !f.correlate(model.ParseIKE) {
			return
		}
		spir := ike.RandomSPI()
		resp := ike.SAInitResponse(hdr, spir, s.keys.WG.Public)
		f.reply(frame(resp), "ike_sa_init")
		is := &ikeSession{vpnFlow: f.vpnFlow(), spir: spir, natt: natt, esp: ike.ESPSPIFor(spir)}
		l.peersMu.Lock()
		if l.ikeSess == nil {
			l.ikeSess, l.espSess = map[[8]byte]*ikeSession{}, map[uint32]*ikeSession{}
		}
		l.gcVPN(f.now)
		l.ikeSess[hdr.SPIi] = is
		l.espSess[is.esp] = is
		l.peersMu.Unlock()
	case hdr.Exchange == ike.ExchangeAuth && hdr.Flags&ike.FlagResponse == 0:
		is := l.lookupIKE(hdr.SPIi, f.now)
		if is == nil || hdr.SPIr != is.spir {
			obs.Unmatched = true
			obs.Detail["session"] = "unknown"
			return
		}
		if !f.samePeer(&is.vpnFlow) {
			return
		}
		is.dataIn++
		if is.dataIn > vpnSessionMaxData {
			f.dataObs(&is.vpnFlow, itoa(int(hdr.MessageID)), len(msg)-ike.HeaderLen)
			obs.Response = "refused"
			return
		}
		is.dataOut++
		is.authd = true
		f.dataObs(&is.vpnFlow, itoa(int(hdr.MessageID)), len(msg)-ike.HeaderLen)
		obs.Detail["stage"] = "ike_auth"
		inner := len(msg) - ike.HeaderLen - 4 - 32
		if inner < 32 {
			inner = 32
		}
		f.reply(frame(ike.Auth(hdr.SPIi, is.spir, hdr.MessageID, inner, true)), "ike_auth")
	default:
		obs.Unmatched = true
	}
}

// matchESP claims ESP-in-UDP only for an SPI we handed out: the shape alone
// (a non-zero first word) fits random datagrams.
func (f *udpFlow) matchESP() bool {
	if !ike.IsESPUDP(f.b) {
		return false
	}
	f.esp = f.l.lookupESP(ike.ESPSPI(f.b), f.now)
	return f.esp != nil
}

// serveESP echoes ESP-in-UDP on a session that went through IKE_AUTH, with
// the same SPI (a real peer would use its own; a DPI cannot tell) and the
// same size.
func (f *udpFlow) serveESP() {
	is, obs := f.esp, &f.obs
	obs.Parse = model.ParseESP
	if !f.samePeer(&is.vpnFlow) {
		return
	}
	if !is.authd {
		obs.Detail["session"] = "not_authenticated"
		return
	}
	is.dataIn++
	if is.dataIn > vpnSessionMaxData {
		f.dataObs(&is.vpnFlow, "", len(f.b)-ike.ESPHeaderLen)
		obs.Response = "refused"
		return
	}
	is.dataOut++
	seq := binary.BigEndian.Uint32(f.b[4:8])
	f.dataObs(&is.vpnFlow, itoa(int(seq)), len(f.b)-ike.ESPHeaderLen)
	f.reply(ike.ESP(is.esp, seq, f.b[ike.ESPHeaderLen:]), "esp_echo")
}

func (f *udpFlow) matchL2TPControl() bool { return l2tp.IsControl(f.b) }

// serveL2TPControl: SCCRQ opens a tunnel under a reservation; the rest of
// the control connection is answered on the tunnel id we assigned.
func (f *udpFlow) serveL2TPControl() {
	l, obs := f.l, &f.obs
	obs.Parse = model.ParseL2TP
	ctl, err := l2tp.ParseControl(f.b)
	if err != nil {
		return
	}
	obs.Detail["message_type"] = itoa(int(ctl.MessageType))
	if ctl.MessageType == l2tp.MsgSCCRQ && ctl.TunnelID == 0 {
		if !f.correlate(model.ParseL2TP) {
			return
		}
		ts := &l2tpSession{vpnFlow: f.vpnFlow(), peerTunnel: ctl.AssignedTunnel, tunnel: l2tp.RandomID()}
		l.peersMu.Lock()
		if l.l2tpSess == nil {
			l.l2tpSess = map[uint16]*l2tpSession{}
		}
		l.gcVPN(f.now)
		l.l2tpSess[ts.tunnel] = ts
		l.peersMu.Unlock()
		f.reply(l2tp.SCCRP(ts.peerTunnel, ts.tunnel, "cpprobe"), "l2tp_sccrp")
		return
	}
	ts := l.lookupL2TP(ctl.TunnelID, f.now)
	if ts == nil {
		obs.Unmatched = true
		obs.Detail["session"] = "unknown"
		return
	}
	if !f.samePeer(&ts.vpnFlow) {
		return
	}
	// Not attribute(): control rows have never carried the variant.
	obs.SessionID, obs.AttemptID, obs.TestID = ts.sessionID, ts.attemptID, ts.testID
	switch ctl.MessageType {
	case l2tp.MsgSCCCN, l2tp.MsgICCN, l2tp.MsgStopCCN:
		ts.ns++
		f.reply(l2tp.ZLB(ts.peerTunnel, ts.peerSession, ts.ns, ctl.Ns+1), "l2tp_zlb")
	case l2tp.MsgICRQ:
		ts.peerSession, ts.session = ctl.AssignedSession, l2tp.RandomID()
		ts.ns++
		f.reply(l2tp.ICRP(ts.peerTunnel, ts.peerSession, ts.session, ts.ns, ctl.Ns+1), "l2tp_icrp")
	case l2tp.MsgZLB:
		f.dontRecord() // acknowledgements are not worth an observation
	default:
		obs.Response = "silence"
	}
}

// matchL2TPData claims data messages only for a tunnel we assigned: random
// bytes pass l2tp.IsData one time in 32.
func (f *udpFlow) matchL2TPData() bool {
	if !l2tp.IsData(f.b) {
		return false
	}
	f.l2tp = f.l.lookupL2TP(l2tp.DataTunnel(f.b), f.now)
	return f.l2tp != nil
}

func (f *udpFlow) serveL2TPData() {
	ts, obs := f.l2tp, &f.obs
	obs.Parse = model.ParseL2TPData
	if !f.samePeer(&ts.vpnFlow) {
		return
	}
	ts.dataIn++
	if ts.dataIn > vpnSessionMaxData || ts.session == 0 {
		f.dataObs(&ts.vpnFlow, "", len(f.b)-l2tp.DataHeaderLen)
		obs.Response = "refused"
		return
	}
	ts.dataOut++
	f.dataObs(&ts.vpnFlow, itoa(ts.dataIn), len(f.b)-l2tp.DataHeaderLen)
	f.reply(l2tp.Data(ts.peerTunnel, ts.peerSession, l2tp.DataPayload(f.b)), "l2tp_data_echo")
}

func (f *udpFlow) matchOVPNReset() bool {
	_, ok := ovpn.IsClientReset(f.b)
	return ok
}

// serveOVPNReset answers a client hard reset, plain (14 bytes) or tls-auth
// (42 bytes). A tls-auth reset whose HMAC does not verify is dropped silently
// like a real server does; when it arrived under a reservation the
// observation says so (detail.mac=invalid → uplink_modified).
func (f *udpFlow) serveOVPNReset() {
	l, s, obs := f.l, f.l.s, &f.obs
	obs.Parse = model.ParseOpenVPN
	auth, _ := ovpn.IsClientReset(f.b)
	obs.Detail["control_auth"] = auth.String()
	layout := s.ovpnLayout(auth)
	csid, err := layout.ParseClientReset(f.b)
	if err != nil {
		if errors.Is(err, ovpn.ErrBadHMAC) {
			obs.Detail["mac"] = "invalid"
			f.correlate(model.ParseOpenVPN)
		}
		return
	}
	obs.Detail["client_session"] = hex.EncodeToString(csid[:])
	if !f.correlate(model.ParseOpenVPN) {
		return
	}
	resp, ssid := layout.ServerReset(csid)
	f.reply(resp, "openvpn_reset")
	ov := &ovpnSession{vpnFlow: f.vpnFlow(), serverSID: ssid, layout: layout, nextPID: 1, dataPID: 1}
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
	l.gcVPN(f.now)
	l.ovpnSess[csid] = ov
	l.ovpnPeer[f.raddr.String()] = ov
	l.peersMu.Unlock()
}

func (f *udpFlow) matchOVPNControl() bool {
	return ovpn.Opcode(f.b) == ovpn.OpAckV1 || ovpn.Opcode(f.b) == ovpn.OpControlV1
}

// serveOVPNControl is the control channel after a reset we answered. Acks
// are counted and stay silent (like a real server); each control packet is
// answered with a control packet of our own that piggy-backs the ack and
// never exceeds the request in size.
func (f *udpFlow) serveOVPNControl() {
	l, obs := f.l, &f.obs
	obs.Parse = model.ParseOpenVPNControl
	csid, ok := ovpn.SessionOf(f.b)
	l.peersMu.Lock()
	ov := l.ovpnSess[csid]
	l.peersMu.Unlock()
	if !ok || ov == nil || f.now.After(ov.expires) {
		obs.Unmatched = true
		obs.Detail["session"] = "unknown"
		return
	}
	if !f.samePeer(&ov.vpnFlow) {
		return
	}
	obs.Detail["control_auth"] = ov.layout.Auth.String()
	p, err := ov.layout.Parse(f.b)
	if err != nil {
		f.dataObs(&ov.vpnFlow, "", 0)
		obs.Detail["stage"] = "control"
		if errors.Is(err, ovpn.ErrBadHMAC) {
			obs.Detail["mac"] = "invalid"
		} else {
			obs.Detail["parse"] = "bad_control"
		}
		return
	}
	if p.Op == ovpn.OpAckV1 {
		f.dontRecord() // acks are not worth an observation each
		return
	}
	ov.ctlIn++
	f.dataObs(&ov.vpnFlow, itoa(int(p.PID)), len(p.Payload))
	obs.Detail["stage"] = "control"
	obs.Detail["ctl_in"] = itoa(ov.ctlIn)
	obs.Detail["ctl_out"] = itoa(ov.ctlOut)
	if ov.ctlIn+ov.dataIn > vpnSessionMaxData {
		obs.Response = "refused"
		return
	}
	if ov.ctlIn == 1 && len(p.Payload) >= 6 && p.Payload[0] == 0x16 && p.Payload[5] == 0x01 {
		obs.Detail["control_payload"] = "tls_client_hello"
	}
	if len(p.Acks) > 0 {
		obs.Detail["acks"] = itoa(len(p.Acks))
	}
	// Our control payload: a handshake-shaped TLS record sized so that
	// the control packet (ack included) ≤ what the client sent.
	n := len(f.b) - ov.layout.HdrLen(1) - 5
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
	f.reply(ctl, "openvpn_control")
}

func (f *udpFlow) matchOVPNData() bool { return ovpn.IsData(f.b) }

// serveOVPNData is the data channel (P_DATA_V2) on a flow we answered: no
// session id on the wire, the peer address is the key. Authenticate under
// the client→server key, echo the plaintext under the server→client key with
// the same length. Anything that does not verify is silence, as with a real
// server.
func (f *udpFlow) serveOVPNData() {
	obs := &f.obs
	obs.Parse = model.ParseOpenVPNData
	ov := f.l.lookupOVPNPeer(f.raddr.String(), f.now)
	if ov == nil || ov.c2s == nil {
		obs.Unmatched = true
		obs.Detail["session"] = "unknown"
		return
	}
	pid, plain, err := ov.c2s.Open(f.b)
	if err != nil {
		obs.Detail["auth"] = "failed"
		f.dataObs(&ov.vpnFlow, itoa(int(pid)), 0)
		return
	}
	ov.dataIn++
	if ov.ctlIn+ov.dataIn > vpnSessionMaxData {
		f.dataObs(&ov.vpnFlow, itoa(int(pid)), len(plain))
		obs.Response = "refused"
		return
	}
	ov.dataOut++
	f.dataObs(&ov.vpnFlow, itoa(int(pid)), len(plain))
	out := ov.s2c.Seal(0, ov.dataPID, plain)
	ov.dataPID++
	f.reply(out, "openvpn_data")
}
