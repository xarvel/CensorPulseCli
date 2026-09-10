package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/ike"
	"github.com/xarvel/CensorPulseCli/internal/l2tp"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// The order protocols are tried in is part of the measurement contract.
func TestUDPDispatchOrder(t *testing.T) {
	want := []string{"envelope", "dns", "stun", "dtls", "wireguard-initiation", "wireguard-transport", "ike", "esp",
		"l2tp-control", "l2tp-data", "openvpn-reset", "openvpn-control", "openvpn-data", "quic", "unknown"}
	if len(udpDispatch) != len(want) {
		t.Fatalf("%d dispatch entries, want %d", len(udpDispatch), len(want))
	}
	for i, p := range udpDispatch {
		if p.name != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p.name, want[i])
		}
		if p.match == nil || p.serve == nil {
			t.Errorf("entry %s lacks a matcher or a handler", p.name)
		}
	}
}

var testPeer = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000}

func flowOf(l *udpListener, b []byte) *udpFlow {
	return &udpFlow{l: l, raddr: testPeer, ip: ipA, now: t0, b: b}
}

func ikeMsg(exchange byte, firstWord uint32) []byte {
	b := make([]byte, ike.HeaderLen)
	binary.BigEndian.PutUint32(b[0:], firstWord)
	b[17], b[18] = ike.Version, exchange
	binary.BigEndian.PutUint32(b[24:], uint32(len(b)))
	return b
}

func TestUDPDispatchShapes(t *testing.T) {
	quicL := &udpListener{quicC: make(chan packet, 1)}
	quicInitial := make([]byte, 1200)
	quicInitial[0], quicInitial[4] = 0xc0, 1
	stunReq := make([]byte, 20)
	binary.BigEndian.PutUint16(stunReq[0:], 0x0001)
	binary.BigEndian.PutUint32(stunReq[4:], 0x2112a442)
	dtls := make([]byte, 64)
	dtls[0], dtls[1], dtls[2] = 0x16, 0xfe, 0xfd
	wgInit := make([]byte, wg.InitiationSize)
	wgInit[0] = wg.MessageInitiationType
	wgData := make([]byte, wg.TransportOverhead)
	wgData[0] = wg.MessageTransportType
	natt := append(make([]byte, ike.NATTMarkerLen), ikeMsg(ike.ExchangeSAInit, 0xdeadbeef)...)
	l2tpCtl := make([]byte, l2tp.ControlHeaderLen)
	binary.BigEndian.PutUint16(l2tpCtl[0:], 0xc802)
	binary.BigEndian.PutUint16(l2tpCtl[2:], uint16(len(l2tpCtl)))
	ovpnReset := make([]byte, ovpn.ClientResetLen)
	ovpnReset[0] = ovpn.OpHardResetClientV2 << 3
	ovpnCtl := append([]byte{ovpn.OpControlV1 << 3}, make([]byte, 40)...)
	ovpnAck := append([]byte{ovpn.OpAckV1 << 3}, make([]byte, 20)...)
	ovpnData := append([]byte{ovpn.OpDataV2 << 3}, make([]byte, 60)...)
	dnsQuery := make([]byte, 30)
	dnsQuery[5] = 1 // one question, QR clear

	for _, tc := range []struct {
		name string
		l    *udpListener
		b    []byte
		want string
	}{
		{"envelope", quicL, append([]byte("CP1\x01\x01\x01"), make([]byte, 80)...), "envelope"},
		{"dns query on a dns port", &udpListener{dns: true}, dnsQuery, "dns"},
		{"dns query on a test port", quicL, dnsQuery, "unknown"},
		{"envelope on a dns port", &udpListener{dns: true}, append([]byte("CP1\x01\x01\x01"), make([]byte, 80)...), "envelope"},
		{"stun", quicL, stunReq, "stun"},
		{"dtls", quicL, dtls, "dtls"},
		{"wireguard initiation", quicL, wgInit, "wireguard-initiation"},
		{"wireguard transport", quicL, wgData, "wireguard-transport"},
		{"ike sa_init", quicL, ikeMsg(ike.ExchangeSAInit, 0xdeadbeef), "ike"},
		{"ike behind the nat-t marker", quicL, natt, "ike"},
		{"l2tp control", quicL, l2tpCtl, "l2tp-control"},
		{"openvpn reset", quicL, ovpnReset, "openvpn-reset"},
		{"openvpn control", quicL, ovpnCtl, "openvpn-control"},
		{"openvpn ack", quicL, ovpnAck, "openvpn-control"},
		{"openvpn data", quicL, ovpnData, "openvpn-data"},
		{"quic initial", quicL, quicInitial, "quic"},
		{"quic initial without the quic endpoint", &udpListener{}, quicInitial, "unknown"},
		{"short header from a stranger", quicL, append([]byte{0x40}, make([]byte, 40)...), "unknown"},
		{"random bytes", quicL, []byte{0x05, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, "unknown"},
		{"empty", quicL, nil, "unknown"},
	} {
		if got := flowOf(tc.l, tc.b).protocol().name; got != tc.want {
			t.Errorf("%s: dispatched to %s, want %s", tc.name, got, tc.want)
		}
	}
}

// The overlaps the order exists for (see the comment on udpDispatch).
func TestUDPDispatchShadowing(t *testing.T) {
	// A remembered QUIC peer: short-header shapes from it go to quic-go,
	// except what an entry above claims first.
	l := &udpListener{quicC: make(chan packet, 1)}
	l.rememberPeer(testPeer.String(), t0)
	for _, tc := range []struct {
		name string
		b    []byte
		want string
	}{
		{"short header", append([]byte{0x40}, make([]byte, 40)...), "quic"},
		{"envelope (0x43 has the fixed bit)", append([]byte("CP1\x01\x01\x01"), make([]byte, 80)...), "envelope"},
		{"openvpn data (0x48 has the fixed bit)", append([]byte{ovpn.OpDataV2 << 3}, make([]byte, 60)...), "openvpn-data"},
	} {
		if got := flowOf(l, tc.b).protocol().name; got != tc.want {
			t.Errorf("known quic peer, %s: dispatched to %s, want %s", tc.name, got, tc.want)
		}
	}
	if got := flowOf(l, append([]byte{0x40}, make([]byte, 40)...)); got.protocol().name != "quic" || flowOf(&udpListener{quicC: l.quicC}, got.b).protocol().name != "unknown" {
		t.Error("short headers must only be forwarded for a remembered peer")
	}
	// 30 s later the peer is forgotten.
	late := flowOf(l, append([]byte{0x40}, make([]byte, 40)...))
	late.now = t0.Add(31 * time.Second)
	if got := late.protocol().name; got != "unknown" {
		t.Errorf("short header 31 s after the Initial: dispatched to %s, want unknown", got)
	}

	// ESP and L2TP data are claimed only for a live session, and the
	// matcher hands that session to the handler.
	const spi = 0xdeadbeef
	is := &ikeSession{vpnFlow: vpnFlow{peer: testPeer.String(), expires: t0.Add(time.Minute)}, esp: spi}
	ts := &l2tpSession{vpnFlow: vpnFlow{peer: testPeer.String(), expires: t0.Add(time.Minute)}, tunnel: 0x1234}
	vl := &udpListener{espSess: map[uint32]*ikeSession{spi: is}, l2tpSess: map[uint16]*l2tpSession{0x1234: ts}}
	esp := make([]byte, ike.ESPHeaderLen+16)
	binary.BigEndian.PutUint32(esp, spi)
	if f := flowOf(vl, esp); f.protocol().name != "esp" || f.esp != is {
		t.Errorf("esp on a known spi: dispatched to %s (session %v)", f.protocol().name, f.esp)
	}
	binary.BigEndian.PutUint32(esp, spi+1)
	if got := flowOf(vl, esp).protocol().name; got != "unknown" {
		t.Errorf("esp shape with an unknown spi: dispatched to %s, want unknown", got)
	}
	expired := flowOf(vl, esp)
	binary.BigEndian.PutUint32(expired.b, spi)
	expired.now = t0.Add(2 * time.Minute)
	if got := expired.protocol().name; got != "unknown" {
		t.Errorf("esp on an expired session: dispatched to %s, want unknown", got)
	}
	// A bare IKE message has the ESP shape; even with its first word equal to
	// a live SPI it stays IKE.
	if got := flowOf(vl, ikeMsg(ike.ExchangeAuth, spi)).protocol().name; got != "ike" {
		t.Errorf("ike message starting with a live esp spi: dispatched to %s, want ike", got)
	}
	data := make([]byte, l2tp.DataHeaderLen+8)
	binary.BigEndian.PutUint16(data[0:], 0x0002)
	binary.BigEndian.PutUint16(data[2:], 0x1234)
	if f := flowOf(vl, data); f.protocol().name != "l2tp-data" || f.l2tp != ts {
		t.Errorf("l2tp data on a known tunnel: dispatched to %s (session %v)", f.protocol().name, f.l2tp)
	}
	binary.BigEndian.PutUint16(data[2:], 0x4321)
	if got := flowOf(vl, data).protocol().name; got != "unknown" {
		t.Errorf("l2tp data shape with an unknown tunnel: dispatched to %s, want unknown", got)
	}
}
