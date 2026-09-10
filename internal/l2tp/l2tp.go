// Package l2tp builds and recognises L2TPv2 (RFC 2661) control messages for
// a tunnel and session setup (SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN) and the data
// messages that carry PPP afterwards. Plain L2TP over UDP 1701, no IPsec: the
// probe measures whether the L2TP wire shape and the PPP data that follows
// survive the path.
package l2tp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	Port = 1701

	flagType   = 0x8000
	flagLength = 0x4000
	flagSeq    = 0x0800
	version    = 2

	ControlHeaderLen = 12
	DataHeaderLen    = 6

	MsgSCCRQ   = 1
	MsgSCCRP   = 2
	MsgSCCCN   = 3
	MsgStopCCN = 4
	MsgICRQ    = 10
	MsgICRP    = 11
	MsgICCN    = 12
	MsgZLB     = 0 // zero-length body: no AVPs

	AVPMessageType      = 0
	AVPProtocolVersion  = 2
	AVPFramingCap       = 3
	AVPHostName         = 7
	AVPVendorName       = 8
	AVPAssignedTunnel   = 9
	AVPReceiveWindow    = 10
	AVPAssignedSession  = 14
	AVPCallSerialNumber = 15
	AVPFramingType      = 19
	AVPTxConnectSpeed   = 24
)

var ErrNotL2TP = errors.New("l2tp: not an L2TPv2 message")

// Control is a parsed control message.
type Control struct {
	TunnelID, SessionID uint16
	Ns, Nr              uint16
	MessageType         uint16 // MsgZLB when there are no AVPs
	AssignedTunnel      uint16
	AssignedSession     uint16
	HostName            string
}

// IsControl is the shape check for a control message (T, L and S bits set).
func IsControl(b []byte) bool {
	if len(b) < ControlHeaderLen {
		return false
	}
	f := binary.BigEndian.Uint16(b[0:2])
	return f&flagType != 0 && f&flagLength != 0 && f&flagSeq != 0 && f&0x000f == version && int(binary.BigEndian.Uint16(b[2:4])) == len(b)
}

// IsData is the shape check for a data message without optional fields.
// Random bytes pass it one time in 32, so the caller must also know the
// tunnel id.
func IsData(b []byte) bool {
	if len(b) < DataHeaderLen {
		return false
	}
	f := binary.BigEndian.Uint16(b[0:2])
	return f&flagType == 0 && f&0x000f == version && f&(flagLength|flagSeq|0x0200) == 0
}

// DataTunnel returns the tunnel id of a data message.
func DataTunnel(b []byte) uint16 { return binary.BigEndian.Uint16(b[2:4]) }

// ParseControl decodes header and the AVPs the probe cares about.
func ParseControl(b []byte) (Control, error) {
	var c Control
	if !IsControl(b) {
		return c, ErrNotL2TP
	}
	c.TunnelID = binary.BigEndian.Uint16(b[4:6])
	c.SessionID = binary.BigEndian.Uint16(b[6:8])
	c.Ns = binary.BigEndian.Uint16(b[8:10])
	c.Nr = binary.BigEndian.Uint16(b[10:12])
	p := b[ControlHeaderLen:]
	for len(p) >= 6 {
		hl := binary.BigEndian.Uint16(p[0:2])
		n := int(hl & 0x03ff)
		if n < 6 || n > len(p) {
			return c, ErrNotL2TP
		}
		vendor := binary.BigEndian.Uint16(p[2:4])
		typ := binary.BigEndian.Uint16(p[4:6])
		val := p[6:n]
		if vendor == 0 {
			switch typ {
			case AVPMessageType:
				if len(val) == 2 {
					c.MessageType = binary.BigEndian.Uint16(val)
				}
			case AVPAssignedTunnel:
				if len(val) == 2 {
					c.AssignedTunnel = binary.BigEndian.Uint16(val)
				}
			case AVPAssignedSession:
				if len(val) == 2 {
					c.AssignedSession = binary.BigEndian.Uint16(val)
				}
			case AVPHostName:
				c.HostName = string(val)
			}
		}
		p = p[n:]
	}
	return c, nil
}

type builder struct{ out []byte }

func newControl(tunnel, session, ns, nr uint16) *builder {
	out := make([]byte, ControlHeaderLen, 256)
	binary.BigEndian.PutUint16(out[0:], flagType|flagLength|flagSeq|version)
	binary.BigEndian.PutUint16(out[4:], tunnel)
	binary.BigEndian.PutUint16(out[6:], session)
	binary.BigEndian.PutUint16(out[8:], ns)
	binary.BigEndian.PutUint16(out[10:], nr)
	return &builder{out: out}
}

func (b *builder) avp(typ uint16, val []byte) *builder {
	hdr := make([]byte, 6)
	binary.BigEndian.PutUint16(hdr[0:], 0x8000|uint16(6+len(val))) // mandatory
	binary.BigEndian.PutUint16(hdr[4:], typ)
	b.out = append(b.out, hdr...)
	b.out = append(b.out, val...)
	return b
}

func (b *builder) u16(typ uint16, v uint16) *builder {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	return b.avp(typ, x[:])
}

func (b *builder) u32(typ uint16, v uint32) *builder {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	return b.avp(typ, x[:])
}

func (b *builder) finish() []byte {
	binary.BigEndian.PutUint16(b.out[2:], uint16(len(b.out)))
	return b.out
}

// RandomID returns a non-zero 16-bit tunnel or session id.
func RandomID() uint16 {
	var x [2]byte
	for {
		rand.Read(x[:])
		if v := binary.BigEndian.Uint16(x[:]); v != 0 {
			return v
		}
	}
}

// SCCRQ builds a Start-Control-Connection-Request (tunnel id 0, our
// assigned tunnel id inside).
func SCCRQ(assignedTunnel uint16, hostName string) []byte {
	return newControl(0, 0, 0, 0).
		u16(AVPMessageType, MsgSCCRQ).
		u16(AVPProtocolVersion, 0x0100).
		avp(AVPHostName, []byte(hostName)).
		u32(AVPFramingCap, 3).
		u16(AVPAssignedTunnel, assignedTunnel).
		u16(AVPReceiveWindow, 4).
		avp(AVPVendorName, []byte("CensorPulse")).
		finish()
}

// SCCRP answers an SCCRQ. Without the vendor name and window it is shorter.
func SCCRP(peerTunnel, assignedTunnel uint16, hostName string) []byte {
	return newControl(peerTunnel, 0, 0, 1).
		u16(AVPMessageType, MsgSCCRP).
		u16(AVPProtocolVersion, 0x0100).
		u32(AVPFramingCap, 3).
		avp(AVPHostName, []byte(hostName)).
		u16(AVPAssignedTunnel, assignedTunnel).
		finish()
}

// SCCCN completes the tunnel.
func SCCCN(peerTunnel uint16) []byte {
	return newControl(peerTunnel, 0, 1, 1).u16(AVPMessageType, MsgSCCCN).finish()
}

// ICRQ opens a session inside the tunnel.
func ICRQ(peerTunnel, assignedSession uint16, ns, nr uint16) []byte {
	var serial [4]byte
	rand.Read(serial[:])
	return newControl(peerTunnel, 0, ns, nr).
		u16(AVPMessageType, MsgICRQ).
		u16(AVPAssignedSession, assignedSession).
		u32(AVPCallSerialNumber, binary.BigEndian.Uint32(serial[:])).
		finish()
}

// ICRP answers an ICRQ.
func ICRP(peerTunnel, peerSession, assignedSession uint16, ns, nr uint16) []byte {
	return newControl(peerTunnel, peerSession, ns, nr).
		u16(AVPMessageType, MsgICRP).
		u16(AVPAssignedSession, assignedSession).
		finish()
}

// ICCN completes the session.
func ICCN(peerTunnel, peerSession uint16, ns, nr uint16) []byte {
	return newControl(peerTunnel, peerSession, ns, nr).
		u16(AVPMessageType, MsgICCN).
		u32(AVPTxConnectSpeed, 100000000).
		u32(AVPFramingType, 1).
		finish()
}

// ZLB is the zero-length-body acknowledgement.
func ZLB(peerTunnel, peerSession, ns, nr uint16) []byte {
	return newControl(peerTunnel, peerSession, ns, nr).finish()
}

// Data wraps a PPP frame into a data message.
func Data(peerTunnel, peerSession uint16, ppp []byte) []byte {
	out := make([]byte, DataHeaderLen+len(ppp))
	binary.BigEndian.PutUint16(out[0:], version)
	binary.BigEndian.PutUint16(out[2:], peerTunnel)
	binary.BigEndian.PutUint16(out[4:], peerSession)
	copy(out[6:], ppp)
	return out
}

// DataPayload returns the PPP frame of a data message.
func DataPayload(b []byte) []byte { return b[DataHeaderLen:] }

// PPPLCPConfigureRequest is the first PPP frame a client sends: LCP
// Configure-Request with MRU and a magic number.
func PPPLCPConfigureRequest(id byte) []byte {
	var magic [4]byte
	rand.Read(magic[:])
	f := []byte{0xff, 0x03, 0xc0, 0x21, 1, id, 0, 14, 1, 4, 0x05, 0xdc, 5, 6}
	return append(f, magic[:]...)
}

// PPPIP wraps payload as a PPP IP frame.
func PPPIP(payload []byte) []byte {
	return append([]byte{0xff, 0x03, 0x00, 0x21}, payload...)
}
