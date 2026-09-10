// Package dtlsx builds and parses the first flights of a DTLS 1.2 handshake
// as WebRTC peers send them: a ClientHello with a chosen fingerprint, the
// HelloVerifyRequest a server answers with, the ClientHello repeated with the
// cookie, and a ServerHello. No key exchange is performed: the probe only
// measures whether these datagrams cross the path, which is what DTLS
// fingerprint rules act on.
package dtlsx

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	contentHandshake = 22
	hsClientHello    = 1
	hsServerHello    = 2
	hsHelloVerify    = 3
	hsServerDone     = 14
	versionDTLS12    = 0xfefd
	versionDTLS10    = 0xfeff
)

// Fingerprints are ClientHello bodies (version onward; the 32-byte random is
// replaced on every use) as captured from real clients.
//
// "pion" is what pion/dtls v3 (Snowflake's client and standalone proxy, via
// pion/webrtc v4 defaults) sends. The browser ones come from
// github.com/theodorsm/covert-dtls fingerprints-captures.
var Fingerprints = map[string]string{
	"pion": "fefd" + "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000" + // session id, cookie: filled at build time
		"0010" + "c02bc02fcca9cca8c00ac014c02cc030" + "0100" +
		"0042" +
		"000d0016" + "0014" + "0403050306030807080408050806040105010601" +
		"ff010001" + "00" +
		"000a0008" + "0006" + "001d00170018" +
		"000b0002" + "01" + "00" +
		"000e0009" + "0006" + "000800070001" + "00" +
		"00170000",
	"firefox-138": "fefd050cbae5108bbad3558bdb8e09ca3f44f723c0d7e517fb1ec5ffc6c0d6fe41c200000010c02bc02fcca9cca8c00ac009c013c0140100006a00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200",
	"chrome-136":  "fefdc8b61395d44e2a57eb9d72ee84ee311d60e4b9d8948e79bfe838fdef0cbaf74d00000016c02bc02fcca9cca8c009c013c00ac014009c002f003501000040000a00080006001d00170018000d0014001204030804040105030805050108060601020100170000000b00020100000e0009000600010008000700ff01000100",
}

// recordVersion is what each client puts in the record-layer header of its
// first flight: browsers (BoringSSL/NSS) use DTLS 1.0 (feff) until the
// version is negotiated, pion/dtls uses 1.2 (fefd) from the start.
var recordVersion = map[string]uint16{"pion": versionDTLS12}

// ClientHello builds one datagram: record layer + handshake header + the
// fingerprint's body with a fresh random and the given cookie. msgSeq is
// both the handshake message sequence and the record sequence (0 for the
// first ClientHello, 1 for the one carrying the cookie), as a fresh client
// would number them.
func ClientHello(fingerprint string, cookie []byte, msgSeq uint16) ([]byte, error) {
	h, ok := Fingerprints[fingerprint]
	if !ok {
		return nil, errors.New("dtlsx: unknown fingerprint " + fingerprint)
	}
	body, err := hex.DecodeString(h)
	if err != nil || len(body) < 36 {
		return nil, errors.New("dtlsx: bad fingerprint")
	}
	rnd := make([]byte, 32)
	rand.Read(rnd)
	// version(2) random(32) sid_len(1)=0 cookie_len(1) cookie rest
	out := make([]byte, 0, len(body)+len(cookie))
	out = append(out, body[0:2]...)
	out = append(out, rnd...)
	out = append(out, 0, byte(len(cookie)))
	out = append(out, cookie...)
	out = append(out, body[36:]...)
	rv, ok := recordVersion[fingerprint]
	if !ok {
		rv = versionDTLS10
	}
	return recordWith(rv, uint64(msgSeq), handshake(hsClientHello, msgSeq, out)), nil
}

func handshake(typ byte, seq uint16, body []byte) []byte {
	h := make([]byte, 12, 12+len(body))
	h[0] = typ
	putUint24(h[1:], len(body))
	binary.BigEndian.PutUint16(h[4:], seq)
	putUint24(h[9:], len(body))
	return append(h, body...)
}

// record frames a server-side flight (record version 1.2, sequence per
// message type: HelloVerifyRequest 0, ServerHello 1, ServerHelloDone 2).
func record(fragment []byte) []byte {
	seq := uint64(0)
	if len(fragment) > 0 {
		switch fragment[0] {
		case hsServerHello:
			seq = 1
		case hsServerDone:
			seq = 2
		}
	}
	return recordWith(versionDTLS12, seq, fragment)
}

func recordWith(version uint16, seq uint64, fragment []byte) []byte {
	r := make([]byte, 13, 13+len(fragment))
	r[0] = contentHandshake
	binary.BigEndian.PutUint16(r[1:], version)
	binary.BigEndian.PutUint64(r[3:], seq&0xffffffffffff) // epoch 0 in the top 16 bits
	binary.BigEndian.PutUint16(r[11:], uint16(len(fragment)))
	return append(r, fragment...)
}

func putUint24(b []byte, v int) { b[0], b[1], b[2] = byte(v>>16), byte(v>>8), byte(v) }
func uint24(b []byte) int       { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// Message is one handshake message found in a datagram.
type Message struct {
	Type byte
	Seq  uint16
	Body []byte
}

// IsHandshake reports whether a datagram starts with a DTLS handshake record.
func IsHandshake(b []byte) bool {
	if len(b) < 25 || b[0] != contentHandshake {
		return false
	}
	v := binary.BigEndian.Uint16(b[1:])
	return v == versionDTLS12 || v == versionDTLS10
}

// Parse walks the handshake records of one datagram.
func Parse(b []byte) ([]Message, error) {
	var out []Message
	for len(b) > 0 {
		if len(b) < 13 {
			return out, errors.New("dtlsx: short record")
		}
		if b[0] != contentHandshake {
			return out, errors.New("dtlsx: not a handshake record")
		}
		l := int(binary.BigEndian.Uint16(b[11:]))
		if len(b) < 13+l {
			return out, errors.New("dtlsx: truncated record")
		}
		frag := b[13 : 13+l]
		b = b[13+l:]
		for len(frag) >= 12 {
			fl := uint24(frag[9:])
			if len(frag) < 12+fl {
				return out, errors.New("dtlsx: truncated fragment")
			}
			out = append(out, Message{Type: frag[0], Seq: binary.BigEndian.Uint16(frag[4:]), Body: frag[12 : 12+fl]})
			frag = frag[12+fl:]
		}
	}
	return out, nil
}

// ClientHelloInfo is what the server reads from a ClientHello.
type ClientHelloInfo struct {
	Cookie       []byte
	CipherSuites []uint16
	Extensions   []uint16
	Version      uint16
}

// ParseClientHello extracts cookie, cipher suites and extension ids.
func ParseClientHello(body []byte) (ClientHelloInfo, error) {
	var info ClientHelloInfo
	if len(body) < 36 {
		return info, errors.New("dtlsx: short ClientHello")
	}
	info.Version = binary.BigEndian.Uint16(body)
	p := 34
	sl := int(body[p])
	p += 1 + sl
	if len(body) < p+1 {
		return info, errors.New("dtlsx: short ClientHello")
	}
	cl := int(body[p])
	p++
	if len(body) < p+cl+2 {
		return info, errors.New("dtlsx: short ClientHello")
	}
	info.Cookie = append([]byte(nil), body[p:p+cl]...)
	p += cl
	csl := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+csl+1 {
		return info, errors.New("dtlsx: short ClientHello")
	}
	for i := 0; i+1 < csl; i += 2 {
		info.CipherSuites = append(info.CipherSuites, binary.BigEndian.Uint16(body[p+i:]))
	}
	p += csl
	cml := int(body[p])
	p += 1 + cml
	if len(body) >= p+2 {
		el := int(binary.BigEndian.Uint16(body[p:]))
		p += 2
		end := p + el
		if end > len(body) {
			end = len(body)
		}
		for p+4 <= end {
			t := binary.BigEndian.Uint16(body[p:])
			l := int(binary.BigEndian.Uint16(body[p+2:]))
			info.Extensions = append(info.Extensions, t)
			p += 4 + l
		}
	}
	return info, nil
}

// HelloVerifyRequest answers a cookie-less ClientHello.
func HelloVerifyRequest(cookie []byte) []byte {
	body := append([]byte{0xfe, 0xff, byte(len(cookie))}, cookie...)
	return record(handshake(hsHelloVerify, 0, body))
}

// ServerHello builds a ServerHello (+ ServerHelloDone in the same datagram)
// selecting cipher and echoing the WebRTC extensions a pion or browser
// server would: renegotiation_info, extended_master_secret, use_srtp,
// ec_point_formats. When withGroups is set, supported_groups is included as
// well: the pion quirk that a censor keyed on in 2021.
func ServerHello(cipher uint16, withGroups bool) []byte {
	rnd := make([]byte, 32)
	rand.Read(rnd)
	body := []byte{0xfe, 0xfd}
	body = append(body, rnd...)
	body = append(body, 0) // session id
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0) // compression
	var ext []byte
	ext = append(ext, 0xff, 0x01, 0x00, 0x01, 0x00)
	ext = append(ext, 0x00, 0x17, 0x00, 0x00)
	ext = append(ext, 0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x07, 0x00)
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)
	if withGroups {
		ext = append(ext, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	out := record(handshake(hsServerHello, 1, body))
	return append(out, record(handshake(hsServerDone, 2, nil))...)
}

// Kinds of message for callers that only need to know what came back.
const (
	TypeClientHello = hsClientHello
	TypeServerHello = hsServerHello
	TypeHelloVerify = hsHelloVerify
)

// CookieOf returns the cookie in a HelloVerifyRequest body.
func CookieOf(body []byte) []byte {
	if len(body) < 3 || len(body) < 3+int(body[2]) {
		return nil
	}
	return append([]byte(nil), body[3:3+int(body[2])]...)
}
