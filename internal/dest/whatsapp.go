package dest

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocols a target's address can speak instead of web TLS (Target.Proto).
// The transport layers then run that protocol's own opening exchange
// (dest.proto) in place of the TLS handshakes: a TLS ClientHello is not what
// such a server expects, and it refuses one on every network, so the SNI
// differential there measures the server, not the path.
const (
	// ProtoWhatsApp is the WhatsApp chat gateway (g.whatsapp.net, :443 and
	// :5222): the clients open a Noise handshake on plain TCP, and the
	// server resets a TLS ClientHello within a round trip.
	ProtoWhatsApp = "whatsapp"
)

// Protos lists the values Target.Proto accepts.
var Protos = []string{ProtoWhatsApp}

func knownProto(p string) bool {
	for _, k := range Protos {
		if k == p {
			return true
		}
	}
	return false
}

// The WhatsApp chat handshake as the clients open it (whatsmeow's
// socket.WAConnHeader and waWa6.HandshakeMessage): a four-byte prologue, "WA"
// then the protocol magic 6 and the dictionary version 3, then frames of a
// 3-byte big-endian length and a protobuf body. The client's first frame is
// HandshakeMessage{clientHello (2): {ephemeral (1): 32 bytes}}, its Curve25519
// public key; the server answers HandshakeMessage{serverHello (3): {ephemeral
// (1): 32 bytes, static (2): its encrypted static key, payload (3): its
// encrypted certificate}}. Any 32 bytes are a valid X25519 public key, so the
// hello needs no key pair: the measurement stops at the server's hello.
var waPrologue = []byte{'W', 'A', 6, 3}

// waMaxFrame bounds the reply: a server hello is a few hundred bytes.
const waMaxFrame = 64 << 10

// WhatsAppHello returns the client's opening bytes: the prologue and a
// ClientHello frame with a fresh random ephemeral key.
func WhatsAppHello() []byte {
	eph := make([]byte, 32)
	rand.Read(eph) //nolint:errcheck // crypto/rand.Read never returns an error
	inner := append([]byte{0x0a, byte(len(eph))}, eph...)
	msg := append([]byte{0x12, byte(len(inner))}, inner...)
	out := append([]byte(nil), waPrologue...)
	out = append(out, byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg)))
	return append(out, msg...)
}

// WhatsAppServerHello is the shape of a server hello: the length of each field.
type WhatsAppServerHello struct {
	Ephemeral, Static, Payload int
}

func (h WhatsAppServerHello) String() string {
	return fmt.Sprintf("ephemeral=%d static=%d payload=%d", h.Ephemeral, h.Static, h.Payload)
}

// ErrNotWhatsApp is a reply that is not a WhatsApp server hello: something
// else answered the client hello (a block page, a proxy).
var ErrNotWhatsApp = errors.New("the reply is not a WhatsApp server hello")

// ReadWhatsAppHello reads one frame from r and parses it as the server hello.
// An I/O error is returned as is (it is the path's outcome); a frame that is
// not a server hello wraps ErrNotWhatsApp.
func ReadWhatsAppHello(r io.Reader) (WhatsAppServerHello, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return WhatsAppServerHello{}, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if n == 0 || n > waMaxFrame {
		return WhatsAppServerHello{}, fmt.Errorf("%w: frame length %d (first bytes %q)", ErrNotWhatsApp, n, hdr[:])
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return WhatsAppServerHello{}, err
	}
	return ParseWhatsAppHello(body)
}

// ParseWhatsAppHello parses a frame body as HandshakeMessage and requires a
// serverHello with a 32-byte ephemeral key, a static key and a payload.
func ParseWhatsAppHello(body []byte) (WhatsAppServerHello, error) {
	var h WhatsAppServerHello
	found := false
	err := protoFields(body, func(field uint64, v []byte) error {
		if field != 3 {
			return nil
		}
		found = true
		return protoFields(v, func(f uint64, b []byte) error {
			switch f {
			case 1:
				h.Ephemeral = len(b)
			case 2:
				h.Static = len(b)
			case 3:
				h.Payload = len(b)
			}
			return nil
		})
	})
	switch {
	case err != nil:
		return h, fmt.Errorf("%w: %v", ErrNotWhatsApp, err)
	case !found:
		return h, fmt.Errorf("%w: no serverHello in a %d-byte frame", ErrNotWhatsApp, len(body))
	case h.Ephemeral != 32 || h.Static == 0 || h.Payload == 0:
		return h, fmt.Errorf("%w: serverHello %s", ErrNotWhatsApp, h)
	}
	return h, nil
}

// protoFields walks the fields of a protobuf message, handing fn the
// length-delimited ones; varints are skipped, other wire types are an error
// (HandshakeMessage has none).
func protoFields(b []byte, fn func(field uint64, v []byte) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errors.New("malformed field key")
		}
		b = b[n:]
		switch key & 7 {
		case 0:
			if _, n = binary.Uvarint(b); n <= 0 {
				return errors.New("malformed varint")
			}
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return errors.New("malformed length")
			}
			v := b[n : n+int(l)]
			b = b[n+int(l):]
			if err := fn(key>>3, v); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected wire type %d", key&7)
		}
	}
	return nil
}
