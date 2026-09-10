package dest

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// waServerHello builds a server hello frame body with fields of the given
// lengths (ephemeral, static, payload); 0 leaves a field out.
func waServerHello(eph, static, payload int) []byte {
	field := func(n uint64, l int) []byte {
		if l == 0 {
			return nil
		}
		b := []byte{byte(n<<3 | 2)}
		for v := uint64(l); ; v >>= 7 {
			if v < 0x80 {
				b = append(b, byte(v))
				break
			}
			b = append(b, byte(v)|0x80)
		}
		return append(b, bytes.Repeat([]byte{0xab}, l)...)
	}
	inner := append(append(field(1, eph), field(2, static)...), field(3, payload)...)
	hdr := field(3, len(inner))
	return append(hdr[:len(hdr)-len(inner)], inner...)
}

func frame(body []byte) []byte {
	return append([]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestWhatsAppHelloLayout(t *testing.T) {
	a, b := WhatsAppHello(), WhatsAppHello()
	want := []byte{'W', 'A', 6, 3, 0, 0, 36, 0x12, 34, 0x0a, 32}
	if len(a) != len(want)+32 || !bytes.HasPrefix(a, want) {
		t.Fatalf("hello % x", a)
	}
	if bytes.Equal(a[len(want):], b[len(want):]) {
		t.Fatal("two hellos carry the same ephemeral key")
	}
}

func TestReadWhatsAppHello(t *testing.T) {
	h, err := ReadWhatsAppHello(bytes.NewReader(frame(waServerHello(32, 48, 257))))
	if err != nil || h != (WhatsAppServerHello{32, 48, 257}) {
		t.Fatalf("real server hello: %v %v", h, err)
	}
	for name, reply := range map[string][]byte{
		"block page":         []byte("HTTP/1.1 403 Forbidden\r\n\r\n"),
		"no server hello":    frame([]byte{0x12, 2, 0x0a, 0}),
		"short ephemeral":    frame(waServerHello(16, 48, 257)),
		"no payload":         frame(waServerHello(32, 48, 0)),
		"garbage in a frame": frame([]byte{0xff, 0xff, 0xff}),
		"empty frame":        {0, 0, 0},
	} {
		if _, err := ReadWhatsAppHello(bytes.NewReader(reply)); !errors.Is(err, ErrNotWhatsApp) {
			t.Errorf("%s: %v, want ErrNotWhatsApp", name, err)
		}
	}
	if _, err := ReadWhatsAppHello(bytes.NewReader(frame(waServerHello(32, 48, 257))[:40])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cut frame: %v, want the I/O error", err)
	}
}

func TestParseProto(t *testing.T) {
	got, err := Parse(strings.NewReader("chat.example category=messenger proto=whatsapp\n"))
	if err != nil || len(got) != 1 || got[0].Proto != ProtoWhatsApp {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Parse(strings.NewReader("chat.example proto=mtproto\n")); err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("unknown proto: %v", err)
	}
	for _, tg := range Default() {
		if tg.Domain == "g.whatsapp.net" && tg.Proto != ProtoWhatsApp {
			t.Fatalf("the WhatsApp gateway must be probed with its own handshake, not TLS: %+v", tg)
		}
	}
}
