package tor

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// The cell parsers read whatever the peer of a TLS session writes. They are
// incremental (n == 0 asks for more bytes), so besides "no panic" the
// property is that a parsed cell re-frames into exactly the bytes consumed.

func FuzzParseVersions(f *testing.F) {
	v := VersionsCell(Versions)
	f.Add(v)
	f.Add(v[:4])
	f.Add(append(VersionsCell(nil), 0xff))
	f.Add([]byte{0, 0, CmdVersions, 0xff, 0xfe}) // announces 65534 bytes of versions
	f.Add([]byte{0, 0, CmdVersions, 0, 3, 0, 3, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		IsVersionsCell(b)
		vs, n, err := ParseVersions(b)
		if err != nil || n == 0 {
			if len(vs) != 0 || n != 0 {
				t.Fatalf("partial result: vs=%v n=%d err=%v", vs, n, err)
			}
			return
		}
		if n > len(b) || !bytes.Equal(VersionsCell(vs), b[:n]) {
			t.Fatalf("VersionsCell(ParseVersions(b)) != b[:%d]\n b %x\n vs %v", n, b, vs)
		}
		Negotiate(Versions, vs)
	})
}

func FuzzParseCell(f *testing.F) {
	netinfo := NetinfoCell(time.Unix(1_800_000_000, 0), net.IPv4(203, 0, 113, 7), []net.IP{net.IPv4(198, 51, 100, 1)})
	f.Add(netinfo)
	f.Add(netinfo[:FixedCellLen-1])
	f.Add(CertsCell())
	f.Add(AuthChallengeCell())
	f.Add(CreateFastCell(1))
	f.Add(CreatedFastCell(1))
	f.Add(VarCell(0, CmdVPadding, nil))
	f.Add([]byte{0, 0, 0, 0, CmdCerts, 0xff, 0xff}) // variable cell announcing 65535 bytes
	f.Fuzz(func(t *testing.T, b []byte) {
		c, n, err := ParseCell(b)
		if err != nil {
			t.Fatalf("ParseCell has no error path today, got %v", err)
		}
		if n == 0 {
			return
		}
		var again []byte
		if c.Cmd == CmdVersions || c.Cmd >= 128 {
			again = VarCell(c.Circ, c.Cmd, c.Body)
		} else {
			again = FixedCell(c.Circ, c.Cmd, c.Body)
		}
		if n > len(b) || !bytes.Equal(again, b[:n]) {
			t.Fatalf("re-framed cell != b[:%d]\n b     %x\n again %x", n, b, again)
		}
		CmdName(c.Cmd)
		if c.Cmd == CmdNetinfo {
			ParseNetinfo(c.Body)
		}
	})
}

func FuzzParseNetinfo(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	for _, ip := range []net.IP{net.IPv4(203, 0, 113, 7), net.ParseIP("2001:db8::7"), nil} {
		c, _, _ := ParseCell(NetinfoCell(now, ip, []net.IP{ip}))
		f.Add(c.Body)
		f.Add(c.Body[:7])
	}
	f.Add([]byte{0, 0, 0, 0, 0x04, 0xff}) // address length past the end
	f.Fuzz(func(t *testing.T, body []byte) {
		ts, other, err := ParseNetinfo(body)
		if err != nil {
			return
		}
		if other != nil && len(other) != net.IPv4len && len(other) != net.IPv6len {
			t.Fatalf("address of %d bytes", len(other))
		}
		// Timestamp and address are the head of the body: rebuilding them
		// must give those bytes back. The builder writes a v4-mapped IPv6
		// address as IPv4, so that one form does not round-trip by design.
		if other != nil && !(len(other) == net.IPv6len && other.To4() != nil) {
			again := NetinfoCell(ts, other, nil)[5:]
			if head := 6 + len(other); !bytes.Equal(again[:head], body[:head]) {
				t.Fatalf("NetinfoCell(ParseNetinfo(body)) head\n body  %x\n again %x", body[:head], again[:head])
			}
		}
	})
}
