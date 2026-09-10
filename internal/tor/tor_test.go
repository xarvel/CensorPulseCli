package tor

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestVersionsRoundTrip(t *testing.T) {
	b := VersionsCell(Versions)
	if !IsVersionsCell(b) || !IsVersionsCell(b[:3]) {
		t.Fatal("VERSIONS cell not recognised")
	}
	vs, n, err := ParseVersions(append(b, 0xff))
	if err != nil || n != len(b) || len(vs) != 3 || vs[2] != 5 {
		t.Fatalf("parse: %v %d %v", err, n, vs)
	}
	if v := Negotiate(Versions, []uint16{3, 4}); v != 4 {
		t.Fatalf("negotiate: %d", v)
	}
	if _, n, _ := ParseVersions(b[:4]); n != 0 {
		t.Fatal("truncated cell must need more bytes")
	}
}

func TestCellsParse(t *testing.T) {
	stream := append(CertsCell(), AuthChallengeCell()...)
	stream = append(stream, NetinfoCell(time.Now(), net.IPv4(203, 0, 113, 7), []net.IP{net.IPv4(198, 51, 100, 1)})...)
	stream = append(stream, CreateFastCell(1)...)
	var cmds []byte
	for len(stream) > 0 {
		c, n, err := ParseCell(stream)
		if err != nil || n == 0 {
			t.Fatalf("parse: %v n=%d", err, n)
		}
		cmds = append(cmds, c.Cmd)
		if c.Cmd == CmdNetinfo {
			ts, other, err := ParseNetinfo(c.Body)
			if err != nil || !other.Equal(net.IPv4(203, 0, 113, 7)) || time.Since(ts) > time.Minute {
				t.Fatalf("netinfo: %v %v %v", err, other, ts)
			}
		}
		if c.Cmd == CmdCreateFast && c.Circ != 1|0x80000000 {
			t.Fatalf("create_fast circ %x", c.Circ)
		}
		stream = stream[n:]
	}
	if string(cmds) != string([]byte{CmdCerts, CmdAuthChallenge, CmdNetinfo, CmdCreateFast}) {
		t.Fatalf("cells %v", cmds)
	}
}

func TestLinkCertShape(t *testing.T) {
	c, err := GenerateLinkCert()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !IsLinkCert(leaf) {
		t.Fatalf("not a link cert: %s / %s", leaf.Subject.CommonName, leaf.Issuer.CommonName)
	}
	if leaf.NotBefore.After(time.Now()) || leaf.NotAfter.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("validity %s..%s", leaf.NotBefore, leaf.NotAfter)
	}
	if !leaf.NotBefore.Equal(leaf.NotBefore.Truncate(24 * time.Hour)) {
		t.Fatal("start should be at a midnight")
	}
}

func TestIsClientHelloRejectsFirefoxShape(t *testing.T) {
	tor := &tls.ClientHelloInfo{CipherSuites: CipherSuites, SignatureSchemes: []tls.SignatureScheme{0x0403, 0x0808}}
	if !IsClientHello(tor) {
		t.Fatal("tor hello not recognised")
	}
	ff := &tls.ClientHelloInfo{CipherSuites: CipherSuites, SupportedProtos: []string{"h2", "http/1.1"}, SignatureSchemes: []tls.SignatureScheme{0x0403}}
	if IsClientHello(ff) {
		t.Fatal("firefox-shaped hello (ALPN, no ed448) must not count as tor")
	}
	sni := &tls.ClientHelloInfo{ServerName: "x", CipherSuites: CipherSuites, SignatureSchemes: []tls.SignatureScheme{0x0808}}
	if IsClientHello(sni) {
		t.Fatal("hello with SNI must not count as tor")
	}
}
