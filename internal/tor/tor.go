// Package tor builds the wire shapes of a Tor client talking to a relay's
// ORPort: the TLS ClientHello a C tor linked against OpenSSL 3 sends (no SNI,
// the fixed Firefox-derived cipher list from src/lib/tls/ciphers.inc, no
// session ticket), the relay-style link certificate (RSA 2048, CN
// "www.<random>.com" issued by "www.<random>.net", random start date), and
// the link-protocol cells of the in-protocol (v3+) handshake: VERSIONS,
// CERTS, AUTH_CHALLENGE, NETINFO, then CREATE_FAST / CREATED_FAST as the
// first circuit-level exchange. The probe never joins the Tor network; both
// ends are ours.
package tor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"regexp"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Link protocol cell commands.
const (
	CmdPadding       = 0
	CmdCreateFast    = 5
	CmdCreatedFast   = 6
	CmdVersions      = 7
	CmdNetinfo       = 8
	CmdVPadding      = 128
	CmdCerts         = 129
	CmdAuthChallenge = 130
)

const (
	// PayloadLen is the body of a fixed-length cell; with the 4-byte circuit
	// id of link protocol 4+ a fixed cell is 514 bytes on the wire.
	PayloadLen   = 509
	FixedCellLen = 4 + 1 + PayloadLen
)

// Versions is what a current tor client offers.
var Versions = []uint16{3, 4, 5}

// CipherSuites is the client list from src/lib/tls/ciphers.inc (TLS 1.2, in
// order) preceded by the three TLS 1.3 suites tor sets with
// SSL_set_ciphersuites. This list, together with the absence of SNI, is what
// makes a tor ClientHello recognisable.
var CipherSuites = []uint16{
	0x1301, 0x1303, 0x1302,
	0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
	0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV: OpenSSL appends it to every initial ClientHello
}

// ClientHelloSpec is the uTLS preset of that ClientHello: OpenSSL 3.0 client
// defaults minus the session ticket (tor sets SSL_OP_NO_TICKET) and without
// a server name. With tls12Only the hello offers TLS 1.2 at most (no
// supported_versions / psk_key_exchange_modes / key_share), which is the
// only way the relay certificate is on the wire in plaintext.
//
// A tor linked against OpenSSL 3.5+ additionally offers X25519MLKEM768 first
// and a hybrid key share; that shape is not reproduced here.
func ClientHelloSpec(tls12Only bool) *utls.ClientHelloSpec {
	suites := append([]uint16(nil), CipherSuites...)
	vmax := uint16(utls.VersionTLS13)
	if tls12Only {
		vmax = utls.VersionTLS12
		suites = suites[3:] // no TLS 1.3 suites in a 1.2-only hello
	}
	ext := []utls.TLSExtension{
		&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.X25519, utls.CurveP256, utls.CurveID(30), utls.CurveP521, utls.CurveP384,
			utls.CurveID(256), utls.CurveID(257), utls.CurveID(258), utls.CurveID(259), utls.CurveID(260),
		}},
		&utls.GenericExtension{Id: 22}, // encrypt_then_mac
		&utls.ExtendedMasterSecretExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
			0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
			0x0302, 0x0402, 0x0502, 0x0602,
		}},
	}
	if !tls12Only {
		ext = append(ext,
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
		)
	}
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         vmax,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         ext,
	}
}

// IsClientHello reports whether a ClientHello the server received has the
// tor shape: no server name, exactly the tor cipher list, no ALPN and the
// OpenSSL signature-algorithm list. The cipher list alone is not enough: tor
// copied it from Firefox, so a Firefox parrot without SNI has the same
// suites; Firefox, however, always offers ALPN and never ed448 / DSA.
func IsClientHello(chi *tls.ClientHelloInfo) bool {
	if chi == nil || chi.ServerName != "" || len(chi.SupportedProtos) != 0 {
		return false
	}
	got := chi.CipherSuites
	if n := len(got); n > 0 && got[n-1] == 0x00ff {
		got = got[:n-1]
	}
	want := CipherSuites[:len(CipherSuites)-1]
	if len(got) == len(want)-3 { // 1.2-only hello: no TLS 1.3 suites
		want = want[3:]
	}
	if len(got) != len(want) {
		return false
	}
	for i, s := range want {
		if got[i] != s {
			return false
		}
	}
	for _, s := range chi.SignatureSchemes {
		if s == 0x0808 { // ed448: OpenSSL default, absent from browsers and Go
			return true
		}
	}
	return false
}

// Link certificate lifetime bounds (tor: SSLKeyLifetime, random between the
// advertised minimum and maximum when unset).
const (
	minCertLifetime = 5 * 24 * time.Hour
	maxCertLifetime = 365 * 24 * time.Hour
)

var certNameRe = regexp.MustCompile(`^www\.[a-z2-7]{8,20}\.(com|net)$`)

func randomHostname(tld string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567" // base32, as tor's crypto_random_hostname
	n := 8 + mrand.Intn(13)
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "www." + string(b) + "." + tld
}

// GenerateLinkCert makes a relay-style link certificate: an RSA-2048 link
// key certified by a separate RSA identity key, subject "www.<random>.com",
// issuer "www.<random>.net", validity of random length starting at a random
// midnight in the past. This is the plaintext a DPI box sees in a TLS 1.2
// handshake with a relay (in TLS 1.3 the certificate is encrypted).
func GenerateLinkCert() (tls.Certificate, error) {
	linkKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The identity key that signs the link certificate is 1024-bit RSA in
	// tor (crypto_pk_generate_key default); the link key itself is 2048.
	idKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, err
	}
	lifetime := minCertLifetime + time.Duration(mrand.Int63n(int64(maxCertLifetime-minCertLifetime)))
	now := time.Now()
	earliest := now.Add(24*time.Hour - lifetime)
	start := earliest.Add(time.Duration(mrand.Int63n(int64(now.Sub(earliest)))))
	start = start.Truncate(24 * time.Hour)
	subject := randomHostname("com")
	issuer := randomHostname("net")
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	idSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	parent := &x509.Certificate{
		SerialNumber: idSerial,
		Subject:      pkix.Name{CommonName: issuer},
		Issuer:       pkix.Name{CommonName: issuer},
		NotBefore:    start,
		NotAfter:     start.Add(lifetime),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: subject},
		NotBefore:          start,
		NotAfter:           start.Add(lifetime),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &linkKey.PublicKey, idKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: linkKey, Leaf: leaf}, nil
}

// IsLinkCert reports whether a certificate has the relay link-cert shape.
func IsLinkCert(c *x509.Certificate) bool {
	return c != nil && certNameRe.MatchString(c.Subject.CommonName) && certNameRe.MatchString(c.Issuer.CommonName) &&
		c.Subject.CommonName != c.Issuer.CommonName
}

// VersionsCell is the first cell on a channel: circuit id 0 on two bytes
// (no version negotiated yet), command 7, a big-endian length and the
// offered versions.
func VersionsCell(vs []uint16) []byte {
	b := make([]byte, 5+2*len(vs))
	b[2] = CmdVersions
	binary.BigEndian.PutUint16(b[3:], uint16(2*len(vs)))
	for i, v := range vs {
		binary.BigEndian.PutUint16(b[5+2*i:], v)
	}
	return b
}

// IsVersionsCell reports whether b starts like a VERSIONS cell (possibly
// truncated: three bytes are enough to dispatch on).
func IsVersionsCell(b []byte) bool {
	if len(b) < 3 || b[0] != 0 || b[1] != 0 || b[2] != CmdVersions {
		return false
	}
	if len(b) >= 5 {
		n := int(binary.BigEndian.Uint16(b[3:]))
		return n%2 == 0 && n <= 64
	}
	return true
}

// ParseVersions returns the versions in a complete VERSIONS cell and the
// number of bytes it occupies; n == 0 when more bytes are needed.
func ParseVersions(b []byte) (vs []uint16, n int, err error) {
	if len(b) < 5 {
		return nil, 0, nil
	}
	if b[0] != 0 || b[1] != 0 || b[2] != CmdVersions {
		return nil, 0, errors.New("tor: not a VERSIONS cell")
	}
	l := int(binary.BigEndian.Uint16(b[3:]))
	if l%2 != 0 {
		return nil, 0, errors.New("tor: odd VERSIONS length")
	}
	if len(b) < 5+l {
		return nil, 0, nil
	}
	for i := 0; i < l; i += 2 {
		vs = append(vs, binary.BigEndian.Uint16(b[5+i:]))
	}
	return vs, 5 + l, nil
}

// Negotiate picks the highest common version, 0 when none.
func Negotiate(ours, theirs []uint16) uint16 {
	var best uint16
	for _, a := range ours {
		for _, b := range theirs {
			if a == b && a > best {
				best = a
			}
		}
	}
	return best
}

// VarCell frames a variable-length cell for link protocol 4+ (4-byte
// circuit id).
func VarCell(circ uint32, cmd byte, body []byte) []byte {
	b := make([]byte, 7+len(body))
	binary.BigEndian.PutUint32(b, circ)
	b[4] = cmd
	binary.BigEndian.PutUint16(b[5:], uint16(len(body)))
	copy(b[7:], body)
	return b
}

// FixedCell frames a fixed-length cell (body zero-padded to PayloadLen).
func FixedCell(circ uint32, cmd byte, body []byte) []byte {
	b := make([]byte, FixedCellLen)
	binary.BigEndian.PutUint32(b, circ)
	b[4] = cmd
	copy(b[5:], body)
	return b
}

// Cell is one parsed cell of link protocol 4+.
type Cell struct {
	Circ uint32
	Cmd  byte
	Body []byte
}

// ParseCell parses the next cell of link protocol 4+ from b. n == 0 means
// more bytes are needed.
func ParseCell(b []byte) (c Cell, n int, err error) {
	if len(b) < 5 {
		return c, 0, nil
	}
	c.Circ = binary.BigEndian.Uint32(b)
	c.Cmd = b[4]
	if c.Cmd == CmdVersions || c.Cmd >= 128 {
		if len(b) < 7 {
			return c, 0, nil
		}
		l := int(binary.BigEndian.Uint16(b[5:]))
		if len(b) < 7+l {
			return c, 0, nil
		}
		c.Body = b[7 : 7+l]
		return c, 7 + l, nil
	}
	if len(b) < FixedCellLen {
		return c, 0, nil
	}
	c.Body = b[5:FixedCellLen]
	return c, FixedCellLen, nil
}

// CertsCell has the shape of a relay's CERTS cell: an RSA identity cert, an
// Ed25519 identity→signing cert, a signing→TLS cert and an RSA→Ed25519
// cross-cert. The contents are random; nothing verifies them, only their
// types and sizes are those of a real relay.
func CertsCell() []byte {
	type ent struct {
		typ byte
		n   int
	}
	ents := []ent{{2, 864}, {4, 140}, {5, 140}, {7, 258}}
	body := []byte{byte(len(ents))}
	for _, e := range ents {
		body = append(body, e.typ)
		body = binary.BigEndian.AppendUint16(body, uint16(e.n))
		blob := make([]byte, e.n)
		rand.Read(blob)
		body = append(body, blob...)
	}
	return VarCell(0, CmdCerts, body)
}

// AuthChallengeCell: 32 random bytes and the two authentication methods.
func AuthChallengeCell() []byte {
	body := make([]byte, 32, 38)
	rand.Read(body)
	body = append(body, 0, 2, 0, 1, 0, 3)
	return VarCell(0, CmdAuthChallenge, body)
}

// NetinfoCell builds the fixed-length NETINFO cell.
func NetinfoCell(now time.Time, other net.IP, mine []net.IP) []byte {
	body := binary.BigEndian.AppendUint32(nil, uint32(now.Unix()))
	body = appendAddr(body, other)
	body = append(body, byte(len(mine)))
	for _, ip := range mine {
		body = appendAddr(body, ip)
	}
	return FixedCell(0, CmdNetinfo, body)
}

func appendAddr(b []byte, ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return append(append(b, 0x04, 4), v4...)
	}
	if v6 := ip.To16(); v6 != nil {
		return append(append(b, 0x06, 16), v6...)
	}
	return append(b, 0x04, 4, 0, 0, 0, 0)
}

// ParseNetinfo extracts the timestamp and the "other" address.
func ParseNetinfo(body []byte) (ts time.Time, other net.IP, err error) {
	if len(body) < 6 {
		return ts, nil, errors.New("tor: short NETINFO")
	}
	ts = time.Unix(int64(binary.BigEndian.Uint32(body)), 0)
	l := int(body[5])
	if len(body) < 6+l {
		return ts, nil, errors.New("tor: short NETINFO address")
	}
	if body[4] == 0x04 && l == 4 || body[4] == 0x06 && l == 16 {
		other = net.IP(append([]byte(nil), body[6:6+l]...))
	}
	return ts, other, nil
}

// CreateFastCell is the first circuit request a client sends: 20 random
// bytes of key material on a fresh circuit id (high bit set by the
// initiator in link protocol 4+).
func CreateFastCell(circ uint32) []byte {
	x := make([]byte, 20)
	rand.Read(x)
	return FixedCell(circ|0x80000000, CmdCreateFast, x)
}

// CreatedFastCell is the relay's answer: 20 bytes of key material and a
// 20-byte derivative key hash.
func CreatedFastCell(circ uint32) []byte {
	y := make([]byte, 40)
	rand.Read(y)
	return FixedCell(circ, CmdCreatedFast, y)
}

// String names a command for logs and details.
func CmdName(cmd byte) string {
	switch cmd {
	case CmdPadding:
		return "PADDING"
	case CmdCreateFast:
		return "CREATE_FAST"
	case CmdCreatedFast:
		return "CREATED_FAST"
	case CmdVersions:
		return "VERSIONS"
	case CmdNetinfo:
		return "NETINFO"
	case CmdVPadding:
		return "VPADDING"
	case CmdCerts:
		return "CERTS"
	case CmdAuthChallenge:
		return "AUTH_CHALLENGE"
	}
	return fmt.Sprintf("cmd%d", cmd)
}
