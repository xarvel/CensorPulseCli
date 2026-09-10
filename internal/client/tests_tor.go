package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/obfs4"
	"github.com/xarvel/CensorPulseCli/internal/tor"
)

// torOptions pick the two plaintext features a DPI box can key on in a
// vanilla Tor connection: the ClientHello shape and the relay-style
// certificate (visible in TLS 1.2; the probe forces 1.2 when the certificate
// is the variable so that it is on the wire).
type torOptions struct {
	TorHello bool // OpenSSL-3/tor ClientHello without SNI; else Go's without SNI
	TorCert  bool // relay-style link cert from the server; else the probe cert
	TLS13    bool // offer TLS 1.3 (certificate encrypted); default TLS 1.2 so that both features are on the wire
	Link     bool // after the handshake, CREATE_FAST/CREATED_FAST rounds (tor.link)
}

func (o torOptions) variant() string {
	h, c := "go-hello", "probe-cert"
	if o.TorHello {
		h = "tor-hello"
	}
	if o.TorCert {
		c = "tor-cert"
	}
	if o.TLS13 {
		return h + "+" + c + "@1.3"
	}
	return h + "+" + c
}

// torHandshake opens a Tor-shaped TLS connection and runs the link
// handshake: VERSIONS both ways, CERTS / AUTH_CHALLENGE / NETINFO from the
// server, NETINFO from us. With Link it continues with circuit requests.
func (c *Client) torHandshake(ctx context.Context, a *Attempt, o torOptions) *Attempt {
	a.Detail["sni"] = ""
	a.Detail["hello"] = strings.SplitN(o.variant(), "+", 2)[0]
	a.Detail["cert"] = strings.SplitN(o.variant(), "+", 2)[1]
	if err := c.reserve(ctx, a, "tcp", model.ParseTLS); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(c.attemptTimeout()))

	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		pin := base64.StdEncoding.EncodeToString(sum[:])
		if tor.IsLinkCert(cert) {
			a.Detail["server_cert"] = "tor"
		} else {
			a.Detail["server_cert"] = "probe"
		}
		want := c.Params.SPKIPin
		if o.TorCert {
			want = c.Params.TorSPKIPin
		}
		if want != "" && want != pin {
			return fmt.Errorf("spki pin mismatch: got %s want %s", pin, want)
		}
		return nil
	}
	var conn net.Conn
	// The version is fixed by the ClientHello itself (uTLS presets override
	// Config.MaxVersion), so the negotiated version is checked afterwards:
	// a 1.2 variant that came out as 1.3 would not have put the certificate
	// on the wire and would measure something else.
	wantVersion := uint16(tls.VersionTLS12)
	if o.TLS13 {
		wantVersion = tls.VersionTLS13
	}
	if o.TorHello {
		ucfg := &utls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: verify}
		uc := utls.UClient(raw, ucfg, utls.HelloCustom)
		if err := uc.ApplyPreset(tor.ClientHelloSpec(!o.TLS13)); err != nil {
			return a.fail(OutcomeServerError, err)
		}
		a.mark("first_write")
		if err := uc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		a.Detail["negotiated_version"] = tlsVersionName(uc.ConnectionState().Version)
		if uc.ConnectionState().Version != wantVersion {
			return a.fail(OutcomeServerError, fmt.Errorf("negotiated TLS %s, the variant needs %s", a.Detail["negotiated_version"], tlsVersionName(wantVersion)))
		}
		conn = uc
	} else {
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: wantVersion, VerifyPeerCertificate: verify} //nolint:gosec
		tc := tls.Client(raw, cfg)
		a.mark("first_write")
		if err := tc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		a.Detail["negotiated_version"] = tlsVersionName(tc.ConnectionState().Version)
		if tc.ConnectionState().Version != wantVersion {
			return a.fail(OutcomeServerError, fmt.Errorf("negotiated TLS %s, the variant needs %s", a.Detail["negotiated_version"], tlsVersionName(wantVersion)))
		}
		conn = tc
	}
	a.mark("handshake")

	// Link handshake.
	br := bufio.NewReaderSize(conn, 16<<10)
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	vc := tor.VersionsCell(tor.Versions)
	if _, err := conn.Write(vc); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut += len(vc)
	a.mark("link_first_write")
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	readMore := func() error {
		n, err := br.Read(tmp)
		if n > 0 && a.BytesIn == 0 {
			a.mark("first_byte")
		}
		buf = append(buf, tmp[:n]...)
		a.BytesIn += n
		return err
	}
	var theirs []uint16
	for {
		vs, n, err := tor.ParseVersions(buf)
		if err != nil {
			a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(len(buf), 16)])
			return a.fail(OutcomeUnexpected, err)
		}
		if n > 0 {
			theirs = vs
			buf = buf[n:]
			break
		}
		if err := readMore(); err != nil {
			return a.fail(classifyNetErr(err, true), err)
		}
	}
	v := tor.Negotiate(tor.Versions, theirs)
	a.Detail["link_version"] = strconv.Itoa(int(v))
	if v < 4 {
		return a.fail(OutcomeUnexpected, fmt.Errorf("no common link version in %v", theirs))
	}
	var cells []string
	for {
		cell, n, err := tor.ParseCell(buf)
		if err != nil {
			return a.fail(OutcomeUnexpected, err)
		}
		if n == 0 {
			if err := readMore(); err != nil {
				a.Detail["cells_recv"] = strings.Join(cells, ",")
				return a.fail(classifyNetErr(err, true), err)
			}
			continue
		}
		buf = buf[n:]
		cells = append(cells, tor.CmdName(cell.Cmd))
		if cell.Cmd == tor.CmdNetinfo {
			if ts, other, err := tor.ParseNetinfo(cell.Body); err == nil {
				a.Detail["netinfo_skew_s"] = strconv.FormatInt(int64(time.Since(ts).Seconds()), 10)
				if other != nil {
					a.Detail["netinfo_my_addr"] = other.String()
				}
			}
			break
		}
		if len(cells) > 8 {
			return a.fail(OutcomeUnexpected, fmt.Errorf("no NETINFO after %d cells", len(cells)))
		}
	}
	a.Detail["cells_recv"] = strings.Join(cells, ",")
	ni := tor.NetinfoCell(time.Now(), c.target.AsSlice(), nil)
	if _, err := conn.Write(ni); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut += len(ni)
	if !o.Link {
		return a.ok()
	}
	// Data phase: CREATE_FAST on a fresh circuit id, CREATED_FAST back.
	circ := uint32(0)
	return c.vpnDataLoop(a, func(i int, _ []byte) error {
		circ = uint32(i + 1)
		cell := tor.CreateFastCell(circ)
		conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
		if _, err := conn.Write(cell); err != nil {
			return err
		}
		a.BytesOut += len(cell)
		return nil
	}, func(deadline time.Time) (int, error) {
		conn.SetReadDeadline(deadline)
		for {
			cell, n, err := tor.ParseCell(buf)
			if err != nil {
				return 0, errModified
			}
			if n > 0 {
				buf = buf[n:]
				if cell.Cmd == tor.CmdCreatedFast {
					return len(cell.Body), nil
				}
				continue
			}
			if err := readMore(); err != nil {
				return 0, err
			}
		}
	}, func(i, size int) []byte { return nil })
}

// torDir sends the directory request a Tor client makes to a DirPort. The
// probe answers with a consensus-shaped body; a 200 with that body is the
// success.
func (c *Client) torDir(ctx context.Context, a *Attempt) *Attempt {
	if err := c.reserve(ctx, a, "tcp", model.ParseHTTP); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	path := "/tor/status-vote/current/consensus-microdesc.z"
	a.Detail["path"] = path
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nAccept-Encoding: deflate, gzip\r\n\r\n", path, c.tcpAddr(a.DstPort))
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write([]byte(req)); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = len(req)
	a.mark("first_write")
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.mark("first_byte")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		raw, _ := io.ReadAll(io.LimitReader(br, 256))
		a.Detail["response_prefix"] = strings.ToValidUTF8(string(raw[:min(len(raw), 64)]), "?")
		return a.fail(OutcomeUnexpected, err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	a.BytesIn = len(body)
	a.Detail["status"] = strconv.Itoa(resp.StatusCode)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "network-status-version 3") {
		a.Detail["body_prefix"] = strings.ToValidUTF8(string(body[:min(len(body), 96)]), "?")
		return a.fail(OutcomeModified, fmt.Errorf("status %d / body is not a consensus", resp.StatusCode))
	}
	return a.ok()
}

// obfs4Handshake sends a client request under the server's bridge identity
// and expects the server response; with session it then pushes framed
// random data through and expects it mirrored.
func (c *Client) obfs4Handshake(ctx context.Context, a *Attempt, session bool) *Attempt {
	rawID, err := base64.StdEncoding.DecodeString(c.Params.Obfs4Cert)
	if err != nil {
		return a.fail(OutcomeServerError, fmt.Errorf("server did not advertise an obfs4 identity"))
	}
	id, err := obfs4.ParseIdentity(rawID)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	if err := c.reserve(ctx, a, "tcp", model.ParseObfs4); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	req := obfs4.ClientRequest(id, time.Now())
	a.Detail["handshake_len"] = strconv.Itoa(len(req))
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write(req); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = len(req)
	a.mark("first_write")
	// The server answers after its quiet period; allow for it.
	deadline := time.Now().Add(c.attemptTimeout() + 1500*time.Millisecond)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 8192)
	var n int
	for {
		m, err := conn.Read(tmp)
		if m > 0 && len(buf) == 0 {
			a.mark("first_byte")
		}
		buf = append(buf, tmp[:m]...)
		a.BytesIn += m
		if k, ok := obfs4.FindServerResponse(buf, id, time.Now()); ok {
			n = k
			break
		}
		if err != nil {
			if len(buf) > 0 {
				a.Detail["response_prefix"] = hex.EncodeToString(buf[:min(len(buf), 16)])
				return a.fail(OutcomeUnexpected, fmt.Errorf("no valid obfs4 response in %d bytes: %w", len(buf), err))
			}
			return a.fail(classifyNetErr(err, true), err)
		}
		if len(buf) > obfs4.MaxHandshakeLen {
			return a.fail(OutcomeUnexpected, fmt.Errorf("no obfs4 mark in %d bytes", len(buf)))
		}
	}
	a.Detail["response_len"] = strconv.Itoa(n)
	a.mark("handshake")
	if !session {
		return a.ok()
	}
	buf = buf[n:]
	return c.vpnDataLoop(a, func(i int, p []byte) error {
		conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
		if _, err := conn.Write(p); err != nil {
			return err
		}
		a.BytesOut += len(p)
		return nil
	}, func(deadline time.Time) (int, error) {
		// mirrored bytes: wait for at least one frame's worth
		want := 34
		conn.SetReadDeadline(deadline)
		for len(buf) < want {
			m, err := conn.Read(tmp)
			buf = append(buf, tmp[:m]...)
			a.BytesIn += m
			if err != nil {
				return 0, err
			}
		}
		got := len(buf)
		buf = buf[:0]
		return got, nil
	}, func(i, size int) []byte { return obfs4.Frame(size) })
}
