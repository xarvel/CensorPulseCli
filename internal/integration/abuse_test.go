package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/dnsx"
)

func udpSilent(t *testing.T, port int, payload []byte, what string) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(payload)
	c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, err := c.Read(buf); err == nil {
		t.Errorf("%s on udp/%d: got %d bytes back without a reservation", what, port, n)
	}
}

// TestNoReflectionWithoutReservation: nothing unreserved is answered on UDP.
func TestNoReflectionWithoutReservation(t *testing.T) {
	startServer(t)
	garbage := append([]byte{0x05}, make([]byte, 19)...)
	rand.Read(garbage[1:])
	udpSilent(t, udpA, garbage, "random datagram")
	ovpn := append([]byte{7 << 3}, make([]byte, 13)...)
	udpSilent(t, udpB, ovpn, "openvpn reset")
	wgShaped := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	udpSilent(t, udpC, wgShaped, "wireguard-shaped initiation")
	quicShaped := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 1195)...)
	udpSilent(t, udpA, quicShaped, "quic initial-shaped datagram")
	// An envelope without a valid cookie must also stay silent.
	badEnv := append([]byte("CP1\x01\x01\x01"), make([]byte, 80)...)
	udpSilent(t, udpA, badEnv, "envelope with bogus cookie")
}

// TestDNSIsNotARecursiveResolver and answers never exceed the query on UDP.
func TestDNSNoRecursionNoAmplification(t *testing.T) {
	startServer(t)
	q, _ := dnsx.BuildQuery(7, "example.com.", dnsmessage.TypeA)
	c, _ := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	defer c.Close()
	c.Write(q)
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("no answer to out-of-zone query")
	}
	ans, _ := dnsx.ParseAnswer(buf[:n])
	if ans.RCode != dnsmessage.RCodeRefused || len(ans.A) != 0 {
		t.Errorf("out-of-zone query was not refused: %+v", ans)
	}
	// Small in-zone query: the answer must be truncated to stay <= query size.
	small, _ := dnsx.BuildQuery(8, dnsx.QueryName("aaaaaaaaaaaaaaaa", "dns.udp"), dnsmessage.TypeTXT)
	c.Write(small)
	n, err = c.Read(buf)
	if err != nil {
		t.Fatal("no answer to small query")
	}
	if n > len(small) {
		t.Errorf("amplification: query %dB, answer %dB", len(small), n)
	}
	if flags := binary.BigEndian.Uint16(buf[2:]); flags&0x0200 == 0 {
		t.Errorf("expected TC bit on the bounded answer")
	}
	// Padded query gets the full answer.
	padded, _ := dnsx.BuildPaddedQuery(9, dnsx.QueryName("aaaaaaaaaaaaaaaa", "dns.udp"), dnsmessage.TypeTXT, 300)
	c.Write(padded)
	n, _ = c.Read(buf)
	ans, _ = dnsx.ParseAnswer(buf[:n])
	if ok, why := dnsx.Verify(ans, dnsx.QueryName("aaaaaaaaaaaaaaaa", "dns.udp"), dnsmessage.TypeTXT); !ok {
		t.Errorf("padded query not answered correctly: %s", why)
	}
	if n > len(padded) {
		t.Errorf("padded: query %dB, answer %dB", len(padded), n)
	}
}

// TestHTTPIsNotAProxy: absolute-URI and CONNECT requests are not relayed.
func TestHTTPIsNotAProxy(t *testing.T) {
	startServer(t)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpA))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, _ := io.ReadAll(c)
	if !bytes.Contains(resp, []byte("\"magic\":\"CP1\"")) {
		t.Errorf("absolute-URI request should get the local echo, got %q", resp)
	}
	if bytes.Contains(resp, []byte("Example Domain")) {
		t.Errorf("request was proxied to example.com")
	}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest(http.MethodConnect, fmt.Sprintf("https://127.0.0.1:%d/", ctrlPort), nil)
	req.Host = "example.com:443"
	r, err := hc.Do(req)
	if err == nil {
		defer r.Body.Close()
		if r.StatusCode == 200 {
			t.Errorf("CONNECT on the control port answered 200")
		}
	}
}

// TestSessionRateLimit: the per-IP session limit is enforced.
func TestSessionRateLimit(t *testing.T) {
	startServer(t) // 50 sessions/min in the test config
	ctx := context.Background()
	var lastErr error
	for i := 0; i < 55; i++ {
		c, _ := client.New(client.Options{Target: "127.0.0.1", ControlPort: ctrlPort, Timeout: 2 * time.Second})
		if err := c.Bootstrap(ctx); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "429") {
		t.Errorf("expected a 429 after the session limit, got %v", lastErr)
	}
}

// TestTokenScope: a token cannot read another session's observations.
func TestTokenScope(t *testing.T) {
	startServer(t)
	ctx := context.Background()
	a, _ := client.New(client.Options{Target: "127.0.0.1", ControlPort: ctrlPort, Timeout: 2 * time.Second})
	b, _ := client.New(client.Options{Target: "127.0.0.1", ControlPort: ctrlPort, Timeout: 2 * time.Second})
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/v1/session/%s/observations", ctrlPort, b.Session.SessionID), nil)
	req.Header.Set("Authorization", "Bearer "+a.Session.Token)
	r, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-session read returned %d", r.StatusCode)
	}
}
