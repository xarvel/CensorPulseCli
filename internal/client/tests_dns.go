package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// dnsName builds <nonce>.<session>.<test>.probe.invalid so the server can
// correlate the query without any envelope.
func (c *Client) dnsName(a *Attempt) string {
	nonce := hex.EncodeToString(proto.RandomPayload(8))
	a.Nonce = nonce
	return nonce + "." + c.Session.SessionID + "." + a.TestID + "." + c.Zone()
}

// dnsSystem asks the machine's own resolver for a whoami name in the probe
// zone. It only makes sense when the server is authoritative for a real
// delegated zone; the answer proves which recursive resolver actually served
// the client and whether its content survived the resolver chain.
func (c *Client) dnsSystem(ctx context.Context, a *Attempt) *Attempt {
	nonce := hex.EncodeToString(proto.RandomPayload(8))
	a.Nonce = nonce
	name := dnsx.WhoamiLabel + "." + nonce + "." + c.Session.SessionID + "." + a.TestID + "." + c.Zone()
	a.Detail["qtype"] = "TXT"
	a.Detail["qname"] = name
	rctx, cancel := context.WithTimeout(ctx, c.attemptTimeout())
	defer cancel()
	a.mark("first_write")
	txts, err := net.DefaultResolver.LookupTXT(rctx, strings.TrimSuffix(name, "."))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsTimeout {
				return a.fail(OutcomeDNSTimeout, err)
			}
			if dnsErr.IsNotFound {
				a.Detail["rcode"] = "NXDOMAIN"
				return a.fail(OutcomeDNSRcode, err)
			}
			if dnsErr.IsTemporary {
				a.Detail["resolver_error"] = dnsErr.Err
				return a.fail(OutcomeDNSRcode, err) // SERVFAIL and friends: the recursor failed, nothing was substituted
			}
		}
		// No answer content to compare against: a resolver/library failure,
		// not a manipulated answer.
		a.Detail["resolver_error"] = err.Error()
		return a.fail(OutcomeInconclusive, err)
	}
	a.mark("first_byte")
	want := dnsx.ExpectedTXT(name)
	ok := false
	for _, t := range txts {
		if t == want {
			ok = true
		}
		if strings.HasPrefix(t, "recursor=") {
			a.Detail["recursor"] = strings.TrimPrefix(t, "recursor=")
		}
	}
	if !ok {
		if len(txts) > 0 {
			a.Detail["txt"] = txts[0]
		}
		return a.fail(OutcomeDNSMismatch, fmt.Errorf("system resolver returned a different answer"))
	}
	return a.ok()
}

func dnsType(v string) dnsmessage.Type {
	if v == "A" {
		return dnsmessage.TypeA
	}
	return dnsmessage.TypeTXT
}

func (c *Client) dnsVerify(a *Attempt, raw []byte, name string, t dnsmessage.Type, id uint16) *Attempt {
	ans, err := dnsx.ParseAnswer(raw)
	if err != nil {
		a.Detail["response_prefix"] = hex.EncodeToString(raw[:min(len(raw), 16)])
		return a.fail(OutcomeUnexpected, err)
	}
	if ans.ID != id {
		a.Detail["id_mismatch"] = "true"
	}
	a.Detail["rcode"] = ans.RCode.String()
	if ok, why := dnsx.Verify(ans, name, t); !ok {
		if len(ans.A) > 0 {
			a.Detail["a"] = net.IP(ans.A[0][:]).String()
		}
		if len(ans.TXT) > 0 {
			a.Detail["txt"] = ans.TXT[0]
		}
		if ans.RCode != dnsmessage.RCodeSuccess {
			return a.fail(OutcomeDNSRcode, fmt.Errorf("%s", why))
		}
		return a.fail(OutcomeDNSMismatch, fmt.Errorf("%s", why))
	}
	return a.ok()
}

// dnsUDP sends a padded query straight to the server on UDP.
func (c *Client) dnsUDP(ctx context.Context, a *Attempt, qtype string) *Attempt {
	name := c.dnsName(a)
	t := dnsType(qtype)
	id := uint16(binary.BigEndian.Uint16(proto.RandomPayload(2)))
	q, err := dnsx.BuildPaddedQuery(id, name, t, 300)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Detail["qtype"] = qtype
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	defer conn.Close()
	if _, err := conn.Write(q); err != nil {
		return a.fail(udpOutcome(err), err)
	}
	a.BytesOut = len(q)
	a.mark("first_write")
	// Read up to two answers: an injected response often races the real one.
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if udpOutcome(err) == OutcomePayloadTimeout {
			return a.fail(OutcomeDNSTimeout, err)
		}
		return a.fail(udpOutcome(err), err)
	}
	a.mark("first_byte")
	a.BytesIn = n
	first := append([]byte(nil), buf[:n]...)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n2, err2 := conn.Read(buf); err2 == nil && n2 > 0 {
		a.Detail["second_answer"] = "true"
		a.Detail["second_answer_sha256"] = hexSum(buf[:n2])
		if !bytes.Equal(buf[:n2], first) {
			a.Detail["answers_differ"] = "true"
		}
	}
	r := c.dnsVerify(a, first, name, t, id)
	if r.Outcome == OutcomeDNSMismatch && a.Detail["second_answer"] == "true" {
		r.Outcome = "dns_injected_race"
	}
	if r.Outcome == OutcomeOK && a.Detail["answers_differ"] == "true" {
		// The genuine answer came first, then a different one for the same
		// query: something on the path answered too, just slower.
		r.Outcome = "dns_injected_race"
		r.Error = "a second, different answer followed the genuine one"
	}
	return r
}

// dnsTrigger asks the probe's DNS port for the trigger name, which is outside
// the probe zone. The server refuses it (REFUSED, no records); any answer
// with records, or a second answer, came from the path.
func (c *Client) dnsTrigger(ctx context.Context, a *Attempt, host string) *Attempt {
	name := host
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	a.Detail["qtype"] = "A"
	a.Detail["qname"] = name
	if err := c.reserve(ctx, a, "udp", model.ParseDNS); err != nil {
		return a.fail(OutcomeServerError, err)
	}
	id := uint16(binary.BigEndian.Uint16(proto.RandomPayload(2)))
	q, err := dnsx.BuildPaddedQuery(id, name, dnsType("A"), 300)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	conn, err := c.udpConn(a)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	defer conn.Close()
	if _, err := conn.Write(q); err != nil {
		return a.fail(udpOutcome(err), err)
	}
	a.BytesOut = len(q)
	a.mark("first_write")
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if udpOutcome(err) == OutcomePayloadTimeout {
			return a.fail(OutcomeDNSTimeout, err)
		}
		return a.fail(udpOutcome(err), err)
	}
	a.mark("first_byte")
	a.BytesIn = n
	first := append([]byte(nil), buf[:n]...)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n2, err2 := conn.Read(buf); err2 == nil && n2 > 0 {
		a.Detail["second_answer"] = "true"
		if !bytes.Equal(buf[:n2], first) {
			a.Detail["answers_differ"] = "true"
		}
	}
	var p dnsmessage.Parser
	hdr, perr := p.Start(first)
	if perr != nil || hdr.ID != id {
		a.Detail["response_prefix"] = hex.EncodeToString(first[:min(len(first), 16)])
		return a.fail(OutcomeUnexpected, fmt.Errorf("not an answer to our query"))
	}
	a.Detail["rcode"] = hdr.RCode.String()
	p.SkipAllQuestions()
	answers, _ := p.AllAnswers()
	a.Detail["answer_count"] = strconv.Itoa(len(answers))
	for _, an := range answers {
		if r, ok := an.Body.(*dnsmessage.AResource); ok {
			a.Detail["injected_a"] = net.IP(r.A[:]).String()
		}
	}
	switch {
	case hdr.RCode == dnsmessage.RCodeRefused && len(answers) == 0 && a.Detail["answers_differ"] != "true":
		return a.ok()
	case a.Detail["second_answer"] == "true":
		return a.fail("dns_injected_race", fmt.Errorf("two answers for a name the server refuses"))
	default:
		return a.fail(OutcomeDNSMismatch, fmt.Errorf("rcode %s with %d records for a name the server refuses", hdr.RCode, len(answers)))
	}
}

// dnsTCP sends the query with 2-byte framing over TCP.
func (c *Client) dnsTCP(ctx context.Context, a *Attempt, qtype string) *Attempt {
	name := c.dnsName(a)
	t := dnsType(qtype)
	id := uint16(binary.BigEndian.Uint16(proto.RandomPayload(2)))
	q, err := dnsx.BuildQuery(id, name, t)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Detail["qtype"] = qtype
	conn, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer conn.Close()
	return c.dnsOverStream(conn, a, q, name, t, id)
}

func (c *Client) dnsOverStream(conn net.Conn, a *Attempt, q []byte, name string, t dnsmessage.Type, id uint16) *Attempt {
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	conn.SetWriteDeadline(time.Now().Add(c.attemptTimeout()))
	if _, err := conn.Write(framed); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesOut = len(framed)
	a.mark("first_write")
	conn.SetReadDeadline(time.Now().Add(c.attemptTimeout()))
	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.mark("first_byte")
	n := int(binary.BigEndian.Uint16(lenb[:]))
	if n == 0 || n > 4096 {
		return a.fail(OutcomeUnexpected, fmt.Errorf("bad dns length %d", n))
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	a.BytesIn = 2 + n
	return c.dnsVerify(a, raw, name, t, id)
}

// dnsDoT runs the query inside a pinned TLS session (RFC 7858).
func (c *Client) dnsDoT(ctx context.Context, a *Attempt, qtype string) *Attempt {
	name := c.dnsName(a)
	t := dnsType(qtype)
	id := uint16(binary.BigEndian.Uint16(proto.RandomPayload(2)))
	q, err := dnsx.BuildQuery(id, name, t)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Detail["qtype"] = qtype
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(c.attemptTimeout()))
	cfg := c.pinnedTLS("")
	cfg.NextProtos = []string{"dot"}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return a.fail(tlsOutcome(err), err)
	}
	a.mark("handshake")
	return c.dnsOverStream(tc, a, q, name, t, id)
}

// dnsDoH POSTs the query to the control port (RFC 8484).
func (c *Client) dnsDoH(ctx context.Context, a *Attempt, qtype string) *Attempt {
	name := c.dnsName(a)
	t := dnsType(qtype)
	id := uint16(binary.BigEndian.Uint16(proto.RandomPayload(2)))
	q, err := dnsx.BuildQuery(id, name, t)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	a.Detail["qtype"] = qtype
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL("/dns-query"), bytes.NewReader(q))
	req.Header.Set("Content-Type", "application/dns-message")
	a.mark("first_write")
	resp, err := c.http.Do(req)
	if err != nil {
		return a.fail(classifyNetErr(err, true), err)
	}
	defer resp.Body.Close()
	a.mark("first_byte")
	a.Detail["status"] = strconv.Itoa(resp.StatusCode)
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	a.BytesIn = len(raw)
	if resp.StatusCode != 200 {
		return a.fail(OutcomeUnexpected, fmt.Errorf("doh status %d", resp.StatusCode))
	}
	return c.dnsVerify(a, raw, name, t, id)
}
