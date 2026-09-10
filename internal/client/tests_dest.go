package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dest"
)

// The dest.* family visits real destinations instead of the probe server:
// how the network treats the sites people actually open. It has no server
// half, so every attempt's merged result is its own outcome, and the
// classifier only pairs a failing cell with a control measured the same way.
//
// Per target: dest.dns (system resolver against three DoH resolvers, with
// the disagreement verified by connecting to the system address), dest.tcp
// (:443 on the trusted address), dest.tls (the real name, a decoy name and
// no name at all on that same address: the SNI differential), dest.http
// (GET / after a clean handshake, for services that refuse a region with
// 451). Family controls: dest.nxdomain (a fresh .invalid name must not
// resolve) and dest.tcp anycast (1.1.1.1 / 1.0.0.1 / 9.9.9.9 on :443).

// DestPort is the port every transport-layer dest test uses.
const DestPort = 443

// DestTests lists the family's test ids in catalog order.
var DestTests = []string{"dest.dns", "dest.nxdomain", "dest.tcp", "dest.tls", "dest.http"}

// IsDestTest reports whether id belongs to the family.
func IsDestTest(id string) bool { return strings.HasPrefix(id, "dest.") }

// destResolution is what the DNS layer learned about one target, shared by
// the transport layers of the same target across rounds.
type destResolution struct {
	ips    []netip.Addr // prioritized: the first one is the address every layer uses
	source string       // trusted|system|fixed|none
}

type destState struct {
	mu       sync.Mutex
	resolved map[string]*destResolution
	hc       *http.Client // DoH and dest.http share the transport (system roots, real verification)
	once     sync.Once
}

// destTargets returns the catalog in use.
func (c *Client) destTargets() []dest.Target {
	if len(c.opt.Targets) > 0 {
		return c.opt.Targets
	}
	return dest.Default()
}

// destHTTP is a client with system roots and the scan's local address, for
// the DoH resolvers and the application-layer check. It is not the pinned
// control-plane client.
func (c *Client) destHTTP() *http.Client {
	c.dest.once.Do(func() {
		tr := &http.Transport{
			DialContext:           c.dialer().DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   c.opt.Timeout,
			ResponseHeaderTimeout: c.opt.Timeout,
			MaxIdleConns:          8,
			IdleConnTimeout:       30 * time.Second,
		}
		c.dest.hc = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		}}
	})
	return c.dest.hc
}

// systemLookup asks the machine's resolver (or the platform hook the
// embedder supplied) for every address of host.
func (c *Client) systemLookup(ctx context.Context, host string) dest.SystemResult {
	ctx, cancel := context.WithTimeout(ctx, c.attemptTimeout())
	defer cancel()
	var ips []netip.Addr
	var err error
	if c.opt.SystemResolver != nil {
		ips, err = c.opt.SystemResolver(ctx, host)
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsNotFound:
				return dest.SystemResult{RCode: "NXDOMAIN"}
			case dnsErr.IsTimeout:
				return dest.SystemResult{RCode: "TIMEOUT", Err: dnsErr.Err}
			}
			return dest.SystemResult{RCode: "ERROR", Err: dnsErr.Err}
		}
		if ctx.Err() != nil {
			return dest.SystemResult{RCode: "TIMEOUT", Err: err.Error()}
		}
		return dest.SystemResult{RCode: "ERROR", Err: err.Error()}
	}
	return dest.SystemResult{IPs: dest.Unique(ips), RCode: "NOERROR"}
}

// destResolve returns the cached resolution of a target, resolving it once
// when no dest.dns attempt has run yet (plans run in random order).
func (c *Client) destResolve(ctx context.Context, t dest.Target) *destResolution {
	c.dest.mu.Lock()
	if r, ok := c.dest.resolved[t.Domain]; ok {
		c.dest.mu.Unlock()
		return r
	}
	c.dest.mu.Unlock()
	// Two layers of one site may get here at once (plans run in random
	// order, in parallel): whichever stored first wins for both, so that
	// every layer is on the same address.
	return c.destStore(t, c.resolveTarget(ctx, t, nil))
}

// destStore records a resolution and returns the one in force: the first
// that produced addresses, for the whole scan (the SNI differential needs
// every layer on one address).
func (c *Client) destStore(t dest.Target, r *destResolution) *destResolution {
	c.dest.mu.Lock()
	defer c.dest.mu.Unlock()
	if c.dest.resolved == nil {
		c.dest.resolved = map[string]*destResolution{}
	}
	if prev, ok := c.dest.resolved[t.Domain]; ok && len(prev.ips) > 0 {
		return prev
	}
	c.dest.resolved[t.Domain] = r
	return r
}

// resolveTarget performs the DNS layer. When a is non-nil the details and
// outcome are recorded on it (the dest.dns attempt); otherwise it only feeds
// the cache.
func (c *Client) resolveTarget(ctx context.Context, t dest.Target, a *Attempt) *destResolution {
	fixed := dest.Prioritize(t.Fixed())
	if t.SkipDNS {
		return &destResolution{ips: fixed, source: "fixed"}
	}
	name := t.QueryName()
	timeout := c.attemptTimeout()
	var sys dest.SystemResult
	var answers []dest.DoHAnswer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sys = c.systemLookup(ctx, name) }()
	go func() { defer wg.Done(); answers = dest.ResolveTrusted(ctx, c.destHTTP(), name, timeout) }()
	wg.Wait()
	trusted := dest.TrustedConsensus(answers)
	cmp := dest.Compare(sys, trusted)
	ips, source := dest.ProbeAddrs(sys, trusted)
	if len(fixed) > 0 {
		ips = dest.Prioritize(append(append([]netip.Addr(nil), fixed...), ips...))
		if source == "none" {
			source = "fixed"
		}
	}
	res := &destResolution{ips: ips, source: source}
	if a == nil {
		return res
	}
	a.mark("first_byte")
	a.Detail["qname"] = name
	a.Detail["system_rcode"] = sys.RCode
	a.Detail["system_ips"] = dest.Strings(sys.IPs)
	if sys.Err != "" {
		a.Detail["system_error"] = sys.Err
	}
	a.Detail["trusted_rcode"] = trusted.RCode
	a.Detail["trusted_ips"] = dest.Strings(trusted.IPs)
	a.Detail["resolvers"] = trusted.Note
	a.Detail["probe_source"] = source
	if cmp.Note != "" {
		a.Detail["note"] = cmp.Note
	}
	switch {
	case cmp.Tampered:
		a.Detail["tamper"] = cmp.Reason
		a.fail(OutcomeDNSMismatch, errors.New(cmp.Note))
	case (trusted.RCode == "ERROR" || trusted.RCode == "OTHER") && len(trusted.IPs) == 0:
		// Every DoH resolver failed or answered SERVFAIL/REFUSED: nothing to
		// compare against. The transport layers go on with the system answers.
		a.fail(OutcomeInconclusive, fmt.Errorf("no usable trusted answer (%s)", trusted.RCode))
	case sys.RCode == "TIMEOUT":
		a.fail(OutcomeDNSTimeout, errors.New("system resolver timed out while the trusted resolvers answered"))
	case sys.RCode == "ERROR":
		a.fail(OutcomeInconclusive, fmt.Errorf("system resolver error: %s", sys.Err))
	case trusted.RCode == "NXDOMAIN" && len(sys.IPs) == 0:
		a.Detail["rcode"] = "NXDOMAIN"
		a.fail(OutcomeDNSRcode, errors.New("NXDOMAIN"))
	case cmp.Disagree:
		c.verifyDisagreement(ctx, t, sys, ips, a)
	default:
		a.ok()
	}
	return res
}

// verifyDisagreement settles "system and trusted answers differ": connect
// to the address the user's apps would use and ask whether it serves the
// name (a handshake with a certificate that verifies for it). If it does
// not while the trusted address does, the system answer is a sinkhole
// (poisoning: a block page terminating TLS with its own certificate does
// not serve); if it does, the disagreement is CDN geo-DNS.
func (c *Client) verifyDisagreement(ctx context.Context, t dest.Target, sys dest.SystemResult, trusted []netip.Addr, a *Attempt) {
	sysIPs := dest.Prioritize(sys.IPs)
	if len(sysIPs) == 0 || len(trusted) == 0 {
		a.ok()
		return
	}
	trustedIP := trusted[0]
	// Like with like: an address of the trusted one's family when the system
	// answer has one (a v6-only system answer on a host without IPv6 is not
	// a sinkhole).
	sysIP := sysIPs[0]
	for _, ip := range sysIPs {
		if ip.Is4() == trustedIP.Is4() {
			sysIP = ip
			break
		}
	}
	a.Detail["verify_ip"] = sysIP.String()
	sysOK, sysChain, sysWhy := c.destServes(ctx, t, sysIP)
	trOK, trChain, trWhy := c.destServes(ctx, t, trustedIP)
	a.Detail["verify_system"], a.Detail["verify_trusted"] = sysWhy, trWhy
	// The system address serves when its handshake completes with a
	// certificate that verifies for the name; a chain that fails on the
	// trusted address as well is this host's root store, not a sinkhole.
	sysServes := sysOK && (sysChain == "true" || (trOK && trChain != "true"))
	// The trusted address serves when it verifies, or when it at least
	// completes the handshake the system address could not.
	trServes := trOK && (trChain == "true" || !sysOK)
	switch {
	case sysServes:
		a.Detail["note"] = "system and trusted resolvers disagree but the system address serves the name: CDN geo-DNS"
		a.ok()
	case trServes:
		// Only a working trusted address makes a failing system address a
		// poisoning signature rather than a broken site.
		a.Detail["tamper"] = "system_address_fails"
		a.Detail["note"] = fmt.Sprintf("system address %s does not serve the name (%s) while trusted address %s does (%s): poisoning", sysIP, sysWhy, trustedIP, trWhy)
		a.fail(OutcomeDNSMismatch, errors.New(a.Detail["note"]))
	default:
		a.Detail["note"] = fmt.Sprintf("neither the system nor the trusted address serves the name (%s / %s): not a resolver signal", sysWhy, trWhy)
		a.ok()
	}
}

// destServes tries ip for the target: :443, then (unless the target skips
// TLS) a handshake with the real name. It reports whether the handshake
// completed, the chain check ("true" or the reason it does not verify; "true"
// for a TLS-less target) and how far it got (tcp:<outcome>, tls:<outcome>,
// cert:<reason>, tls:ok).
func (c *Client) destServes(ctx context.Context, t dest.Target, ip netip.Addr) (handshake bool, chain, why string) {
	out, conn := c.destConnect(ctx, ip, 0)
	if out != OutcomeOK {
		return false, "", "tcp:" + out
	}
	defer conn.Close()
	if t.SkipTLS {
		return true, "true", "tcp:ok"
	}
	out, chain = c.destHandshakeOn(ctx, conn, t.ServerName(), nil)
	if out != OutcomeOK {
		return false, "", "tls:" + out
	}
	if chain != "true" {
		return true, chain, "cert:" + chain
	}
	return true, chain, "tls:ok"
}

// destDNS is the dest.dns attempt.
func (c *Client) destDNS(ctx context.Context, a *Attempt, t dest.Target) *Attempt {
	c.destNote(a, t)
	a.mark("first_write")
	res := c.resolveTarget(ctx, t, a)
	c.destStore(t, res)
	return a
}

func (c *Client) destNote(a *Attempt, t dest.Target) {
	a.Detail["domain"] = t.Domain
	a.Detail["category"] = string(t.Category)
	if t.Label != "" {
		a.Detail["label"] = t.Label
	}
	for i, x := range c.destTargets() {
		if x.Domain == t.Domain {
			a.Detail["order"] = strconv.Itoa(i) // catalog position, for the per-site summary
			break
		}
	}
}

// destNXDomain is the family's resolver control: a fresh name under the
// reserved .invalid TLD must be NXDOMAIN on both sides.
func (c *Client) destNXDomain(ctx context.Context, a *Attempt) *Attempt {
	name := dest.NXDomainName()
	a.Detail["qname"] = name
	a.mark("first_write")
	// Rooted for the system resolver: a search list with a wildcard domain
	// must not turn the control into a false hijack. An embedder's hook gets
	// the bare name (its platform resolver may reject a trailing dot).
	sysName := name
	if c.opt.SystemResolver == nil {
		sysName = name + "."
	}
	var sys dest.SystemResult
	var answers []dest.DoHAnswer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sys = c.systemLookup(ctx, sysName) }()
	go func() { defer wg.Done(); answers = dest.ResolveTrusted(ctx, c.destHTTP(), name, c.attemptTimeout()) }()
	wg.Wait()
	trusted := dest.TrustedConsensus(answers)
	a.mark("first_byte")
	a.Detail["system_rcode"] = sys.RCode
	a.Detail["system_ips"] = dest.Strings(sys.IPs)
	a.Detail["trusted_rcode"] = trusted.RCode
	a.Detail["trusted_ips"] = dest.Strings(trusted.IPs)
	a.Detail["resolvers"] = trusted.Note
	switch {
	case len(sys.IPs) > 0:
		a.Detail["hijack"] = "system"
		return a.fail(OutcomeDNSMismatch, fmt.Errorf("the system resolver answered %s for a .invalid name", dest.Strings(sys.IPs)))
	case len(trusted.IPs) > 0:
		a.Detail["hijack"] = "trusted"
		return a.fail(OutcomeDNSMismatch, fmt.Errorf("a trusted resolver answered %s for a .invalid name: the DoH path itself is answered by something else", dest.Strings(trusted.IPs)))
	case sys.RCode == "TIMEOUT":
		return a.fail(OutcomeDNSTimeout, errors.New("system resolver timed out"))
	case sys.RCode == "ERROR":
		return a.fail(OutcomeInconclusive, fmt.Errorf("system resolver error: %s", sys.Err))
	}
	return a.ok()
}

// destConnect dials ip:443 with the attempt timeout and returns the outcome
// and, on success, the open connection. When a is non-nil the connect stage
// and source port are recorded on it.
func (c *Client) destConnect(ctx context.Context, ip netip.Addr, _ int) (string, net.Conn) {
	return c.destConnectAttempt(ctx, ip, nil)
}

func (c *Client) destConnectAttempt(ctx context.Context, ip netip.Addr, a *Attempt) (string, net.Conn) {
	dctx, cancel := context.WithTimeout(ctx, c.attemptTimeout())
	defer cancel()
	start := time.Now()
	conn, err := c.dialer().DialContext(dctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(DestPort)))
	if err != nil {
		return classifyNetErr(err, false), nil
	}
	if a != nil {
		a.markSince("connect", start)
		if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			a.SrcPort = ta.Port
		}
	}
	return OutcomeOK, conn
}

// destTCP is the dest.tcp attempt: :443 on the target's addresses in
// priority order until one connects.
func (c *Client) destTCP(ctx context.Context, a *Attempt, t dest.Target) *Attempt {
	c.destNote(a, t)
	res := c.destResolve(ctx, t)
	a.Detail["probe_source"] = res.source
	if len(res.ips) == 0 {
		return a.fail(OutcomeSkipped, errors.New("no address to connect to"))
	}
	a.mark("first_write")
	var tried []string
	last, lastErr := OutcomeSkipped, ""
	for i, ip := range res.ips {
		if i >= 4 {
			break
		}
		tried = append(tried, ip.String())
		out, conn := c.destConnectAttempt(ctx, ip, a)
		if out == OutcomeOK {
			conn.Close()
			a.Detail["endpoint"] = net.JoinHostPort(ip.String(), strconv.Itoa(DestPort))
			a.Detail["tried"] = strings.Join(tried, ",")
			return a.ok()
		}
		last, lastErr = out, out
	}
	a.Detail["endpoint"] = net.JoinHostPort(res.ips[0].String(), strconv.Itoa(DestPort))
	a.Detail["tried"] = strings.Join(tried, ",")
	return a.fail(last, fmt.Errorf("%s on every address tried", lastErr))
}

// destTCPControl is the anycast control: the first clean address that
// connects on :443.
func (c *Client) destTCPControl(ctx context.Context, a *Attempt) *Attempt {
	a.mark("first_write")
	last := OutcomeSkipped
	var tried []string
	for _, s := range dest.ControlAddrs {
		ip := netip.MustParseAddr(s)
		tried = append(tried, s)
		out, conn := c.destConnectAttempt(ctx, ip, a)
		if out == OutcomeOK {
			conn.Close()
			a.Detail["endpoint"] = net.JoinHostPort(s, strconv.Itoa(DestPort))
			a.Detail["tried"] = strings.Join(tried, ",")
			return a.ok()
		}
		last = out
	}
	a.Detail["tried"] = strings.Join(tried, ",")
	return a.fail(last, errors.New("no anycast control address connects on :443"))
}

// destTLSMode selects the handshake of a dest.tls variant.
type destTLSMode int

const (
	destSNIReal destTLSMode = iota
	destSNIDecoy
	destSNIAbsent
)

// destTLS is one handshake on the target's address: the real name, a decoy
// name, or no name. The three cells together are the SNI differential.
func (c *Client) destTLS(ctx context.Context, a *Attempt, t dest.Target, mode destTLSMode) *Attempt {
	c.destNote(a, t)
	res := c.destResolve(ctx, t)
	if len(res.ips) == 0 {
		return a.fail(OutcomeSkipped, errors.New("no address to connect to"))
	}
	ip := res.ips[0]
	a.Detail["ip"] = ip.String()
	sni := t.ServerName()
	switch mode {
	case destSNIDecoy:
		sni = dest.PickDecoy(t.ServerName(), t.Domain)
	case destSNIAbsent:
		sni = ""
	}
	a.Detail["sni"] = sni
	out, conn := c.destConnectAttempt(ctx, ip, a)
	if out != OutcomeOK {
		// No ClientHello left the host: this is the address failing, not
		// the name (the classifier keeps it out of the SNI differential).
		a.Detail["stage"] = "connect"
		return a.fail(out, fmt.Errorf("tcp connect to %s: %s", ip, out))
	}
	defer conn.Close()
	a.mark("first_write")
	out, _ = c.destHandshakeOn(ctx, conn, sni, a)
	if out == OutcomeOK || out == OutcomeTLSAlert {
		// An alert is the server answering our ClientHello: the path let it
		// through, which is all the differential asks. It stays visible in
		// detail.alert.
		return a.ok()
	}
	return a.fail(out, errors.New(a.Error))
}

// destHandshakeOn runs a TLS handshake with sni on an open connection and
// returns the outcome and, when the handshake completed, the chain check
// ("true" or the reason it does not verify). Certificates are not verified
// during the handshake (the handshake result is the evidence) but the chain
// is checked afterwards and recorded, so that a handshake that completes
// with a foreign certificate is visible.
func (c *Client) destHandshakeOn(ctx context.Context, conn net.Conn, sni string, a *Attempt) (outcome, chain string) {
	conn.SetDeadline(time.Now().Add(c.attemptTimeout()))
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // the handshake itself is the measurement
	tc := tls.Client(conn, cfg)
	err := tc.HandshakeContext(ctx)
	if err != nil {
		if a != nil {
			noteTLSFailure(a, err)
			a.Error = err.Error()
		}
		if alert, ok := remoteAlert(err); ok {
			// The server answered our ClientHello: the path let it through,
			// whatever it thought of the name. decode_error and
			// illegal_parameter are the exception: a hello the peer could
			// not read is not a hello that reached the server intact.
			if alert == tls.AlertError(50) || alert == tls.AlertError(47) {
				return OutcomeTLSParse, ""
			}
			return OutcomeTLSAlert, ""
		}
		return tlsOutcome(err), ""
	}
	st := tc.ConnectionState()
	chain = verifyChain(st.PeerCertificates, sni)
	if a != nil {
		a.mark("handshake")
		a.Detail["negotiated_version"] = tlsVersionName(st.Version)
		a.Detail["cipher"] = tls.CipherSuiteName(st.CipherSuite)
		if len(st.PeerCertificates) > 0 {
			leaf := st.PeerCertificates[0]
			a.Detail["cert_subject"] = leaf.Subject.String()
			a.Detail["cert_issuer"] = leaf.Issuer.String()
			a.Detail["cert_verified"] = chain
		}
	}
	return OutcomeOK, chain
}

// verifyChain checks the presented chain against the system roots and the
// name; "true", or the reason it does not verify.
func verifyChain(chain []*x509.Certificate, sni string) string {
	if len(chain) == 0 {
		return "no certificate"
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Intermediates: inter}
	if sni != "" && net.ParseIP(sni) == nil {
		opts.DNSName = sni
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return err.Error()
	}
	return "true"
}

// destHTTPCheck is dest.http: GET https://domain/ on the target's address,
// with real certificate verification and a browser User-Agent. The network
// layers are the other tests' business; this one asks whether the service
// itself refuses the region.
func (c *Client) destHTTPCheck(ctx context.Context, a *Attempt, t dest.Target) *Attempt {
	c.destNote(a, t)
	res := c.destResolve(ctx, t)
	if len(res.ips) == 0 {
		return a.fail(OutcomeSkipped, errors.New("no address to connect to"))
	}
	ip := res.ips[0]
	a.Detail["ip"] = ip.String()
	base := c.destHTTP()
	tr := base.Transport.(*http.Transport).Clone()
	// The clone is this attempt's: its keep-alive connections (and their
	// goroutines) must not outlive it in a long-running embedder.
	defer tr.CloseIdleConnections()
	// The transport dials from its own goroutine, which may still be running
	// when Do returns on a timeout: the connect time is handed over under a
	// lock and recorded on the attempt only from this goroutine.
	var dialMu sync.Mutex
	var connectMs float64
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Pin the target's own name to the address the other layers used;
		// redirect targets on other hosts resolve normally.
		host, port, err := net.SplitHostPort(addr)
		if err == nil && strings.EqualFold(host, t.Domain) {
			addr = net.JoinHostPort(ip.String(), port)
		}
		start := time.Now()
		conn, err := c.dialer().DialContext(ctx, network, addr)
		if err == nil {
			dialMu.Lock()
			if connectMs == 0 {
				connectMs = float64(time.Since(start).Microseconds()) / 1000
			}
			dialMu.Unlock()
		}
		return conn, err
	}
	recordConnect := func() {
		dialMu.Lock()
		defer dialMu.Unlock()
		if connectMs != 0 && a.Stages["connect"] == 0 {
			a.Stages["connect"] = connectMs
		}
	}
	hc := &http.Client{Transport: tr, CheckRedirect: base.CheckRedirect, Timeout: 2 * c.attemptTimeout()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+t.Domain+"/", nil)
	if err != nil {
		return a.fail(OutcomeServerError, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	a.mark("first_write")
	resp, err := hc.Do(req)
	recordConnect()
	if err != nil {
		var uae x509.UnknownAuthorityError
		var he x509.HostnameError
		var cie x509.CertificateInvalidError
		if errors.As(err, &uae) || errors.As(err, &he) || errors.As(err, &cie) {
			a.Detail["cert_error"] = err.Error()
			return a.fail(OutcomeCertMismatch, err)
		}
		return a.fail(classifyNetErr(err, true), err)
	}
	defer resp.Body.Close()
	a.mark("first_byte")
	a.Detail["status"] = strconv.Itoa(resp.StatusCode)
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Host != t.Domain {
		a.Detail["final_host"] = resp.Request.URL.Host
	}
	legal, note := dest.ClassifyHTTP(resp.StatusCode)
	a.Detail["note"] = note
	if legal {
		return a.fail(OutcomeHTTPLegalBlock, errors.New(note))
	}
	return a.ok()
}

// destPlans builds the family's plans: the two controls, then the layers of
// every target. Groups are per target ("dest/<domain>") so that retry rounds
// re-run a whole site, controls included ("dest/control").
func (c *Client) destPlans(want map[string]bool) []Plan {
	var plans []Plan
	add := func(test, role, variant, transport string, port int, group string, run func(ctx context.Context, c *Client, a *Attempt) *Attempt) {
		if !want[test] {
			return
		}
		plans = append(plans, Plan{TestID: test, Group: group, Role: role, Variant: variant, Transport: transport, Port: port, run: run})
	}
	add("dest.nxdomain", RoleControl, "invalid", "udp", 53, "dest/control", func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destNXDomain(ctx, a) })
	add("dest.tcp", RoleControl, "anycast", "tcp", DestPort, "dest/control", func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destTCPControl(ctx, a) })
	for _, t := range c.destTargets() {
		t := t
		group := "dest/" + t.Domain
		role := RoleVariant
		if t.Category == dest.CategoryControl {
			role = RoleBaseline
		}
		if !t.SkipDNS {
			add("dest.dns", role, t.Domain, "udp", 53, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destDNS(ctx, a, t) })
		}
		add("dest.tcp", role, t.Domain, "tcp", DestPort, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destTCP(ctx, a, t) })
		if t.SkipTLS {
			continue
		}
		add("dest.tls", role, t.Domain, "tcp", DestPort, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destTLS(ctx, a, t, destSNIReal) })
		add("dest.tls", RoleControl, "decoy:"+t.Domain, "tcp", DestPort, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destTLS(ctx, a, t, destSNIDecoy) })
		add("dest.tls", RoleControl, "absent:"+t.Domain, "tcp", DestPort, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destTLS(ctx, a, t, destSNIAbsent) })
		if t.HTTPCheck {
			add("dest.http", role, t.Domain, "tcp", DestPort, group, func(ctx context.Context, c *Client, a *Attempt) *Attempt { return c.destHTTPCheck(ctx, a, t) })
		}
	}
	return plans
}

// destWanted decides which dest tests a scan runs: with --tests, the listed
// ids; otherwise, when the family is enabled, all of them.
func (c *Client) destWanted() map[string]bool {
	want := map[string]bool{}
	if len(c.opt.Tests) > 0 {
		for _, t := range c.opt.Tests {
			if IsDestTest(t) {
				want[t] = true
			}
		}
		return want
	}
	if c.opt.Sites || c.Standalone() {
		for _, t := range DestTests {
			want[t] = true
		}
	}
	return want
}
