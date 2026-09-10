// Package client is the measurement engine: it opens a session on the control
// point, runs the test catalog as differential groups, fetches the server's
// observations and hands everything to the classifier.
//
// It is written to be embeddable (Stage 3 wraps it with gomobile): no global
// state, context-aware, JSON in/JSON out.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dest"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// Version is stamped into reports; overridden via -ldflags.
var Version = "dev"

// Options configure a scan.
type Options struct {
	Target          string // IP (v4 or v6) of the control point
	ControlPort     int
	Pin             string // expected SPKI pin; empty = trust on first use (recorded in report)
	Tests           []string
	Profile         string // "" or "full" = the whole catalog; "quick" = the phone profile (profile.go)
	Repeat          int    // rounds every plan runs
	Retry           int    // extra rounds for the port groups that had a failure in the first rounds
	Parallel        int
	Timeout         time.Duration // per attempt
	TriggerHost     string        // Host/SNI value used as the "trigger" variant
	SNIList         []string      // extra SNI values for tls.sni / tcp.bulk (whitelist search)
	BulkKB          int           // size of one bulk transfer, kilobytes (default 64)
	SessionPackets  int           // data packets per *.session test after the handshake (default 12)
	RealitySNI      string        // foreign SNI carried by vless.reality (default www.microsoft.com)
	BurstN          int           // parallel handshakes per tls.burst attempt (default 4)
	AdaptiveTimeout bool          // derive per-attempt timeouts from the control RTT
	DetectBypass    bool          // warn when a known circumvention tool is running
	Log             *slog.Logger
	// Interface, when set, binds every socket to this local address (e.g. to
	// force a specific cellular/Wi-Fi interface on multi-homed hosts).
	LocalAddr string
	// Sites adds the dest.* family (real destinations, tests_dest.go) to the
	// scan. With an empty Target the scan is that family alone and needs no
	// server (Standalone).
	Sites bool
	// Targets replaces the built-in destination catalog (dest.Default).
	Targets []dest.Target
	// SystemResolver replaces net.DefaultResolver for the dest.* family: an
	// embedder whose platform resolver Go cannot see (a phone) supplies the
	// system view of a name here. Errors should be *net.DNSError when the
	// distinction between NXDOMAIN, timeout and failure is known.
	SystemResolver func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Client holds session state for one scan.
type Client struct {
	opt    Options
	target netip.Addr
	http   *http.Client
	log    *slog.Logger

	Params  model.Params
	Session model.SessionResponse
	sid     [proto.SessionIDLen]byte
	key     []byte
	cookie  []byte

	ObservedPin string // pin of the certificate actually presented on the control port
	PinMatched  bool

	controlRTT time.Duration // best TCP connect time to the control port
	standalone bool          // no server: the dest.* family alone
	dest       destState
	// ClockSkew is the server clock minus the client clock, estimated from
	// params.server_time at the midpoint of the request. Observations are
	// stamped by the server; the merge subtracts it to compare them with the
	// client's stages.
	ClockSkew time.Duration
	Warnings  []string
}

// New prepares a client; nothing is sent until Bootstrap.
func New(opt Options) (*Client, error) {
	if opt.ControlPort == 0 {
		opt.ControlPort = 8443
	}
	if opt.Repeat <= 0 {
		opt.Repeat = 3
	}
	if opt.Parallel <= 0 {
		opt.Parallel = 4
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 6 * time.Second
	}
	if opt.TriggerHost == "" {
		opt.TriggerHost = "www.youtube.com"
	}
	if opt.BulkKB <= 0 {
		opt.BulkKB = 64
	}
	if opt.SessionPackets <= 0 {
		opt.SessionPackets = 12
	}
	if opt.RealitySNI == "" {
		opt.RealitySNI = "www.microsoft.com"
	}
	if opt.BurstN <= 0 {
		opt.BurstN = 4
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.Pin != "" {
		pin, err := base64.StdEncoding.DecodeString(opt.Pin)
		if err != nil || len(pin) != sha256.Size {
			return nil, fmt.Errorf("pin must be base64-encoded SHA-256 (44 characters, as printed by the server)")
		}
	}
	if opt.LocalAddr != "" {
		if _, err := netip.ParseAddr(opt.LocalAddr); err != nil {
			return nil, fmt.Errorf("local-addr must be an IP address: %w", err)
		}
	}
	if opt.Target == "" {
		// The real-destinations family needs no server. Anything else does.
		for _, t := range opt.Tests {
			if !IsDestTest(t) {
				return nil, fmt.Errorf("test %s needs a probe server (--target)", t)
			}
		}
		if !opt.Sites && len(opt.Tests) == 0 {
			return nil, fmt.Errorf("target is required (an IP address), unless the scan is the real-destinations family alone")
		}
		return &Client{opt: opt, log: opt.Log, standalone: true}, nil
	}
	ip, err := netip.ParseAddr(opt.Target)
	if err != nil {
		// allow host names for lab use, but resolve once up front
		addrs, rerr := net.DefaultResolver.LookupNetIP(context.Background(), "ip", opt.Target)
		if rerr != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("target must be an IP address: %w", err)
		}
		ip = addrs[0]
	}
	c := &Client{opt: opt, target: ip.Unmap(), log: opt.Log}
	c.http = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext:       c.controlDial,
		TLSClientConfig:   c.pinnedTLS(""),
		ForceAttemptHTTP2: true,
	}}
	return c, nil
}

// controlDial dials the control port and keeps the best connect time as the
// path RTT estimate for adaptive timeouts.
func (c *Client) controlDial(ctx context.Context, network, addr string) (net.Conn, error) {
	start := time.Now()
	conn, err := c.dialer().DialContext(ctx, network, addr)
	if err == nil {
		if d := time.Since(start); c.controlRTT == 0 || d < c.controlRTT {
			c.controlRTT = d
		}
	}
	return conn, err
}

// Target returns the resolved control point address.
func (c *Client) Target() netip.Addr { return c.target }

// Standalone reports whether the scan has no server: only the dest.* family
// runs, nothing is reserved and no observations are fetched.
func (c *Client) Standalone() bool { return c.standalone }

func (c *Client) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: c.opt.Timeout}
	if c.opt.LocalAddr != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(c.opt.LocalAddr)}
	}
	return d
}

func (c *Client) udpLocal() *net.UDPAddr {
	if c.opt.LocalAddr != "" {
		return &net.UDPAddr{IP: net.ParseIP(c.opt.LocalAddr)}
	}
	return nil
}

// pinnedTLS returns a client config that ignores names and CAs but records
// (and, when configured, enforces) the SPKI pin.
func (c *Client) pinnedTLS(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // pin-based trust by design
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			pin := base64.StdEncoding.EncodeToString(sum[:])
			c.ObservedPin = pin
			want := c.opt.Pin
			if want == "" {
				want = c.Params.SPKIPin
			}
			if want != "" && want != pin {
				c.PinMatched = false
				return fmt.Errorf("spki pin mismatch: got %s want %s", pin, want)
			}
			c.PinMatched = want != ""
			return nil
		},
	}
}

func (c *Client) controlURL(path string) string {
	return "https://" + net.JoinHostPort(c.target.String(), strconv.Itoa(c.opt.ControlPort)) + path
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, auth bool) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.controlURL(path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cpprobe/"+Version)
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.Session.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("control %s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(rb))
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// EstimateSkew returns the server clock minus the client clock, given the
// server's timestamp on a response and the client's clock before and after
// the request: the server is assumed to have stamped it at the midpoint.
// An unparsable timestamp yields zero.
func EstimateSkew(serverTime string, before, after time.Time) time.Duration {
	st, err := time.Parse(time.RFC3339Nano, serverTime)
	if err != nil {
		return 0
	}
	mid := before.Add(after.Sub(before) / 2)
	return st.Sub(mid)
}

// Bootstrap fetches params and opens a session. It returns an error the
// classifier maps to probe_unreachable.
func (c *Client) Bootstrap(ctx context.Context) error {
	t0 := time.Now()
	if err := c.doJSON(ctx, http.MethodGet, "/v1/params", nil, &c.Params, false); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	c.ClockSkew = EstimateSkew(c.Params.ServerTime, t0, time.Now())
	if c.opt.Pin == "" {
		// Trust on first use: from now on enforce what the server advertised
		// and what we actually saw. If those differ, something in the path
		// rewrote either the TLS session or the JSON.
		if c.ObservedPin != c.Params.SPKIPin {
			return fmt.Errorf("control plane inconsistency: presented pin %s but advertises %s", c.ObservedPin, c.Params.SPKIPin)
		}
		c.PinMatched = true
	}
	nonce := proto.RandomPayload(32)
	req := model.SessionRequest{ClientVersion: Version, ClientNonce: hex.EncodeToString(nonce), Tests: c.opt.Tests, Capabilities: []string{"cp1", "utls", "quic"}}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/session", req, &c.Session, false); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	sid, err := proto.ParseSessionID(c.Session.SessionID)
	if err != nil {
		return err
	}
	c.sid = sid
	if c.key, err = hex.DecodeString(c.Session.SessionKey); err != nil {
		return err
	}
	if c.cookie, err = hex.DecodeString(c.Session.UDPCookie); err != nil {
		return err
	}
	return nil
}

// ControlRTT is the best TCP connect time seen on the control port.
func (c *Client) ControlRTT() time.Duration { return c.controlRTT }

// EffectiveTimeout is the per-attempt timeout in use.
func (c *Client) EffectiveTimeout() time.Duration { return c.attemptTimeout() }

// Zone is the DNS zone the server serves (trailing dot).
func (c *Client) Zone() string {
	if c.Params.DNSZone != "" {
		return c.Params.DNSZone
	}
	return "probe.invalid."
}

// Health fetches the listener snapshot.
func (c *Client) Health(ctx context.Context) (model.Health, error) {
	var h model.Health
	err := c.doJSON(ctx, http.MethodGet, "/v1/health", nil, &h, true)
	return h, err
}

// Reserve asks the server for a correlation window for a native handshake.
func (c *Client) Reserve(ctx context.Context, testID, transport string, port int, kind, variant string) (string, error) {
	var out model.AttemptResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/session/"+c.Session.SessionID+"/attempt",
		model.AttemptRequest{TestID: testID, Transport: transport, DstPort: port, Kind: kind, Variant: variant}, &out, true)
	return out.AttemptID, err
}

// reserve is Reserve for one attempt: it records the reservation id and
// restarts the attempt clock, so that connect/first_write/... measure the
// flow under test and not the control-plane round trip that preceded it.
func (c *Client) reserve(ctx context.Context, a *Attempt, transport, kind string) error {
	id, err := c.Reserve(ctx, a.TestID, transport, a.DstPort, kind, a.Variant)
	if err != nil {
		return err
	}
	a.AttemptID = id
	a.restart()
	return nil
}

// Observations fetches everything the server recorded for this session.
func (c *Client) Observations(ctx context.Context) ([]model.Observation, error) {
	var out model.ObservationsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/session/"+c.Session.SessionID+"/observations", nil, &out, true); err != nil {
		return nil, err
	}
	return out.Observations, nil
}

// envelope builds an authenticated request for testID.
func (c *Client) envelope(testID string, seq uint32, payload []byte, udp bool) ([]byte, [proto.NonceLen]byte, error) {
	r := &proto.Request{SessionID: c.sid, TestID: testID, Nonce: proto.NewNonce(), Seq: seq, Payload: payload}
	if udp {
		r.Cookie = c.cookie
	}
	b, err := proto.EncodeRequest(r, c.key)
	return b, r.Nonce, err
}

// checkReply validates an echo reply for the request that produced nonce.
func (c *Client) checkReply(b []byte, nonce [proto.NonceLen]byte, payload []byte) (*proto.Reply, string) {
	rep, err := proto.DecodeReply(b, c.key)
	if err != nil {
		if errors.Is(err, proto.ErrBadMAC) {
			return rep, "modified"
		}
		return nil, "unexpected_response"
	}
	if rep.Nonce != nonce {
		return rep, "nonce_mismatch"
	}
	sum := sha256.Sum256(payload)
	if rep.PayloadSHA256 != sum || int(rep.RecvLen) != len(payload) {
		return rep, "uplink_modified"
	}
	return rep, ""
}
