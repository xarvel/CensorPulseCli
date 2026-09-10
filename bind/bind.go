// Package cpprobe is the mobile binding of the probe engine, shaped for
// gomobile: strings and JSON in, a JSON report out, interfaces for the
// callbacks the platform provides. Build it with
//
//	gomobile bind -target ios -o Cpprobe.xcframework ./bind
//	gomobile bind -target android -androidapi 24 -o cpprobe.aar ./bind
//
// (see bind/README.md). Nothing here is needed by the CLI; the engine
// package is the Go API.
//
// A scan runs like this from the platform side:
//
//	s, err := cpprobe.NewScan(configJSON, listener, resolver)
//	report, err := s.Run()   // blocks; call from a background thread
//	s.Cancel()               // from any thread, at any time
//
// configJSON is a config (see DefaultConfig for every field and its
// default); the result is the report of docs/report.md as JSON.
package cpprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/CensorPulseCli/engine"
)

// Listener receives progress and diagnostics while a scan runs. Calls
// arrive from the scan's own goroutines (never the caller's thread), one
// at a time per method, and must return quickly.
type Listener interface {
	// OnProgress is called after each finished attempt: done of total so
	// far (total grows when retry rounds are added), the test id, its
	// classification group ("tcp/443"), the variant and the client-side
	// outcome ("ok", "connect_timeout", …; docs/report.md).
	OnProgress(done int, total int, testID string, group string, variant string, outcome string)
	// OnLog receives one diagnostic line with its level (debug, info, warn,
	// error).
	OnLog(level string, message string)
}

// Resolver is the platform's system resolver, used by the dest.* family
// (real destinations) for the "what the user's apps see" side of the DNS
// comparison. Go on a phone cannot see the system resolver on its own.
type Resolver interface {
	// Lookup returns every address the system resolver gives for host, as
	// a comma-separated list ("1.2.3.4,2606:4700::1"). An empty list is
	// "no such host". When the name does not exist, return an error whose
	// message contains "nxdomain"; when the resolver did not answer in
	// time, one containing "timeout"; any other error is a resolver
	// failure. Lookup must return: the engine stops waiting for it at the
	// attempt timeout, but a call that never returns stays blocked.
	Lookup(host string) (string, error)
}

// config is the JSON form of engine.Config. Zero values mean the defaults
// noted in DefaultConfig.
type config struct {
	Target      string `json:"target"`
	ControlPort int    `json:"control_port"`
	Pin         string `json:"pin"`

	Tests   []string `json:"tests"`
	Profile string   `json:"profile"`

	Repeat   int `json:"repeat"`
	Retry    int `json:"retry"`
	Parallel int `json:"parallel"`

	TimeoutMs         int  `json:"timeout_ms"`
	NoAdaptiveTimeout bool `json:"no_adaptive_timeout"`
	DeadlineMs        int  `json:"deadline_ms"`

	TriggerHost    string   `json:"trigger_host"`
	SNIList        []string `json:"sni_list"`
	SNISample      int      `json:"sni_sample"`
	BulkKB         int      `json:"bulk_kb"`
	SessionPackets int      `json:"session_packets"`
	RealitySNI     string   `json:"reality_sni"`
	BurstN         int      `json:"burst_n"`

	LocalAddr    string `json:"local_addr"`
	DetectBypass bool   `json:"detect_bypass"`

	Sites   bool   `json:"sites"`
	Targets string `json:"targets"`

	GeoIPDir    string `json:"geoip_dir"`
	GeoIPOnline bool   `json:"geoip_online"`
}

func (c config) engine() engine.Config {
	return engine.Config{
		Target: c.Target, ControlPort: c.ControlPort, Pin: c.Pin,
		Tests: c.Tests, Profile: c.Profile,
		Repeat: c.Repeat, Retry: c.Retry, Parallel: c.Parallel,
		Timeout: time.Duration(c.TimeoutMs) * time.Millisecond, NoAdaptiveTimeout: c.NoAdaptiveTimeout,
		Deadline:    time.Duration(c.DeadlineMs) * time.Millisecond,
		TriggerHost: c.TriggerHost, SNIList: c.SNIList, SNISample: c.SNISample, BulkKB: c.BulkKB,
		SessionPackets: c.SessionPackets, RealitySNI: c.RealitySNI, BurstN: c.BurstN,
		LocalAddr: c.LocalAddr, DetectBypass: c.DetectBypass,
		Sites: c.Sites, Targets: c.Targets,
		GeoIPDir: c.GeoIPDir, GeoIPOnline: c.GeoIPOnline,
	}
}

// DefaultConfig returns a config JSON with every field present and the
// defaults the engine applies to zero values spelled out: a quick scan
// against a control point with the real-destinations family, the shape a
// phone runs. Edit and pass to NewScan.
func DefaultConfig() string {
	c := config{
		Target: "", ControlPort: 8443, Pin: "",
		Tests: []string{}, Profile: "quick",
		Repeat: 1, Retry: 2, Parallel: 4,
		TimeoutMs: 6000, NoAdaptiveTimeout: false, DeadlineMs: 0,
		TriggerHost: "www.youtube.com", SNIList: []string{}, SNISample: 0, BulkKB: 64,
		SessionPackets: 12, RealitySNI: "www.microsoft.com", BurstN: 4,
		LocalAddr: "", DetectBypass: false,
		Sites: true, Targets: "",
		GeoIPDir: "", GeoIPOnline: false,
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return string(b)
}

// Version is the engine version recorded in reports: the module version
// when built from a tagged release, else "dev".
func Version() string {
	if engine.Version != "dev" {
		return engine.Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/xarvel/CensorPulseCli" && d.Version != "" && d.Version != "(devel)" {
				return d.Version
			}
		}
		if bi.Main.Path == "github.com/xarvel/CensorPulseCli" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
	}
	return engine.Version
}

// KnownTests returns every test id config.tests accepts, as a JSON array.
func KnownTests() string {
	b, _ := json.Marshal(engine.KnownTests())
	return string(b)
}

// ValidateConfig checks a config JSON without running anything: unknown
// fields, ranges, test ids, the targets text. A malformed pin or local
// address is only caught when the scan starts.
func ValidateConfig(configJSON string) error {
	c, err := parseConfig(configJSON)
	if err != nil {
		return err
	}
	return c.engine().Validate()
}

func parseConfig(configJSON string) (config, error) {
	var c config
	dec := json.NewDecoder(strings.NewReader(configJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

// Scan is one scan: created by NewScan, run once by Run, stoppable by
// Cancel.
type Scan struct {
	cfg      engine.Config
	listener Listener
	resolver Resolver

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	started bool
}

// NewScan validates configJSON and returns a scan ready to Run. listener
// and resolver may be nil: progress and logs are then dropped, and the
// dest.* family falls back to Go's resolver (which on a phone is not the
// system resolver).
func NewScan(configJSON string, listener Listener, resolver Resolver) (*Scan, error) {
	c, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	cfg := c.engine()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scan{cfg: cfg, listener: listener, resolver: resolver, ctx: ctx, cancel: cancel}, nil
}

// Run prepares and runs the scan and returns the report as JSON. It blocks
// for the whole scan (minutes): call it from a background thread. A scan
// whose control point is unreachable returns its report without an error
// (probe_reachable is false and bootstrap_error says why: the generated
// Java and Objective-C bindings drop the return value when an error is
// set, so the two are never returned together); a cancelled scan returns
// the report of what ran. An error means there is no report. Run may be
// called once.
func (s *Scan) Run() (string, error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return "", errors.New("scan already started")
	}
	s.started = true
	s.mu.Unlock()
	defer s.cancel()

	hooks := engine.Hooks{}
	if s.listener != nil {
		l := s.listener
		hooks.Progress = func(p engine.Progress) {
			l.OnProgress(p.Done, p.Total, p.TestID, p.Group, p.Variant, p.Outcome)
		}
		hooks.Log = slog.New(slog.NewTextHandler(&logWriter{l: l}, &slog.HandlerOptions{Level: slog.LevelInfo}))
		hooks.Notice = func(msg string) { l.OnLog("info", msg) }
	}
	if s.resolver != nil {
		r := s.resolver
		hooks.SystemResolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return lookupVia(ctx, r, host)
		}
	}
	rep, err := engine.Run(s.ctx, s.cfg, hooks)
	if rep == nil {
		return "", err
	}
	var buf bytes.Buffer
	if werr := rep.WriteJSON(&buf); werr != nil {
		return "", werr
	}
	if err != nil && !errors.Is(err, engine.ErrProbeUnreachable) {
		return "", err
	}
	return buf.String(), nil
}

// Cancel stops a running scan; Run then returns the report of what ran.
// Safe to call from any thread, before Run (a sites-only Run then returns
// its empty report at once; a scan against a control point cannot
// bootstrap and returns the unreachable report) or after it finished (no
// effect).
func (s *Scan) Cancel() { s.cancel() }

// lookupVia adapts the platform resolver to the engine's hook, mapping the
// documented error strings to *net.DNSError so that dest.dns can tell
// NXDOMAIN from a timeout.
func lookupVia(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := r.Lookup(host)
		ch <- result{s, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-ctx.Done():
		return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
	}
	if res.err != nil {
		msg := strings.ToLower(res.err.Error())
		switch {
		case strings.Contains(msg, "nxdomain"):
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		case strings.Contains(msg, "timeout"):
			return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
		}
		return nil, &net.DNSError{Err: res.err.Error(), Name: host}
	}
	var ips []netip.Addr
	for _, f := range strings.Split(res.s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ip, err := netip.ParseAddr(f)
		if err != nil {
			return nil, &net.DNSError{Err: "resolver returned a non-address: " + f, Name: host}
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

// logWriter turns slog text lines into Listener.OnLog calls.
type logWriter struct {
	l   Listener
	buf bytes.Buffer
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(w.buf.Next(i + 1))
		line = strings.TrimRight(line, "\n")
		level := "info"
		switch {
		case strings.Contains(line, "level=DEBUG"):
			level = "debug"
		case strings.Contains(line, "level=WARN"):
			level = "warn"
		case strings.Contains(line, "level=ERROR"):
			level = "error"
		}
		w.l.OnLog(level, line)
	}
}
