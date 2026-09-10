// Package engine runs a scan end to end: it is what `cpprobe scan` and
// `cpprobe sites` do, without flags, files, terminals or signals, so that an
// application can embed the probe. Prepare validates the configuration,
// contacts the control point (unless the scan is the real-destinations
// family alone) and builds the plan; Run executes it and returns the report.
//
// The report's JSON (docs/report.md, schema_version 1) is the stable
// contract; the Go types under internal/ are not.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/classify"
	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/dest"
	"github.com/xarvel/CensorPulseCli/internal/geoip"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/report"
)

// Version is recorded in every report as client_version. The CLI stamps it
// at build time; an embedder may set it to its own build identifier.
var Version = "dev"

// ErrProbeUnreachable is returned by Run when the control point could not be
// bootstrapped. The report is still returned: it carries bootstrap_error and
// the probe_unreachable verdict.
var ErrProbeUnreachable = errors.New("probe unreachable")

// Config describes one scan. Zero values mean the defaults noted on each
// field, so Config{Target: ip} is a full scan with the CLI's defaults.
type Config struct {
	// Target is the IP address of the control point. Empty runs the
	// real-destinations family alone (Sites must be set, or Tests must name
	// only dest.* ids): no server, no session, mode "sites" in the report.
	Target      string
	ControlPort int    // 8443
	Pin         string // expected SPKI pin (base64); empty = trust on first use, recorded as pin_enforced=false

	// Tests selects test ids explicitly (see KnownTests); it overrides
	// Profile. Empty = everything the server offers, filtered by Profile.
	Tests   []string
	Profile string // "full" (the whole catalog) or "quick" (the phone profile); default full

	Repeat   int // rounds per plan; 0 = 3 for full, 1 for quick and for a sites-only scan (empty Target)
	Retry    int // extra rounds for the port groups that failed; 0 = the profile default (0 full, 2 quick and sites-only), -1 = none
	Parallel int // concurrent attempts; 0 = 4

	Timeout           time.Duration // per attempt; 0 = 6s
	NoAdaptiveTimeout bool          // keep Timeout fixed instead of deriving it from the control RTT
	Deadline          time.Duration // wall-clock cap for the attempts (Run), not for Prepare's bootstrap; 0 = none. A blackholed network must not hang the caller

	TriggerHost    string   // Host/SNI of the trigger variants; "" = www.youtube.com
	SNIList        []string // extra names for tls.sni and the TLS bulk upload
	SNISample      int      // use only N randomly chosen entries of SNIList; 0 = all
	BulkKB         int      // size of one bulk transfer; 0 = 64
	SessionPackets int      // data packets per *.session test; 0 = 12
	RealitySNI     string   // foreign SNI of vless.reality; "" = www.microsoft.com
	BurstN         int      // parallel handshakes per tls.burst attempt; 0 = 4

	// LocalAddr binds every socket to this local IP (interface selection on
	// a multi-homed host, the cellular interface on a phone).
	LocalAddr string

	// DetectBypass looks for known VPN / circumvention processes on the host
	// and records a warning when one runs. Meaningful on desktops only.
	DetectBypass bool

	// Sites adds the real-destinations family (dest.*) to a scan; with an
	// empty Target it is the whole scan. That family sends traffic to the
	// catalog sites, to public DoH resolvers and to anycast control
	// addresses, not to the control point.
	Sites bool
	// Targets replaces the built-in destination catalog: the text of a
	// --targets file (one site per line, `#` comments; see `cpprobe help
	// sites`). Empty = the built-in catalog.
	Targets string

	// GeoIPDir holds GeoLite2 CSV tables (see `cpprobe geoip update`); when
	// present, the report's network field is looked up offline from the
	// address the server saw. Empty = no offline lookup.
	GeoIPDir string
	// GeoIPOnline asks a public geo-ASN API for the network when the offline
	// tables did not answer (always the case for a sites-only scan).
	GeoIPOnline bool
}

// Progress is one finished attempt, delivered to Hooks.Progress as attempts
// complete. Done and Total count attempts, including retry rounds that were
// added along the way: Done grows by one with every delivery and Total
// never shrinks.
type Progress struct {
	Done, Total int
	TestID      string
	Group       string // classification group, e.g. "tcp/443"
	Role        string // baseline | variant | control
	Variant     string
	Transport   string
	Port        int
	Round       int
	Outcome     string // client-side outcome (docs/report.md)
	Error       string
}

// Hooks are the embedder's callbacks. Every field is optional.
type Hooks struct {
	// Progress is called after each finished attempt, from the scan's
	// goroutines but never concurrently with itself; it must return
	// quickly.
	Progress func(Progress)
	// Log receives the client's diagnostics. nil discards them.
	Log *slog.Logger
	// Notice receives advisory messages a CLI would print to stderr (no
	// GeoIP tables, online lookup failed). nil discards them.
	Notice func(string)
	// SystemResolver replaces the process resolver for the dest.* family.
	// A phone whose platform resolver Go cannot see supplies the system
	// view of a name here; errors should be *net.DNSError when NXDOMAIN,
	// timeout and failure can be told apart.
	SystemResolver func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Plan is one cell of the scan: a test on a transport and port with a
// variant, run Repeat times.
type Plan struct {
	TestID    string
	Group     string
	Role      string
	Variant   string
	Transport string
	Port      int
	// Last plans run after everything else, one at a time (the tests that
	// may leave the path in a state, such as tls.burst and the Tor shapes).
	Last bool
}

// Scan is a prepared scan: configuration applied, control point contacted
// (or found unreachable), plan built. Run executes it once.
type Scan struct {
	cfg       Config
	hooks     Hooks
	c         *client.Client
	rep       *report.Report
	plans     []client.Plan
	reachable bool
	ran       bool
}

// KnownTests lists every test id Config.Tests accepts: the server's
// responders, dns.doh (a feature of the control listener) and the
// client-only dest.* family.
func KnownTests() []string {
	out := append([]string(nil), model.KnownTests...)
	out = append(out, "dns.doh")
	out = append(out, client.DestTests...)
	return out
}

// ParseTests validates a comma-separated list of test ids and returns them
// deduplicated, in order. Empty input yields nil (no restriction).
func ParseTests(list string) ([]string, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	known := map[string]bool{}
	for _, t := range KnownTests() {
		known[t] = true
	}
	for _, raw := range strings.Split(list, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if !known[t] {
			return nil, fmt.Errorf("unknown test %q (run 'cpprobe tests' to list test ids)", t)
		}
		if !seen[t] {
			out = append(out, t)
			seen[t] = true
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the test list did not contain a test id")
	}
	return out, nil
}

// withDefaults returns the configuration with every zero value replaced by
// its default, and the derived facts settled (sites-only, profile "custom").
func (c Config) withDefaults() Config {
	d := c
	sites := d.Target == ""
	if d.Profile == "" {
		d.Profile = "full"
	}
	quick := d.Profile == "quick"
	if d.ControlPort == 0 {
		d.ControlPort = 8443
	}
	if d.Repeat == 0 {
		d.Repeat = 3
		if quick || sites {
			d.Repeat = 1
		}
	}
	switch {
	case d.Retry < 0:
		d.Retry = 0
	case d.Retry == 0:
		if quick || sites {
			d.Retry = 2
		}
	}
	if d.Parallel == 0 {
		d.Parallel = 4
	}
	if d.Timeout == 0 {
		d.Timeout = 6 * time.Second
	}
	if d.TriggerHost == "" {
		d.TriggerHost = "www.youtube.com"
	}
	if d.BulkKB == 0 {
		d.BulkKB = 64
	}
	if d.SessionPackets == 0 {
		d.SessionPackets = 12
	}
	if d.RealitySNI == "" {
		d.RealitySNI = "www.microsoft.com"
	}
	if d.BurstN == 0 {
		d.BurstN = 4
	}
	for _, t := range d.Tests {
		if client.IsDestTest(t) {
			d.Sites = true
		}
	}
	if sites {
		d.Sites = true
	}
	return d
}

// Validate checks the configuration the way the CLI checks its flags. It
// is called by Prepare; embedders may call it early to report a bad form.
func (c Config) Validate() error {
	d := c.withDefaults()
	if d.ControlPort < 1 || d.ControlPort > 65535 {
		return errors.New("control port must be between 1 and 65535")
	}
	if d.Repeat < 1 || d.Repeat > 10 {
		return errors.New("repeat must be between 1 and 10")
	}
	if d.Retry < 0 || d.Retry > 10 {
		return errors.New("retry must be between 0 and 10")
	}
	if d.Parallel < 1 || d.Parallel > 32 {
		return errors.New("parallel must be between 1 and 32")
	}
	if d.Timeout < 500*time.Millisecond {
		return errors.New("timeout must be at least 500ms")
	}
	if d.Deadline < 0 {
		return errors.New("deadline cannot be negative")
	}
	if d.BulkKB < 1 || d.BulkKB > 1024 {
		return errors.New("bulk size must be between 1 and 1024 KB")
	}
	if d.SessionPackets < 3 || d.SessionPackets > 256 {
		return errors.New("session packets must be between 3 and 256")
	}
	if d.SNISample < 0 {
		return errors.New("sni sample cannot be negative")
	}
	if d.BurstN < 2 || d.BurstN > 32 {
		return errors.New("burst size must be between 2 and 32")
	}
	if d.Profile != "full" && d.Profile != "quick" {
		return fmt.Errorf("profile must be full or quick (got %q)", d.Profile)
	}
	if len(d.Tests) > 0 {
		known := map[string]bool{}
		for _, t := range KnownTests() {
			known[t] = true
		}
		for _, t := range d.Tests {
			if !known[t] {
				return fmt.Errorf("unknown test %q (run 'cpprobe tests' to list test ids)", t)
			}
		}
	}
	if d.Target == "" {
		for _, t := range d.Tests {
			if !client.IsDestTest(t) {
				return fmt.Errorf("test %s needs a probe server (target)", t)
			}
		}
		if !c.Sites && len(d.Tests) == 0 {
			return errors.New("target is required (an IP address), unless the scan is the real-destinations family alone (sites)")
		}
	}
	if d.Targets != "" && !d.Sites {
		return errors.New("targets need sites")
	}
	if d.Targets != "" {
		if _, err := dest.Parse(strings.NewReader(d.Targets)); err != nil {
			return fmt.Errorf("targets: %w", err)
		}
	}
	return nil
}

// Prepare validates cfg, contacts the control point (a scan) or builds the
// standalone plan (sites), and returns the prepared scan. A control point
// that cannot be bootstrapped is not an error here: Reachable reports it,
// and Run returns the report with ErrProbeUnreachable.
func Prepare(ctx context.Context, cfg Config, hooks Hooks) (*Scan, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	d := cfg.withDefaults()
	client.Version = Version
	sites := d.Target == ""

	var targets []dest.Target
	if d.Targets != "" {
		ts, err := dest.Parse(strings.NewReader(d.Targets))
		if err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
		targets = ts
	}
	snis := append([]string(nil), d.SNIList...)
	if d.SNISample > 0 && d.SNISample < len(snis) {
		rand.Shuffle(len(snis), func(i, j int) { snis[i], snis[j] = snis[j], snis[i] })
		snis = snis[:d.SNISample]
	}
	profile := d.Profile
	if len(d.Tests) > 0 {
		profile = "custom" // explicit tests override the profile's plan selection
	}

	rep := &report.Report{SchemaVersion: 1, ClientVersion: Version, StartedAt: time.Now()}
	opt := client.Options{Sites: d.Sites, Targets: targets, Tests: d.Tests, Repeat: d.Repeat, Retry: d.Retry, Parallel: d.Parallel,
		Timeout: d.Timeout, LocalAddr: d.LocalAddr, DetectBypass: d.DetectBypass, Log: hooks.Log, SystemResolver: hooks.SystemResolver}
	if sites {
		rep.Mode = "sites"
	} else {
		rep.Target, rep.ControlPort = d.Target, d.ControlPort
		opt.Target, opt.ControlPort, opt.Pin, opt.Profile = d.Target, d.ControlPort, d.Pin, profile
		opt.TriggerHost, opt.SNIList, opt.BulkKB, opt.SessionPackets = d.TriggerHost, snis, d.BulkKB, d.SessionPackets
		opt.RealitySNI, opt.BurstN, opt.AdaptiveTimeout = d.RealitySNI, d.BurstN, !d.NoAdaptiveTimeout
	}
	c, err := client.New(opt)
	if err != nil {
		return nil, err
	}
	if d.DetectBypass {
		if tools := client.DetectBypassTools(); len(tools) > 0 {
			rep.Warnings = append(rep.Warnings, "circumvention/VPN software is running ("+strings.Join(tools, ", ")+"): results describe the tunnel, not the network")
		}
	}
	s := &Scan{cfg: d, hooks: hooks, c: c, rep: rep}

	if sites {
		rep.TimeoutMs = float64(c.EffectiveTimeout().Milliseconds())
		s.plans = c.Catalog()
		if len(s.plans) == 0 {
			return nil, errors.New("selected tests produced an empty plan")
		}
		// The online network lookup, when asked for, happens in Run: a
		// prepared-only scan (the CLI's --plan) makes no network call.
		s.reachable = true
		return s, nil
	}

	if err := c.Bootstrap(ctx); err != nil {
		rep.BootstrapErr = err.Error()
		rep.ObservedPin = c.ObservedPin
		return s, nil
	}
	s.reachable = true
	rep.ProbeReached = true
	rep.ObservedPin = c.ObservedPin
	// A pin learned from the endpoint is TOFU, even though it is enforced for
	// the remainder of this scan. Only an out-of-band pin is a pinned scan.
	rep.PinEnforced = d.Pin != "" && c.PinMatched
	p := c.Params
	rep.Params = &p
	rep.SessionID = c.Session.SessionID
	rep.ClientAddr = c.Session.ClientAddr
	if d.GeoIPDir != "" {
		if db, err := geoip.Load(d.GeoIPDir); err == nil {
			if ip, perr := netip.ParseAddr(rep.ClientAddr); perr == nil {
				info := db.Lookup(ip)
				rep.Network = &report.Network{ASN: info.ASN, Org: info.Org, Country: info.Country, Prefix: info.Prefix,
					Source: "GeoLite2 CSV (" + strings.Join(db.Files, ", ") + ")", TablesAt: db.Updated.UTC().Format(time.RFC3339)}
			}
		} else if err != geoip.ErrNoTables {
			rep.Notes = append(rep.Notes, "geoip: "+err.Error())
		} else if !d.GeoIPOnline {
			s.notice("no GeoLite2 tables in " + d.GeoIPDir + "; run 'cpprobe geoip update' once to record ASN/country in reports")
		}
	}
	if d.GeoIPOnline {
		s.onlineNetwork(ctx)
	}
	rep.ControlRTTms = float64(c.ControlRTT().Microseconds()) / 1000
	rep.TimeoutMs = float64(c.EffectiveTimeout().Milliseconds())
	if h, err := c.Health(ctx); err == nil {
		rep.Health = &h
	} else {
		rep.Notes = append(rep.Notes, "health: "+err.Error())
	}
	s.plans = c.Catalog()
	if len(d.Tests) > 0 {
		granted := make(map[string]bool, len(c.Session.Tests)+1)
		for _, t := range c.Session.Tests {
			granted[t] = true
		}
		if contains(c.Params.Features, "doh") {
			granted["dns.doh"] = true
		}
		for _, t := range client.DestTests {
			granted[t] = true // client-only family
		}
		var unavailable []string
		for _, t := range d.Tests {
			if !granted[t] {
				unavailable = append(unavailable, t)
			}
		}
		if len(unavailable) > 0 {
			return nil, fmt.Errorf("server does not offer requested tests: %s", strings.Join(unavailable, ", "))
		}
	}
	if len(s.plans) == 0 {
		return nil, errors.New("selected tests produced an empty plan; run 'cpprobe tests' and check the server configuration")
	}
	return s, nil
}

// Run prepares and runs a scan in one call.
func Run(ctx context.Context, cfg Config, hooks Hooks) (*report.Report, error) {
	s, err := Prepare(ctx, cfg, hooks)
	if err != nil {
		return nil, err
	}
	return s.Run(ctx)
}

// Config returns the configuration with defaults applied.
func (s *Scan) Config() Config { return s.cfg }

// Reachable reports whether the control point answered the bootstrap (always
// true for a sites-only scan).
func (s *Scan) Reachable() bool { return s.reachable }

// SessionID is the server-issued session, empty for a sites-only scan or an
// unreachable control point.
func (s *Scan) SessionID() string { return s.rep.SessionID }

// Plans lists the cells of the scan in catalog order.
func (s *Scan) Plans() []Plan {
	out := make([]Plan, 0, len(s.plans))
	for _, p := range s.plans {
		out = append(out, Plan{TestID: p.TestID, Group: p.Group, Role: p.Role, Variant: p.Variant, Transport: p.Transport, Port: p.Port, Last: p.Last})
	}
	return out
}

// Attempts is the number of attempts the first rounds will make
// (plans × repeat); retry rounds add to it while the scan runs.
func (s *Scan) Attempts() int { return len(s.plans) * s.cfg.Repeat }

// Report returns the report as filled in so far (parameters, session,
// network, health); after Run it is the complete report.
func (s *Scan) Report() *report.Report { return s.rep }

// Run executes the prepared scan and returns the complete report. It runs
// once; a cancelled ctx stops the scan and the report covers what ran.
func (s *Scan) Run(ctx context.Context) (*report.Report, error) {
	if s.ran {
		return s.rep, errors.New("scan already ran")
	}
	s.ran = true
	rep := s.rep
	if !s.reachable {
		res := classify.Classify(nil, false)
		rep.Verdicts, rep.Summary = res.Verdicts, res.Summary
		rep.FinishedAt = time.Now()
		return rep, ErrProbeUnreachable
	}
	if s.cfg.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Deadline)
		defer cancel()
	}
	if rep.Sites() && s.cfg.GeoIPOnline {
		s.onlineNetwork(ctx)
	}
	var progress client.Progress
	if s.hooks.Progress != nil {
		// The client calls progress from its workers concurrently; the
		// embedder's hook sees one call at a time.
		// The client takes its counters before it calls, so two workers
		// can deliver them out of order: Done is counted here, under the
		// lock, and Total never shrinks, so a progress bar only moves
		// forward.
		var mu sync.Mutex
		delivered, most := 0, 0
		progress = func(_, total int, a *client.Attempt) {
			mu.Lock()
			defer mu.Unlock()
			delivered++
			if total > most {
				most = total
			}
			if delivered > most {
				most = delivered
			}
			s.hooks.Progress(Progress{Done: delivered, Total: most, TestID: a.TestID, Group: a.Group, Role: a.Role, Variant: a.Variant,
				Transport: a.Transport, Port: a.DstPort, Round: a.Round, Outcome: a.Outcome, Error: a.Error})
		}
	}
	attempts, err := s.c.Run(ctx, s.plans, progress)
	if err != nil {
		rep.Notes = append(rep.Notes, err.Error())
	}
	if ctx.Err() != nil && s.cfg.Deadline > 0 {
		what := "cells"
		if rep.Sites() {
			what = "sites"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("the run hit the %s deadline; %s not reached are missing, not clear", s.cfg.Deadline, what))
	}
	rep.Attempts = attempts
	var res classify.Result
	if rep.Sites() {
		res = classify.ClassifyStandalone(attempts)
	} else {
		rep.Notes = append(rep.Notes, BurstNotes(attempts)...)
		res = classify.Classify(attempts, true)
	}
	rep.Cells, rep.Verdicts, rep.Summary, rep.Destinations = res.Cells, res.Verdicts, res.Summary, res.Destinations
	rep.Notes = append(rep.Notes, res.Notes...)
	if !rep.Sites() && !rep.PinEnforced {
		rep.Notes = append(rep.Notes, "SPKI pin was learned on first use; verify it out of band and pass --pin '"+rep.ObservedPin+"' on future scans")
	}
	rep.FinishedAt = time.Now()
	return rep, nil
}

// onlineNetwork fills the report's network from a public geo-ASN API when
// the offline tables did not.
func (s *Scan) onlineNetwork(ctx context.Context) {
	rep := s.rep
	if rep.Network != nil && (rep.Network.ASN != 0 || rep.Network.Country != "") {
		return
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	info, src, err := geoip.LookupOnline(lctx, nil)
	if err != nil {
		rep.Notes = append(rep.Notes, err.Error())
		s.notice("online geoip lookup failed; the report carries no network")
		return
	}
	rep.Network = &report.Network{ASN: info.ASN, Org: info.Org, Country: info.Country, Source: "online: " + src}
}

func (s *Scan) notice(msg string) {
	if s.hooks.Notice != nil {
		s.hooks.Notice(msg)
	}
}

// BurstNotes explains what tls.burst did to the probe address and what was
// actually observed. A lasting freeze is only claimed when the single
// handshakes that follow a burst failed too; when they passed, the rule
// dropped the burst and nothing more. Run adds them to the report;
// `cpprobe classify` recomputes them when it reclassifies one.
func BurstNotes(attempts []*client.Attempt) []string {
	burst, dropped, lasting := false, 0, 0
	for _, a := range attempts {
		if a.TestID != "tls.burst" {
			continue
		}
		burst = true
		if a.Outcome == client.OutcomeBurstFreeze {
			dropped++
		}
		if a.Outcome != client.OutcomeOK && (a.Detail["beta_outcome"] != client.OutcomeOK || a.Detail["gamma_outcome"] != client.OutcomeOK) {
			lasting++
		}
	}
	if !burst {
		return nil
	}
	notes := []string{"tls.burst deliberately sent bursts of parallel TLS handshakes to the probe IP; a rate rule keyed on the client address can freeze TLS to that IP for minutes for every host behind the same address"}
	switch {
	case lasting > 0:
		notes = append(notes, fmt.Sprintf("a burst freeze was observed in %d round(s): the single handshakes after a burst failed too, so TLS to the probe IP may stay frozen for a few minutes; a rescan started before it lifts is not comparable to this one", lasting))
	case dropped > 0:
		notes = append(notes, fmt.Sprintf("the parallel handshakes were dropped in %d round(s) while the single handshake right after each burst passed: the rule acted on the burst itself, no lasting freeze of the address was observed", dropped))
	}
	return notes
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
