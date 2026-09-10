// cpprobe is the CensorPulse probe: `cpprobe server` runs the control point,
// `cpprobe scan` runs the client test catalog against one IP.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/xarvel/CensorPulseCli/engine"
	"github.com/xarvel/CensorPulseCli/internal/classify"
	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/dest"
	"github.com/xarvel/CensorPulseCli/internal/geoip"
	"github.com/xarvel/CensorPulseCli/internal/report"
	"github.com/xarvel/CensorPulseCli/internal/server"
)

var version = "dev"

func main() {
	if version == "dev" {
		// `go install …/cmd/cpprobe@vX.Y.Z` applies no ldflags; the module
		// version is in the build info instead. Local builds say "(devel)".
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
	server.Version = version
	engine.Version = version
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "sites":
		err = runSites(os.Args[2:])
	case "keys":
		err = runKeys(os.Args[2:])
	case "classify":
		err = runClassify(os.Args[2:])
	case "config":
		err = runConfig(os.Args[2:])
	case "tests":
		err = runTests(os.Args[2:])
	case "geoip":
		err = runGeoIP(os.Args[2:])
	case "version":
		fmt.Println("cpprobe", version)
	case "-h", "--help", "help":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "scan":
				err = runScan([]string{"--help"})
			case "sites":
				err = runSites([]string{"--help"})
			case "classify":
				err = runClassify([]string{"--help"})
			case "server":
				err = runServer([]string{"--help"})
			case "geoip":
				err = runGeoIP([]string{"--help"})
			case "tests":
				err = runTests([]string{"--help"})
			case "keys":
				err = runKeys([]string{"--help"})
			case "config":
				fmt.Println("usage: cpprobe config\n\nPrints the default server configuration (probe.yaml) with comments.")
			default:
				usage()
			}
		} else {
			usage()
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cpprobe - CensorPulse DPI probe

Usage:
  cpprobe server [--config probe.yaml] [--data-dir ./data] [--bind ADDR]
  cpprobe scan   --target IP [--pin SPKI] [--profile full|quick] [--sites] [--out report.json]
  cpprobe sites  [--targets FILE] [--out report.json]   real destinations only, no probe server
  cpprobe keys   [--data-dir ./data]        print the SPKI pin and WireGuard public key
  cpprobe classify --in report.json [--out new.json]   recompute cells and verdicts from the raw attempts
  cpprobe tests                             list test ids and scan profiles
  cpprobe geoip update [--dir DIR]          update offline ASN/country tables
  cpprobe config                            print the default server configuration
  cpprobe version

Examples:
  cpprobe scan --target 203.0.113.10 --pin '<spki-pin>'
  cpprobe scan --target 203.0.113.10 --profile quick
  cpprobe scan --target 203.0.113.10 --plan
  cpprobe scan --target 203.0.113.10 --profile quick --sites
  cpprobe sites --geoip-online

`)
}

func runTests(args []string) error {
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
		return fmt.Errorf("tests takes no arguments")
	}
	quickTests := client.QuickTests()
	quick := make(map[string]bool, len(quickTests))
	for _, t := range quickTests {
		quick[t] = true
	}
	fmt.Println("Scan profiles:")
	fmt.Println("  full   complete catalog, 3 rounds (default; stateful/rate tests run last)")
	fmt.Println("  quick  the phone profile: about forty flows in one round, the ports that")
	fmt.Println("         failed get two more rounds; web ports, TLS, DNS, QUIC and the VPN")
	fmt.Println("         session tests (OpenVPN, WireGuard, obfs4, VLESS-Reality) on their usual ports")
	fmt.Println("\nTest ids (* = drawn from by quick, s = real destinations, needs no server):")
	tests := engine.KnownTests()
	sort.Strings(tests)
	for _, t := range tests {
		mark := " "
		if quick[t] {
			mark = "*"
		}
		if client.IsDestTest(t) {
			mark = "s"
		}
		fmt.Printf("  %s %s\n", mark, t)
	}
	fmt.Println("\nSelect individual tests with: --tests tcp.echo,tls.sni")
	fmt.Println("The dest.* family visits real sites (DNS system vs DoH, TCP, SNI differential,")
	fmt.Println("HTTP 451): add it to a scan with --sites, or run it alone with: cpprobe sites")
	return nil
}

// loadTargets reads a --targets file into the text the engine parses; empty
// path = the built-in catalog.
func loadTargets(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("targets: %w", err)
	}
	if _, err := dest.Parse(strings.NewReader(string(b))); err != nil {
		return "", fmt.Errorf("targets: %w", err)
	}
	return string(b), nil
}

// loadSNIList reads a --sni-list file: one name per line, `#` comments and
// trailing notes ignored.
func loadSNIList(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sni-list: %w", err)
	}
	var snis []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if i := strings.IndexAny(l, " \t#"); i >= 0 {
			l = strings.TrimSpace(l[:i]) // "domain  # comment" and table-ish lines
		}
		if l != "" {
			snis = append(snis, l)
		}
	}
	return snis, nil
}

// cliRetry maps the --retry flag to engine.Config.Retry: the flag's -1
// means "profile default" (engine 0), the flag's 0 means none (engine -1).
func cliRetry(flag int) int {
	switch flag {
	case -1:
		return 0
	case 0:
		return -1
	}
	return flag
}

// cliRanges rejects zero and out-of-range values of the numeric flags with
// the flag's name, before the engine would take a zero for "default": a
// mistyped flag fails like it always did.
func cliRanges(port, parallel int, timeout time.Duration, bulkKB, sessionPkts, sniSample, burstN int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	if parallel < 1 || parallel > 32 {
		return fmt.Errorf("--parallel must be between 1 and 32")
	}
	if timeout < 500*time.Millisecond {
		return fmt.Errorf("--timeout must be at least 500ms")
	}
	if bulkKB < 1 || bulkKB > 1024 {
		return fmt.Errorf("--bulk-kb must be between 1 and 1024")
	}
	if sessionPkts < 3 || sessionPkts > 256 {
		return fmt.Errorf("--session-packets must be between 3 and 256")
	}
	if sniSample < 0 {
		return fmt.Errorf("--sni-sample cannot be negative")
	}
	if burstN < 2 || burstN > 32 {
		return fmt.Errorf("--burst-n must be between 2 and 32")
	}
	return nil
}

// cliHooks wires the engine's callbacks to the terminal: the progress line
// on stderr and advisory notices, unless --quiet.
func cliHooks(progressStyle report.Style, quiet bool) (engine.Hooks, func()) {
	progress, done := progressPrinter(progressStyle, quiet)
	hooks := engine.Hooks{Progress: progress}
	if !quiet {
		hooks.Notice = func(msg string) { fmt.Fprintln(os.Stderr, msg) }
	}
	return hooks, done
}

// runSites runs the real-destinations family without a probe server.
func runSites(args []string) error {
	fs := flag.NewFlagSet("sites", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file with one destination per line (default: the built-in catalog; see 'cpprobe help sites')")
	tests := fs.String("tests", "", "comma-separated dest.* test ids (default: the whole family)")
	repeat := fs.Int("repeat", 1, "rounds per plan")
	retry := fs.Int("retry", 2, "extra rounds for the sites that had a failure in the first rounds")
	parallel := fs.Int("parallel", 4, "concurrent attempts")
	timeout := fs.Duration("timeout", 6*time.Second, "per-attempt timeout")
	deadline := fs.Duration("deadline", 2*time.Minute, "wall-clock cap for the whole run (0 = none); a blackholed network must not hang the caller")
	out := fs.String("out", "", "write JSON report here (default: sites-<timestamp>.json)")
	quiet := fs.Bool("quiet", false, "no progress output")
	local := fs.String("local-addr", "", "bind sockets to this local IP")
	jsonOnly := fs.Bool("json", false, "print JSON report to stdout instead of the text summary")
	bypass := fs.Bool("bypass-check", true, "warn when a known VPN/circumvention tool is running")
	geoipOnline := fs.Bool("geoip-online", false, "ask a public geo-ASN API (ipwho.is, then ipapi.co) for the network's ASN/country; without a server the client does not know its own address, so the offline tables cannot be used here; the address the API returns is discarded")
	color := fs.String("color", "auto", "colour the text report and progress: auto|always|never (NO_COLOR is honoured)")
	planOnly := fs.Bool("plan", false, "show the selected plan without running it or writing a report")
	verbose := fs.Bool("verbose", false, "show every result cell and every site (default: anomalies and the sites that are not clear)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cpprobe sites [flags]")
		fmt.Fprintln(os.Stderr, "\nRuns the real-destinations family alone: DNS (system resolver against three DoH")
		fmt.Fprintln(os.Stderr, "resolvers), TCP :443, the SNI differential (real name, decoy name, no name on the")
		fmt.Fprintln(os.Stderr, "same address) and an HTTP 451 check, against the built-in catalog or --targets.")
		fmt.Fprintln(os.Stderr, "Traffic goes to those sites, to Cloudflare/Google/Quad9 DoH and to 1.1.1.1/9.9.9.9.")
		fmt.Fprintln(os.Stderr, "\n--targets file: one site per line, `#` comments; options after the domain:")
		fmt.Fprintln(os.Stderr, "  category=news  label=\"...\"  ip=1.2.3.4,5.6.7.8  sni=name  dns=name  tcp-only  no-dns  http")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if err := validateColor(*color); err != nil {
		return err
	}
	if *retry < -1 {
		return fmt.Errorf("--retry must be between 0 and 10")
	}
	if *repeat < 1 {
		return fmt.Errorf("--repeat must be between 1 and 10")
	}
	if *deadline < 0 {
		return fmt.Errorf("--deadline cannot be negative")
	}
	if err := cliRanges(8443, *parallel, *timeout, 64, 12, 0, 4); err != nil {
		return err
	}
	testList, err := engine.ParseTests(*tests)
	if err != nil {
		return err
	}
	for _, t := range testList {
		if !client.IsDestTest(t) {
			return fmt.Errorf("test %s needs a probe server: use 'cpprobe scan --target IP --sites --tests %s'", t, t)
		}
	}
	targets, err := loadTargets(*targetsFile)
	if err != nil {
		return err
	}
	cfg := engine.Config{Sites: true, Targets: targets, Tests: testList, Repeat: *repeat, Retry: cliRetry(*retry), Parallel: *parallel,
		Timeout: *timeout, Deadline: *deadline, LocalAddr: *local, DetectBypass: *bypass, GeoIPOnline: *geoipOnline}
	if err := cfg.Validate(); err != nil {
		return err
	}
	style := styleFor(*color, os.Stdout)
	style.Verbose = *verbose
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	hooks, progressDone := cliHooks(styleFor(*color, os.Stderr), *quiet)
	s, err := engine.Prepare(ctx, cfg, hooks)
	if err != nil {
		return err
	}
	d := s.Config()
	if *planOnly {
		writePlan(os.Stdout, s.Plans(), d.Repeat, d.Retry, d.Parallel, "sites")
		return nil
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "real destinations: %d plans × %d %s%s, %d parallel\n", len(s.Plans()), d.Repeat, plural(d.Repeat, "round", "rounds"), retryNote(d.Retry), d.Parallel)
	}
	rep, err := s.Run(ctx)
	progressDone()
	if err != nil {
		return err
	}
	if *out == "" {
		*out = "sites-" + rep.StartedAt.UTC().Format("20060102-150405") + ".json"
	}
	return finish(rep, *out, *jsonOnly, style)
}

// progressPrinter is the per-attempt progress line on stderr.
func progressPrinter(progressStyle report.Style, quiet bool) (func(engine.Progress), func()) {
	tty := false
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		tty = true
	}
	okCount, failCount := 0, 0
	progress := func(a engine.Progress) {
		if quiet {
			return
		}
		failed := a.Outcome != client.OutcomeOK
		if failed {
			failCount++
		} else {
			okCount++
		}
		where := fmt.Sprintf("%s/%d", a.Transport, a.Port)
		line := fmt.Sprintf("%s [%3d/%3d] %-18s %-10s %-26s %s", progressStyle.OutcomeGlyph(a.Outcome), a.Done, a.Total, a.TestID, where, a.Variant, progressStyle.PaintOutcome(a.Outcome))
		if !tty {
			fmt.Fprintln(os.Stderr, line)
			return
		}
		// On a terminal the running line is overwritten in place; failures
		// are left standing so that they are not lost under the next line.
		fmt.Fprintf(os.Stderr, "\r\x1b[2K%s", line)
		if failed {
			fmt.Fprintln(os.Stderr)
		}
	}
	done := func() {
		if quiet {
			return
		}
		if tty {
			fmt.Fprint(os.Stderr, "\r\x1b[2K")
		}
		fmt.Fprintf(os.Stderr, "done: %d attempts, %s ok, %s failed\n", okCount+failCount, progressStyle.PaintOutcome("ok")+" "+fmt.Sprint(okCount), fmt.Sprint(failCount))
	}
	return progress, done
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "", "YAML config (defaults are used when empty)")
	dataDir := fs.String("data-dir", "", "override data_dir")
	bind := fs.String("bind", "", "override bind address")
	logLevel := fs.String("log", "", "override log level: debug|info")
	fs.Parse(args)
	cfg, err := server.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *bind != "" {
		cfg.Bind = *bind
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}
	lvl := slog.LevelInfo
	if cfg.Log.Level == "debug" {
		lvl = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	srv, err := server.New(cfg, logger)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	fmt.Fprintf(os.Stderr, "SPKI pin: %s\nWireGuard public key: %s\n", srv.Keys().SPKIPin, base64.StdEncoding.EncodeToString(srv.Keys().WG.Public[:]))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("shutting down")
	return srv.Close()
}

func runKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	fs.Parse(args)
	k, err := server.LoadOrCreateKeys(*dataDir)
	if err != nil {
		return err
	}
	fmt.Printf("spki_pin: %s\nwg_public_key: %s\n", k.SPKIPin, base64.StdEncoding.EncodeToString(k.WG.Public[:]))
	return nil
}

// runClassify re-derives cells and verdicts from a report's raw attempts with
// the classifier of this build, so that old reports benefit from newer rules.
func runClassify(args []string) error {
	fs := flag.NewFlagSet("classify", flag.ExitOnError)
	in := fs.String("in", "", "report JSON to reclassify (required)")
	out := fs.String("out", "", "write the reclassified report here (default: print the text summary only)")
	jsonOnly := fs.Bool("json", false, "print the reclassified JSON to stdout")
	verbose := fs.Bool("verbose", false, "show every result cell (default: anomalies and family coverage)")
	color := fs.String("color", "auto", "colour the text report: auto|always|never (NO_COLOR is honoured)")
	fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	if err := validateColor(*color); err != nil {
		return err
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	var rep report.Report
	if err := json.NewDecoder(f).Decode(&rep); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	// The merge table is re-applied too: the report carries every server
	// observation. The clock skew is what the scan would have estimated,
	// from the params timestamp against the scan's start.
	var skew time.Duration
	if rep.Params != nil {
		skew = client.EstimateSkew(rep.Params.ServerTime, rep.StartedAt, rep.StartedAt.Add(time.Duration(rep.ControlRTTms*float64(time.Millisecond))))
	}
	client.Remerge(rep.Attempts, skew)
	var res classify.Result
	if rep.Sites() {
		res = classify.ClassifyStandalone(rep.Attempts)
	} else {
		res = classify.Classify(rep.Attempts, rep.ProbeReached)
	}
	rep.Cells, rep.Verdicts, rep.Summary, rep.Destinations = res.Cells, res.Verdicts, res.Summary, res.Destinations
	// Notes derived from the attempts are rewritten by this build; the
	// scan's own notes (errors, pin, geoip) stay.
	var kept []string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "tls.burst deliberately") || strings.HasPrefix(n, "a burst freeze was observed") || strings.HasPrefix(n, "the parallel handshakes were dropped") || strings.HasPrefix(n, "transient outage:") || strings.HasPrefix(n, "reclassified by cpprobe") {
			continue
		}
		kept = append(kept, n)
	}
	rep.Notes = append(kept, engine.BurstNotes(rep.Attempts)...)
	rep.Notes = append(rep.Notes, res.Notes...)
	rep.Notes = append(rep.Notes, "reclassified by cpprobe "+version)
	if *out != "" {
		w, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer w.Close()
		if err := rep.WriteJSON(w); err != nil {
			return err
		}
	}
	if *jsonOnly {
		return rep.WriteJSON(os.Stdout)
	}
	style := styleFor(*color, os.Stdout)
	style.Verbose = *verbose
	rep.WriteStyled(os.Stdout, style)
	return nil
}

func runConfig(args []string) error {
	cfg := server.Default()
	fmt.Print(server.RenderDefault(cfg))
	return nil
}

func runGeoIP(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: cpprobe geoip update [--dir DIR]")
		return nil
	}
	if args[0] != "update" {
		return fmt.Errorf("unknown geoip command %q (expected: update)", args[0])
	}
	fs := flag.NewFlagSet("geoip update", flag.ExitOnError)
	dir := fs.String("dir", geoip.DefaultDir(), "directory for GeoLite2 CSV tables")
	fs.Parse(args[1:])
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	fmt.Fprintf(os.Stderr, "Updating offline GeoIP tables in %s\n", *dir)
	err := geoip.Update(ctx, *dir, func(name string, n int64) {
		fmt.Fprintf(os.Stderr, "  ✓ %-40s %.1f MB\n", name, float64(n)/(1024*1024))
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "GeoIP tables are ready; future scans will record ASN and country.")
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	target := fs.String("target", "", "IP address of the control point (required)")
	port := fs.Int("port", 8443, "control port")
	pin := fs.String("pin", "", "expected SPKI pin (base64); empty = trust on first use")
	tests := fs.String("tests", "", "comma-separated test ids (default: all the server offers)")
	repeat := fs.Int("repeat", 0, "rounds per plan (default: 3 for full, 1 for quick)")
	retry := fs.Int("retry", -1, "extra rounds for the port groups that had a failure in the first rounds (default: 0 for full, 2 for quick)")
	parallel := fs.Int("parallel", 4, "concurrent attempts")
	timeout := fs.Duration("timeout", 6*time.Second, "per-attempt timeout")
	trigger := fs.String("trigger-host", "www.youtube.com", "Host/SNI used as the trigger variant")
	out := fs.String("out", "", "write JSON report here (default: report-<timestamp>.json)")
	quiet := fs.Bool("quiet", false, "no progress output")
	local := fs.String("local-addr", "", "bind sockets to this local IP")
	jsonOnly := fs.Bool("json", false, "print JSON report to stdout instead of the text summary")
	sniList := fs.String("sni-list", "", "file with one SNI per line: each is tried as tls.sni and as a TLS bulk upload")
	bulkKB := fs.Int("bulk-kb", 64, "size of each bulk transfer in KB (tcp.bulk)")
	realitySNI := fs.String("reality-sni", "www.microsoft.com", "foreign SNI carried by the vless.reality ClientHello (a name that does not belong to the probe IP)")
	sessionPkts := fs.Int("session-packets", 12, "data packets exchanged after the handshake in wireguard.session / openvpn.session")
	adaptive := fs.Bool("adaptive-timeout", true, "derive per-attempt timeouts from the control RTT (6×RTT+0.5s, within 1.5s..--timeout)")
	bypass := fs.Bool("bypass-check", true, "warn when a known VPN/circumvention tool is running")
	sniSample := fs.Int("sni-sample", 0, "use only N randomly chosen entries of --sni-list (0 = all)")
	burstN := fs.Int("burst-n", 4, "parallel handshakes per tls.burst attempt")
	geoipDir := fs.String("geoip-dir", geoip.DefaultDir(), "directory with GeoLite2 CSV tables (see: cpprobe geoip update); records ASN/country offline")
	color := fs.String("color", "auto", "colour the text report and progress: auto|always|never (NO_COLOR is honoured)")
	profile := fs.String("profile", "full", "scan profile: full|quick (--tests overrides it)")
	planOnly := fs.Bool("plan", false, "connect and show the selected plan without running it or writing a report")
	verbose := fs.Bool("verbose", false, "show every result cell (default: anomalies and family coverage)")
	sites := fs.Bool("sites", false, "also run the real-destinations family (dest.*: DNS system vs DoH, TCP, SNI differential, HTTP 451 against real sites); traffic then leaves for those sites and the DoH resolvers")
	targetsFile := fs.String("targets", "", "with --sites: file with one destination per line instead of the built-in catalog (see 'cpprobe help sites')")
	geoipOnline := fs.Bool("geoip-online", false, "when the offline tables are absent, ask a public geo-ASN API (ipwho.is, then ipapi.co) for the network's ASN/country")
	fs.Parse(args)
	if *retry < -1 {
		return fmt.Errorf("--retry must be between 0 and 10")
	}
	if *repeat < 0 {
		return fmt.Errorf("--repeat must be between 1 and 10")
	}
	if err := cliRanges(*port, *parallel, *timeout, *bulkKB, *sessionPkts, *sniSample, *burstN); err != nil {
		return err
	}
	if err := validateColor(*color); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("--target is required (example: cpprobe scan --target 203.0.113.10 --pin '<spki-pin>')")
	}
	testList, err := engine.ParseTests(*tests)
	if err != nil {
		return err
	}
	for _, t := range testList {
		if client.IsDestTest(t) {
			*sites = true
		}
	}
	if *targetsFile != "" && !*sites {
		return fmt.Errorf("--targets needs --sites")
	}
	targets, err := loadTargets(*targetsFile)
	if err != nil {
		return err
	}
	snis, err := loadSNIList(*sniList)
	if err != nil {
		return err
	}
	// The quick profile is a filter over whatever the server offers (see
	// quickFilter and its fallbacks), not a list of required tests: a server
	// without one of its ids must not abort the scan.
	cfg := engine.Config{Target: *target, ControlPort: *port, Pin: *pin, Tests: testList, Profile: *profile,
		Repeat: *repeat, Retry: cliRetry(*retry), Parallel: *parallel, Timeout: *timeout, NoAdaptiveTimeout: !*adaptive,
		TriggerHost: *trigger, SNIList: snis, SNISample: *sniSample, BulkKB: *bulkKB, SessionPackets: *sessionPkts,
		RealitySNI: *realitySNI, BurstN: *burstN, LocalAddr: *local, DetectBypass: *bypass, Sites: *sites, Targets: targets,
		GeoIPDir: *geoipDir, GeoIPOnline: *geoipOnline}
	if err := cfg.Validate(); err != nil {
		return err
	}
	style := styleFor(*color, os.Stdout)
	style.Verbose = *verbose
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	hooks, progressDone := cliHooks(styleFor(*color, os.Stderr), *quiet)
	s, err := engine.Prepare(ctx, cfg, hooks)
	if err != nil {
		return err
	}
	if !s.Reachable() {
		rep, _ := s.Run(ctx)
		return finish(rep, *out, *jsonOnly, style)
	}
	d := s.Config()
	scanProfile := d.Profile
	if len(d.Tests) > 0 {
		scanProfile = "custom" // --tests overrides the profile's plan selection
	}
	if *planOnly {
		writePlan(os.Stdout, s.Plans(), d.Repeat, d.Retry, d.Parallel, scanProfile)
		return nil
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "session %s: %d plans × %d %s%s, %d parallel\n", s.SessionID(), len(s.Plans()), d.Repeat, plural(d.Repeat, "round", "rounds"), retryNote(d.Retry), d.Parallel)
	}
	rep, err := s.Run(ctx)
	progressDone()
	if err != nil {
		return err
	}
	return finish(rep, *out, *jsonOnly, style)
}

// styleFor resolves --color for a stream.
func styleFor(mode string, w *os.File) report.Style {
	switch mode {
	case "always":
		return report.Style{Color: true}
	case "never":
		return report.Style{}
	}
	return report.AutoStyle(w)
}

func validateColor(mode string) error {
	switch mode {
	case "auto", "always", "never":
		return nil
	default:
		return fmt.Errorf("--color must be auto, always, or never (got %q)", mode)
	}
}

// retryNote describes the retry rounds in the plan and session lines.
func retryNote(retry int) string {
	if retry <= 0 {
		return ""
	}
	return fmt.Sprintf(" (+%d retry %s for the ports with a failure)", retry, plural(retry, "round", "rounds"))
}

func writePlan(w io.Writer, plans []engine.Plan, repeat, retry, parallel int, profile string) {
	counts := map[string]int{}
	order := []string{}
	for _, p := range plans {
		if _, ok := counts[p.TestID]; !ok {
			order = append(order, p.TestID)
		}
		counts[p.TestID]++
	}
	fmt.Fprintf(w, "Scan plan: %s profile, %d %s × %d %s%s = %d %s, %d parallel\n\n",
		profile, len(plans), plural(len(plans), "plan", "plans"), repeat, plural(repeat, "round", "rounds"), retryNote(retry),
		len(plans)*repeat, plural(len(plans)*repeat, "attempt", "attempts"), parallel)
	for _, t := range order {
		n := counts[t]
		a := n * repeat
		fmt.Fprintf(w, "  %-24s %d %s (%d %s)\n", t, n, plural(n, "plan", "plans"), a, plural(a, "attempt", "attempts"))
	}
	fmt.Fprintln(w, "\nNo tests were run and no report was written.")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func finish(rep *report.Report, out string, jsonOnly bool, style report.Style) error {
	if out == "" {
		out = "report-" + rep.StartedAt.UTC().Format("20060102-150405") + ".json"
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := rep.WriteJSON(f); err != nil {
		return err
	}
	f.Close()
	if jsonOnly {
		return rep.WriteJSON(os.Stdout)
	}
	rep.WriteStyled(os.Stdout, style)
	fmt.Printf("\nFull JSON report: %s\n", out)
	if !style.Verbose && len(rep.Cells) > 0 {
		fmt.Printf("Every result cell: cpprobe classify --in %s --verbose\n", out)
	}
	if !rep.ProbeReached && !rep.Sites() {
		return fmt.Errorf("probe unreachable")
	}
	return nil
}
