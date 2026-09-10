package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/classify"
)

// Style controls the human report: colours and glyphs on a terminal, plain
// ASCII in a file or a pipe.
type Style struct {
	Color   bool
	Verbose bool // include passing cells; compact mode shows only anomalies
}

// AutoStyle picks colours when w is a terminal and NO_COLOR is unset.
func AutoStyle(w io.Writer) Style {
	if os.Getenv("NO_COLOR") != "" {
		return Style{}
	}
	if f, ok := w.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return Style{Color: true}
		}
	}
	return Style{}
}

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cCyan   = "\x1b[36m"
)

func (s Style) paint(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return code + text + cReset
}

func (s Style) bold(t string) string   { return s.paint(cBold, t) }
func (s Style) dim(t string) string    { return s.paint(cDim, t) }
func (s Style) red(t string) string    { return s.paint(cRed, t) }
func (s Style) green(t string) string  { return s.paint(cGreen, t) }
func (s Style) yellow(t string) string { return s.paint(cYellow, t) }
func (s Style) cyan(t string) string   { return s.paint(cCyan, t) }

// Glyphs: ✓ pass, ✗ fail, ~ mixed, · n/a.
func (s Style) glyphFor(c classify.Cell) string {
	switch {
	case c.Total == 0:
		return s.dim("·")
	case c.OK == c.Total:
		return s.green("✓")
	case c.OK == 0:
		return s.red("✗")
	default:
		return s.yellow("~")
	}
}

// OutcomeGlyph is the one-character status of an attempt outcome, for the
// scan progress line.
func (s Style) OutcomeGlyph(outcome string) string {
	switch outcome {
	case "ok":
		return s.green("✓")
	case "skipped", "inconclusive", "server_error":
		return s.yellow("~")
	}
	return s.red("✗")
}

// PaintOutcome colours an outcome name like its glyph.
func (s Style) PaintOutcome(outcome string) string {
	switch outcome {
	case "ok":
		return s.green(outcome)
	case "skipped", "inconclusive", "server_error":
		return s.yellow(outcome)
	}
	return s.red(outcome)
}

func (s Style) confidence(conf string) string {
	switch conf {
	case "high":
		return s.red(conf)
	case "medium":
		return s.yellow(conf)
	}
	return s.dim(conf)
}

func dominant(c classify.Cell) string {
	dom, best := "", -1
	for k, v := range c.Merged {
		if v > best || (v == best && k < dom) {
			dom, best = k, v
		}
	}
	return dom
}

func family(test string) string {
	if i := strings.IndexByte(test, '.'); i > 0 {
		return test[:i]
	}
	return test
}

// WriteStyled prints the human summary with the given style.
func (r *Report) WriteStyled(w io.Writer, s Style) {
	kv := func(k, v string) string { return s.dim(k+" ") + v }
	target := kv("target", fmt.Sprintf("%s:%d", r.Target, r.ControlPort))
	if r.Sites() {
		target = kv("mode", "real destinations, no probe server")
	}
	fmt.Fprintf(w, "%s  %s\n", s.bold("CensorPulse probe report"), strings.Join([]string{target, kv("client", r.ClientVersion)}, "  "))
	fmt.Fprintf(w, "%s\n", strings.Join([]string{
		kv("started", r.StartedAt.Format("2006-01-02 15:04:05 MST")),
		kv("duration", r.FinishedAt.Sub(r.StartedAt).Round(100*time.Millisecond).String()),
	}, "  "))
	unreachable := !r.ProbeReached && !r.Sites()
	if unreachable {
		fmt.Fprintf(w, "\n%s %s\n", s.red(s.bold("PROBE UNREACHABLE")), r.BootstrapErr)
		if len(r.Attempts) == 0 {
			return
		}
		// The real-destinations family needs no server and ran anyway.
		fmt.Fprintln(w, s.dim("the real-destinations family ran without the control point:"))
	}
	if !r.Sites() && !unreachable {
		pin := s.green("enforced")
		if !r.PinEnforced {
			pin = s.yellow("trust-on-first-use")
		}
		sid := r.SessionID
		if len(sid) > 12 {
			sid = sid[:12] + "…"
		}
		meta := []string{kv("session", sid)}
		if r.Params != nil && r.Params.ServerVersion != "" {
			meta = append(meta, kv("server", r.Params.ServerVersion))
		}
		meta = append(meta, kv("pin", pin))
		if r.ClientAddr != "" {
			meta = append(meta, kv("client_addr", r.ClientAddr))
		}
		if r.ControlRTTms > 0 {
			meta = append(meta, kv("rtt", formatMillis(r.ControlRTTms)))
		}
		if r.TimeoutMs > 0 {
			meta = append(meta, kv("timeout", formatMillis(r.TimeoutMs)))
		}
		fmt.Fprintln(w, strings.Join(meta, "  "))
	} else if r.TimeoutMs > 0 {
		fmt.Fprintln(w, kv("timeout", formatMillis(r.TimeoutMs)))
	}
	if n := r.Network; n != nil && (n.ASN != 0 || n.Country != "") {
		fmt.Fprintf(w, "%s\n", strings.TrimSpace(kv("network", fmt.Sprintf("AS%d %s (%s) %s", n.ASN, n.Org, n.Country, n.Prefix))))
	}
	for _, wn := range r.Warnings {
		fmt.Fprintf(w, "%s %s\n", s.yellow(s.bold("WARNING")), wn)
	}
	if r.Health != nil {
		var bad []string
		for k, v := range r.Health.Listeners {
			if v != "ok" {
				bad = append(bad, k+"="+v)
			}
		}
		sort.Strings(bad)
		if len(bad) > 0 {
			fmt.Fprintf(w, "%s listener problems on the server: %s\n", s.yellow(s.bold("WARNING")), strings.Join(bad, ", "))
		}
	}

	// Cells, grouped by family, with a status glyph per cell. Compact output
	// keeps the useful overview but omits the often 100+ passing rows; the raw
	// cells always remain in the JSON report.
	pass, fail, mixed := 0, 0, 0
	type familyCount struct{ pass, fail, mixed int }
	families := map[string]*familyCount{}
	familyOrder := []string{}
	for _, c := range r.Cells {
		f := family(c.TestID)
		fc := families[f]
		if fc == nil {
			fc = &familyCount{}
			families[f] = fc
			familyOrder = append(familyOrder, f)
		}
		switch {
		case c.Total > 0 && c.OK == c.Total:
			pass++
			fc.pass++
		case c.Total > 0 && c.OK == 0:
			fail++
			fc.fail++
		case c.Total > 0:
			mixed++
			fc.mixed++
		}
	}
	fmt.Fprintf(w, "\n%s  %s\n", s.bold("RESULTS"), s.dim(fmt.Sprintf("%d cells: %s %d ok, %s %d failed, %s %d mixed",
		len(r.Cells), s.green("✓"), pass, s.red("✗"), fail, s.yellow("~"), mixed)))
	if len(familyOrder) > 0 {
		parts := make([]string, 0, len(familyOrder))
		for _, f := range familyOrder {
			fc := families[f]
			total := fc.pass + fc.fail + fc.mixed
			status := s.green("✓")
			if fc.fail > 0 {
				status = s.red("✗")
			} else if fc.mixed > 0 {
				status = s.yellow("~")
			}
			parts = append(parts, fmt.Sprintf("%s %s %d/%d", status, f, fc.pass, total))
		}
		for i := 0; i < len(parts); i += 5 {
			end := i + 5
			if end > len(parts) {
				end = len(parts)
			}
			label := "         "
			if i == 0 {
				label = s.dim("coverage:")
			}
			fmt.Fprintf(w, "%s %s\n", label, strings.Join(parts[i:end], "  "))
		}
	}
	// Columns are padded on the plain text and coloured afterwards, since
	// escape sequences would otherwise count towards the width.
	type row struct {
		plain []string
		paint []func(string) string
		sep   bool
	}
	id := func(t string) string { return t }
	head := row{plain: []string{" ", "TEST", "WHERE", "VARIANT", "ROLE", "OK", "DOMINANT (client+server)", "SAW"}}
	head.paint = []func(string) string{id, s.dim, s.dim, s.dim, s.dim, s.dim, s.dim, s.dim}
	rows := []row{head}
	lastFamily := ""
	for _, c := range r.Cells {
		if !s.Verbose && c.Total > 0 && c.OK == c.Total {
			continue
		}
		if f := family(c.TestID); f != lastFamily {
			if lastFamily != "" {
				rows = append(rows, row{sep: true})
			}
			lastFamily = f
		}
		okPaint, domPaint := id, s.dim
		switch {
		case c.Total > 0 && c.OK == 0:
			okPaint, domPaint = s.red, s.red
		case c.Total > 0 && c.OK < c.Total:
			okPaint, domPaint = s.yellow, s.yellow
		}
		rolePaint := s.dim
		if c.Role == "baseline" {
			rolePaint = s.cyan
		}
		glyph := s.glyphFor(c)
		rows = append(rows, row{
			plain: []string{"?", c.TestID, fmt.Sprintf("%s/%d", c.Transport, c.Port), c.Variant, c.Role, fmt.Sprintf("%d/%d", c.OK, c.Total), dominant(c), fmt.Sprint(c.ServerSaw)},
			paint: []func(string) string{func(string) string { return glyph }, id, id, id, rolePaint, okPaint, domPaint, id},
		})
	}
	if len(rows) == 1 {
		fmt.Fprintf(w, "%s\n", s.green("All result cells passed."))
	} else if !s.Verbose {
		fmt.Fprintf(w, "%s\n", s.bold("ANOMALIES"))
	}
	widths := make([]int, len(head.plain))
	for _, rw := range rows {
		for i, col := range rw.plain {
			if n := len([]rune(col)); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, rw := range rows {
		if len(rows) == 1 {
			continue
		}
		if rw.sep {
			fmt.Fprintln(w)
			continue
		}
		parts := make([]string, len(rw.plain))
		for i, col := range rw.plain {
			pad := strings.Repeat(" ", widths[i]-len([]rune(col)))
			if i == len(rw.plain)-1 {
				pad = ""
			}
			parts[i] = rw.paint[i](col) + pad
		}
		fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
	}

	// Real destinations: one line per site; compact output keeps the ones
	// that are not clear.
	if len(r.Destinations) > 0 {
		clear := 0
		for _, d := range r.Destinations {
			if d.Verdict == "clear" {
				clear++
			}
		}
		fmt.Fprintf(w, "\n%s  %s\n", s.bold("DESTINATIONS"), s.dim(fmt.Sprintf("%d sites: %s %d clear, %d not", len(r.Destinations), s.green("✓"), clear, len(r.Destinations)-clear)))
		layers := []string{"dns", "tcp", "tls", "decoy", "absent", "http"}
		for _, d := range r.Destinations {
			if !s.Verbose && d.Verdict == "clear" {
				continue
			}
			glyph, paint := s.red("✗"), s.red
			switch d.Verdict {
			case "clear":
				glyph, paint = s.green("✓"), s.green
			case "degraded", "inconclusive", "nxdomain":
				glyph, paint = s.yellow("~"), s.yellow
			}
			var parts []string
			for _, l := range layers {
				v, ok := d.Layers[l]
				if !ok {
					continue
				}
				if v == "ok" {
					parts = append(parts, s.dim(l+" ok"))
				} else {
					parts = append(parts, l+" "+paint(v))
				}
			}
			verdict := paint(d.Verdict)
			if d.Confidence != "" {
				verdict += " " + s.dim("["+d.Confidence+"]")
			}
			fmt.Fprintf(w, "  %s %-24s %-10s %s\n      %s\n", glyph, d.Domain, s.dim(d.Category), verdict, strings.Join(parts, s.dim(" · ")))
		}
		if !s.Verbose && clear == len(r.Destinations) {
			fmt.Fprintf(w, "  %s\n", s.green("every site is clear on every layer"))
		}
	}

	// Verdicts.
	fmt.Fprintln(w)
	if len(r.Verdicts) == 0 {
		fmt.Fprintf(w, "%s %s\n", s.green(s.bold("VERDICTS: none.")), r.Summary)
	} else {
		fmt.Fprintf(w, "%s  %s\n", s.bold(fmt.Sprintf("VERDICTS (%d)", len(r.Verdicts))), s.dim("behaviour compatible with …, not attribution"))
		for _, v := range r.Verdicts {
			fmt.Fprintf(w, "\n  %s %s  [%s]  %s\n", s.red("✗"), s.bold(v.Kind), s.confidence(v.Confidence), s.cyan(v.Subject))
			for _, e := range v.Evidence {
				fmt.Fprintf(w, "      %s %s\n", s.dim("·"), e)
			}
		}
		fmt.Fprintf(w, "\n%s %s\n", s.bold("summary:"), r.Summary)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "%s %s\n", s.dim("note:"), n)
	}
}

func formatMillis(ms float64) string {
	if ms > 0 && ms < 1 {
		return "<1 ms"
	}
	return fmt.Sprintf("%.0f ms", ms)
}
