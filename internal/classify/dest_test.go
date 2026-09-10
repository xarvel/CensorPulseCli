package classify

import (
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// mkDest builds a dest.* attempt; merged equals the outcome for the family.
func mkDest(test, role, variant string, port int, outcome string, detail map[string]string) *client.Attempt {
	tr := "tcp"
	if test == "dest.dns" || test == "dest.nxdomain" {
		tr, port = "udp", 53
	}
	a := &client.Attempt{TestID: test, Role: role, Variant: variant, Transport: tr, DstPort: port, Outcome: outcome, Merged: outcome, Detail: map[string]string{}}
	for k, v := range detail {
		a.Detail[k] = v
	}
	if d := destDomain(variant); variant != "anycast" && variant != "invalid" {
		a.Detail["domain"] = d
	}
	return a
}

func destSite(domain, category string, n int, dns, tcp, tls, decoy, absent string) []*client.Attempt {
	var at []*client.Attempt
	meta := map[string]string{"category": category}
	for i := 0; i < n; i++ {
		at = append(at, mkDest("dest.dns", "variant", domain, 53, dns, meta))
		at = append(at, mkDest("dest.tcp", "variant", domain, 443, tcp, meta))
		at = append(at, mkDest("dest.tls", "variant", domain, 443, tls, meta))
		at = append(at, mkDest("dest.tls", "control", "decoy:"+domain, 443, decoy, meta))
		at = append(at, mkDest("dest.tls", "control", "absent:"+domain, 443, absent, meta))
	}
	return at
}

func destControls(n int, anycast, nx string) []*client.Attempt {
	var at []*client.Attempt
	for i := 0; i < n; i++ {
		at = append(at, mkDest("dest.tcp", "control", "anycast", 443, anycast, nil))
		at = append(at, mkDest("dest.nxdomain", "control", "invalid", 53, nx, nil))
	}
	return at
}

func TestDestSNIBlockingNeedsDecoyOnSameAddressAndIsCappedAtMedium(t *testing.T) {
	at := destControls(3, "ok", "ok")
	at = append(at, destSite("wikipedia.org", "control", 3, "ok", "ok", "ok", "ok", "ok")...)
	at = append(at, destSite("youtube.com", "dpi", 3, "ok", "ok", "midstream_reset", "ok", "ok")...)
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["dest_sni_blocking_suspected"] != 1 || len(r.Verdicts) != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	if r.Verdicts[0].Confidence != "medium" {
		t.Fatalf("one-sided evidence must be capped at medium, got %s", r.Verdicts[0].Confidence)
	}
	if r.Verdicts[0].Subject != "dest.tls tcp/443 youtube.com" {
		t.Fatalf("subject %s", r.Verdicts[0].Subject)
	}
	var yt Destination
	for _, d := range r.Destinations {
		if d.Domain == "youtube.com" {
			yt = d
		}
	}
	if yt.Verdict != "dest_sni_blocking_suspected" || yt.Layers["tls"] != "midstream_reset" || yt.Layers["decoy"] != "ok" || yt.Category != "dpi" {
		t.Fatalf("destination: %+v", yt)
	}
	for _, d := range r.Destinations {
		if d.Domain == "wikipedia.org" && d.Verdict != "clear" {
			t.Fatalf("control site: %+v", d)
		}
	}
}

func TestDestTLSBlockingWhenDecoyFailsToo(t *testing.T) {
	at := destControls(3, "ok", "ok")
	at = append(at, destSite("x.com", "social", 3, "ok", "ok", "payload_timeout", "payload_timeout", "ok")...)
	r := ClassifyStandalone(at)
	if kinds(r)["dest_tls_blocking_suspected"] != 1 || kinds(r)["dest_sni_blocking_suspected"] != 0 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
}

func TestDestTCPVerdictsNameBlackholeOrReset(t *testing.T) {
	at := destControls(3, "ok", "ok")
	at = append(at, destSite("a.example", "news", 3, "ok", "connect_timeout", "skipped", "skipped", "skipped")...)
	at = append(at, destSite("b.example", "news", 3, "ok", "connect_reset", "skipped", "skipped", "skipped")...)
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["dest_tcp_blackhole_suspected"] != 1 || k["dest_tcp_reset_suspected"] != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	// TLS cells that were skipped because TCP failed do not add a TLS verdict.
	if k["dest_tls_blocking_suspected"] != 0 {
		t.Fatalf("skipped TLS produced a verdict: %+v", r.Verdicts)
	}
}

func TestDestNoTransportVerdictWithoutAnycastControl(t *testing.T) {
	at := destControls(3, "connect_timeout", "ok")
	at = append(at, destSite("a.example", "news", 3, "ok", "connect_timeout", "skipped", "skipped", "skipped")...)
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["control_failed_inconclusive"] != 1 || k["dest_tcp_blackhole_suspected"] != 0 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	for _, d := range r.Destinations {
		if d.Verdict != "degraded" {
			t.Fatalf("without a control the site is degraded, got %+v", d)
		}
	}
}

func TestDestDNSPoisoningAndNXDomainHijack(t *testing.T) {
	at := destControls(2, "ok", "dns_answer_mismatch")
	at = append(at, destSite("wikipedia.org", "control", 2, "ok", "ok", "ok", "ok", "ok")...)
	at = append(at, destSite("meduza.io", "news", 2, "dns_answer_mismatch", "ok", "ok", "ok", "ok")...)
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["dest_dns_poisoning_suspected"] != 1 || k["nxdomain_hijack_suspected"] != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	for _, v := range r.Verdicts {
		if v.Confidence != "medium" {
			t.Fatalf("%s: %s", v.Kind, v.Confidence)
		}
	}
	for _, d := range r.Destinations {
		if d.Domain == "meduza.io" && d.Verdict != "dest_dns_poisoning_suspected" {
			t.Fatalf("meduza: %+v", d)
		}
	}
}

func TestDestSystemResolverDownIsOneVerdict(t *testing.T) {
	at := destControls(2, "ok", "ok")
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		at = append(at, destSite(d, "news", 2, "dns_timeout", "ok", "ok", "ok", "ok")...)
	}
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["system_resolver_unreachable_suspected"] != 1 || k["dest_dns_poisoning_suspected"] != 0 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
}

func TestDestLegalBlockAndNXDomainSummary(t *testing.T) {
	at := destControls(2, "ok", "ok")
	meta := map[string]string{"category": "ai"}
	for i := 0; i < 2; i++ {
		at = append(at, mkDest("dest.dns", "variant", "claude.ai", 53, "ok", meta))
		at = append(at, mkDest("dest.tcp", "variant", "claude.ai", 443, "ok", meta))
		at = append(at, mkDest("dest.tls", "variant", "claude.ai", 443, "ok", meta))
		at = append(at, mkDest("dest.tls", "control", "decoy:claude.ai", 443, "ok", meta))
		at = append(at, mkDest("dest.http", "variant", "claude.ai", 443, "http_legal_block", meta))
		at = append(at, mkDest("dest.dns", "variant", "gone.example", 53, "dns_rcode", meta))
		at = append(at, mkDest("dest.tcp", "variant", "gone.example", 443, "skipped", meta))
	}
	r := ClassifyStandalone(at)
	if kinds(r)["dest_legal_block_suspected"] != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	got := map[string]string{}
	for _, d := range r.Destinations {
		got[d.Domain] = d.Verdict
	}
	if got["claude.ai"] != "dest_legal_block_suspected" || got["gone.example"] != "nxdomain" {
		t.Fatalf("destinations: %v", got)
	}
}

func TestDestFamilyDoesNotDisturbServerRules(t *testing.T) {
	// A server scan with the family on: server rules see no dest cells as
	// baselines, and the summary counts both kinds of verdict.
	var at []*client.Attempt
	at = append(at, rep(3, func() *client.Attempt { return mk("tcp.echo", "baseline", "cp1-64", "tcp", 443, "ok", "ok", true) })...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("tls.sni", "baseline", "benign", "tcp", 443, "ok", "ok", true)
	})...)
	at = append(at, rep(3, func() *client.Attempt {
		return mk("tls.sni", "variant", "trigger:www.youtube.com", "tcp", 443, "midstream_reset", "rst_injected_or_path_reset", false)
	})...)
	at = append(at, destControls(3, "ok", "ok")...)
	at = append(at, destSite("youtube.com", "dpi", 3, "ok", "ok", "midstream_reset", "ok", "ok")...)
	r := Classify(at, true)
	k := kinds(r)
	if k["sni_or_host_blocking_suspected"] != 1 || k["dest_sni_blocking_suspected"] != 1 || k["port_blocking_suspected"] != 0 || k["protocol_blocking_suspected"] != 0 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
}

func TestClassifyStandaloneHasNoUnreachableVerdict(t *testing.T) {
	r := ClassifyStandalone(nil)
	if len(r.Verdicts) != 0 || r.Destinations != nil {
		t.Fatalf("got %+v", r)
	}
}

// dest.tls that never connected (the site's first address dropped while
// dest.tcp connected to another one) is an address finding, not an SNI one,
// even when the decoy cell (on the same dropped address) happens to pass.
func TestDestConnectStageFailureIsNotSNIBlocking(t *testing.T) {
	at := destControls(3, "ok", "ok")
	at = append(at, destSite("wikipedia.org", "control", 3, "ok", "ok", "ok", "ok", "ok")...)
	at = append(at, destSite("youtube.com", "dpi", 3, "ok", "ok", "connect_timeout", "ok", "ok")...)
	r := ClassifyStandalone(at)
	k := kinds(r)
	if k["dest_sni_blocking_suspected"] != 0 || k["dest_tls_blocking_suspected"] != 0 || k["dest_tcp_blackhole_suspected"] != 1 {
		t.Fatalf("verdicts: %+v", r.Verdicts)
	}
	for _, v := range r.Verdicts {
		if v.Kind == "dest_tcp_blackhole_suspected" && v.Confidence != "low" {
			t.Fatalf("address finding from one layer must stay low: %+v", v)
		}
	}
}
