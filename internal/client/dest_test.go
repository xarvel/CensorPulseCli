package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/dest"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

func TestNewStandaloneNeedsOnlyDestTests(t *testing.T) {
	c, err := New(Options{Sites: true})
	if err != nil || !c.Standalone() {
		t.Fatalf("sites without a target: %v", err)
	}
	if _, err := New(Options{Tests: []string{"dest.dns"}}); err != nil {
		t.Fatalf("dest tests without a target: %v", err)
	}
	if _, err := New(Options{Tests: []string{"tcp.echo"}}); err == nil {
		t.Fatal("a server test without a target was accepted")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("nothing to run was accepted")
	}
}

func TestDestPlansCoverEveryLayerAndControl(t *testing.T) {
	targets := []dest.Target{
		{Domain: "ctl.example", Category: dest.CategoryControl},
		{Domain: "site.example", Category: dest.CategoryAI, HTTPCheck: true},
		{Domain: "dc", Category: dest.CategoryMessenger, SkipDNS: true, SkipTLS: true, FixedIPs: []string{"149.154.167.51"}},
		{Domain: "chat.example", Category: dest.CategoryMessenger, Proto: dest.ProtoWhatsApp},
	}
	c, err := New(Options{Sites: true, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	plans := c.Catalog()
	count := map[string]int{}
	groups := map[string]bool{}
	for _, p := range plans {
		count[p.TestID+" "+p.Variant]++
		groups[p.Group] = true
		if p.serial != "" || p.Last {
			t.Errorf("%s %s must not reserve or run last", p.TestID, p.Variant)
		}
	}
	want := []string{"dest.nxdomain invalid", "dest.tcp anycast",
		"dest.dns ctl.example", "dest.tcp ctl.example", "dest.tls ctl.example", "dest.tls decoy:ctl.example", "dest.tls absent:ctl.example",
		"dest.dns site.example", "dest.tcp site.example", "dest.tls site.example", "dest.tls decoy:site.example", "dest.tls absent:site.example", "dest.http site.example",
		"dest.tcp dc",
		"dest.dns chat.example", "dest.tcp chat.example", "dest.proto chat.example"}
	for _, w := range want {
		if count[w] != 1 {
			t.Errorf("missing plan %q (have %v)", w, count)
		}
	}
	if len(plans) != len(want) {
		t.Errorf("%d plans, want %d: %v", len(plans), len(want), count)
	}
	for _, g := range []string{"dest/control", "dest/ctl.example", "dest/site.example", "dest/dc", "dest/chat.example"} {
		if !groups[g] {
			t.Errorf("group %s missing", g)
		}
	}
	for _, p := range plans {
		if p.Variant == "ctl.example" && p.Role != RoleBaseline {
			t.Errorf("control site is the baseline, got %s", p.Role)
		}
		if p.TestID == "dest.http" && p.Variant == "site.example" && p.Role != RoleVariant {
			t.Errorf("site role %s", p.Role)
		}
	}
}

func TestDestTestsSelectableByID(t *testing.T) {
	c, err := New(Options{Tests: []string{"dest.tcp"}, Targets: []dest.Target{{Domain: "a.example", Category: dest.CategoryNews}}})
	if err != nil {
		t.Fatal(err)
	}
	plans := c.Catalog()
	if len(plans) != 2 || plans[0].TestID != "dest.tcp" || plans[1].TestID != "dest.tcp" {
		t.Fatalf("got %+v", plans)
	}
}

func TestServerScanAddsDestOnlyWithSites(t *testing.T) {
	base := Options{Target: "127.0.0.1", Sites: false}
	c := &Client{opt: base, Params: model.Params{TCPPorts: []int{443}}, Session: model.SessionResponse{Tests: []string{"tcp.echo"}}}
	for _, p := range c.Catalog() {
		if IsDestTest(p.TestID) {
			t.Fatalf("dest plan without --sites: %+v", p)
		}
	}
	c.opt.Sites = true
	c.opt.Targets = []dest.Target{{Domain: "a.example"}}
	var dst, srv int
	for _, p := range c.Catalog() {
		if IsDestTest(p.TestID) {
			dst++
		} else {
			srv++
		}
	}
	if dst == 0 || srv == 0 {
		t.Fatalf("dest=%d server=%d", dst, srv)
	}
	// The quick profile filter must not drop the family.
	c.opt.Profile = "quick"
	dst = 0
	for _, p := range c.Catalog() {
		if IsDestTest(p.TestID) {
			dst++
		}
	}
	if dst == 0 {
		t.Fatal("quick profile dropped the dest family")
	}
}

func TestMergeVerdictForDestIsTheOutcome(t *testing.T) {
	a := &Attempt{TestID: "dest.tls", Outcome: OutcomeConnectTimeout}
	if got := mergeVerdict(a); got != OutcomeConnectTimeout {
		t.Fatalf("got %s", got)
	}
}

func TestSystemLookupMapsResolverErrors(t *testing.T) {
	mk := func(err error, ips ...string) Options {
		return Options{Sites: true, SystemResolver: func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, s := range ips {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, err
		}}
	}
	c, _ := New(mk(&net.DNSError{Err: "no such host", IsNotFound: true}))
	if r := c.systemLookup(context.Background(), "x"); r.RCode != "NXDOMAIN" {
		t.Fatalf("nxdomain: %+v", r)
	}
	c, _ = New(mk(&net.DNSError{Err: "i/o timeout", IsTimeout: true}))
	if r := c.systemLookup(context.Background(), "x"); r.RCode != "TIMEOUT" {
		t.Fatalf("timeout: %+v", r)
	}
	c, _ = New(mk(nil, "::ffff:1.2.3.4", "1.2.3.4"))
	if r := c.systemLookup(context.Background(), "x"); r.RCode != "NOERROR" || dest.Strings(r.IPs) != "1.2.3.4" {
		t.Fatalf("ok: %+v", r)
	}
}

func TestResolveTargetWithFixedAddressesOnly(t *testing.T) {
	c, _ := New(Options{Sites: true})
	tg := dest.Target{Domain: "dc", SkipDNS: true, FixedIPs: []string{"127.0.0.1", "149.154.167.50"}}
	r := c.destResolve(context.Background(), tg)
	if r.source != "fixed" || dest.Strings(r.ips) != "149.154.167.50" {
		t.Fatalf("got %+v", r)
	}
	// Cached: a second call does not resolve again.
	if r2 := c.destResolve(context.Background(), tg); r2 != r {
		t.Fatal("not cached")
	}
}

func TestRemoteAlertIsRecognisedAndTreatedAsAnAnswer(t *testing.T) {
	err := &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}
	alert, ok := remoteAlert(err)
	if !ok || alert.Error() != "tls: handshake failure" {
		t.Fatalf("got %v %v", alert, ok)
	}
	if tlsOutcome(err) != OutcomeTLSAlert {
		t.Fatalf("tlsOutcome: %s", tlsOutcome(err))
	}
	if _, ok := remoteAlert(errors.New("tls: something else")); ok {
		t.Fatal("a local tls error is not a remote alert")
	}
	a := &Attempt{Detail: map[string]string{}}
	noteTLSFailure(a, err)
	if a.Detail["alert"] != "tls: handshake failure" {
		t.Fatalf("detail: %v", a.Detail)
	}
}
