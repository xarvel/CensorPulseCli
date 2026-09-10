package dest

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestIsBogon(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "0.1.2.3", "127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.1", "100.64.0.1", "169.254.1.1", "255.1.1.1", "::", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "203.0.113.7"} {
		if !IsBogon(ip(s)) {
			t.Errorf("%s should be a bogon", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "149.154.167.50", "2606:4700::1111", "100.128.0.1", "172.32.0.1"} {
		if IsBogon(ip(s)) {
			t.Errorf("%s is public", s)
		}
	}
}

func TestPrioritizePutsPublicV4First(t *testing.T) {
	got := Prioritize([]netip.Addr{ip("2606:4700::1111"), ip("127.0.0.1"), ip("1.1.1.1"), ip("1.0.0.1"), ip("1.1.1.1")})
	if Strings(got) != "1.1.1.1,1.0.0.1,2606:4700::1111" {
		t.Fatalf("got %s", Strings(got))
	}
}

func TestCompareRules(t *testing.T) {
	cases := []struct {
		name    string
		sys     SystemResult
		trusted Consensus
		want    Comparison
	}{
		{"clean", SystemResult{IPs: []netip.Addr{ip("1.1.1.1")}, RCode: "NOERROR"}, Consensus{IPs: []netip.Addr{ip("1.1.1.1")}, RCode: "NOERROR"}, Comparison{}},
		{"bogon", SystemResult{IPs: []netip.Addr{ip("127.0.0.1")}, RCode: "NOERROR"}, Consensus{IPs: []netip.Addr{ip("1.1.1.1")}, RCode: "NOERROR"}, Comparison{Tampered: true, Reason: "bogon"}},
		{"hijack", SystemResult{IPs: []netip.Addr{ip("5.5.5.5")}, RCode: "NOERROR"}, Consensus{RCode: "NXDOMAIN"}, Comparison{Tampered: true, Reason: "hijack"}},
		{"disagree", SystemResult{IPs: []netip.Addr{ip("5.5.5.5")}, RCode: "NOERROR"}, Consensus{IPs: []netip.Addr{ip("1.1.1.1")}, RCode: "NOERROR"}, Comparison{Disagree: true}},
		{"trusted down", SystemResult{IPs: []netip.Addr{ip("127.0.0.1")}, RCode: "NOERROR"}, Consensus{RCode: "ERROR"}, Comparison{}},
		{"nx both", SystemResult{RCode: "NXDOMAIN"}, Consensus{RCode: "NXDOMAIN"}, Comparison{}},
		// The ISP resolver denies a name every trusted resolver has: a block.
		{"system nx", SystemResult{RCode: "NXDOMAIN"}, Consensus{IPs: []netip.Addr{ip("1.1.1.1")}, RCode: "NOERROR"}, Comparison{Tampered: true, Reason: "nxdomain"}},
		// SERVFAIL/REFUSED on the trusted side: nothing to compare with.
		{"trusted other", SystemResult{IPs: []netip.Addr{ip("5.5.5.5")}, RCode: "NOERROR"}, Consensus{RCode: "OTHER"}, Comparison{}},
	}
	for _, c := range cases {
		got := Compare(c.sys, c.trusted)
		if got.Tampered != c.want.Tampered || got.Reason != c.want.Reason || got.Disagree != c.want.Disagree {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
}

func TestProbeAddrsFallsBackToPublicSystemAnswers(t *testing.T) {
	ips, src := ProbeAddrs(SystemResult{IPs: []netip.Addr{ip("127.0.0.1"), ip("5.5.5.5")}}, Consensus{RCode: "ERROR"})
	if src != "system" || Strings(ips) != "5.5.5.5" {
		t.Fatalf("got %s %s", src, Strings(ips))
	}
	if _, src := ProbeAddrs(SystemResult{}, Consensus{}); src != "none" {
		t.Fatalf("got %s", src)
	}
}

func TestTrustedConsensus(t *testing.T) {
	c := TrustedConsensus([]DoHAnswer{
		{Resolver: "cloudflare", RCode: "NOERROR", IPs: []netip.Addr{ip("1.1.1.1")}},
		{Resolver: "google", RCode: "ERROR"},
		{Resolver: "quad9", RCode: "NOERROR", IPs: []netip.Addr{ip("1.0.0.1"), ip("1.1.1.1")}},
	})
	if c.RCode != "NOERROR" || Strings(c.IPs) != "1.1.1.1,1.0.0.1" || !strings.Contains(c.Note, "google:ERROR") {
		t.Fatalf("got %+v", c)
	}
	if c := TrustedConsensus([]DoHAnswer{{RCode: "NXDOMAIN"}, {RCode: "ERROR"}}); c.RCode != "NXDOMAIN" {
		t.Fatalf("nx: %+v", c)
	}
	if c := TrustedConsensus([]DoHAnswer{{RCode: "ERROR"}, {RCode: "ERROR"}}); c.RCode != "ERROR" {
		t.Fatalf("err: %+v", c)
	}
}

func TestDefaultCatalogIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	controls := 0
	for _, tg := range Default() {
		if seen[tg.Domain] {
			t.Errorf("duplicate %s", tg.Domain)
		}
		seen[tg.Domain] = true
		if tg.Category == CategoryControl {
			controls++
		}
		if tg.SkipDNS && len(tg.Fixed()) == 0 {
			t.Errorf("%s skips DNS without fixed addresses", tg.Domain)
		}
		if len(tg.FixedIPs) != len(tg.Fixed()) {
			t.Errorf("%s has a malformed fixed address", tg.Domain)
		}
	}
	if controls < 2 {
		t.Fatalf("catalog needs at least two control sites, has %d", controls)
	}
}

func TestParseTargets(t *testing.T) {
	in := `
# comment
example.org category=news label="Example news"
dc.example no-dns ip=203.0.113.5,203.0.113.6 tcp-only sni=example.org
api.example http category=nonsense
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Category != CategoryNews || got[0].Label != "Example news" {
		t.Fatalf("got %+v", got)
	}
	if !got[1].SkipDNS || !got[1].SkipTLS || got[1].SNI != "example.org" || Strings(got[1].Fixed()) != "203.0.113.5,203.0.113.6" {
		t.Fatalf("dc: %+v", got[1])
	}
	if !got[2].HTTPCheck || got[2].Category != CategoryCustom {
		t.Fatalf("api: %+v", got[2])
	}
	for _, bad := range []string{"", "a.example bogus=1", "a.example no-dns", "a.example\na.example", "=x"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestClassifyHTTP(t *testing.T) {
	if lb, _ := ClassifyHTTP(451); !lb {
		t.Fatal("451 is a legal block")
	}
	for _, s := range []int{403, 200, 0, 500} {
		if lb, _ := ClassifyHTTP(s); lb {
			t.Errorf("%d is not a legal block", s)
		}
	}
}

// answer builds a DNS response for the query body.
func answer(q []byte, rcode dnsmessage.RCode, ips ...string) []byte {
	var p dnsmessage.Parser
	h, _ := p.Start(q)
	qq, _ := p.Question()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: rcode})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(qq)
	b.StartAnswers()
	for _, s := range ips {
		a := netip.MustParseAddr(s)
		rh := dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}
		if a.Is4() && qq.Type == dnsmessage.TypeA {
			b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		} else if a.Is6() && qq.Type == dnsmessage.TypeAAAA {
			b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	out, _ := b.Finish()
	return out
}

func TestQueryDoHWireAndFallbacks(t *testing.T) {
	// A wire endpoint that rejects POST, answers GET; a JSON API; a dead one.
	var posts, gets, jsons int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns-query":
			if r.Method == http.MethodPost {
				posts++
				http.Error(w, "no", http.StatusMethodNotAllowed)
				return
			}
			gets++
			raw, _ := base64DecodeURL(r.URL.Query().Get("dns"))
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(answer(raw, dnsmessage.RCodeSuccess, "203.0.113.9", "2001:db8::9"))
		case "/resolve":
			jsons++
			w.Header().Set("Content-Type", "application/dns-json")
			if r.URL.Query().Get("type") == "A" {
				w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"data":"203.0.113.10"},{"type":5,"data":"cname"}]}`))
			} else {
				w.Write([]byte(`{"Status":0}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	hc := srv.Client()
	got := QueryDoH(t.Context(), hc, Resolver{Name: "t", URLs: []string{srv.URL + "/dns-query"}}, "example.org", 2*time.Second)
	if got.RCode != "NOERROR" || Strings(got.IPs) != "203.0.113.9,2001:db8::9" || got.Endpoint == "" {
		t.Fatalf("wire: %+v", got)
	}
	if posts == 0 || gets == 0 {
		t.Fatalf("expected POST then GET, got %d/%d", posts, gets)
	}
	got = QueryDoH(t.Context(), hc, Resolver{Name: "j", URLs: []string{srv.URL + "/dead"}, JSON: srv.URL + "/resolve"}, "example.org", 2*time.Second)
	if got.RCode != "NOERROR" || Strings(got.IPs) != "203.0.113.10" || !strings.HasSuffix(got.Endpoint, "(json)") {
		t.Fatalf("json: %+v", got)
	}
	got = QueryDoH(t.Context(), hc, Resolver{Name: "d", URLs: []string{srv.URL + "/dead"}}, "example.org", 2*time.Second)
	if got.RCode != "ERROR" || got.Err == "" {
		t.Fatalf("dead: %+v", got)
	}
}

func TestParseAnswerNXDOMAIN(t *testing.T) {
	q, _ := buildQuery("nope.invalid", dnsmessage.TypeA)
	r, err := parseAnswer(answer(q, dnsmessage.RCodeNameError))
	if err != nil || r.rcode != "NXDOMAIN" || len(r.ips) != 0 {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := parseAnswer(q); err == nil {
		t.Fatal("a query is not a response")
	}
}

func TestPickDecoyAvoidsExcluded(t *testing.T) {
	for i := 0; i < 50; i++ {
		if d := PickDecoy(DecoyNames[:len(DecoyNames)-1]...); d != DecoyNames[len(DecoyNames)-1] {
			t.Fatalf("picked excluded %s", d)
		}
	}
	if n := NXDomainName(); !strings.HasSuffix(n, ".invalid") {
		t.Fatal(n)
	}
}

// A decoy on the target's own site would fail under the same suffix rule.
func TestPickDecoyAvoidsSameSite(t *testing.T) {
	if !sameSite("www.wikipedia.org", "wikipedia.org") || !sameSite("en.wikipedia.org", "wikipedia.org") || sameSite("wikipedia.org", "wikimedia.org") {
		t.Fatal("sameSite")
	}
	for i := 0; i < 50; i++ {
		d := PickDecoy("wikipedia.org", "www.wikipedia.org")
		if sameSite(d, "wikipedia.org") {
			t.Fatalf("decoy %s is on the target's site", d)
		}
	}
}
