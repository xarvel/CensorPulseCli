package dest

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Parse reads a targets file the user points the scan at (on mobile: text
// pasted into the app). parseAnswer reads DoH response bodies, which come
// from whoever answers on the resolver's address.

// within fails the test when fn does not return: a record walk that stops
// advancing would otherwise hang the fuzzer without a report. A panic inside
// fn is re-raised on the test goroutine so the fuzzer can minimise the input.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case p := <-done:
		if p != nil {
			panic(p)
		}
	case <-timer.C:
		t.Fatalf("parser did not return within %s", d)
	}
}

func FuzzParseTargets(f *testing.F) {
	f.Add("# comment\nexample.org category=news label=\"Example news\"\n")
	f.Add("dc.example no-dns ip=203.0.113.5,203.0.113.6 tcp-only sni=example.org dns=dc.example.net")
	f.Add("api.example http category=nonsense")
	f.Add("chat.example proto=whatsapp tcp-only")
	f.Add("chat.example proto=nonsense")
	f.Add("a.example\na.example")
	f.Add("a.example no-dns")
	f.Add("a.example ip=")
	f.Add("a.example ip=fe80::1%eth0")
	f.Add("\"\"")
	f.Add("\" \" label=\"unterminated")
	f.Add("=x")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		var got []Target
		var err error
		within(t, 5*time.Second, func() { got, err = Parse(strings.NewReader(in)) })
		if err != nil {
			if got != nil {
				t.Fatalf("targets next to an error: %+v", got)
			}
			return
		}
		if len(got) == 0 {
			t.Fatal("no targets and no error")
		}
		seen := map[string]bool{}
		for _, tg := range got {
			if tg.Domain == "" || tg.Domain != strings.ToLower(tg.Domain) || strings.ContainsAny(tg.Domain, "=/ ") {
				t.Fatalf("domain %q", tg.Domain)
			}
			if seen[tg.Domain] {
				t.Fatalf("duplicate %q", tg.Domain)
			}
			seen[tg.Domain] = true
			if !knownCategory(tg.Category) {
				t.Fatalf("category %q", tg.Category)
			}
			// Every ip= was validated, so none may be dropped later, and a
			// no-dns target always has somewhere to go.
			if len(tg.Fixed()) != len(tg.FixedIPs) || (tg.SkipDNS && len(tg.FixedIPs) == 0) {
				t.Fatalf("fixed ips of %q: %v", tg.Domain, tg.FixedIPs)
			}
			if tg.Proto != "" && !knownProto(tg.Proto) {
				t.Fatalf("proto %q", tg.Proto)
			}
			tg.QueryName()
			tg.ServerName()
		}
		SortedCategories(got)
	})
}

func FuzzParseDoHAnswer(f *testing.F) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q, err := buildQuery("example.org", typ)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(q) // a query is not a response
		ok := answer(q, dnsmessage.RCodeSuccess, "203.0.113.9", "2001:db8::9")
		f.Add(ok)
		f.Add(ok[:len(ok)-1])
		f.Add(answer(q, dnsmessage.RCodeNameError))
	}
	// The record that made dnsx.ParseAnswer loop (fixed today): four bytes
	// of RDATA announced, none carried. This parser walks the same way.
	f.Add([]byte{
		0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	})
	f.Fuzz(func(t *testing.T, b []byte) {
		var r wireResult
		var err error
		within(t, 5*time.Second, func() { r, err = parseAnswer(b) })
		if err != nil {
			if len(r.ips) != 0 {
				t.Fatalf("addresses next to an error: %v", r.ips)
			}
			return
		}
		if r.rcode != "NOERROR" && r.rcode != "NXDOMAIN" && r.rcode != "OTHER" {
			t.Fatalf("rcode %q", r.rcode)
		}
		for _, ip := range r.ips {
			if !ip.IsValid() {
				t.Fatalf("invalid address in %v", r.ips)
			}
		}
		// The rest of the pipeline takes these addresses as they are.
		combine(r, wireResult{rcode: "ERROR"})
		Prioritize(Unique(append([]netip.Addr(nil), r.ips...)))
	})
}
