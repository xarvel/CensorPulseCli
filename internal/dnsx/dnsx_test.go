package dnsx

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestQueryAnswer(t *testing.T) {
	name := QueryName("0011223344556677", "dns.udp")
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeA} {
		q, err := BuildQuery(0x1234, name, typ)
		if err != nil {
			t.Fatal(err)
		}
		if !LooksLikeQuery(q) {
			t.Fatal("query shape not recognised")
		}
		pq, err := ParseQuery(q)
		if err != nil || pq.Name != name || pq.ID != 0x1234 {
			t.Fatalf("parse query: %v %+v", err, pq)
		}
		ans, err := BuildAnswer(pq)
		if err != nil {
			t.Fatal(err)
		}
		pa, err := ParseAnswer(ans)
		if err != nil {
			t.Fatal(err)
		}
		if ok, why := Verify(pa, name, typ); !ok {
			t.Fatalf("verify %v: %s", typ, why)
		}
		if ok, _ := Verify(pa, QueryName("ffff", "dns.udp"), typ); ok {
			t.Fatal("verify accepted wrong name")
		}
	}
	// whoami names carry the source address of the query as a second TXT.
	wq, _ := BuildQuery(3, WhoamiLabel+"."+QueryName("0011", "dns.system"), dnsmessage.TypeTXT)
	wpq, _ := ParseQuery(wq)
	wans, _ := BuildAnswerFrom(wpq, "203.0.113.9")
	wpa, _ := ParseAnswer(wans)
	if ok, why := Verify(wpa, wpq.Name, dnsmessage.TypeTXT); !ok {
		t.Fatalf("whoami verify: %s", why)
	}
	if len(wpa.TXT) != 2 || wpa.TXT[1] != "recursor=203.0.113.9" {
		t.Fatalf("whoami TXT: %v", wpa.TXT)
	}
	// SetZone normalises input.
	SetZone("Probe.Example.")
	if Zone != "probe.example." || QueryName("ab", "t") != "ab.t.probe.example." {
		t.Fatalf("zone: %q", Zone)
	}
	SetZone("")
	if Zone != "probe.invalid." {
		t.Fatalf("zone reset: %q", Zone)
	}
	// Out-of-zone query must be refused, never resolved.
	q, _ := BuildQuery(1, "example.com.", dnsmessage.TypeA)
	pq, _ := ParseQuery(q)
	ans, _ := BuildAnswer(pq)
	pa, _ := ParseAnswer(ans)
	if pa.RCode != dnsmessage.RCodeRefused || len(pa.A) != 0 {
		t.Fatalf("out-of-zone answer: %+v", pa)
	}
}

// A response whose only answer announces four bytes of RDATA and carries
// none: the walk has to stop there instead of reading the same header again.
func TestParseAnswerTruncatedResource(t *testing.T) {
	msg := []byte{
		0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // response, ANCOUNT 1
		0x00,                   // root name
		0x00, 0x01, 0x00, 0x01, // A, IN
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x04, // RDLENGTH 4, no RDATA
	}
	done := make(chan *Answer, 1)
	go func() {
		a, _ := ParseAnswer(msg)
		done <- a
	}()
	select {
	case a := <-done:
		if a == nil || len(a.A) != 0 {
			t.Fatalf("answer %+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ParseAnswer did not return on a truncated A record")
	}
}
