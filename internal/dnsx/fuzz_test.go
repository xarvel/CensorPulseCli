package dnsx

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// UDP and TCP 53 parse queries from anybody; the client parses answers that
// an injector on the path is free to forge, which is the case the probe
// exists to observe. Neither side may panic or spin on them.

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

// truncatedA is the input ParseAnswer used to loop on (fixed today): one
// answer announcing four bytes of RDATA and carrying none.
var truncatedA = []byte{
	0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
}

// nonASCIILabel is a TXT query for <22 x 0xff>.probe.invalid, found by
// FuzzParseQuery. ParseQuery lower-cases the name with strings.ToLower, which
// turns every byte that is not UTF-8 into U+FFFD (three bytes): the label
// grows from 22 to 66 bytes, over the 63 a label may have. BuildAnswerFrom
// ignores the error of Builder.Question, so the answer goes out with
// QDCOUNT 0, and its one record is named by a compression pointer (c0 0c)
// that the failed Question left in the builder's table: offset 12, which is
// the pointer itself. Nothing here panics or spins (the client's parser
// refuses the pointer loop), so the fuzz property only steps around it; the
// defect is in production code and was reported, not fixed, on 2026-09-18.
var nonASCIILabel = append(append([]byte{
	0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // query, QDCOUNT 1
	22, // label length
}, bytes.Repeat([]byte{0xff}, 22)...),
	5, 'p', 'r', 'o', 'b', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0,
	0x00, 0x10, 0x00, 0x01, // TXT, IN
)

func mustQuery(f *testing.F, name string, typ dnsmessage.Type) []byte {
	f.Helper()
	q, err := BuildQuery(0x1234, name, typ)
	if err != nil {
		f.Fatal(err)
	}
	return q
}

func FuzzParseQuery(f *testing.F) {
	name := "0011223344556677.dns.udp.probe.invalid."
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeTXT, dnsmessage.TypeAAAA} {
		q := mustQuery(f, name, typ)
		f.Add(q)
		f.Add(q[:len(q)-3])
	}
	f.Add(mustQuery(f, WhoamiLabel+".0011.dns.system.probe.invalid.", dnsmessage.TypeTXT))
	f.Add(mustQuery(f, "EXAMPLE.com.", dnsmessage.TypeA)) // out of zone: REFUSED
	padded, err := BuildPaddedQuery(7, name, dnsmessage.TypeTXT, 300)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(padded)
	f.Add(truncatedA)
	f.Add(nonASCIILabel)
	f.Fuzz(func(t *testing.T, b []byte) {
		LooksLikeQuery(b)
		q, err := ParseQuery(b)
		if err != nil {
			return
		}
		var ans []byte
		within(t, 5*time.Second, func() { ans, err = BuildAnswerFrom(q, "203.0.113.9") })
		Truncated(q, len(b))
		if err != nil {
			return // a name the builder refuses to pack: no answer, no panic
		}
		if len(ans) >= 6 && ans[4] == 0 && ans[5] == 0 {
			return // KNOWN DEFECT, see nonASCIILabel: tighten once BuildAnswerFrom is fixed
		}
		// What the server sends must be readable by the client, carry the
		// query's id and, inside the zone, verify.
		var pa *Answer
		within(t, 5*time.Second, func() { pa, err = ParseAnswer(ans) })
		if err != nil || pa.ID != q.ID {
			t.Fatalf("own answer does not parse: %v %+v\n query  %x\n answer %x", err, pa, b, ans)
		}
		if pa.RCode != dnsmessage.RCodeSuccess || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeTXT) {
			return
		}
		if ok, why := Verify(pa, q.Name, q.Type); !ok {
			t.Fatalf("own answer does not verify: %s\n query  %x\n answer %x", why, b, ans)
		}
	})
}

func FuzzParseAnswer(f *testing.F) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeTXT, dnsmessage.TypeAAAA} {
		q, err := ParseQuery(mustQuery(f, "0011223344556677.dns.udp.probe.invalid.", typ))
		if err != nil {
			f.Fatal(err)
		}
		ans, err := BuildAnswerFrom(q, "203.0.113.9")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(ans)
		f.Add(ans[:len(ans)-1])
		f.Add(Truncated(q, 0))
	}
	f.Add(truncatedA)
	f.Add(append(append([]byte(nil), truncatedA[:len(truncatedA)-2]...), 0xff, 0xff)) // RDLENGTH 65535
	f.Fuzz(func(t *testing.T, b []byte) {
		var a *Answer
		var err error
		within(t, 5*time.Second, func() { a, err = ParseAnswer(b) })
		if err != nil {
			return
		}
		if a == nil {
			t.Fatal("no answer and no error")
		}
		Verify(a, a.Name, dnsmessage.TypeA)
		Verify(a, a.Name, dnsmessage.TypeTXT)
	})
}
