package dnsx

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS over UDP/TCP 53 is plaintext both ways, and what comes back is
// compared bit for bit with what the server sent: a resolver or a middlebox
// that rewrites a flag shows up as a difference, so the flags the two sides
// build must not drift. Nothing here is random; every message is pinned
// whole. Field names as in RFC 1035 §4.1, the OPT record as in RFC 6891 and
// the padding option as in RFC 7830.

const (
	wireName = "0011223344556677.dns.udp.probe.invalid."
	// The question section of every golden for wireName: 40 bytes at offset 12.
	wireQName = `
		10 30303131323233333434353536363737 | QNAME label "0011223344556677": the nonce
		03 646e73         | label "dns"
		03 756470         | label "udp": the test id
		05 70726f6265     | label "probe"
		07 696e76616c6964 | label "invalid"
		00                | root`
)

func wireQuery(t *testing.T, id uint16, name string, typ dnsmessage.Type) *Query {
	t.Helper()
	raw, err := BuildQuery(id, name, typ)
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestWireQuery(t *testing.T) {
	q, err := BuildQuery(0x1234, wireName, dnsmessage.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "query", q, `
		1234              | ID
		0100              | flags: a query, RD set, nothing else
		0001 0000 0000 0000 | QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 0`+wireQName+`
		0010              | QTYPE TXT
		0001              | QCLASS IN`)

	// Padded to 300 bytes with an EDNS0 padding option, so that no answer is
	// ever larger than its question.
	padded, err := BuildPaddedQuery(7, wireName, dnsmessage.TypeA, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 300 {
		t.Fatalf("padded query: %d bytes, want exactly the 300 asked for", len(padded))
	}
	checkWire(t, "padded query", padded[:71], `
		0007              | ID
		0100              | flags: a query, RD set
		0001 0000 0000 0001 | QDCOUNT 1, ARCOUNT 1: the OPT record`+wireQName+`
		0001              | QTYPE A
		0001              | QCLASS IN
		00                | OPT: owner name, the root
		0029              | TYPE OPT
		04d0              | CLASS: requestor's UDP payload size, 1232
		00000000          | TTL: extended RCODE 0, version 0, DO clear
		00e9              | RDLENGTH 233
		000c              | option code 12: Padding
		00e5              | option length 229`)
	if pad := bytes.TrimRight(padded[71:], "\x00"); len(pad) != 0 {
		t.Errorf("padded query: the padding is not zero: %x", pad)
	}
}

func TestWireAnswers(t *testing.T) {
	txt, err := BuildAnswer(wireQuery(t, 0x1234, wireName, dnsmessage.TypeTXT))
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "TXT answer", txt, `
		1234              | ID of the query
		8500              | flags: QR, AA, RD echoed; RA clear; RCODE 0
		0001 0001 0000 0000 | QDCOUNT 1, ANCOUNT 1`+wireQName+`
		0010              | QTYPE TXT
		0001              | QCLASS IN
		c00c              | NAME: pointer to the question at offset 12
		0010              | TYPE TXT
		0001              | CLASS IN
		00000000          | TTL 0: never cached
		0025              | RDLENGTH 37
		24                | character-string length 36
		435031206436616664376362326533636262626434353764366264353562333561376366 | "CP1 " + sha256(qname)[:32] in hex`)

	a, err := BuildAnswer(wireQuery(t, 0x1234, wireName, dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "A answer", a, `
		1234              | ID of the query
		8500              | flags: QR, AA, RD
		0001 0001 0000 0000 | QDCOUNT 1, ANCOUNT 1`+wireQName+`
		0001              | QTYPE A
		0001              | QCLASS IN
		c00c              | NAME: pointer to the question
		0001              | TYPE A
		0001              | CLASS IN
		00000000          | TTL 0
		0004              | RDLENGTH 4
		c612496d          | 198.18.73.109: 198.18/15 (benchmarking, never a real host), low bits from sha256("a:" + qname)`)

	// Any other type inside the zone: NODATA.
	nodata, err := BuildAnswer(wireQuery(t, 0x1234, wireName, dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "NODATA answer", nodata, `
		1234              | ID of the query
		8500              | flags: QR, AA, RD; RCODE 0
		0001 0000 0000 0000 | QDCOUNT 1, ANCOUNT 0`+wireQName+`
		001c              | QTYPE AAAA
		0001              | QCLASS IN`)
}

func TestWireWhoamiRefusedTruncated(t *testing.T) {
	who, err := BuildAnswerFrom(wireQuery(t, 3, WhoamiLabel+".0011.dns.system.probe.invalid.", dnsmessage.TypeTXT), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "whoami answer", who, `
		0003              | ID of the query
		8500              | flags: QR, AA, RD
		0001 0001 0000 0000 | QDCOUNT 1, ANCOUNT 1
		06 77686f616d69   | QNAME label "whoami"
		04 30303131       | label "0011"
		03 646e73         | label "dns"
		06 73797374656d   | label "system"
		05 70726f6265     | label "probe"
		07 696e76616c6964 | label "invalid"
		00                | root
		0010 0001         | QTYPE TXT, QCLASS IN
		c00c 0010 0001    | NAME pointer, TYPE TXT, CLASS IN
		00000000          | TTL 0
		003a              | RDLENGTH 58: two character-strings in one record
		24                | length 36
		435031206535613238383133646465303032656666636664343232386631613531303632 | "CP1 " + sha256(qname)[:32] in hex
		14                | length 20
		7265637572736f723d3230332e302e3131332e39 | "recursor=203.0.113.9": where the query came from`)

	// Outside the zone the server refuses, so that it is no resolver to anyone.
	refused, err := BuildAnswer(wireQuery(t, 1, "example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, "REFUSED", refused, `
		0001              | ID of the query
		8505              | flags: QR, AA, RD; RCODE 5 REFUSED
		0001 0000 0000 0000 | QDCOUNT 1, no records
		07 6578616d706c65 | QNAME label "example"
		03 636f6d         | label "com"
		00                | root
		0001 0001         | QTYPE A, QCLASS IN`)

	checkWire(t, "truncated", Truncated(wireQuery(t, 0x1234, wireName, dnsmessage.TypeTXT), 0), `
		1234              | ID of the query
		8700              | flags: QR, AA, TC, RD: retry over TCP
		0001 0000 0000 0000 | QDCOUNT 1, no records`+wireQName+`
		0010 0001         | QTYPE TXT, QCLASS IN`)
}

// checkWire compares got with a golden written as an annotated dump, one
// field per line: "hex | field name". Hex digits are exact bytes (blanks are
// free); "??*N" stands for N bytes that differ from packet to packet. A
// mismatch is reported with the name of the field, not as two hex strings to
// diff by eye. The offsets of the unpinned regions are returned for
// checkRandom. (Each protocol package carries a copy of these two helpers:
// test code cannot be imported across packages.)
func checkWire(t *testing.T, what string, got []byte, golden string) (random [][2]int) {
	t.Helper()
	off, failed := 0, false
	for _, line := range strings.Split(strings.TrimSpace(golden), "\n") {
		spec, name, _ := strings.Cut(line, "|")
		spec, name = strings.Join(strings.Fields(spec), ""), strings.TrimSpace(name)
		n := len(spec) / 2
		if c, ok := strings.CutPrefix(spec, "??*"); ok {
			n, _ = strconv.Atoi(c)
		}
		if off+n > len(got) {
			t.Errorf("%s: field %q wants bytes %d..%d, the packet has %d", what, name, off, off+n, len(got))
			failed = true
			break
		}
		if strings.HasPrefix(spec, "??") {
			random = append(random, [2]int{off, off + n})
		} else if want, err := hex.DecodeString(spec); err != nil {
			t.Fatalf("%s: golden line %q: %v", what, line, err)
		} else if !bytes.Equal(got[off:off+n], want) {
			t.Errorf("%s: field %q at offset %d: got %x, want %x", what, name, off, got[off:off+n], want)
			failed = true
		}
		off += n
	}
	if off != len(got) && !failed {
		t.Errorf("%s: %d bytes on the wire, the golden describes %d", what, len(got), off)
		failed = true
	}
	if failed {
		t.Logf("%s, whole packet: %x", what, got)
	}
	return random
}
