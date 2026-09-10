// Package dnsx builds and answers the synthetic DNS queries used by the probe.
// Queries always target a name of the form <nonce>.<test>.probe.invalid and the
// server answers with a TXT record carrying "CP1 <sha256(qname)[:32]>" plus an
// A record derived from the nonce, so that any interception, spoofing or
// resolver hijack shows up as an answer mismatch.
package dnsx

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Zone is the DNS zone the server answers for. The default is a name that
// can never exist in the public DNS; operators who delegate a real subdomain to
// the probe set it via the server config so that system-resolver tests work.
var Zone = "probe.invalid."

// SetZone normalises and installs the zone (lower case, trailing dot).
func SetZone(z string) {
	z = strings.ToLower(strings.Trim(z, "."))
	if z == "" {
		z = "probe.invalid"
	}
	Zone = z + "."
}

// WhoamiLabel marks queries whose TXT answer must also carry the address the
// query arrived from (the recursive resolver actually used by the client).
const WhoamiLabel = "whoami"

var ErrNotQuery = errors.New("dnsx: not a DNS query")

// Query is a decoded incoming query.
type Query struct {
	ID    uint16
	Name  string
	Type  dnsmessage.Type
	Raw   []byte
	EDNS0 bool
}

// QueryName composes the synthetic name.
func QueryName(nonceHex, test string) string {
	return strings.ToLower(nonceHex) + "." + test + "." + Zone
}

// ExpectedTXT is the TXT payload the server must return for name.
func ExpectedTXT(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(name)))
	return "CP1 " + hex.EncodeToString(sum[:])[:32]
}

// ExpectedA is the A record the server must return for name.
func ExpectedA(name string) [4]byte {
	sum := sha256.Sum256([]byte("a:" + strings.ToLower(name)))
	// 198.18.0.0/15 is reserved for benchmarking: never a real host.
	return [4]byte{198, 18 + sum[0]&1, sum[1], sum[2]}
}

// BuildQuery returns a wire-format query.
func BuildQuery(id uint16, name string, t dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// ParseQuery decodes a query and returns its first question.
func ParseQuery(b []byte) (*Query, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || h.Response {
		return nil, ErrNotQuery
	}
	q, err := p.Question()
	if err != nil {
		return nil, ErrNotQuery
	}
	return &Query{ID: h.ID, Name: strings.ToLower(q.Name.String()), Type: q.Type, Raw: b}, nil
}

// LooksLikeQuery is a cheap shape check for the UDP demuxer.
func LooksLikeQuery(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(b[2:])
	return flags&0x8000 == 0 && binary.BigEndian.Uint16(b[4:]) >= 1
}

// BuildAnswer answers q. Names outside the probe zone get REFUSED so the
// server can never act as a resolver for anyone.
func BuildAnswer(q *Query) ([]byte, error) { return BuildAnswerFrom(q, "") }

// BuildAnswerFrom is BuildAnswer with the source address of the query; for
// names starting with the whoami label a second TXT "recursor=<addr>" is added.
func BuildAnswerFrom(q *Query, src string) ([]byte, error) {
	name, err := dnsmessage.NewName(q.Name)
	if err != nil {
		return nil, err
	}
	inZone := strings.HasSuffix(q.Name, "."+Zone) || q.Name == Zone
	hdr := dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionDesired: true}
	if !inZone {
		hdr.RCode = dnsmessage.RCodeRefused
	}
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: dnsmessage.ClassINET})
	if !inZone {
		return b.Finish()
	}
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 0}
	switch q.Type {
	case dnsmessage.TypeA:
		rh.Type = dnsmessage.TypeA
		b.AResource(rh, dnsmessage.AResource{A: ExpectedA(q.Name)})
	case dnsmessage.TypeTXT:
		rh.Type = dnsmessage.TypeTXT
		txt := []string{ExpectedTXT(q.Name)}
		if src != "" && strings.HasPrefix(q.Name, WhoamiLabel+".") {
			txt = append(txt, "recursor="+src)
		}
		b.TXTResource(rh, dnsmessage.TXTResource{TXT: txt})
	default:
		// NODATA: authoritative empty answer.
	}
	return b.Finish()
}

// Answer is what the client extracts from a response.
type Answer struct {
	ID    uint16
	RCode dnsmessage.RCode
	Name  string
	TXT   []string
	A     [][4]byte
}

// ParseAnswer decodes a response.
func ParseAnswer(b []byte) (*Answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, err
	}
	if !h.Response {
		return nil, errors.New("dnsx: not a response")
	}
	a := &Answer{ID: h.ID, RCode: h.RCode}
	if q, err := p.Question(); err == nil {
		a.Name = strings.ToLower(q.Name.String())
	}
	p.SkipAllQuestions()
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		// A resource that fails to parse ends the walk: the parser does not
		// advance past it, so AnswerHeader would hand out the same header
		// again, forever (a truncated reply is all an injector needs).
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return a, nil
			}
			a.A = append(a.A, r.A)
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return a, nil
			}
			a.TXT = append(a.TXT, r.TXT...)
		default:
			if p.SkipAnswer() != nil {
				return a, nil
			}
		}
	}
	return a, nil
}

// Verify checks that ans is the expected answer for name/type.
func Verify(ans *Answer, name string, t dnsmessage.Type) (ok bool, reason string) {
	if ans.RCode != dnsmessage.RCodeSuccess {
		return false, "rcode_" + ans.RCode.String()
	}
	name = strings.ToLower(name)
	switch t {
	case dnsmessage.TypeTXT:
		want := ExpectedTXT(name)
		for _, s := range ans.TXT {
			if s == want {
				return true, ""
			}
		}
		return false, "txt_mismatch"
	case dnsmessage.TypeA:
		want := ExpectedA(name)
		for _, a := range ans.A {
			if a == want {
				return true, ""
			}
		}
		return false, "a_mismatch"
	}
	return false, "unsupported_type"
}

// Truncated builds a minimal TC=1 response (header + question only) so that a
// UDP answer never exceeds the request size; the client retries over TCP.
func Truncated(q *Query, _ int) []byte {
	name, err := dnsmessage.NewName(q.Name)
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, Truncated: true, RecursionDesired: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

// BuildPaddedQuery builds a query padded with an EDNS0 padding option (RFC
// 7830) to at least size bytes, so that the answer is never larger than the
// question (amplification factor <= 1).
func BuildPaddedQuery(id uint16, name string, t dnsmessage.Type, size int) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	base, err := b.Finish()
	if err != nil {
		return nil, err
	}
	pad := size - len(base) - 11 - 4 // OPT RR header (11) + option header (4)
	if pad < 0 {
		pad = 0
	}
	b2 := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b2.EnableCompression()
	b2.StartQuestions()
	b2.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET})
	b2.StartAdditionals()
	rh := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}
	if err := b2.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, pad)}}}); err != nil {
		return nil, err
	}
	return b2.Finish()
}
