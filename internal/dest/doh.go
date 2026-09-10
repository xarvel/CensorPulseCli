package dest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DoHAnswer is one resolver's view of a name (A and AAAA together).
type DoHAnswer struct {
	Resolver string
	RCode    string // NOERROR|NXDOMAIN|OTHER|ERROR
	IPs      []netip.Addr
	Endpoint string // which endpoint / API answered
	Err      string
	MS       float64
}

// Consensus is what the trusted resolvers say together.
type Consensus struct {
	IPs   []netip.Addr
	RCode string // NOERROR|NXDOMAIN|OTHER|ERROR
	Note  string // per-resolver summary "cloudflare:NOERROR/2, google:NOERROR/2, quad9:ERROR"
}

// ResolveTrusted queries every trusted resolver in parallel, each with one
// timeout budget shared out over its endpoints.
func ResolveTrusted(ctx context.Context, hc *http.Client, name string, timeout time.Duration) []DoHAnswer {
	out := make([]DoHAnswer, len(TrustedResolvers))
	var wg sync.WaitGroup
	for i, r := range TrustedResolvers {
		wg.Add(1)
		go func(i int, r Resolver) {
			defer wg.Done()
			out[i] = QueryDoH(ctx, hc, r, name, timeout)
		}(i, r)
	}
	wg.Wait()
	return out
}

// QueryDoH asks one resolver for A and AAAA: the domain endpoint, then the
// IP-literal one, then the JSON API. The first endpoint that answers either
// type wins.
func QueryDoH(ctx context.Context, hc *http.Client, r Resolver, name string, timeout time.Duration) DoHAnswer {
	// One budget for the resolver as a whole, shared out over its endpoints
	// as they are tried: a blackholed domain endpoint costs its share, not
	// the whole timeout, and the IP-literal and JSON fallbacks still get a
	// turn (an endpoint that fails fast leaves its time to the next).
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	remaining := len(r.URLs)
	if r.JSON != "" {
		remaining++
	}
	share := func() time.Duration {
		if remaining < 1 {
			remaining = 1
		}
		d := time.Until(deadline) / time.Duration(remaining)
		remaining--
		return d
	}
	t0 := time.Now()
	ans := DoHAnswer{Resolver: r.Name, RCode: "ERROR"}
	var lastErr error
	for _, ep := range r.URLs {
		a, aaaa, err := wirePair(ctx, hc, ep, name, share())
		if err == nil {
			ans.Endpoint = ep
			ans.RCode, ans.IPs = combine(a, aaaa)
			ans.MS = ms(t0)
			return ans
		}
		lastErr = err
	}
	if r.JSON != "" {
		a, aaaa, err := jsonPair(ctx, hc, r.JSON, name, share())
		if err == nil {
			ans.Endpoint = r.JSON + " (json)"
			ans.RCode, ans.IPs = combine(a, aaaa)
			ans.MS = ms(t0)
			return ans
		}
		lastErr = err
	}
	if lastErr != nil {
		ans.Err = lastErr.Error()
	}
	ans.MS = ms(t0)
	return ans
}

func ms(t0 time.Time) float64 { return float64(time.Since(t0).Microseconds()) / 1000 }

type wireResult struct {
	rcode string
	ips   []netip.Addr
}

// wirePair runs A and AAAA against one endpoint under one deadline. It fails
// only when neither query produced a DNS response.
func wirePair(ctx context.Context, hc *http.Client, endpoint, name string, timeout time.Duration) (a, aaaa wireResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var wg sync.WaitGroup
	var errA, errAAAA error
	wg.Add(2)
	go func() { defer wg.Done(); a, errA = queryWire(ctx, hc, endpoint, name, dnsmessage.TypeA) }()
	go func() { defer wg.Done(); aaaa, errAAAA = queryWire(ctx, hc, endpoint, name, dnsmessage.TypeAAAA) }()
	wg.Wait()
	if errA != nil && errAAAA != nil {
		return a, aaaa, errA
	}
	if errA != nil {
		a = wireResult{rcode: "ERROR"}
	}
	if errAAAA != nil {
		aaaa = wireResult{rcode: "ERROR"}
	}
	return a, aaaa, nil
}

// queryWire is RFC 8484: POST application/dns-message, then GET ?dns=.
func queryWire(ctx context.Context, hc *http.Client, endpoint, name string, t dnsmessage.Type) (wireResult, error) {
	q, err := buildQuery(name, t)
	if err != nil {
		return wireResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(q))
	if err != nil {
		return wireResult{}, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	res, postErr := doWire(hc, req)
	if postErr == nil {
		return res, nil
	}
	// GET with the base64url query: some paths reject POST bodies.
	u := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(q)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return wireResult{}, err
	}
	req.Header.Set("Accept", "application/dns-message")
	res, getErr := doWire(hc, req)
	if getErr == nil {
		return res, nil
	}
	return wireResult{}, fmt.Errorf("post: %v; get: %v", postErr, getErr)
}

func doWire(hc *http.Client, req *http.Request) (wireResult, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return wireResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return wireResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return wireResult{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	return parseAnswer(body)
}

func buildQuery(name string, t dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	_, _ = randRead(idb[:])
	// RFC 8484 §4.1: an ID of 0 lets caches work; a random one costs nothing.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: binary.BigEndian.Uint16(idb[:]), RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parseAnswer extracts the rcode and every A/AAAA record of a response.
func parseAnswer(b []byte) (wireResult, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return wireResult{}, err
	}
	if !h.Response {
		return wireResult{}, errors.New("not a DNS response")
	}
	out := wireResult{rcode: rcodeName(h.RCode)}
	if err := p.SkipAllQuestions(); err != nil {
		return out, nil
	}
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			if r, err := p.AResource(); err == nil {
				out.ips = append(out.ips, netip.AddrFrom4(r.A))
			} else {
				return out, nil
			}
		case dnsmessage.TypeAAAA:
			if r, err := p.AAAAResource(); err == nil {
				out.ips = append(out.ips, netip.AddrFrom16(r.AAAA))
			} else {
				return out, nil
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, nil
			}
		}
	}
	return out, nil
}

func rcodeName(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	}
	return "OTHER"
}

// jsonPair uses the Google/Cloudflare JSON API (application/dns-json).
func jsonPair(ctx context.Context, hc *http.Client, api, name string, timeout time.Duration) (a, aaaa wireResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if a, err = queryJSON(ctx, hc, api, name, "A"); err != nil {
		return
	}
	aaaa, err = queryJSON(ctx, hc, api, name, "AAAA")
	if err != nil {
		aaaa, err = wireResult{rcode: "ERROR"}, nil
	}
	return
}

func queryJSON(ctx context.Context, hc *http.Client, api, name, qtype string) (wireResult, error) {
	u := api + "?name=" + url.QueryEscape(name) + "&type=" + qtype
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return wireResult{}, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := hc.Do(req)
	if err != nil {
		return wireResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wireResult{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	var body struct {
		Status *int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return wireResult{}, err
	}
	if body.Status == nil {
		return wireResult{}, errors.New("json: no Status")
	}
	out := wireResult{rcode: rcodeName(dnsmessage.RCode(*body.Status))}
	for _, r := range body.Answer {
		if r.Type != 1 && r.Type != 28 {
			continue
		}
		if ip, err := netip.ParseAddr(r.Data); err == nil {
			out.ips = append(out.ips, ip)
		}
	}
	return out, nil
}

// combine folds the A and AAAA results into one rcode and address list.
func combine(a, aaaa wireResult) (string, []netip.Addr) {
	ips := Unique(append(append([]netip.Addr(nil), a.ips...), aaaa.ips...))
	if len(ips) > 0 {
		return "NOERROR", ips
	}
	switch {
	case a.rcode == "ERROR" && aaaa.rcode == "ERROR":
		return "ERROR", nil
	case a.rcode == "NXDOMAIN" && (aaaa.rcode == "NXDOMAIN" || aaaa.rcode == "ERROR"),
		aaaa.rcode == "NXDOMAIN" && (a.rcode == "NXDOMAIN" || a.rcode == "ERROR"):
		return "NXDOMAIN", nil
	case a.rcode == "OTHER" || aaaa.rcode == "OTHER":
		return "OTHER", nil
	}
	return "NOERROR", nil // NODATA on both types
}

// TrustedConsensus merges the answers: the union of addresses from the
// resolvers that answered; NXDOMAIN only when every answering resolver said
// so; ERROR when none answered.
func TrustedConsensus(answers []DoHAnswer) Consensus {
	var ok []DoHAnswer
	for _, a := range answers {
		if a.RCode != "ERROR" {
			ok = append(ok, a)
		}
	}
	parts := make([]string, 0, len(answers))
	for _, a := range answers {
		if a.RCode == "ERROR" {
			parts = append(parts, a.Resolver+":ERROR")
		} else {
			parts = append(parts, fmt.Sprintf("%s:%s/%d", a.Resolver, a.RCode, len(a.IPs)))
		}
	}
	sort.Strings(parts)
	note := strings.Join(parts, ", ")
	if len(ok) == 0 {
		return Consensus{RCode: "ERROR", Note: note}
	}
	nx := 0
	var ips []netip.Addr
	for _, a := range ok {
		if a.RCode == "NXDOMAIN" && len(a.IPs) == 0 {
			nx++
		}
		ips = append(ips, a.IPs...)
	}
	ips = Unique(ips)
	switch {
	case nx == len(ok):
		return Consensus{RCode: "NXDOMAIN", Note: note}
	case len(ips) > 0:
		return Consensus{IPs: ips, RCode: "NOERROR", Note: note}
	}
	return Consensus{RCode: "OTHER", Note: note}
}
