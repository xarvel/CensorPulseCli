// Package dest holds what the "real destinations" family needs and does not
// get from the probe server: the catalog of sites a scan visits, the trusted
// DNS-over-HTTPS resolvers it compares the system resolver against, the
// anycast control addresses, the decoy names for the SNI differential, and
// the address heuristics (bogons, ordering) shared by those tests.
//
// Everything here is one-sided: there is no server half of the evidence, so
// the classifier caps every verdict built on it at medium confidence and
// only ever compares a failing cell with a passing control measured the same
// way (a decoy name on the same address, a control site, the anycast
// address).
package dest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Category groups targets by what a failure would tell.
type Category string

const (
	CategoryControl   Category = "control"
	CategoryDPI       Category = "dpi"
	CategorySocial    Category = "social"
	CategoryMessenger Category = "messenger"
	CategoryStore     Category = "store"
	CategoryVCS       Category = "vcs"
	CategoryStreaming Category = "streaming"
	CategoryGaming    Category = "gaming"
	CategoryDev       Category = "dev"
	CategoryNews      Category = "news"
	CategoryAI        Category = "ai"
	CategoryCustom    Category = "custom"
)

// Categories lists the known categories in display order.
var Categories = []Category{CategoryControl, CategoryDPI, CategorySocial, CategoryMessenger, CategoryStore, CategoryVCS, CategoryStreaming, CategoryGaming, CategoryDev, CategoryNews, CategoryAI, CategoryCustom}

// Target is one destination of the family.
type Target struct {
	// Domain is the report key: the site as the user knows it.
	Domain   string   `json:"domain"`
	Category Category `json:"category"`
	Label    string   `json:"label,omitempty"`
	// DNSName is the name to resolve when it differs from Domain.
	DNSName string `json:"dns_name,omitempty"`
	// FixedIPs are probed ahead of (or, with SkipDNS, instead of) the
	// resolved addresses.
	FixedIPs []string `json:"fixed_ips,omitempty"`
	// SkipDNS: no resolution at all, only FixedIPs (a messenger data centre).
	SkipDNS bool `json:"skip_dns,omitempty"`
	// SkipTLS: TCP only (the address speaks a protocol other than web TLS).
	SkipTLS bool `json:"skip_tls,omitempty"`
	// HTTPCheck: after a clean TLS handshake, GET / and look at the status.
	// For services that refuse a region at the application layer (451).
	HTTPCheck bool `json:"http_check,omitempty"`
	// SNI is the server name for the TLS handshake when it differs from Domain.
	SNI string `json:"sni,omitempty"`
}

// QueryName is the name the DNS layer resolves.
func (t Target) QueryName() string {
	if t.DNSName != "" {
		return t.DNSName
	}
	return t.Domain
}

// ServerName is the SNI of the real handshake.
func (t Target) ServerName() string {
	if t.SNI != "" {
		return t.SNI
	}
	return t.Domain
}

// Fixed returns the parsed fixed addresses; malformed entries are dropped.
func (t Target) Fixed() []netip.Addr {
	var out []netip.Addr
	for _, s := range t.FixedIPs {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// TelegramDCIPs are the Telegram production data centres, historically on
// 149.154.167.x:443 (MTProto, not web TLS).
var TelegramDCIPs = []string{"149.154.167.50", "149.154.167.51", "149.154.167.91", "149.154.167.99"}

// Default is the built-in catalog: two control sites that should be clear
// anywhere, then the services whose blocking is the usual question. Order is
// display order.
func Default() []Target {
	return []Target{
		{Domain: "wikipedia.org", Category: CategoryControl, Label: "Control"},
		{Domain: "example.com", Category: CategoryControl, Label: "Control"},
		{Domain: "youtube.com", Category: CategoryDPI, Label: "YouTube"},
		{Domain: "instagram.com", Category: CategorySocial, Label: "Instagram"},
		{Domain: "facebook.com", Category: CategorySocial, Label: "Facebook"},
		{Domain: "x.com", Category: CategorySocial, Label: "X"},
		{Domain: "www.linkedin.com", Category: CategorySocial, Label: "LinkedIn"},
		{Domain: "tiktok.com", Category: CategorySocial, Label: "TikTok"},
		{Domain: "telegram.org", Category: CategoryMessenger, Label: "Telegram web"},
		{Domain: "telegram-dc", Category: CategoryMessenger, Label: "Telegram DC", SkipDNS: true, SkipTLS: true, FixedIPs: TelegramDCIPs, SNI: "telegram.org"},
		{Domain: "whatsapp.com", Category: CategoryMessenger, Label: "WhatsApp"},
		{Domain: "g.whatsapp.net", Category: CategoryMessenger, Label: "WhatsApp backend"},
		{Domain: "discord.com", Category: CategoryMessenger, Label: "Discord"},
		{Domain: "gateway.discord.gg", Category: CategoryMessenger, Label: "Discord gateway"},
		{Domain: "apps.apple.com", Category: CategoryStore, Label: "App Store"},
		{Domain: "play.google.com", Category: CategoryStore, Label: "Google Play"},
		{Domain: "zoom.us", Category: CategoryVCS, Label: "Zoom"},
		{Domain: "meet.google.com", Category: CategoryVCS, Label: "Google Meet"},
		{Domain: "teams.microsoft.com", Category: CategoryVCS, Label: "Microsoft Teams"},
		{Domain: "netflix.com", Category: CategoryStreaming, Label: "Netflix"},
		{Domain: "twitch.tv", Category: CategoryStreaming, Label: "Twitch"},
		{Domain: "spotify.com", Category: CategoryStreaming, Label: "Spotify"},
		{Domain: "steamcommunity.com", Category: CategoryGaming, Label: "Steam"},
		{Domain: "github.com", Category: CategoryDev, Label: "GitHub"},
		{Domain: "meduza.io", Category: CategoryNews, Label: "Meduza"},
		{Domain: "bbc.com", Category: CategoryNews, Label: "BBC"},
		{Domain: "dw.com", Category: CategoryNews, Label: "DW"},
		{Domain: "svoboda.org", Category: CategoryNews, Label: "RFE/RL"},
		{Domain: "chatgpt.com", Category: CategoryAI, Label: "ChatGPT", HTTPCheck: true},
		{Domain: "claude.ai", Category: CategoryAI, Label: "Claude", HTTPCheck: true},
		{Domain: "gemini.google.com", Category: CategoryAI, Label: "Gemini", HTTPCheck: true},
		{Domain: "openai.com", Category: CategoryAI, Label: "OpenAI", HTTPCheck: true},
	}
}

// Parse reads a target list: one target per line, `#` comments, fields
// separated by blanks. The first field is the domain, the rest are options:
//
//	category=news  label="..."  ip=1.2.3.4,5.6.7.8  sni=name  dns=name  tcp-only  no-dns  http
//
// Unknown categories are kept as "custom"; a line without a domain is an error.
func Parse(r io.Reader) ([]Target, error) {
	var out []Target
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		fields := splitFields(l)
		t := Target{Domain: strings.ToLower(fields[0]), Category: CategoryCustom}
		if strings.ContainsAny(t.Domain, "=/ ") {
			return nil, fmt.Errorf("line %d: expected a domain first, got %q", line, fields[0])
		}
		if seen[t.Domain] {
			return nil, fmt.Errorf("line %d: duplicate target %s", line, t.Domain)
		}
		seen[t.Domain] = true
		for _, f := range fields[1:] {
			k, v, hasValue := strings.Cut(f, "=")
			switch k {
			case "category":
				t.Category = Category(strings.ToLower(v))
				if !knownCategory(t.Category) {
					t.Category = CategoryCustom
				}
			case "label":
				t.Label = v
			case "ip":
				for _, s := range strings.Split(v, ",") {
					if _, err := netip.ParseAddr(s); err != nil {
						return nil, fmt.Errorf("line %d: ip=%s: %w", line, s, err)
					}
					t.FixedIPs = append(t.FixedIPs, s)
				}
			case "sni":
				t.SNI = v
			case "dns":
				t.DNSName = v
			case "tcp-only":
				t.SkipTLS = true
			case "no-dns":
				t.SkipDNS = true
			case "http":
				t.HTTPCheck = true
			default:
				if hasValue {
					return nil, fmt.Errorf("line %d: unknown option %q", line, k)
				}
				return nil, fmt.Errorf("line %d: unknown flag %q", line, f)
			}
		}
		if t.SkipDNS && len(t.FixedIPs) == 0 {
			return nil, fmt.Errorf("line %d: no-dns needs ip=", line)
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no targets")
	}
	return out, nil
}

// splitFields splits on blanks, keeping double-quoted runs together
// (label="Example news"). Quotes are removed.
func splitFields(l string) []string {
	var out []string
	var cur strings.Builder
	inQuote, has := false, false
	for _, r := range l {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case !inQuote && (r == ' ' || r == '\t'):
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

func knownCategory(c Category) bool {
	for _, k := range Categories {
		if k == c {
			return true
		}
	}
	return false
}

// Resolver is one trusted DNS-over-HTTPS provider. The domain endpoint comes
// first; the IP-literal endpoint needs no DNS and sends no SNI, which keeps
// DoH usable on networks that block the resolver *names* (all three
// certificates carry IP SANs). JSON is the provider's JSON API, tried when
// both wire endpoints fail (a rule on the application/dns-message media type
// does not catch it).
type Resolver struct {
	Name string
	URLs []string
	JSON string // "" when the provider has no JSON API
}

// TrustedResolvers are queried in parallel; their agreement is the trusted
// view of a name.
var TrustedResolvers = []Resolver{
	{Name: "cloudflare", URLs: []string{"https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query"}, JSON: "https://cloudflare-dns.com/dns-query"},
	{Name: "google", URLs: []string{"https://dns.google/dns-query", "https://8.8.8.8/dns-query"}, JSON: "https://dns.google/resolve"},
	{Name: "quad9", URLs: []string{"https://dns.quad9.net/dns-query", "https://9.9.9.9/dns-query"}},
}

// ControlAddrs are clean anycast addresses that answer on :443 without any
// name: the TCP control of the family. The first that connects is the
// control; all failing means the network, not a site.
var ControlAddrs = []string{"1.1.1.1", "1.0.0.1", "9.9.9.9"}

// DecoyNames are rarely filtered names used as the decoy SNI on a target's
// own address. A real name failing while a decoy passes on the same address
// is the SNI-keyed signature.
var DecoyNames = []string{"www.microsoft.com", "www.apple.com", "www.cloudflare.com", "example.com", "www.wikipedia.org"}

// IsBogon reports whether an address can never be a public web endpoint: the
// typical sinkhole answers of a poisoning resolver (0.0.0.0, 127.0.0.1,
// 10.x, 192.168.x, CGNAT, link-local, ::, ::1, ULA).
func IsBogon(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		switch {
		case b[0] == 0, b[0] == 127, b[0] == 255:
			return true
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // CGNAT
			return true
		case b[0] == 169 && b[1] == 254:
			return true
		case b[0] == 192 && b[1] == 0 && b[2] == 2, b[0] == 198 && b[1] == 51 && b[2] == 100, b[0] == 203 && b[1] == 0 && b[2] == 113: // TEST-NET
			return true
		}
	}
	return false
}

// Unique deduplicates, keeping order and unmapping v4-in-v6.
func Unique(ips []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// Prioritize drops bogons and orders the rest: public IPv4 first, in input
// order, then IPv6. The first element is the address every layer of a target
// uses, so that the SNI differential compares handshakes on one address.
func Prioritize(ips []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, ip := range Unique(ips) {
		if IsBogon(ip) {
			continue
		}
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return append(v4, v6...)
}

// Strings renders addresses for a detail field.
func Strings(ips []netip.Addr) string {
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return strings.Join(s, ",")
}

// SystemResult is the system resolver's view of a name.
type SystemResult struct {
	IPs   []netip.Addr
	RCode string // NOERROR|NXDOMAIN|TIMEOUT|ERROR
	Err   string
}

// Comparison is what the two views say together.
type Comparison struct {
	// Tampered: the system answer cannot be the real one; Reason says why
	// (bogon, hijack, nxdomain). Verified downstream when only Disagree is set.
	Tampered bool
	Reason   string
	// Disagree: both sides answered and share no address. CDN geo-DNS or
	// poisoning; the caller decides by connecting to the system address.
	Disagree bool
	Note     string
}

// Compare applies the resolver-disagreement rules of the family.
func Compare(sys SystemResult, trusted Consensus) Comparison {
	sysPublic, sysBogons := 0, 0
	for _, ip := range sys.IPs {
		if IsBogon(ip) {
			sysBogons++
		} else {
			sysPublic++
		}
	}
	trustedPublic := 0
	for _, ip := range trusted.IPs {
		if !IsBogon(ip) {
			trustedPublic++
		}
	}
	switch {
	case trusted.RCode == "ERROR" && len(trusted.IPs) == 0:
		return Comparison{Note: "every trusted resolver failed: tampering cannot be assessed"}
	case sys.RCode == "TIMEOUT":
		return Comparison{Note: "system resolver timed out"}
	case trusted.RCode == "NXDOMAIN" && len(sys.IPs) == 0:
		return Comparison{Note: "NXDOMAIN on both sides"}
	case trusted.RCode == "OTHER" && len(trusted.IPs) == 0:
		return Comparison{Note: "the trusted resolvers returned SERVFAIL/REFUSED: tampering cannot be assessed"}
	case sys.RCode == "NXDOMAIN" && trustedPublic > 0:
		// The commonest resolver-level block: the ISP resolver denies the
		// name exists while every trusted resolver has addresses for it.
		return Comparison{Tampered: true, Reason: "nxdomain", Note: "the system resolver says the name does not exist while the trusted resolvers return addresses"}
	case sysBogons > 0 && trustedPublic > 0:
		return Comparison{Tampered: true, Reason: "bogon", Note: "the system resolver returned sinkhole addresses while the trusted resolvers returned public ones"}
	case trusted.RCode == "NXDOMAIN" && len(sys.IPs) > 0:
		return Comparison{Tampered: true, Reason: "hijack", Note: "the trusted resolvers say the name does not exist; the system resolver returned addresses"}
	case sysPublic > 0 && trustedPublic > 0 && !intersects(sys.IPs, trusted.IPs):
		return Comparison{Disagree: true, Note: "system and trusted answers share no address: geo-DNS or poisoning, verified by connecting to the system address"}
	}
	return Comparison{}
}

func intersects(a, b []netip.Addr) bool {
	set := map[netip.Addr]bool{}
	for _, ip := range b {
		set[ip.Unmap()] = true
	}
	for _, ip := range a {
		if set[ip.Unmap()] {
			return true
		}
	}
	return false
}

// ProbeAddrs picks what the transport layers probe: the trusted answers,
// else the public system answers (every DoH resolver blocked), and says which.
func ProbeAddrs(sys SystemResult, trusted Consensus) (ips []netip.Addr, source string) {
	if t := Prioritize(trusted.IPs); len(t) > 0 {
		return t, "trusted"
	}
	if s := Prioritize(sys.IPs); len(s) > 0 {
		return s, "system"
	}
	return nil, "none"
}

// ClassifyHTTP answers the geo/policy question for a status. Only 451
// (Unavailable For Legal Reasons) is an unambiguous region block: a bare
// client has no JS engine, so a 403 is as likely a bot wall as a country
// gate; it is surfaced, never called a block.
func ClassifyHTTP(status int) (legalBlock bool, note string) {
	switch {
	case status == 451:
		return true, "HTTP 451: unavailable for legal reasons"
	case status == 403:
		return false, "HTTP 403: inconclusive (region gate or bot wall)"
	case status == 0:
		return false, "no HTTP response"
	}
	return false, fmt.Sprintf("HTTP %d", status)
}

// SortedCategories returns the categories present in targets, in catalog order.
func SortedCategories(targets []Target) []Category {
	present := map[Category]bool{}
	for _, t := range targets {
		present[t.Category] = true
	}
	var out []Category
	for _, c := range Categories {
		if present[c] {
			out = append(out, c)
		}
	}
	var extra []string
	for c := range present {
		if !knownCategory(c) {
			extra = append(extra, string(c))
		}
	}
	sort.Strings(extra)
	for _, c := range extra {
		out = append(out, Category(c))
	}
	return out
}
