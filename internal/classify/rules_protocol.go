package classify

import (
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// nativeTests are the families that speak a real protocol: the ones rule 4
// compares with the opaque echo and random payloads of the same port.
var nativeTests = map[string]bool{"tcp.bulk": true, "openvpn.reset": true, "wireguard.init": true, "openvpn.session": true, "wireguard.session": true, "ikev2.init": true, "ikev2.session": true, "l2tp.init": true, "l2tp.session": true, "socks5.connect": true, "socks5.session": true, "vless.reality": true, "vless.session": true, "quic.v1": true, "tls.sni": true, "tls.version": true, "tls.alpn": true, "tls.fingerprint": true, "http.host": true, "dns.udp": true, "dns.tcp": true, "dns.dot": true,
	"tor.handshake": true, "tor.link": true, "tor.dir": true, "obfs4.handshake": true, "obfs4.session": true, "dtls.hello": true, "stun.binding": true}

// ruleProtocol is rule 4, protocol blocking: native handshake fails while
// echo + random pass on the same port.
func (rc *ruleCtx) ruleProtocol() {
	reportedFamily := map[string]bool{}
	for _, c := range rc.cells {
		if !nativeTests[c.TestID] || !c.fail() {
			continue
		}
		if init, ok := rc.handshakeCell(c); ok {
			if init.pass() {
				continue // handshake passes, data does not: rule 5c reports it
			}
			if init.fail() {
				continue // the handshake's own verdict covers the session
			}
		}
		famKey := familyKey(c.TestID, c.Transport, c.Port)
		if reportedFamily[famKey] {
			continue
		}
		echo, okE := rc.find(echoTestFor(c.Transport), c.Transport, c.Port, "")
		rnd, okR := rc.find(plainTestFor(c.Transport, "payload.random"), c.Transport, c.Port, "")
		if okE && echo.pass() && okR && rnd.fail() && c.Role != client.RoleControl {
			rc.add("control_failed_inconclusive", c.Key(), "low", rc.ev(c), "random-payload control also failed on this port: "+rc.ev(rnd), "echo passed: "+rc.ev(echo))
			continue
		}
		// Only call it protocol blocking when the whole test family on
		// this port fails; per-variant failures are rule 5's.
		if okE && echo.pass() && (!okR || rnd.pass()) && rc.familyFails(c) && c.Role != client.RoleControl {
			e := []string{rc.ev(c), "passing echo control: " + rc.ev(echo)}
			if okR {
				e = append(e, "passing random control: "+rc.ev(rnd))
			}
			conf := confidence(c, echo)
			if strings.HasPrefix(c.TestID, "ikev2.") || strings.HasPrefix(c.TestID, "l2tp.") {
				e = append(e, "consumer NAT routers with IPsec / L2TP passthrough ALGs drop or rewrite exactly these packets: a known confound on home networks, not necessarily the censor")
				// With a NAT in the path the ALG explanation is live and
				// the verdict cannot be high: the two are not separable
				// from one vantage point.
				if nat, line := natDetected(rc.attempts); nat {
					e = append(e, line+"; an ALG on it cannot be ruled out from this vantage point")
					if conf == "high" {
						conf = "medium"
					}
				}
			}
			reportedFamily[famKey] = true
			rc.add("protocol_blocking_suspected", famKey, conf, e...)
		}
	}
}

// familyFails reports whether every cell of c's test family on c's port
// fails; a cell that measured nothing does not count either way.
func (rc *ruleCtx) familyFails(c Cell) bool {
	for _, o := range rc.byTest[c.TestID] {
		if o.Port == c.Port && o.Transport == c.Transport && o.Measured() > 0 && !o.fail() {
			return false
		}
	}
	return true
}

// ruleVariant is rule 5: variant-level differentials inside one test family
// on one port. Both maps are walked in map order: every verdict here has a
// subject of its own, so the final sort fixes the order of the output.
func (rc *ruleCtx) ruleVariant() {
	for test, group := range rc.byTest {
		if client.IsDestTest(test) {
			continue // one-sided family with its own rules (dest.go)
		}
		byPort := map[string][]Cell{}
		for _, c := range group {
			byPort[portKey(c.Transport, c.Port)] = append(byPort[portKey(c.Transport, c.Port)], c)
		}
		for _, cs := range byPort {
			base := variantBaseline(test, cs)
			if base == nil {
				continue
			}
			for _, v := range cs {
				if v.Role == client.RoleBaseline || !v.fail() || v.Key() == base.Key() {
					continue
				}
				// A session variant whose own handshake passes is rule 5c's
				// finding (a session cut), not a variant differential.
				if init, ok := rc.handshakeCell(v); ok && init.pass() {
					continue
				}
				e := []string{rc.ev(v), "passing baseline: " + rc.ev(*base)}
				if test == "tor.handshake" {
					if line := torFeatureLine(cs, v.Variant); line != "" {
						e = append(e, line)
					}
				}
				rc.add(variantKind(test, v.Variant), v.Key(), confidence(v, *base), e...)
			}
		}
	}
}

// variantBaseline picks the passing cell the variants of one family on one
// port are compared with, nil when there is none. It is the baseline (for
// vless, which has none, the control).
func variantBaseline(test string, cs []Cell) *Cell {
	var base *Cell
	for i := range cs {
		if cs[i].Role == client.RoleBaseline || (base == nil && cs[i].Role == client.RoleControl && strings.HasPrefix(test, "vless.")) {
			base = &cs[i]
		}
	}
	if base != nil && base.pass() {
		return base
	}
	// When the nominal baseline fails but another variant of the same
	// family passes on the port, that variant is the control: the
	// rule then keys on what the baseline has and the passing one
	// lacks (a chrome parrot blocked while edge passes, for example).
	for i := range cs {
		if cs[i].pass() && cs[i].Role != client.RoleControl {
			return &cs[i]
		}
	}
	return nil
}

// variantKind names the finding of a failing variant after what the family
// varies.
func variantKind(test, variant string) string {
	switch test {
	case "tls.sni", "http.host":
		if strings.HasPrefix(variant, "trigger:") {
			return "sni_or_host_blocking_suspected"
		}
		return "sni_or_host_policy_suspected"
	case "tls.fingerprint":
		return "fingerprint_blocking_suspected"
	case "vless.reality", "vless.session":
		if strings.HasPrefix(variant, "reality:") {
			return "sni_ip_mismatch_blocking_suspected"
		}
	case "tls.alpn":
		return "alpn_policy_suspected"
	case "tls.version":
		return "tls_version_policy_suspected"
	case "dns.udp":
		return "dns_qtype_policy_suspected"
	case "socks5.connect":
		return "socks5_auth_policy_suspected"
	case "tor.handshake":
		return "tor_handshake_blocking_suspected"
	case "dtls.hello":
		return "dtls_fingerprint_blocking_suspected"
	}
	return "variant_blocking_suspected"
}

// torFeatureLine says which plaintext feature a tor.handshake rule keys on:
// the ClientHello, the certificate, or only the two together. cs are the
// family's cells on the port, variant the failing one.
func torFeatureLine(cs []Cell, variant string) string {
	state := func(variant string) string {
		for _, o := range cs {
			if o.Variant == variant {
				if o.fail() {
					return "fail"
				} else if o.pass() {
					return "pass"
				}
			}
		}
		return ""
	}
	hello, cert := state("tor-hello+probe-cert"), state("go-hello+tor-cert")
	switch {
	case hello == "fail" && cert == "fail":
		return "both the tor ClientHello alone and the relay certificate alone fail: two independent rules, or a rule on either feature"
	case hello == "fail" && cert == "pass":
		return "the tor ClientHello alone fails while the relay certificate with a plain hello passes: the rule keys on the ClientHello (no SNI + tor cipher list)"
	case hello == "pass" && cert == "fail":
		return "the relay certificate alone fails while the tor ClientHello with the probe certificate passes: the rule keys on the TLS 1.2 certificate (www.<random>.com / .net)"
	case hello == "pass" && cert == "pass" && variant == "tor-hello+tor-cert":
		return "each feature alone passes; only the full tor shape fails: the rule needs both the ClientHello and the certificate"
	}
	return ""
}
