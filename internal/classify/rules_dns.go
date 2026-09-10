package classify

import (
	"strings"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// ruleDNS is rule 6: DNS transport differentials and manipulation. The
// three parts run in this order: when two of them name one cell, rule 7
// attaches the mechanism to the later verdict.
func (rc *ruleCtx) ruleDNS() {
	rc.dnsManipulation()
	var dnsUDP, dnsTCP *Cell
	for i := range rc.cells {
		if rc.cells[i].TestID == "dns.udp" && rc.cells[i].Variant == "TXT" {
			dnsUDP = &rc.cells[i]
		}
		if rc.cells[i].TestID == "dns.tcp" {
			dnsTCP = &rc.cells[i]
		}
	}
	// UDP-only: the same query passes over TCP.
	udpOnly := dnsUDP != nil && dnsTCP != nil && dnsTCP.pass()
	if udpOnly && dnsUDP.fail() {
		rc.add("dns_udp_blocking_suspected", dnsUDP.Key(), confidence(*dnsUDP, *dnsTCP), rc.ev(*dnsUDP), "passing control: "+rc.ev(*dnsTCP))
	}
	rc.dnsPortBlocking(udpOnly)
}

// dnsManipulation reports the cells where an answer came back and was not
// the authoritative one, whatever the cell did otherwise.
func (rc *ruleCtx) dnsManipulation() {
	for _, c := range rc.cells {
		if !strings.HasPrefix(c.TestID, "dns.") {
			continue
		}
		if c.Outcomes[client.OutcomeDNSMismatch]+c.Outcomes["dns_injected_race"] > 0 {
			kind := "dns_manipulation_suspected"
			if c.TestID == "dns.system" {
				kind = "system_resolver_manipulation_suspected"
			}
			rc.add(kind, c.Key(), "medium", rc.ev(c), "answer content did not match the authoritative nonce answer")
		}
	}
}

// dnsPortBlocking: the DNS ports carry no echo test, so a blanket block of
// port 53 or 853 would otherwise produce no verdict at all: use any passing
// echo of the same transport as the control. udpOnly says that dns.tcp
// passes next to dns.udp: the dns.udp cells are then
// dns_udp_blocking_suspected's.
func (rc *ruleCtx) dnsPortBlocking(udpOnly bool) {
	for _, c := range rc.cells {
		if !strings.HasPrefix(c.TestID, "dns.") || c.TestID == "dns.system" || c.TestID == "dns.doh" || !c.fail() {
			continue
		}
		if _, ok := rc.find("tcp.echo", c.Transport, c.Port, ""); ok {
			continue
		}
		if _, ok := rc.find("udp.echo", c.Transport, c.Port, ""); ok {
			continue
		}
		if udpOnly && c.TestID == "dns.udp" {
			continue // already reported as dns_udp_blocking_suspected
		}
		echoTest := echoTestFor(c.Transport)
		var ctrl *Cell
		for i := range rc.cells {
			if rc.cells[i].TestID == echoTest && rc.cells[i].pass() {
				ctrl = &rc.cells[i]
				break
			}
		}
		if ctrl == nil {
			continue
		}
		rc.add("dns_port_blocking_suspected", c.Key(), confidence(c, *ctrl), rc.ev(c), "no echo runs on this port; passing echo on another port of the same transport: "+rc.ev(*ctrl))
	}
}
