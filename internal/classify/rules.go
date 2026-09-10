package classify

import (
	"fmt"

	"github.com/xarvel/CensorPulseCli/internal/client"
)

// ruleCtx is what every rule reads and the one thing the rules write: the
// verdict list. The cells are built once, without the transient attempts;
// the attempts are there for the evidence (offsets, packet counts, timings).
type ruleCtx struct {
	attempts  []*client.Attempt
	cells     []Cell            // sorted by key
	byTest    map[string][]Cell // test id → its cells, in cell order
	baselines []Cell            // the tcp.echo / udp.echo cells, in cell order
	verdicts  []Verdict
}

func newRuleCtx(attempts []*client.Attempt, cells []Cell) *ruleCtx {
	rc := &ruleCtx{attempts: attempts, cells: cells, byTest: map[string][]Cell{}}
	for _, c := range cells {
		rc.byTest[c.TestID] = append(rc.byTest[c.TestID], c)
		if c.TestID == "tcp.echo" || c.TestID == "udp.echo" {
			rc.baselines = append(rc.baselines, c)
		}
	}
	return rc
}

// find returns the first cell of a test on a port; an empty variant matches
// any variant.
func (rc *ruleCtx) find(test, transport string, port int, variant string) (Cell, bool) {
	for _, c := range rc.cells {
		if c.TestID == test && c.Transport == transport && c.Port == port && (variant == "" || c.Variant == variant) {
			return c, true
		}
	}
	return Cell{}, false
}

// handshakeCell finds the handshake-only control of a session cell: the
// handshake variant of the same signature (a session variant is the
// handshake variant plus "+control" / "+data": noise-ik+data ↔ noise-ik,
// udp+tls-auth+data ↔ udp+tls-auth, udp+control+data ↔ udp), else the
// same variant name, else any variant.
func (rc *ruleCtx) handshakeCell(c Cell) (Cell, bool) {
	hs := handshakeTestOf(c.TestID)
	if hs == "" {
		return Cell{}, false
	}
	if h, ok := rc.find(hs, c.Transport, c.Port, handshakeVariantOf(c.Variant)); ok {
		return h, true
	}
	if h, ok := rc.find(hs, c.Transport, c.Port, c.Variant); ok {
		return h, true
	}
	return rc.find(hs, c.Transport, c.Port, "")
}

func (rc *ruleCtx) add(kind, subject, conf string, ev ...string) {
	rc.verdicts = append(rc.verdicts, Verdict{Kind: kind, Subject: subject, Confidence: conf, Evidence: ev})
}

// ev is the evidence line of a cell.
func (rc *ruleCtx) ev(c Cell) string {
	return fmt.Sprintf("%s: %d/%d ok, dominant=%s, server_saw=%d", c.Key(), c.OK, c.Total, c.dominant(), c.ServerSaw)
}

// run applies the rules in order. The verdict list is sorted afterwards, so
// the order shows in the output only where a rule reads what an earlier one
// wrote:
//
//   - ruleModification looks the cell up among the verdicts of every rule
//     before it, by subject, to attach the mechanism instead of reporting it
//     twice; when two verdicts name the cell, the later one gets it. It must
//     stay after rules 1-6 (and the three parts of ruleDNS in their order)
//     and before ruleSynAck and the dest.* verdicts, which it never decorates.
//   - ruleSynAck reads rulePortOrProxy's transparent_proxy_suspected.
func (rc *ruleCtx) run() {
	for _, rule := range []func(){
		rc.ruleEndpoint,     // 1
		rc.rulePortOrProxy,  // 2
		rc.ruleUDP,          // 3
		rc.ruleProtocol,     // 4
		rc.ruleVariant,      // 5
		rc.ruleBulkCut,      // 5b
		rc.rulePacketCut,    // 5b'
		rc.ruleBurstFreeze,  // 5b''
		rc.ruleSessionCut,   // 5c
		rc.ruleDNS,          // 6
		rc.ruleModification, // 7
		rc.ruleSynAck,       // 8
	} {
		rule()
	}
}
