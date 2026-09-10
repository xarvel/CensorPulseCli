package l2tp

import (
	"bytes"
	"testing"
	"time"
)

// UDP 1701 is open to the world: ParseControl walks AVPs whose lengths the
// sender chose, and the data accessors index a datagram the demuxer has only
// shape-checked.

// within fails the test when fn does not return: an AVP walk that stops
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

func FuzzParseControl(f *testing.F) {
	sccrq := SCCRQ(0x1234, "probe-1")
	f.Add(sccrq)
	f.Add(sccrq[:len(sccrq)-3])
	f.Add(SCCRP(0x1234, 0x5678, "cpprobe"))
	f.Add(SCCCN(0x5678))
	f.Add(ICRQ(0x5678, 5, 2, 1))
	f.Add(ICRP(0x1234, 5, 6, 1, 3))
	f.Add(ICCN(0x5678, 6, 3, 2))
	f.Add(ZLB(0x1234, 5, 1, 2))
	f.Add(Data(0x1234, 5, PPPLCPConfigureRequest(1)))
	zeroAVP := append(ZLB(1, 0, 0, 0), 0x80, 0, 0, 0, 0, 0) // AVP of length 0: must not loop
	zeroAVP[3] = byte(len(zeroAVP))
	f.Add(zeroAVP)
	f.Fuzz(func(t *testing.T, b []byte) {
		var c Control
		var err error
		within(t, 5*time.Second, func() { c, err = ParseControl(b) })
		if err != nil {
			return
		}
		if !IsControl(b) || IsData(b) {
			t.Fatalf("parsed a datagram the shape checks disagree on: %x", b)
		}
		// The header is fixed-size: a ZLB built from the parsed ids is the
		// first 12 bytes again, length field aside.
		head := ZLB(c.TunnelID, c.SessionID, c.Ns, c.Nr)
		if !bytes.Equal(head[:2], []byte{0xc8, 0x02}) || !bytes.Equal(head[4:], b[4:ControlHeaderLen]) {
			t.Fatalf("header round trip\n b    %x\n head %x", b[:ControlHeaderLen], head)
		}
	})
}

// FuzzControlRoundTrip: Parse(Build(x)) == x for the two messages that carry
// caller-chosen values.
func FuzzControlRoundTrip(f *testing.F) {
	f.Add(uint16(1), uint16(2), "probe-1")
	f.Add(uint16(0xffff), uint16(0), "")
	f.Add(uint16(7), uint16(9), string(bytes.Repeat([]byte{'h'}, 200)))
	f.Fuzz(func(t *testing.T, peer, assigned uint16, host string) {
		if len(host) > 1023-6 {
			return // an AVP length is 10 bits; the probe's host names are short
		}
		c, err := ParseControl(SCCRQ(assigned, host))
		if err != nil || c.MessageType != MsgSCCRQ || c.TunnelID != 0 || c.AssignedTunnel != assigned || c.HostName != host {
			t.Fatalf("sccrq: %+v %v", c, err)
		}
		c, err = ParseControl(SCCRP(peer, assigned, host))
		if err != nil || c.MessageType != MsgSCCRP || c.TunnelID != peer || c.AssignedTunnel != assigned || c.HostName != host {
			t.Fatalf("sccrp: %+v %v", c, err)
		}
	})
}

func FuzzData(f *testing.F) {
	f.Add(Data(0x1234, 5, PPPLCPConfigureRequest(1)))
	f.Add(Data(0xffff, 0xffff, nil))
	f.Add(Data(1, 2, PPPIP([]byte("payload")))[:5])
	f.Add(SCCCN(0x5678))
	f.Fuzz(func(t *testing.T, b []byte) {
		// DataTunnel and DataPayload index b unchecked; IsData is the guard
		// the UDP demuxer runs first (server/udp.go).
		if !IsData(b) {
			return
		}
		if IsControl(b) {
			t.Fatalf("both data and control: %x", b)
		}
		tunnel, ppp := DataTunnel(b), DataPayload(b)
		session := uint16(b[4])<<8 | uint16(b[5])
		again := Data(tunnel, session, ppp)
		// Flag bits the builder never sets (priority, reserved) are the only
		// part of an accepted datagram it cannot reproduce.
		if !bytes.Equal(again[2:], b[2:]) {
			t.Fatalf("Data(DataTunnel, session, DataPayload) != b\n b     %x\n again %x", b, again)
		}
	})
}
