package l2tp

import "testing"

func TestControlRoundTrip(t *testing.T) {
	tid := RandomID()
	req := SCCRQ(tid, "probe-1")
	if !IsControl(req) || IsData(req) {
		t.Fatal("sccrq shape")
	}
	c, err := ParseControl(req)
	if err != nil || c.MessageType != MsgSCCRQ || c.AssignedTunnel != tid || c.TunnelID != 0 || c.HostName != "probe-1" {
		t.Fatalf("sccrq parse %+v %v", c, err)
	}
	srv := RandomID()
	resp := SCCRP(tid, srv, "cpprobe")
	if len(resp) >= len(req) {
		t.Fatalf("sccrp %d must be shorter than sccrq %d", len(resp), len(req))
	}
	r, err := ParseControl(resp)
	if err != nil || r.MessageType != MsgSCCRP || r.TunnelID != tid || r.AssignedTunnel != srv {
		t.Fatalf("sccrp parse %+v %v", r, err)
	}
	if z, err := ParseControl(ZLB(tid, 0, 1, 2)); err != nil || z.MessageType != MsgZLB || z.Ns != 1 || z.Nr != 2 {
		t.Fatalf("zlb %+v %v", z, err)
	}
	icrq := ICRQ(srv, 5, 2, 2)
	icrp := ICRP(tid, 5, 6, 2, 3)
	if len(icrp) > len(icrq) {
		t.Fatalf("icrp %d longer than icrq %d", len(icrp), len(icrq))
	}
	d := Data(tid, 5, PPPLCPConfigureRequest(1))
	if !IsData(d) || IsControl(d) || DataTunnel(d) != tid || len(DataPayload(d)) != 18 {
		t.Fatal("data shape")
	}
}
