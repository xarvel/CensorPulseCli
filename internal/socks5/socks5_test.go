package socks5

import "testing"

func TestMessages(t *testing.T) {
	g := Greeting(MethodNoAuth, MethodUser)
	if !IsGreeting(g) || len(GreetingMethods(g)) != 2 {
		t.Fatal("greeting")
	}
	u, p, err := ParseUserPass(UserPass("probe", "secret"))
	if err != nil || u != "probe" || p != "secret" {
		t.Fatal("userpass")
	}
	req := Connect("x.probe.invalid", 443)
	r, err := ParseRequest(req)
	if err != nil || r.Cmd != CmdConnect || r.Host != "x.probe.invalid" || r.Port != 443 || r.Len != len(req) {
		t.Fatalf("connect %+v %v", r, err)
	}
	if _, err := ParseRequest(req[:8]); err == nil {
		t.Fatal("truncated request must not parse")
	}
	if !IsReply(Reply(RepSuccess)) || len(Reply(0)) != 10 {
		t.Fatal("reply")
	}
	if IsGreeting([]byte{4, 1, 0}) {
		t.Fatal("socks4 is not socks5")
	}
}
