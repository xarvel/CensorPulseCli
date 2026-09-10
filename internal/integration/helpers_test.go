package integration

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/classify"
	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/server"
)

// ports used by the in-process server (loopback, unprivileged).
const (
	ctrlPort = 28443
	tcpA     = 20080
	tcpB     = 20443
	tcpC     = 21194
	udpA     = 20443
	udpB     = 21194
	udpC     = 25820
	dnsPort  = 20053
	dotPort  = 20853
)

func startServer(t *testing.T) *server.Server {
	t.Helper()
	cfg := server.Default()
	cfg.Bind = "127.0.0.1"
	cfg.DataDir = t.TempDir()
	cfg.ControlPort = ctrlPort
	cfg.TCPPorts = []int{tcpA, tcpB, tcpC}
	cfg.UDPPorts = []int{udpA, udpB, udpC}
	cfg.DNSPorts = []int{dnsPort}
	cfg.DoTPort = dotPort
	cfg.Limits.AttemptsPer10Min = 5000
	cfg.Limits.SessionsPerMinute = 50
	cfg.Limits.IdleTimeoutSeconds = 2
	s, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func scan(t *testing.T, target string, tests []string, repeat int) ([]*client.Attempt, classify.Result, *client.Client) {
	t.Helper()
	return scanWithTimeout(t, target, tests, repeat, 3*time.Second)
}

func scanWithTimeout(t *testing.T, target string, tests []string, repeat int, timeout time.Duration) ([]*client.Attempt, classify.Result, *client.Client) {
	t.Helper()
	c, err := client.New(client.Options{Target: target, ControlPort: ctrlPort, Tests: tests, Repeat: repeat, Parallel: 4, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := c.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	attempts, err := c.Run(ctx, c.Catalog(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return attempts, classify.Classify(attempts, true), c
}

// faultProxy is a TCP relay on proxyIP that forwards to 127.0.0.1 on the same
// port and can inject path failures.
type faultProxy struct {
	mu   sync.Mutex
	mode func(port int, firstClientBytes []byte) faultAction
	lns  []net.Listener
}

type faultAction int

const (
	actPass           faultAction = iota
	actDropUplink                 // swallow client bytes forever (server never sees them)
	actRST                        // reset the client connection after the first client bytes
	actModifyDown                 // forward, but corrupt the first server reply byte-for-byte
	actDelay                      // forward after 400 ms
	actCutAfter16KB               // forward, but reset the client once 16 KB have crossed in either direction
	actCutAfter20Pkts             // forward, but go silent once 20 client segments have crossed (a per-flow packet counter)
	actDropOVPNData               // forward, but swallow every OpenVPN P_DATA_V2 frame the client sends (2-byte length framing)
)

func startProxy(t *testing.T, proxyIP string, ports []int, mode func(port int, first []byte) faultAction) *faultProxy {
	t.Helper()
	p := &faultProxy{mode: mode}
	for _, port := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(proxyIP, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("proxy listen %d: %v", port, err)
		}
		p.lns = append(p.lns, ln)
		go p.serve(ln, port)
	}
	t.Cleanup(func() {
		for _, ln := range p.lns {
			ln.Close()
		}
	})
	return p
}

func (p *faultProxy) serve(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c, port)
	}
}

func (p *faultProxy) handle(c net.Conn, port int) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16384)
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if err != nil && n == 0 {
		return
	}
	first := buf[:n]
	act := p.mode(port, first)
	switch act {
	case actDropUplink:
		io.Copy(io.Discard, c) // hold the connection open, never forward
		return
	case actRST:
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		return
	case actDelay:
		time.Sleep(400 * time.Millisecond)
	}
	up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(first); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	if act == actDropOVPNData {
		// Client → server: reassemble OpenVPN/TCP frames and forward all but
		// the data-channel ones (opcode 9), the way a DPI that lets the
		// control channel through and cuts the tunnel behaves. Server →
		// client is relayed untouched.
		go func() {
			var buf []byte
			b := make([]byte, 4096)
			for {
				n, err := c.Read(b)
				if n > 0 {
					buf = append(buf, b[:n]...)
					for len(buf) >= 2 {
						fl := int(binary.BigEndian.Uint16(buf))
						if len(buf) < 2+fl {
							break
						}
						frame := buf[:2+fl]
						if fl == 0 || frame[2]>>3 != 9 {
							if _, werr := up.Write(frame); werr != nil {
								break
							}
						}
						buf = append([]byte(nil), buf[2+fl:]...)
					}
				}
				if err != nil {
					break
				}
			}
			up.(*net.TCPConn).CloseWrite()
			done <- struct{}{}
		}()
		go func() { io.Copy(c, up); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
		<-done
		<-done
		return
	}
	if act == actCutAfter20Pkts {
		// Every proxy read from the client is one segment on loopback when
		// the client paces its writes. After 20 of them the flow is frozen:
		// nothing is forwarded in either direction, the sockets stay open.
		segs := 1 // the first read
		var mu sync.Mutex
		frozen := false
		relay := func(dst, src net.Conn, count bool) {
			b := make([]byte, 4096)
			for {
				n, err := src.Read(b)
				if n > 0 {
					mu.Lock()
					if count {
						segs++
						if segs > 20 {
							frozen = true
						}
					}
					f := frozen
					mu.Unlock()
					if !f {
						if _, werr := dst.Write(b[:n]); werr != nil {
							break
						}
					}
				}
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}
		go relay(up, c, true)
		go relay(c, up, false)
		<-done
		<-done
		return
	}
	if act == actCutAfter16KB {
		var total int64
		var mu sync.Mutex
		cut := func() {
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			c.Close()
			up.Close()
		}
		relay := func(dst, src net.Conn) {
			b := make([]byte, 4096)
			for {
				n, err := src.Read(b)
				if n > 0 {
					mu.Lock()
					total += int64(n)
					over := total > 16<<10
					mu.Unlock()
					if over {
						cut()
						break
					}
					if _, werr := dst.Write(b[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}
		mu.Lock()
		total += int64(len(first))
		mu.Unlock()
		go relay(up, c)
		go relay(c, up)
		<-done
		<-done
		return
	}
	go func() { io.Copy(up, c); up.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() {
		if act == actModifyDown {
			b := make([]byte, 16384)
			for {
				n, err := up.Read(b)
				if n > 0 {
					// flip a byte deep inside the reply so framing survives but content does not
					if n > 40 {
						b[n-20] ^= 0xff
					}
					c.Write(b[:n])
				}
				if err != nil {
					break
				}
			}
		} else {
			io.Copy(c, up)
		}
		c.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// udpRelay forwards datagrams from proxyIP to 127.0.0.1 on the same ports,
// one upstream socket per client address so that the server sees a stable
// 5-tuple per flow, and drops the client datagrams drop() selects.
type udpRelay struct {
	mu   sync.Mutex
	drop func(port int, b []byte) bool
	lns  []*net.UDPConn
	ups  map[string]*net.UDPConn
}

func startUDPRelay(t *testing.T, proxyIP string, ports []int, drop func(port int, b []byte) bool) *udpRelay {
	t.Helper()
	r := &udpRelay{drop: drop, ups: map[string]*net.UDPConn{}}
	for _, port := range ports {
		ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(proxyIP), Port: port})
		if err != nil {
			t.Fatalf("udp relay listen %d: %v", port, err)
		}
		r.lns = append(r.lns, ln)
		go r.serve(ln, port)
	}
	t.Cleanup(func() {
		for _, ln := range r.lns {
			ln.Close()
		}
		r.mu.Lock()
		for _, up := range r.ups {
			up.Close()
		}
		r.mu.Unlock()
	})
	return r
}

func (r *udpRelay) serve(ln *net.UDPConn, port int) {
	buf := make([]byte, 65535)
	for {
		n, client, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if r.drop != nil && r.drop(port, pkt) {
			continue
		}
		key := strconv.Itoa(port) + "/" + client.String()
		r.mu.Lock()
		up, ok := r.ups[key]
		if !ok {
			up, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
			if err != nil {
				r.mu.Unlock()
				continue
			}
			r.ups[key] = up
			go func(up *net.UDPConn, client *net.UDPAddr) {
				b := make([]byte, 65535)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					ln.WriteToUDP(b[:n], client)
				}
			}(up, client)
		}
		r.mu.Unlock()
		up.Write(pkt)
	}
}

func cellsByTest(res classify.Result, test string) []classify.Cell {
	var out []classify.Cell
	for _, c := range res.Cells {
		if c.TestID == test {
			out = append(out, c)
		}
	}
	return out
}

func hasVerdict(res classify.Result, kind, subjectContains string) bool {
	for _, v := range res.Verdicts {
		if v.Kind == kind && (subjectContains == "" || contains(v.Subject, subjectContains)) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
