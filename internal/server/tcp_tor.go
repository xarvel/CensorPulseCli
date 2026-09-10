package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/obfs4"
	"github.com/xarvel/CensorPulseCli/internal/tor"
)

// wantTorCert decides which certificate a TLS flow gets. A pending
// reservation of a tor.* test names the certificate explicitly
// ("...+tor-cert" / "...+probe-cert"); otherwise a Tor-shaped ClientHello
// gets the relay-style certificate and everything else the probe's own.
func (s *Server) wantTorCert(chi *tls.ClientHelloInfo, ip netip.Addr, obs *model.Observation) bool {
	torHello := tor.IsClientHello(chi)
	if torHello {
		obs.Detail["hello_shape"] = "tor"
	}
	// A pending tor.* reservation decides, but only for a ClientHello that
	// could be a tor test's (no SNI): a neighbour behind the same address
	// running ordinary TLS tests with a server name must never be handed the
	// relay certificate and fail its pin.
	test, variant := s.store.peekReservation(ip, "tcp", obs.DstPort, model.ParseTLS, time.Now())
	if strings.HasPrefix(test, "tor.") && (torHello || chi.ServerName == "") {
		if strings.Contains(variant, "probe-cert") {
			return false
		}
		if strings.Contains(variant, "tor-cert") {
			obs.Detail["cert"] = "tor"
			return true
		}
	}
	if torHello {
		obs.Detail["cert"] = "tor"
		return true
	}
	return false
}

// tcpTorLink plays the responder side of the Tor link handshake inside an
// established TLS session: VERSIONS in both directions, then CERTS,
// AUTH_CHALLENGE and NETINFO from us, NETINFO from the client, and
// CREATE_FAST cells answered with CREATED_FAST (the session test's data
// phase). Nothing is verified and no circuit exists; the shapes are what a
// relay would send.
func (s *Server) tcpTorLink(pc *peekConn, obs *model.Observation) {
	obs.Detail["inner"] = "tor_link"
	idle := s.idle()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	readMore := func() error {
		pc.SetReadDeadline(time.Now().Add(idle))
		n, err := pc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		return err
	}
	var theirs []uint16
	for {
		vs, n, err := tor.ParseVersions(buf)
		if err != nil {
			obs.Detail["link"] = "bad_versions"
			obs.Close = "normal"
			return
		}
		if n > 0 {
			theirs = vs
			buf = buf[n:]
			break
		}
		if err := readMore(); err != nil {
			obs.Close = closeReason(err)
			return
		}
	}
	obs.Detail["link_versions_offered"] = fmt.Sprint(theirs)
	v := tor.Negotiate(tor.Versions, theirs)
	obs.Detail["link_version"] = itoa(int(v))
	if v < 4 {
		obs.Response = "tor_versions_mismatch"
		obs.Close = "normal"
		return
	}
	clientIP, _ := addrPortOf(pc.RemoteAddr())
	var mine []net.IP
	if la, ok := pc.LocalAddr().(*net.TCPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		mine = []net.IP{la.IP}
	}
	out := tor.VersionsCell(tor.Versions)
	out = append(out, tor.CertsCell()...)
	out = append(out, tor.AuthChallengeCell()...)
	out = append(out, tor.NetinfoCell(time.Now(), clientIP.AsSlice(), mine)...)
	pc.SetWriteDeadline(time.Now().Add(idle))
	if _, err := pc.Write(out); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "server_hello+tor_versions"
	obs.RepliedAt = ptrTime(time.Now())
	// Client NETINFO, then circuit requests. Bounded in cells as well as in
	// time so that a peer cannot hold the flow with padding.
	dataIn, dataOut, cells := 0, 0, 0
cells:
	for cells < 4*vpnSessionMaxData {
		c, n, err := tor.ParseCell(buf)
		if err != nil {
			obs.Detail["link"] = "bad_cell"
			break
		}
		if n == 0 {
			if err := readMore(); err != nil {
				obs.Close = closeReason(err)
				if obs.Close == "timeout" {
					obs.Close = "normal"
				}
				break
			}
			continue
		}
		buf = buf[n:]
		cells++
		switch c.Cmd {
		case tor.CmdNetinfo:
			obs.Detail["netinfo"] = "received"
		case tor.CmdCreateFast:
			dataIn++
			if dataIn > vpnSessionMaxData {
				obs.Response = "refused"
				continue
			}
			pc.SetWriteDeadline(time.Now().Add(idle))
			if _, err := pc.Write(tor.CreatedFastCell(c.Circ)); err != nil {
				obs.Close = closeReason(err)
				break cells
			}
			dataOut++
			obs.RepliedAt = ptrTime(time.Now())
		case tor.CmdPadding, tor.CmdVPadding:
		default:
			obs.Detail["unexpected_cell"] = tor.CmdName(c.Cmd)
		}
	}
	if dataIn > 0 {
		obs.Detail["stage"] = "transport"
		obs.Detail["data_in"] = itoa(dataIn)
		obs.Detail["data_out"] = itoa(dataOut)
		obs.Response = "server_hello+tor_versions+created_fast"
	}
	if obs.Close == "" || obs.Close == "n/a" {
		obs.Close = "normal"
	}
}

// tcpObfs4 answers a client request whose mark verified under our bridge
// identity and then mirrors whatever frames follow. The response is never
// longer than the request. raw holds everything read so far; n is where the
// handshake ends and data may already begin.
func (s *Server) tcpObfs4(pc *peekConn, obs *model.Observation, raw []byte, n int) {
	obs.Parse = model.ParseObfs4
	obs.Detail["handshake_len"] = itoa(n)
	resp := obfs4.ServerResponse(s.keys.Obfs4, time.Now(), n)
	if _, err := pc.Write(resp); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "obfs4_response"
	obs.RepliedAt = ptrTime(time.Now())
	obs.BytesOut = len(resp)
	if len(raw) > n {
		pc.prefix = append(append([]byte(nil), raw[n:]...), pc.prefix...)
	}
	s.tcpEchoStream(pc, obs, s.idle())
	if obs.Detail["data_in"] != "" {
		obs.Response = "obfs4_response+echo"
	}
}

// tcpTorDir answers a directory request the way a relay's DirPort would
// begin to: an HTTP/1.0 200 with a consensus-shaped body. Nothing here is a
// real consensus; the request line and path are what a DPI rule would key on.
func (s *Server) tcpTorDir(pc *peekConn, req *http.Request, obs *model.Observation) {
	obs.Detail["path"] = req.URL.Path
	obs.Detail["tor_dir"] = "true"
	obs.Detail["method"] = req.Method
	ip, _ := addrPortOf(pc.RemoteAddr())
	now := time.Now().UTC()
	body := fmt.Sprintf("network-status-version 3 microdesc\nvote-status consensus\nconsensus-method 33\nvalid-after %s\nfresh-until %s\nvalid-until %s\nvoting-delay 300 300\nclient-versions 0.4.8.14,0.4.9.12\nserver-versions 0.4.8.14,0.4.9.12\nknown-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid\nparams CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1\n",
		now.Format("2006-01-02 15:04:05"), now.Add(2*time.Hour).Format("2006-01-02 15:04:05"), now.Add(3*time.Hour).Format("2006-01-02 15:04:05"))
	resp := fmt.Sprintf("HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Type: text/plain\r\nX-Your-Address-Is: %s\r\nContent-Length: %d\r\n\r\n%s", now.Format(http.TimeFormat), ip, len(body), body)
	if _, err := pc.Write([]byte(resp)); err != nil {
		obs.Close = closeReason(err)
		return
	}
	obs.Response = "http_200"
	obs.RepliedAt = ptrTime(time.Now())
	obs.Close = "normal"
}
