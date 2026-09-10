package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dtlsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

// dtlsCookie is the stateless HelloVerifyRequest cookie for a peer.
func (l *udpListener) dtlsCookie(raddr *net.UDPAddr) []byte {
	h := hmac.New(sha256.New, l.s.keys.Master)
	h.Write([]byte("dtls-cookie|"))
	h.Write([]byte(raddr.String()))
	return h.Sum(nil)[:16]
}

func (l *udpListener) rememberDTLS(peer string, f *vpnFlow) {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	if l.dtlsFlows == nil {
		l.dtlsFlows = map[string]*vpnFlow{}
	}
	now := time.Now()
	for k, v := range l.dtlsFlows {
		if now.After(v.expires) {
			delete(l.dtlsFlows, k)
		}
	}
	l.dtlsFlows[peer] = f
}

func (l *udpListener) lookupDTLS(peer string, now time.Time) *vpnFlow {
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	f, ok := l.dtlsFlows[peer]
	if !ok || now.After(f.expires) {
		return nil
	}
	return f
}

func (f *udpFlow) matchDTLS() bool { return dtlsx.IsHandshake(f.b) }

// serveDTLS answers a WebRTC-style DTLS 1.2 client: HelloVerifyRequest to
// the first ClientHello (under a reservation, else silence), ServerHello +
// ServerHelloDone to the ClientHello that brings the cookie back. The
// handshake goes no further: what is measured is whether these datagrams
// cross the path, which is what DTLS fingerprint rules act on.
func (f *udpFlow) serveDTLS() {
	l, obs := f.l, &f.obs
	obs.Parse = model.ParseDTLS
	msgs, err := dtlsx.Parse(f.b)
	if err != nil || len(msgs) == 0 || msgs[0].Type != dtlsx.TypeClientHello {
		obs.Detail["parse"] = "bad_handshake"
		return
	}
	info, err := dtlsx.ParseClientHello(msgs[0].Body)
	if err != nil {
		obs.Detail["parse"] = "bad_client_hello"
		return
	}
	obs.Detail["dtls_version"] = fmt.Sprintf("%04x", info.Version)
	obs.Detail["cipher_count"] = itoa(len(info.CipherSuites))
	ext := make([]string, 0, len(info.Extensions))
	for _, e := range info.Extensions {
		ext = append(ext, fmt.Sprintf("%d", e))
	}
	obs.Detail["extensions"] = strings.Join(ext, ",")
	fp := sha256.New()
	for _, c := range info.CipherSuites {
		fp.Write([]byte{byte(c >> 8), byte(c)})
	}
	fp.Write([]byte{0})
	for _, e := range info.Extensions {
		fp.Write([]byte{byte(e >> 8), byte(e)})
	}
	obs.Detail["hello_fp"] = hex.EncodeToString(fp.Sum(nil)[:12])
	cookie := l.dtlsCookie(f.raddr)
	if len(info.Cookie) == 0 {
		obs.Detail["stage"] = "hello"
		if !f.correlate(model.ParseDTLS) {
			return
		}
		v := f.vpnFlow()
		l.rememberDTLS(f.raddr.String(), &v)
		f.reply(dtlsx.HelloVerifyRequest(cookie), "dtls_hello_verify")
		return
	}
	obs.Detail["stage"] = "cookie"
	v := l.lookupDTLS(f.raddr.String(), f.now)
	if v == nil {
		obs.Unmatched = true
		return
	}
	f.attribute(v)
	if !hmac.Equal(info.Cookie, cookie) {
		obs.Detail["cookie"] = "invalid"
		return
	}
	f.reply(dtlsx.ServerHello(0xc02b, strings.Contains(v.variant, "groups")), "dtls_server_hello")
}
