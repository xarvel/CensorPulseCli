// Package server implements the CensorPulse control point ("the probe"): a
// set of TCP/UDP listeners that answer every supported test with a bounded,
// authenticated reply and record a server-side observation for each flow, plus
// the pinned-TLS control API the client uses to open sessions and fetch those
// observations.
//
// The server never dials out. Every protocol terminates locally.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

// Version is stamped into params/health; overridden at build time via -ldflags.
var Version = "dev"

// Server is one running probe.
type Server struct {
	cfg   Config
	keys  *Keys
	store *store
	log   *slog.Logger
	start time.Time

	mu        sync.Mutex
	listeners map[string]string // "tcp/443" -> "ok" | error
	closers   []func() error
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	// set of test ids accepted in sessions
	enabled map[string]bool
	// concurrent TCP flows per client address
	conns map[netip.Addr]int
}

// KnownTests lists every test id the server has a responder for
// (model.KnownTests; the engine adds the client-only ids).
var KnownTests = model.KnownTests

// New validates cfg and loads keys but does not bind anything yet.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	keys, err := LoadOrCreateKeys(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{
		cfg:       cfg,
		keys:      keys,
		log:       logger,
		listeners: map[string]string{},
		enabled:   map[string]bool{},
		store: newStore(cfg.Limits.MaxObservations,
			time.Duration(cfg.Limits.RetentionHours)*time.Hour,
			cfg.Limits.SessionsPerMinute, cfg.Limits.AttemptsPer10Min),
	}
	if len(cfg.EnabledTests) == 0 {
		for _, t := range KnownTests {
			s.enabled[t] = true
		}
	} else {
		for _, t := range cfg.EnabledTests {
			s.enabled[t] = true
		}
	}
	dnsx.SetZone(cfg.DNSZone)
	if cfg.Limits.BulkMBPerDay > 0 {
		s.store.bulkPerDay = int64(cfg.Limits.BulkMBPerDay) << 20
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// Keys exposes public material (pin, WG public key) to the CLI.
func (s *Server) Keys() *Keys { return s.keys }

// Params builds the public bootstrap document.
func (s *Server) Params() model.Params {
	tests := make([]string, 0, len(s.enabled))
	for _, t := range KnownTests {
		if s.enabled[t] {
			tests = append(tests, t)
		}
	}
	p := model.Params{
		SchemaVersion:  model.SchemaVersion,
		ServerVersion:  Version,
		ServerTime:     time.Now().UTC().Format(time.RFC3339Nano),
		SPKIPin:        s.keys.SPKIPin,
		WGPublicKey:    base64Std(s.keys.WG.Public[:]),
		TCPPorts:       s.cfg.TCPPorts,
		UDPPorts:       s.cfg.UDPPorts,
		DNSPorts:       s.cfg.DNSPorts,
		DoTPort:        s.cfg.DoTPort,
		DNSZone:        dnsx.Zone,
		EnabledTests:   tests,
		MaxUDPPayload:  1000,
		Features:       []string{"cp1", "reservations", "doh", "bulk", "whoami", "vpn-session", "ike", "l2tp", "socks5", "vless", "burst", "packets", "tor", "obfs4", "dtls", "stun"},
		Obfs4Cert:      base64Std(s.keys.Obfs4.Bytes()),
		TorSPKIPin:     s.keys.TorSPKIPin,
		OVPNTLSAuthKey: base64Std(s.keys.OVPNTLSAuth),
	}
	if s.cfg.QUIC {
		p.QUICPorts = s.cfg.UDPPorts
	}
	return p
}

// Start binds all listeners. It fails closed: any bind error aborts startup.
func (s *Server) Start() error {
	s.start = time.Now()
	var errs []error
	fail := func(name string, err error) {
		s.setListener(name, "error: "+err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}
	// control API
	if err := s.startControl(); err != nil {
		fail("tcp/"+strconv.Itoa(s.cfg.ControlPort), err)
	}
	for _, p := range s.cfg.TCPPorts {
		if err := s.startTCP(p, tcpRoleGeneric); err != nil {
			fail("tcp/"+strconv.Itoa(p), err)
		}
	}
	for _, p := range s.cfg.DNSPorts {
		if err := s.startTCP(p, tcpRoleDNS); err != nil {
			fail("tcp/"+strconv.Itoa(p), err)
		}
		if err := s.startUDP(p, true); err != nil {
			fail("udp/"+strconv.Itoa(p), err)
		}
	}
	if s.cfg.DoTPort != 0 {
		if err := s.startTCP(s.cfg.DoTPort, tcpRoleDoT); err != nil {
			fail("tcp/"+strconv.Itoa(s.cfg.DoTPort), err)
		}
	}
	for _, p := range s.cfg.UDPPorts {
		if err := s.startUDP(p, false); err != nil {
			fail("udp/"+strconv.Itoa(p), err)
		}
	}
	if len(errs) > 0 {
		_ = s.Close()
		err := errors.Join(errs...)
		if strings.Contains(err.Error(), ":53: bind: address already in use") {
			err = fmt.Errorf("%w\nhint: port 53 is usually held by systemd-resolved's stub listener; run scripts/install-server.sh, disable DNSStubListener, or change dns_ports in probe.yaml", err)
		}
		return err
	}
	s.wg.Add(1)
	go s.gcLoop()
	s.log.Info("probe started", "version", Version, "spki_pin", s.keys.SPKIPin, "wg_public_key", base64Std(s.keys.WG.Public[:]))
	return nil
}

// Close stops everything.
func (s *Server) Close() error {
	s.cancel()
	s.mu.Lock()
	closers := s.closers
	s.closers = nil
	s.mu.Unlock()
	for _, c := range closers {
		_ = c()
	}
	s.wg.Wait()
	return nil
}

// Wait blocks until Close.
func (s *Server) Wait() { <-s.ctx.Done() }

func (s *Server) addCloser(f func() error) {
	s.mu.Lock()
	s.closers = append(s.closers, f)
	s.mu.Unlock()
}

func (s *Server) setListener(name, status string) {
	s.mu.Lock()
	s.listeners[name] = status
	s.mu.Unlock()
}

func (s *Server) health() model.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]string, len(s.listeners))
	for k, v := range s.listeners {
		m[k] = v
	}
	return model.Health{ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Listeners: m, Uptime: time.Since(s.start).Round(time.Second).String()}
}

func (s *Server) gcLoop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.store.gc(now)
			// Refused observations are reported here, once a minute, never
			// per packet: a flood must not turn into a flood of log lines.
			if d, held := s.store.takeDrops(); d.total() > 0 {
				s.log.Debug("observations dropped", "no_live_session", d.noSession, "session_cap", d.sessionCap, "global_cap", d.globalCap, "held", held)
			}
		}
	}
}

// idle is the read deadline of the TCP responders (limits.idle_timeout_seconds).
func (s *Server) idle() time.Duration {
	return time.Duration(s.cfg.Limits.IdleTimeoutSeconds) * time.Second
}

func (s *Server) bindAddr(port int) string {
	return net.JoinHostPort(s.cfg.Bind, strconv.Itoa(port))
}

// tlsConfigCapturing returns a server TLS config that presents the probe
// certificate for any SNI and records the ClientHello into capture.
func (s *Server) tlsConfig(capture func(*tls.ClientHelloInfo)) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{s.keys.TLSCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1", "dot", "cp1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if capture != nil {
				capture(chi)
			}
			return nil, nil
		},
	}
}

func addrPortOf(a net.Addr) (netip.Addr, int) {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, 0
	}
	return ap.Addr().Unmap(), int(ap.Port())
}

func ptrTime(t time.Time) *time.Time { return &t }
