package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/dnsx"
	"github.com/xarvel/CensorPulseCli/internal/model"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// startControl serves the pinned-TLS control API.
func (s *Server) startControl() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/params", s.handleParams)
	mux.HandleFunc("POST /v1/session", s.handleSession)
	mux.HandleFunc("GET /v1/health", s.auth(s.handleHealth))
	mux.HandleFunc("POST /v1/session/{id}/attempt", s.auth(s.handleAttempt))
	mux.HandleFunc("GET /v1/session/{id}/observations", s.auth(s.handleObservations))
	mux.HandleFunc("POST /dns-query", s.handleDoH)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "censorpulse-probe control api", http.StatusNotFound)
	})
	ln, err := net.Listen("tcp", s.bindAddr(s.cfg.ControlPort))
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         s.tlsConfig(nil),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	name := "tcp/" + itoa(s.cfg.ControlPort)
	s.setListener(name, "ok")
	s.addCloser(srv.Close)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.setListener(name, "error: "+err.Error())
			s.log.Error("control api stopped", "err", err)
		}
	}()
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) netip.Addr {
	ip, _ := addrPortOf(strAddr(r.RemoteAddr))
	return ip
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }

func (s *Server) handleParams(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Params())
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	ip := clientIP(r)
	if !s.store.allowSession(ip, now) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "session rate limit"})
		return
	}
	var req model.SessionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if n, err := hex.DecodeString(req.ClientNonce); err != nil || len(n) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_nonce must be 32 hex bytes"})
		return
	}
	sid := proto.NewSessionID()
	exp := now.Add(time.Duration(s.cfg.Limits.SessionTTLSeconds) * time.Second)
	sess := &session{ID: sid, Key: proto.SessionKey(s.keys.Master, sid), Expires: exp, Created: now, ClientIP: ip, Tests: map[string]bool{}}
	var granted []string
	for _, t := range req.Tests {
		if s.enabled[t] {
			sess.Tests[t] = true
			granted = append(granted, t)
		}
	}
	if len(req.Tests) == 0 {
		for _, t := range KnownTests {
			if s.enabled[t] {
				sess.Tests[t] = true
				granted = append(granted, t)
			}
		}
	}
	s.store.putSession(sess)
	writeJSON(w, http.StatusOK, model.SessionResponse{
		SchemaVersion: model.SchemaVersion,
		SessionID:     hex.EncodeToString(sid[:]),
		ExpiresAt:     exp.UTC().Format(time.RFC3339),
		ServerTime:    now.UTC().Format(time.RFC3339Nano),
		Tests:         granted,
		Token:         proto.Token(s.keys.Master, sid, exp),
		UDPCookie:     hex.EncodeToString(proto.Cookie(s.keys.Master, sid, ip, exp)),
		SessionKey:    hex.EncodeToString(sess.Key),
		ClientAddr:    ip.String(),
	})
}

// auth validates the bearer token and the {id} path parameter when present.
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sid, _, err := proto.VerifyToken(s.keys.Master, tok, time.Now())
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		if id := r.PathValue("id"); id != "" && id != hex.EncodeToString(sid[:]) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "token does not match session"})
			return
		}
		sess := s.store.getSession(sid, time.Now())
		if sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired or unknown"})
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ *session) {
	writeJSON(w, http.StatusOK, s.health())
}

func (s *Server) handleAttempt(w http.ResponseWriter, r *http.Request, sess *session) {
	var req model.AttemptRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if !sess.Tests[req.TestID] {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "test not granted to this session"})
		return
	}
	if req.Transport != "tcp" && req.Transport != "udp" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "transport must be tcp or udp"})
		return
	}
	now := time.Now()
	if !s.store.allowAttempt(sess.ClientIP, now) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "attempt rate limit"})
		return
	}
	res := &reservation{SessionID: sess.ID, Expires: now.Add(15 * time.Second), ClientIP: sess.ClientIP,
		DstPort: req.DstPort, Transport: req.Transport, Kind: req.Kind, TestID: req.TestID, Variant: req.Variant}
	id := s.store.reserve(res)
	writeJSON(w, http.StatusOK, model.AttemptResponse{AttemptID: id, ExpiresAt: res.Expires.UTC().Format(time.RFC3339)})
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request, sess *session) {
	sid := hex.EncodeToString(sess.ID[:])
	obs := s.store.observationsFor(sid)
	if obs == nil {
		obs = []model.Observation{}
	}
	writeJSON(w, http.StatusOK, model.ObservationsResponse{SessionID: sid, ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Observations: obs})
}

// handleDoH answers RFC 8484 POST queries for the probe zone only. It sits on
// the control port so that DoH is tested against the same pinned endpoint.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	q, err := dnsx.ParseQuery(body)
	if err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	ip, port := addrPortOf(strAddr(r.RemoteAddr))
	ans, err := dnsx.BuildAnswerFrom(q, ip.String())
	if err != nil {
		http.Error(w, "cannot answer", http.StatusInternalServerError)
		return
	}
	s.store.addObservation(model.Observation{Transport: "tcp", DstPort: s.cfg.ControlPort, SrcPort: port,
		FirstSeenAt: time.Now(), RepliedAt: ptrTime(time.Now()), BytesIn: len(body), BytesOut: len(ans),
		Parse: model.ParseDNS, Detail: map[string]string{"qname": q.Name, "qtype": q.Type.String(), "via": "doh"},
		Response: "dns_answer", Close: "normal", SessionID: sessionFromQName(q.Name), TestID: "dns.doh"})
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(ans)
}

// sessionFromQName extracts the session id when the query name follows the
// client convention <nonce>.<sid>.<test>.probe.invalid.
func sessionFromQName(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	// nonce, sid, test..., probe, invalid
	if len(parts) >= 5 && len(parts[1]) == 32 {
		if _, err := hex.DecodeString(parts[1]); err == nil {
			return parts[1]
		}
	}
	return ""
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + intToStr(i)) }

func intToStr(i int) string {
	b := make([]byte, 0, 8)
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
