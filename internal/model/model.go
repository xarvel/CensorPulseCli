// Package model holds the JSON types exchanged over the control plane and
// written into reports. It is shared by the server, the client and the
// classifier so that the wire schema lives in exactly one place.
package model

import "time"

// SchemaVersion is bumped on any incompatible change to the JSON below.
const SchemaVersion = 1

// Params are the public parameters a client needs beyond the IP address. They
// are served unauthenticated by the control API so that a client only needs
// the IP (and, optionally, an out-of-band pin) to bootstrap.
type Params struct {
	SchemaVersion int      `json:"schema_version"`
	ServerVersion string   `json:"server_version"`
	ServerTime    string   `json:"server_time"`
	SPKIPin       string   `json:"spki_pin"`               // base64(sha256(SubjectPublicKeyInfo)) of the control/test TLS cert
	WGPublicKey   string   `json:"wg_public_key"`          // base64 static key used by the WireGuard responder
	TCPPorts      []int    `json:"tcp_ports"`              // ports with the generic TCP dispatcher
	UDPPorts      []int    `json:"udp_ports"`              // ports with the generic UDP dispatcher
	DNSPorts      []int    `json:"dns_ports"`              // ports (udp+tcp) answering the probe zone
	DoTPort       int      `json:"dot_port"`               // TLS+DNS, 0 when disabled
	DNSZone       string   `json:"dns_zone"`               // zone served by the DNS responder (trailing dot)
	QUICPorts     []int    `json:"quic_ports"`             // UDP ports where a QUIC/H3 endpoint is multiplexed
	EnabledTests  []string `json:"enabled_tests"`          // test ids the server will accept
	MaxUDPPayload int      `json:"max_udp_payload"`        // bytes
	Features      []string `json:"features,omitempty"`     // free-form capability flags
	Obfs4Cert     string   `json:"obfs4_cert,omitempty"`   // base64(node id | Curve25519 public key) of the obfs4 responder
	TorSPKIPin    string   `json:"tor_spki_pin,omitempty"` // pin of the relay-style link certificate served to Tor-shaped handshakes
	// OVPNTLSAuthKey is the base64 64-byte static key of the OpenVPN tls-auth
	// responder (bytes 0..20 authenticate client→server control packets,
	// 32..52 server→client), regenerated at every server start. Absent on a
	// server without the tls-auth variants.
	OVPNTLSAuthKey string `json:"ovpn_tls_auth_key,omitempty"`
}

// SessionRequest is POSTed by the client.
type SessionRequest struct {
	ClientVersion string   `json:"client_version"`
	ClientNonce   string   `json:"client_nonce"` // hex, 32 bytes
	Tests         []string `json:"tests"`
	Capabilities  []string `json:"capabilities,omitempty"`
}

// SessionResponse is the server's answer.
type SessionResponse struct {
	SchemaVersion int      `json:"schema_version"`
	SessionID     string   `json:"session_id"` // hex
	ExpiresAt     string   `json:"expires_at"`
	ServerTime    string   `json:"server_time"`
	Tests         []string `json:"tests"`
	Token         string   `json:"token"`
	UDPCookie     string   `json:"udp_cookie"`  // hex
	SessionKey    string   `json:"session_key"` // hex, HMAC key for envelopes
	ClientAddr    string   `json:"client_addr"` // what the server saw (IP only)
}

// AttemptRequest reserves a correlation window for a native handshake that
// cannot carry an envelope.
type AttemptRequest struct {
	TestID    string `json:"test_id"`
	Transport string `json:"transport"` // tcp|udp
	DstPort   int    `json:"dst_port"`
	Kind      string `json:"kind"` // expected parse kind, see Observation.Parse
	Variant   string `json:"variant,omitempty"`
}

// AttemptResponse returns the id the client must record.
type AttemptResponse struct {
	AttemptID string `json:"attempt_id"`
	ExpiresAt string `json:"expires_at"`
}

// Observation is the server-side half of the evidence for one flow.
type Observation struct {
	ID          string            `json:"id"`
	SessionID   string            `json:"session_id,omitempty"`
	AttemptID   string            `json:"attempt_id,omitempty"`
	TestID      string            `json:"test_id,omitempty"`
	Nonce       string            `json:"nonce,omitempty"`
	Seq         uint32            `json:"seq,omitempty"`
	Transport   string            `json:"transport"`
	DstPort     int               `json:"dst_port"`
	SrcPort     int               `json:"src_port"`
	FirstSeenAt time.Time         `json:"first_seen_at"`
	RepliedAt   *time.Time        `json:"replied_at,omitempty"`
	ClosedAt    *time.Time        `json:"closed_at,omitempty"`
	BytesIn     int               `json:"bytes_in"`
	BytesOut    int               `json:"bytes_out"`
	PayloadSHA  string            `json:"payload_sha256,omitempty"`
	Parse       string            `json:"parse"` // cp1_envelope|tls_client_hello|http_request|dns_query|openvpn_reset|wireguard_initiation|quic|unknown|empty
	Detail      map[string]string `json:"detail,omitempty"`
	Response    string            `json:"response"` // echo|hash_ack|server_hello|http_200|dns_answer|openvpn_reset|wireguard_response|silence|refused
	Close       string            `json:"close"`    // normal|client_eof|client_reset|timeout|server_error|n/a
	ServerError string            `json:"server_error,omitempty"`
	Unmatched   bool              `json:"unmatched,omitempty"` // no session/attempt could be associated
}

// ObservationsResponse wraps a session's observations.
type ObservationsResponse struct {
	SessionID    string        `json:"session_id"`
	ServerTime   string        `json:"server_time"`
	Observations []Observation `json:"observations"`
}

// Health is the authenticated listener snapshot.
type Health struct {
	ServerTime string            `json:"server_time"`
	Listeners  map[string]string `json:"listeners"` // "tcp/443": "ok" | error text
	Uptime     string            `json:"uptime"`
}

// Parse kinds (Observation.Parse and AttemptRequest.Kind).
const (
	ParseEnvelope  = "cp1_envelope"
	ParseTLS       = "tls_client_hello"
	ParseHTTP      = "http_request"
	ParseDNS       = "dns_query"
	ParseOpenVPN   = "openvpn_reset"
	ParseWireGuard = "wireguard_initiation"
	// Post-handshake packets of the *.session tests. Their observations carry
	// detail.stage = "transport" and are correlated through the handshake's
	// attempt id.
	ParseOpenVPNControl = "openvpn_control"
	ParseOpenVPNData    = "openvpn_data"
	ParseWireGuardData  = "wireguard_data"
	ParseIKE            = "ikev2"
	ParseESP            = "esp_udp"
	ParseL2TP           = "l2tp_control"
	ParseL2TPData       = "l2tp_data"
	ParseSOCKS5         = "socks5"
	ParseVLESS          = "vless" // inside a TLS stream; the outer flow is tls_client_hello
	ParseQUIC           = "quic"
	ParseDTLS           = "dtls_client_hello"
	ParseSTUN           = "stun_binding"
	ParseObfs4          = "obfs4_handshake"
	ParseUnknown        = "unknown"
	ParseEmpty          = "empty"
)

// KnownTests lists every test id the server has a responder for. The
// server validates enabled_tests against it and the client uses it to
// validate --tests; the client-only ids (dns.doh as a feature, dest.*) are
// added by the engine.
var KnownTests = []string{
	"tcp.echo", "tcp.payload.random", "tcp.rtt",
	"udp.echo", "udp.payload.random",
	"http.host",
	"dns.udp", "dns.tcp", "dns.dot",
	"tls.version", "tls.sni", "tls.alpn", "tls.fingerprint", "tls.burst",
	"tcp.bulk", "tcp.packets", "udp.packets", "dns.system",
	"quic.v1",
	"openvpn.reset", "wireguard.init",
	"openvpn.session", "wireguard.session",
	"ikev2.init", "ikev2.session", "l2tp.init", "l2tp.session",
	"socks5.connect", "socks5.session", "vless.reality", "vless.session",
	"tor.handshake", "tor.link", "tor.dir", "obfs4.handshake", "obfs4.session",
	"dtls.hello", "stun.binding",
}
