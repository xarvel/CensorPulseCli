package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the single versioned YAML file that drives the probe server.
type Config struct {
	SchemaVersion int    `yaml:"schema_version"`
	Bind          string `yaml:"bind"`     // "" or "0.0.0.0" / "::" ; dual-stack when "::"
	DataDir       string `yaml:"data_dir"` // keys and persisted material
	ControlPort   int    `yaml:"control_port"`

	TCPPorts []int  `yaml:"tcp_ports"` // generic dispatcher: echo/random/http/tls/openvpn/socks5
	UDPPorts []int  `yaml:"udp_ports"` // generic dispatcher: echo/openvpn/wireguard/ikev2/l2tp/quic
	DNSPorts []int  `yaml:"dns_ports"` // udp+tcp DNS for the probe zone
	DoTPort  int    `yaml:"dot_port"`
	DNSZone  string `yaml:"dns_zone"` // zone the DNS responder is authoritative for
	QUIC     bool   `yaml:"quic"`     // multiplex QUIC/H3 on every UDP port

	EnabledTests []string `yaml:"enabled_tests"` // empty = all known

	Limits struct {
		SessionsPerMinute  int `yaml:"sessions_per_minute"`
		AttemptsPer10Min   int `yaml:"attempts_per_10min"`
		SessionTTLSeconds  int `yaml:"session_ttl_seconds"`
		RetentionHours     int `yaml:"retention_hours"`
		MaxObservations    int `yaml:"max_observations"` // ring size
		IdleTimeoutSeconds int `yaml:"idle_timeout_seconds"`
		BulkMBPerDay       int `yaml:"bulk_mb_per_day"` // per source IP
	} `yaml:"limits"`

	Log struct {
		Level string `yaml:"level"` // debug|info
	} `yaml:"log"`
}

// Default returns a configuration matching TEST-CATALOG P0 ports.
func Default() Config {
	var c Config
	c.SchemaVersion = 1
	c.Bind = ""
	c.DataDir = "./data"
	c.ControlPort = 8443
	c.TCPPorts = []int{80, 443, 1194, 8080, 8388, 4433, 1080, 9001, 9030}
	c.UDPPorts = []int{443, 1194, 51820, 8388, 4433, 500, 4500, 1701, 3478}
	c.DNSPorts = []int{53}
	c.DoTPort = 853
	c.DNSZone = "probe.invalid"
	c.QUIC = true
	c.Limits.SessionsPerMinute = 10
	c.Limits.AttemptsPer10Min = 1200 // a full 3-round scan reserves ~400 flows and echoes ~300 envelopes
	c.Limits.SessionTTLSeconds = 600
	c.Limits.RetentionHours = 24
	c.Limits.MaxObservations = 100000
	c.Limits.IdleTimeoutSeconds = 5
	c.Limits.BulkMBPerDay = 64
	c.Log.Level = "info"
	return c
}

// Load reads a YAML file over the defaults.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	return c, c.Validate()
}

// Validate fails closed on conflicting ports.
func (c *Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("config: unsupported schema_version %d", c.SchemaVersion)
	}
	seenTCP := map[int]string{}
	add := func(m map[int]string, p int, role string) error {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("config: bad port %d for %s", p, role)
		}
		if prev, ok := m[p]; ok && prev != role {
			return fmt.Errorf("config: port %d used by both %s and %s", p, prev, role)
		}
		m[p] = role
		return nil
	}
	if err := add(seenTCP, c.ControlPort, "control"); err != nil {
		return err
	}
	for _, p := range c.TCPPorts {
		if err := add(seenTCP, p, "tcp"); err != nil {
			return err
		}
	}
	for _, p := range c.DNSPorts {
		if err := add(seenTCP, p, "dns"); err != nil {
			return err
		}
	}
	if c.DoTPort != 0 {
		if err := add(seenTCP, c.DoTPort, "dot"); err != nil {
			return err
		}
	}
	seenUDP := map[int]string{}
	for _, p := range c.UDPPorts {
		if err := add(seenUDP, p, "udp"); err != nil {
			return err
		}
	}
	for _, p := range c.DNSPorts {
		if err := add(seenUDP, p, "dns"); err != nil {
			return err
		}
	}
	if c.Limits.SessionTTLSeconds <= 0 || c.Limits.SessionTTLSeconds > 600 {
		return fmt.Errorf("config: session_ttl_seconds must be 1..600")
	}
	if c.DNSZone == "" {
		c.DNSZone = "probe.invalid"
	}
	return nil
}

// RenderDefault prints a commented YAML document for `cpprobe config`.
func RenderDefault(c Config) string {
	b, _ := yaml.Marshal(c)
	return "# censorpulse-probe server configuration (schema 1)\n" +
		"# bind: \"\" listens on all addresses (dual-stack); set \"0.0.0.0\" for IPv4 only.\n" +
		"# Ports must not overlap between roles; startup fails closed on conflicts.\n" +
		string(b)
}
