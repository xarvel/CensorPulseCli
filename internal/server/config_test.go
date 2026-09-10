package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("Default() does not validate: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring; "" = valid
	}{
		{"schema version", func(c *Config) { c.SchemaVersion = 2 }, "unsupported schema_version 2"},
		{"control port on a tcp port", func(c *Config) { c.ControlPort = 443 }, "port 443 used by both control and tcp"},
		{"dns port on a tcp port", func(c *Config) { c.DNSPorts = []int{80} }, "port 80 used by both tcp and dns"},
		{"dot port on a tcp port", func(c *Config) { c.DoTPort = 8080 }, "port 8080 used by both tcp and dot"},
		{"dot port on the dns port", func(c *Config) { c.DoTPort = 53 }, "port 53 used by both dns and dot"},
		{"dns port on a udp port", func(c *Config) { c.DNSPorts = []int{500} }, "port 500 used by both udp and dns"},
		{"tcp port 0", func(c *Config) { c.TCPPorts = []int{0} }, "bad port 0 for tcp"},
		{"udp port above 65535", func(c *Config) { c.UDPPorts = []int{65536} }, "bad port 65536 for udp"},
		{"negative control port", func(c *Config) { c.ControlPort = -1 }, "bad port -1 for control"},
		// TCP and UDP are separate spaces, and a port listed twice in its own
		// role is not a conflict.
		{"same number on tcp and udp", func(c *Config) { c.TCPPorts, c.UDPPorts = []int{443}, []int{443} }, ""},
		{"control port number on udp", func(c *Config) { c.UDPPorts = []int{8443} }, ""},
		{"duplicate within a role", func(c *Config) { c.TCPPorts = []int{80, 80} }, ""},
		{"dot disabled", func(c *Config) { c.DoTPort = 0 }, ""},
		{"no test ports at all", func(c *Config) { c.TCPPorts, c.UDPPorts, c.DNSPorts, c.DoTPort = nil, nil, nil, 0 }, ""},
		{"session ttl 0", func(c *Config) { c.Limits.SessionTTLSeconds = 0 }, "session_ttl_seconds must be 1..600"},
		{"session ttl 601", func(c *Config) { c.Limits.SessionTTLSeconds = 601 }, "session_ttl_seconds must be 1..600"},
		{"session ttl 1", func(c *Config) { c.Limits.SessionTTLSeconds = 1 }, ""},
		{"max observations 0", func(c *Config) { c.Limits.MaxObservations = 0 }, "max_observations must be at least 1"},
		{"max observations 1", func(c *Config) { c.Limits.MaxObservations = 1 }, ""},
		{"idle timeout 0", func(c *Config) { c.Limits.IdleTimeoutSeconds = 0 }, "idle_timeout_seconds must be at least 1"},
		// Not validated: these limits fail closed (nothing is granted) or have
		// a built-in default.
		{"zero rate limits", func(c *Config) { c.Limits.SessionsPerMinute, c.Limits.AttemptsPer10Min = 0, 0 }, ""},
		{"zero bulk quota and retention", func(c *Config) { c.Limits.BulkMBPerDay, c.Limits.RetentionHours = 0, 0 }, ""},
	} {
		c := Default()
		tc.mutate(&c)
		err := c.Validate()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: valid, want error containing %q", tc.name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error %q, want it to contain %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestValidateDefaultsZone(t *testing.T) {
	c := Default()
	c.DNSZone = ""
	if err := c.Validate(); err != nil || c.DNSZone != "probe.invalid" {
		t.Errorf("empty dns_zone: err=%v zone=%q, want the default zone", err, c.DNSZone)
	}
}

func TestLoad(t *testing.T) {
	if c, err := Load(""); err != nil || c.ControlPort != Default().ControlPort {
		t.Errorf("Load(\"\") = %v, want the defaults", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: no error")
	}
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "probe.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Keys of the file overlay the defaults; untouched keys keep theirs.
	c, err := Load(write("control_port: 9443\ntcp_ports: [8080]\nlimits:\n  max_observations: 5\n  retention_hours: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ControlPort != 9443 || len(c.TCPPorts) != 1 || c.Limits.MaxObservations != 5 || c.Limits.RetentionHours != 1 {
		t.Errorf("file values not applied: %+v", c)
	}
	if c.Limits.SessionTTLSeconds != 600 || c.DoTPort != 853 || !c.QUIC {
		t.Errorf("defaults lost for keys the file does not set: %+v", c)
	}
	// An explicit zero is not "use the default": it fails validation.
	if _, err := Load(write("limits:\n  max_observations: 0\n")); err == nil {
		t.Error("max_observations: 0 accepted")
	}
	if _, err := Load(write("control_port: 443\n")); err == nil {
		t.Error("port conflict accepted")
	}
	if _, err := Load(write("tcp_ports: {")); err == nil || !strings.Contains(err.Error(), "config:") {
		t.Errorf("bad yaml: err = %v", err)
	}
}

// The shipped deploy/probe.yaml must load, and must say what Default() says:
// it is the documentation of the defaults.
func TestDeployConfigMatchesDefaults(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "deploy", "probe.yaml"))
	if err != nil {
		t.Fatalf("deploy/probe.yaml: %v", err)
	}
	d := Default()
	if c.Limits != d.Limits {
		t.Errorf("deploy/probe.yaml limits = %+v, defaults = %+v", c.Limits, d.Limits)
	}
	if c.ControlPort != d.ControlPort || c.DoTPort != d.DoTPort || c.DNSZone != d.DNSZone || c.QUIC != d.QUIC {
		t.Errorf("deploy/probe.yaml differs from the defaults: %+v", c)
	}
}

func TestRenderDefaultRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "probe.yaml")
	if err := os.WriteFile(p, []byte(RenderDefault(Default())), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("rendered default does not load: %v", err)
	}
	if c.Limits != Default().Limits || c.ControlPort != Default().ControlPort {
		t.Errorf("round trip changed the config: %+v", c)
	}
}
