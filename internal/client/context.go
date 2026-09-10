package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// bypassTools maps a tool name to the process names it runs as. A scan taken
// while one of these is active measures the tunnel, not the network, so the
// report carries a warning. The list is deliberately vendor-neutral.
var bypassTools = map[string][]string{
	"zapret":          {"nfqws", "tpws", "winws", "dvtws"},
	"GoodbyeDPI":      {"goodbyedpi", "windivert"},
	"ByeDPI":          {"byedpi", "ciadpi"},
	"SpoofDPI":        {"spoofdpi"},
	"PowerTunnel":     {"powertunnel"},
	"xray/v2ray":      {"xray", "v2ray"},
	"sing-box":        {"sing-box", "hiddify", "hiddify-core"},
	"clash":           {"mihomo", "clash", "clash-meta", "clash-verge", "flclash"},
	"Hysteria":        {"hysteria"},
	"Trojan":          {"trojan", "trojan-go"},
	"NaiveProxy":      {"naive"},
	"Shadowsocks":     {"ss-local", "sslocal", "shadowsocks", "ssr-local", "outline"},
	"Tor":             {"tor", "obfs4proxy", "snowflake-client", "lyrebird"},
	"Psiphon":         {"psiphon", "psiphon-tunnel-core"},
	"Lantern":         {"lantern"},
	"WireGuard":       {"wireguard", "wg-quick", "wireguard-go", "amneziawg", "awg"},
	"OpenVPN":         {"openvpn"},
	"Tailscale":       {"tailscaled"},
	"ZeroTier":        {"zerotier-one"},
	"Cloudflare WARP": {"warp-svc", "cloudflarewarp"},
	"Mullvad":         {"mullvad-daemon"},
	"NordVPN":         {"nordvpnd", "nordvpn"},
	"ProtonVPN":       {"protonvpn"},
	"dnscrypt-proxy":  {"dnscrypt-proxy"},
}

// DetectBypassTools returns the names of known circumvention/VPN tools whose
// processes are running. Best effort: an empty result is not proof of absence.
func DetectBypassTools() []string {
	names := runningProcessNames()
	if len(names) == 0 {
		return nil
	}
	found := map[string]bool{}
	for tool, procs := range bypassTools {
		for _, p := range procs {
			if names[p] {
				found[tool] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for t := range found {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func runningProcessNames() map[string]bool {
	names := map[string]bool{}
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimSuffix(n, ".exe")
		if n != "" {
			names[filepath.Base(n)] = true
		}
	}
	switch runtime.GOOS {
	case "linux", "android":
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return names
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
				continue
			}
			if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil {
				add(string(b))
			}
		}
	case "darwin", "freebsd", "openbsd":
		out, err := exec.Command("ps", "-axo", "comm=").Output()
		if err != nil {
			return names
		}
		for _, l := range strings.Split(string(out), "\n") {
			add(l)
		}
	case "windows":
		out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
		if err != nil {
			return names
		}
		for _, l := range strings.Split(string(out), "\n") {
			if i := strings.Index(l, "\",\""); i > 1 {
				add(strings.Trim(l[:i], "\""))
			}
		}
	}
	return names
}

// attemptTimeout is the per-attempt deadline. With adaptive timing it is
// derived from the control-plane RTT measured during bootstrap (6×RTT + 500 ms,
// clamped to 1.5 s … --timeout), so a fast path does not wait 6 s for every
// dropped probe and a slow path is not misread as dropping.
func (c *Client) attemptTimeout() time.Duration {
	if !c.opt.AdaptiveTimeout || c.controlRTT <= 0 {
		return c.opt.Timeout
	}
	t := 6*c.controlRTT + 500*time.Millisecond
	if t < 1500*time.Millisecond {
		t = 1500 * time.Millisecond
	}
	if t > c.opt.Timeout {
		t = c.opt.Timeout
	}
	return t
}

// stallTimeout is how long a bulk transfer may make no progress.
func (c *Client) stallTimeout() time.Duration {
	t := c.attemptTimeout()
	if t < 3*time.Second {
		t = 3 * time.Second
	}
	return t
}
