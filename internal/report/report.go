// Package report assembles the versioned JSON report and a human summary.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/classify"
	"github.com/xarvel/CensorPulseCli/internal/client"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

// Report is the on-disk artefact. Raw attempts are always kept.
type Report struct {
	SchemaVersion int    `json:"schema_version"`
	ClientVersion string `json:"client_version"`
	// Mode is "scan" (against a probe server) or "sites" (the real
	// destinations family alone, no server). Empty means scan.
	Mode         string                 `json:"mode,omitempty"`
	Target       string                 `json:"target"`
	ControlPort  int                    `json:"control_port"`
	StartedAt    time.Time              `json:"started_at"`
	FinishedAt   time.Time              `json:"finished_at"`
	ProbeReached bool                   `json:"probe_reachable"`
	BootstrapErr string                 `json:"bootstrap_error,omitempty"`
	ObservedPin  string                 `json:"observed_spki_pin,omitempty"`
	PinEnforced  bool                   `json:"pin_enforced"`
	Params       *model.Params          `json:"params,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	ClientAddr   string                 `json:"client_public_addr,omitempty"` // as seen by the server
	Network      *Network               `json:"network,omitempty"`            // offline GeoLite2 lookup of client_public_addr
	ControlRTTms float64                `json:"control_rtt_ms,omitempty"`
	TimeoutMs    float64                `json:"attempt_timeout_ms,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"` // e.g. circumvention tools running
	Health       *model.Health          `json:"health,omitempty"`
	Attempts     []*client.Attempt      `json:"attempts"`
	Cells        []classify.Cell        `json:"cells"`
	Verdicts     []classify.Verdict     `json:"verdicts"`
	Destinations []classify.Destination `json:"destinations,omitempty"` // per-site summary of the dest.* family
	Summary      string                 `json:"summary"`
	Notes        []string               `json:"notes,omitempty"`
	Unmatched    []model.Observation    `json:"unmatched_observations,omitempty"`
}

// Network is the vantage point: derived offline from the public address the
// server saw, or, on request, from a public geo-ASN API (Source names it).
// Without it a report cannot be aggregated per carrier.
type Network struct {
	ASN      int    `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	Country  string `json:"country,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Source   string `json:"source,omitempty"`    // which tables or online service answered
	TablesAt string `json:"tables_at,omitempty"` // modification time of the tables (RFC 3339)
}

// Sites reports whether the report is a standalone real-destinations scan.
func (r *Report) Sites() bool { return r.Mode == "sites" }

// WriteJSON writes the report with stable key order. Nil slices are emitted
// as empty arrays so consumers never see null for list fields.
func (r *Report) WriteJSON(w io.Writer) error {
	if r.Attempts == nil {
		r.Attempts = []*client.Attempt{}
	}
	if r.Cells == nil {
		r.Cells = []classify.Cell{}
	}
	if r.Verdicts == nil {
		r.Verdicts = []classify.Verdict{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText prints the human summary, coloured when w is a terminal.
func (r *Report) WriteText(w io.Writer) { r.WriteStyled(w, AutoStyle(w)) }
