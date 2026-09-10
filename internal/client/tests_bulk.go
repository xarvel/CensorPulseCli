package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/httpecho"
	"github.com/xarvel/CensorPulseCli/internal/proto"
)

// bulkOptions describe one long-transfer attempt.
type bulkOptions struct {
	Dir     string // up | down
	TLS     bool
	SNI     string
	TotalKB int
	ChunkKB int
}

// bulkTransfer moves TotalKB kilobytes over one keep-alive HTTP/1.1
// connection and records exactly where the path stopped it, if it did.
// Upload: ChunkKB-sized POSTs, each acknowledged by the server. Download: one
// GET, body verified against the keystream in 4 KB windows.
func (c *Client) bulkTransfer(ctx context.Context, a *Attempt, o bulkOptions) *Attempt {
	if o.ChunkKB <= 0 {
		o.ChunkKB = 4
	}
	if o.TotalKB <= 0 {
		o.TotalKB = 64
	}
	nonce := hex.EncodeToString(proto.RandomPayload(12))
	a.Nonce = nonce
	a.Detail["bulk_dir"] = o.Dir
	a.Detail["bulk_total_kb"] = strconv.Itoa(o.TotalKB)
	if o.TLS {
		a.Detail["sni"] = o.SNI
	}
	raw, err := c.dialTCP(ctx, a)
	if err != nil {
		return a.fail(classifyNetErr(err, false), err)
	}
	defer raw.Close()
	var conn net.Conn = raw
	if o.TLS {
		cfg := c.pinnedTLS(o.SNI)
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(raw, cfg)
		raw.SetDeadline(time.Now().Add(c.attemptTimeout()))
		if err := tc.HandshakeContext(ctx); err != nil {
			noteTLSFailure(a, err)
			return a.fail(tlsOutcome(err), err)
		}
		a.mark("handshake")
		conn = tc
	}
	host := o.SNI
	if host == "" {
		host = c.target.String()
	}
	stall := c.stallTimeout()
	br := bufio.NewReaderSize(conn, 64<<10)
	var moved int64
	fail := func(outcome string, err error) *Attempt {
		a.Detail["bulk_bytes"] = strconv.FormatInt(moved, 10)
		a.Detail["bulk_cut_kb"] = strconv.FormatInt(moved>>10, 10)
		return a.fail(outcome, err)
	}
	bulkOutcome := func(err error) string {
		switch classifyNetErr(err, true) {
		case OutcomePayloadTimeout:
			return OutcomeBulkStall
		case OutcomeMidstreamReset, OutcomeMidstreamEOF:
			return OutcomeBulkReset
		default:
			return classifyNetErr(err, true)
		}
	}

	switch o.Dir {
	case "up":
		chunk := make([]byte, o.ChunkKB<<10)
		n := (o.TotalKB + o.ChunkKB - 1) / o.ChunkKB
		for seq := 0; seq < n; seq++ {
			httpecho.Keystream(nonce, int64(seq)*int64(len(chunk)), chunk)
			path := httpecho.BulkPath(c.Session.SessionID, a.TestID, nonce, "up", seq)
			hdr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", path, host, len(chunk))
			conn.SetWriteDeadline(time.Now().Add(stall))
			if _, err := conn.Write(append([]byte(hdr), chunk...)); err != nil {
				return fail(bulkOutcome(err), err)
			}
			if seq == 0 {
				a.mark("first_write")
			}
			a.BytesOut += len(hdr) + len(chunk)
			conn.SetReadDeadline(time.Now().Add(stall))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				return fail(bulkOutcome(err), err)
			}
			if seq == 0 {
				a.mark("first_byte")
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			a.BytesIn += len(body)
			if resp.StatusCode != http.StatusOK || resp.Header.Get("X-CP1-Nonce") != nonce {
				a.Detail["status"] = strconv.Itoa(resp.StatusCode)
				a.Detail["body_prefix"] = string(body[:min(len(body), 96)])
				return fail(OutcomeUnexpected, fmt.Errorf("bulk up: status %d", resp.StatusCode))
			}
			moved += int64(len(chunk))
		}
	case "down":
		want := int64(o.TotalKB) << 10
		path := httpecho.BulkPath(c.Session.SessionID, a.TestID, nonce, "down", int(want))
		hdr := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36\r\nConnection: keep-alive\r\n\r\n", path, host)
		conn.SetWriteDeadline(time.Now().Add(stall))
		if _, err := conn.Write([]byte(hdr)); err != nil {
			return fail(bulkOutcome(err), err)
		}
		a.mark("first_write")
		a.BytesOut += len(hdr)
		conn.SetReadDeadline(time.Now().Add(stall))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return fail(bulkOutcome(err), err)
		}
		a.mark("first_byte")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-CP1-Nonce") != nonce {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			a.Detail["status"] = strconv.Itoa(resp.StatusCode)
			a.Detail["body_prefix"] = string(body)
			return fail(OutcomeUnexpected, fmt.Errorf("bulk down: status %d", resp.StatusCode))
		}
		buf := make([]byte, 4096)
		expect := make([]byte, 4096)
		for moved < want {
			conn.SetReadDeadline(time.Now().Add(stall))
			n, err := io.ReadFull(resp.Body, buf[:min(len(buf), int(want-moved))])
			if n > 0 {
				httpecho.Keystream(nonce, moved, expect[:n])
				if !bytes.Equal(buf[:n], expect[:n]) {
					a.BytesIn += n
					return fail(OutcomeModified, fmt.Errorf("bulk down: body differs at byte %d", moved))
				}
				moved += int64(n)
				a.BytesIn += n
			}
			if err != nil {
				return fail(bulkOutcome(err), err)
			}
		}
		resp.Body.Close()
	default:
		return a.fail(OutcomeSkipped, fmt.Errorf("unknown bulk direction %q", o.Dir))
	}
	a.Detail["bulk_bytes"] = strconv.FormatInt(moved, 10)
	ms := a.Stages["first_write"]
	if el := float64(time.Since(a.StartedAt).Microseconds())/1000 - ms; el > 0 {
		a.Detail["bulk_kbps"] = fmt.Sprintf("%.0f", float64(moved)/1024/(el/1000))
	}
	return a.ok()
}
