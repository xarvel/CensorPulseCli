package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/httpecho"
	"github.com/xarvel/CensorPulseCli/internal/model"
)

const (
	bulkMaxChunk    = 64 << 10        // one upload request body
	bulkMaxDownload = 8 << 20         // one download request
	bulkIdle        = 8 * time.Second // keep-alive idle before the server hangs up
)

// tcpBulk serves a keep-alive sequence of bulk requests on one connection.
// The first request has already been parsed by tcpHTTP.
func (s *Server) tcpBulk(pc *peekConn, br *bufio.Reader, req *http.Request, first *httpecho.BulkRequest, obs *model.Observation, ip netip.Addr) {
	obs.Parse = model.ParseHTTP
	obs.SessionID, obs.TestID, obs.Nonce = first.SessionID, first.TestID, first.Nonce
	obs.Detail["bulk"] = first.Dir
	var upBytes, downBytes int64
	chunks := 0
	lastSeq := -1
	finish := func(reason string) {
		obs.Detail["bulk_up_bytes"] = strconv.FormatInt(upBytes, 10)
		obs.Detail["bulk_down_bytes"] = strconv.FormatInt(downBytes, 10)
		obs.Detail["bulk_chunks"] = strconv.Itoa(chunks)
		obs.Detail["bulk_last_seq"] = strconv.Itoa(lastSeq)
		obs.Close = reason
	}
	sess := s.store.sessionByHex(first.SessionID)
	if sess == nil || !sess.Tests[first.TestID] {
		writeSimple(pc, http.StatusForbidden, "unknown session or test not granted")
		finish("normal")
		return
	}
	for {
		b, ok := httpecho.ParseBulkPath(req.URL.Path)
		if !ok || b.SessionID != first.SessionID || b.Nonce != first.Nonce {
			writeSimple(pc, http.StatusBadRequest, "bulk path mismatch")
			finish("normal")
			return
		}
		switch b.Dir {
		case "up":
			n, err := io.Copy(io.Discard, io.LimitReader(req.Body, bulkMaxChunk+1))
			req.Body.Close()
			if err != nil {
				finish(closeReason(err))
				return
			}
			if n > bulkMaxChunk || !s.store.consumeBulk(ip, n, time.Now()) {
				writeSimple(pc, http.StatusRequestEntityTooLarge, "chunk too large or bulk quota exhausted")
				finish("normal")
				return
			}
			upBytes += n
			chunks++
			lastSeq = b.N
			body, _ := json.Marshal(map[string]any{"seq": b.N, "bytes": n, "total_in": upBytes})
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-CP1-Nonce: %s\r\n\r\n", len(body), b.Nonce)
			if _, err := pc.Write(append([]byte(resp), body...)); err != nil {
				finish(closeReason(err))
				return
			}
		case "down":
			io.Copy(io.Discard, io.LimitReader(req.Body, 4096))
			req.Body.Close()
			want := int64(b.N)
			if want <= 0 || want > bulkMaxDownload || !s.store.consumeBulk(ip, want, time.Now()) {
				writeSimple(pc, http.StatusRequestEntityTooLarge, "download too large or bulk quota exhausted")
				finish("normal")
				return
			}
			hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-CP1-Nonce: %s\r\n\r\n", want, b.Nonce)
			if _, err := pc.Write([]byte(hdr)); err != nil {
				finish(closeReason(err))
				return
			}
			buf := make([]byte, 4096)
			var off int64
			for off < want {
				n := int64(len(buf))
				if want-off < n {
					n = want - off
				}
				httpecho.Keystream(b.Nonce, off, buf[:n])
				pc.SetWriteDeadline(time.Now().Add(bulkIdle))
				if _, err := pc.Write(buf[:n]); err != nil {
					obs.Detail["bulk_down_sent"] = strconv.FormatInt(off, 10)
					finish(closeReason(err))
					return
				}
				off += n
			}
			downBytes += off
			chunks++
			lastSeq = b.N
		}
		obs.RepliedAt = ptrTime(time.Now())
		obs.Response = "bulk_" + b.Dir
		// next request on the same connection
		pc.SetReadDeadline(time.Now().Add(bulkIdle))
		var err error
		req, err = http.ReadRequest(br)
		if err != nil {
			finish(closeReason(err))
			return
		}
	}
}

func writeSimple(pc *peekConn, code int, msg string) {
	fmt.Fprintf(pc, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, http.StatusText(code), len(msg), msg)
}
