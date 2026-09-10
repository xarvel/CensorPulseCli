// Package httpecho defines the deterministic HTTP echo shared by the plain
// HTTP, HTTPS and HTTP/3 tests: the request path carries session, test and
// nonce; the body is a function of (host, path, nonce) that both sides can
// compute, so any rewrite of the request or the response is detectable.
package httpecho

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Path builds /v1/echo/<session_hex>/<test_id>/<nonce_hex>.
func Path(sid, test, nonce string) string { return "/v1/echo/" + sid + "/" + test + "/" + nonce }

// ParsePath is the inverse of Path.
func ParsePath(p string) (sid, test, nonce string, ok bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != "echo" {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil || len(parts[2]) != 32 {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[4]); err != nil {
		return "", "", "", false
	}
	return parts[2], parts[3], parts[4], true
}

// Body is the exact response body for a request.
func Body(host, path, nonce string) []byte {
	hostSum := sha256.Sum256([]byte(host))
	b, _ := json.Marshal(map[string]string{
		"magic":       "CP1",
		"nonce":       nonce,
		"path":        path,
		"host_sha256": hex.EncodeToString(hostSum[:]),
	})
	return append(b, '\n')
}
