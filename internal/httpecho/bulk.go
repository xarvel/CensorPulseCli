package httpecho

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// Bulk transfer paths, shared by the client and the server:
//
//	POST /v1/bulk/<session>/<test>/<nonce>/up/<seq>      body: chunk bytes
//	GET  /v1/bulk/<session>/<test>/<nonce>/down/<bytes>  reply: <bytes> of keystream
//
// Both directions run over one keep-alive HTTP/1.1 connection so that a path
// which cuts or stalls long-lived flows after N kilobytes is caught with the
// exact byte offset on both ends.

// BulkPath builds a bulk path. dir is "up" or "down"; n is the chunk sequence
// number (up) or the byte count (down).
func BulkPath(sid, test, nonce, dir string, n int) string {
	return "/v1/bulk/" + sid + "/" + test + "/" + nonce + "/" + dir + "/" + strconv.Itoa(n)
}

// BulkRequest is a parsed bulk path.
type BulkRequest struct {
	SessionID, TestID, Nonce, Dir string
	N                             int
}

// ParseBulkPath is the inverse of BulkPath.
func ParseBulkPath(p string) (*BulkRequest, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 7 || parts[0] != "v1" || parts[1] != "bulk" || len(parts[2]) != 32 {
		return nil, false
	}
	// Hex like ParsePath: the nonce is echoed in a response header, and a
	// percent-decoded path can carry a line break.
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return nil, false
	}
	if _, err := hex.DecodeString(parts[4]); err != nil {
		return nil, false
	}
	if parts[5] != "up" && parts[5] != "down" {
		return nil, false
	}
	n, err := strconv.Atoi(parts[6])
	if err != nil || n < 0 {
		return nil, false
	}
	return &BulkRequest{SessionID: parts[2], TestID: parts[3], Nonce: parts[4], Dir: parts[5], N: n}, true
}

// Keystream fills dst with a deterministic pseudo-random stream derived from
// seed and the absolute byte offset, so the client can verify any window of a
// download without keeping the whole body.
func Keystream(seed string, offset int64, dst []byte) {
	var block [32]byte
	var counter [8]byte
	i := 0
	for i < len(dst) {
		blk := (offset + int64(i)) / 32
		inBlk := int((offset + int64(i)) % 32)
		binary.BigEndian.PutUint64(counter[:], uint64(blk))
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write(counter[:])
		copy(block[:], h.Sum(nil))
		n := copy(dst[i:], block[inBlk:])
		i += n
	}
}
