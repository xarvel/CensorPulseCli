package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
