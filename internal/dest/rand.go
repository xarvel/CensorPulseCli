package dest

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

// Nonce is a short random hex label.
func Nonce(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// PickDecoy returns a random decoy name that is not one of exclude nor on
// the same site as any of them (www.wikipedia.org is no decoy for
// wikipedia.org: a suffix-keyed rule would fail both).
func PickDecoy(exclude ...string) string {
	var pool []string
	for _, d := range DecoyNames {
		same := false
		for _, e := range exclude {
			if sameSite(d, e) {
				same = true
				break
			}
		}
		if !same {
			pool = append(pool, d)
		}
	}
	if len(pool) == 0 {
		pool = DecoyNames
	}
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		return pool[0]
	}
	return pool[i.Int64()]
}

// sameSite reports whether two names are the same site: equal once a
// leading "www." is dropped, or one a subdomain of the other.
func sameSite(a, b string) bool {
	a = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(a, ".")), "www.")
	b = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(b, ".")), "www.")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// NXDomainName is a fresh name under the reserved .invalid TLD (RFC 6761):
// it must resolve to NXDOMAIN everywhere; any answer is a hijack.
func NXDomainName() string { return "cp-nxd-" + Nonce(6) + ".invalid" }
