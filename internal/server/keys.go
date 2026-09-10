package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/obfs4"
	"github.com/xarvel/CensorPulseCli/internal/ovpn"
	"github.com/xarvel/CensorPulseCli/internal/tor"
	"github.com/xarvel/CensorPulseCli/internal/wg"
)

// Keys is the persistent key material of a probe server. Everything lives in
// DataDir with 0600 permissions; nothing is ever sent to a client except the
// public halves.
type Keys struct {
	Master  []byte // 32 bytes, HMAC root for tokens/cookies/session keys
	TLSCert tls.Certificate
	SPKIPin string // base64(sha256(SPKI))
	WG      wg.KeyPair
	// Obfs4 is the bridge identity (node id + Curve25519 key) the obfs4
	// responder recognises client handshakes with; the public half is
	// advertised in /v1/params like a bridge line's cert=.
	Obfs4 obfs4.Identity
	// TorCert is the relay-style link certificate presented to Tor-shaped
	// handshakes. It is regenerated at every start (like a relay's link key)
	// and pinned through /v1/params.
	TorCert    tls.Certificate
	TorSPKIPin string
	// OVPNTLSAuth is the static key of the OpenVPN tls-auth responder,
	// regenerated at every start and advertised in /v1/params. Like the
	// WireGuard public key it only lets a client speak the wire format; the
	// responder still answers reserved flows only.
	OVPNTLSAuth []byte
}

// LoadOrCreateKeys reads keys from dir, generating any that are missing.
func LoadOrCreateKeys(dir string) (*Keys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k := &Keys{}
	var err error
	if k.Master, err = loadOrCreateRaw(filepath.Join(dir, "master.key"), 32); err != nil {
		return nil, err
	}
	wgPriv, err := loadOrCreateRaw(filepath.Join(dir, "wireguard.key"), 32)
	if err != nil {
		return nil, err
	}
	var priv [32]byte
	copy(priv[:], wgPriv)
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	if k.WG, err = wg.KeyPairFromPrivate(priv); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := generateCert(certPath, keyPath); err != nil {
			return nil, err
		}
	}
	if k.TLSCert, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("keys: load tls: %w", err)
	}
	leaf, err := x509.ParseCertificate(k.TLSCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	k.SPKIPin = SPKIPin(leaf)
	nodeID, err := loadOrCreateRaw(filepath.Join(dir, "obfs4-node.id"), obfs4.NodeIDLen)
	if err != nil {
		return nil, err
	}
	obfsPriv, err := loadOrCreateRaw(filepath.Join(dir, "obfs4.key"), 32)
	if err != nil {
		return nil, err
	}
	var op [32]byte
	copy(op[:], obfsPriv)
	op[0] &= 248
	op[31] = (op[31] & 127) | 64
	okp, err := wg.KeyPairFromPrivate(op)
	if err != nil {
		return nil, err
	}
	copy(k.Obfs4.NodeID[:], nodeID)
	k.Obfs4.Public = okp.Public
	if k.TorCert, err = tor.GenerateLinkCert(); err != nil {
		return nil, fmt.Errorf("keys: tor link cert: %w", err)
	}
	k.TorSPKIPin = SPKIPin(k.TorCert.Leaf)
	k.OVPNTLSAuth = ovpn.NewTLSAuthKey()
	return k, nil
}

// SPKIPin computes the HPKP-style pin of a certificate.
func SPKIPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func loadOrCreateRaw(path string, n int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil && len(b) == n {
		return b, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// generateCert writes a self-signed ECDSA P-256 certificate valid for 10 years.
// The certificate deliberately carries no SAN: clients must pin the SPKI, not
// trust a name. It is the same cert on the control port and on every TLS test
// port so that SNI-dependent behaviour cannot be caused by the server itself.
func generateCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "censorpulse-probe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}
