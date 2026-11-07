package firstrun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"godebplay/backend/core"
)

// EnsureCert returns the self-signed certificate for the setup and LAN
// listeners, creating it on first use. Browsers warn about it; the SHA-256
// fingerprint printed by `godeb-play setup-url` lets the admin check it.
func EnsureCert() (tls.Certificate, string, error) {
	if cert, err := tls.LoadX509KeyPair(certPath(), keyPath()); err == nil {
		return cert, fingerprint(cert.Certificate[0]), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "GoDeb " + host, Organization: []string{"GoDeb"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	for _, ip := range hostIPs() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFile(keyPath(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFile(certPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	cert, err := tls.LoadX509KeyPair(certPath(), keyPath())
	return cert, fingerprint(der), err
}

// CertFingerprint reads the certificate without creating it; the agent
// uses it, as creating files in the state directory is the web's job.
func CertFingerprint() (string, error) {
	cert, err := tls.LoadX509KeyPair(certPath(), keyPath())
	if err != nil {
		return "", err
	}
	return fingerprint(cert.Certificate[0]), nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

// hostIPs are the addresses the browser may use: the default route source
// (public IP on a VPS) and the LAN addresses.
func hostIPs() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(ip string) {
		if ip != "" && !seen[ip] && net.ParseIP(ip) != nil {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(core.DefaultRoute(context.Background()).Src)
	for _, a := range core.LANAddresses() {
		add(a.Address)
	}
	return out
}
