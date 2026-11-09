// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

// Mem is a registry in memory with a tunnel CA of its own, for tests of the relay and of the
// tool's side of the tunnel without a reference operator.
type Mem struct {
	trust string
	ca    *x509.Certificate
	caKey ed25519.PrivateKey
	roots *x509.CertPool

	mu     sync.Mutex
	routes map[string]Route
	denied map[string]bool
	gone   map[string]bool
}

// NewMem returns a registry for the trust domain.
func NewMem(trustDomain string) *Mem {
	_, key := must2(ed25519.GenerateKey(rand.Reader))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mem tunnel CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedURIDomains: []string{trustDomain},
	}
	ca := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, template, template, key.Public(), key))))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &Mem{trust: trustDomain, ca: ca, caKey: key, roots: roots, routes: map[string]Route{}, denied: map[string]bool{}, gone: map[string]bool{}}
}

// Name adds a name of the installation; verified is false for an own-domain name that is pending.
func (m *Mem) Name(name, home string, verified bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[strings.ToLower(name)] = Route{Home: home, Verified: verified}
}

// Unpair makes the installation inactive.
func (m *Mem) Unpair(home string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gone[home] = true
}

// Deny puts the serial of a certificate on the denylist.
func (m *Mem) Deny(c tls.Certificate) {
	leaf := must(x509.ParseCertificate(c.Certificate[0]))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.denied[hex.EncodeToString(leaf.SerialNumber.Bytes())] = true
}

// Issue makes a tunnel certificate for the home ID that starts at notBefore and lasts an hour.
// With a nil key it makes one; edit changes the template (tests of broken certificates).
func (m *Mem) Issue(home string, notBefore time.Time, key crypto.Signer, edit func(*x509.Certificate)) tls.Certificate {
	if key == nil {
		_, key = must2(ed25519.GenerateKey(rand.Reader))
	}
	san := must(tunnelcert.SANValue("spiffe://" + m.trust + "/home/" + home + "/gateway"))
	template := &x509.Certificate{
		SerialNumber: must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))),
		NotBefore:    notBefore, NotAfter: notBefore.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}},
	}
	if edit != nil {
		edit(template)
	}
	der := must(x509.CreateCertificate(rand.Reader, template, m.ca, key.Public(), m.caKey))
	return tls.Certificate{Certificate: [][]byte{der, m.ca.Raw}, PrivateKey: key}
}

// Routes implements Registry.
func (m *Mem) Routes() map[string]Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Route, len(m.routes))
	for k, v := range m.routes {
		out[k] = v
	}
	return out
}

// Active implements Registry.
func (m *Mem) Active(home string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.gone[home]
}

// Denied implements Registry.
func (m *Mem) Denied(serial string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied[serial]
}

// Roots implements Registry.
func (m *Mem) Roots() *x509.CertPool { return m.roots }

// TrustDomain implements Registry.
func (m *Mem) TrustDomain() string { return m.trust }
