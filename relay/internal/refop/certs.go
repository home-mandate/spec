// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

const (
	// backdate puts notBefore in the past, within the five minutes RELAY-v0 section 5.4 allows,
	// so that a second certificate of an installation in the same second still has a later
	// notBefore without waiting.
	backdate = 4 * time.Minute
	lifetime = 24 * time.Hour
	// serialBytes gives serial numbers of 128 random bits.
	serialBytes = 16
)

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// issuer is the CA of the tunnel certificates, with the name constraint of RELAY-v0 section 5.4.
type issuer struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newIssuer(trustDomain string) *issuer {
	_, key := must2(ed25519.GenerateKey(rand.Reader))
	template := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Reference tunnel CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedURIDomains: []string{trustDomain}, PermittedDNSDomainsCritical: true,
	}
	der := must(x509.CreateCertificate(rand.Reader, template, template, key.Public(), key))
	return &issuer{key: key, cert: must(x509.ParseCertificate(der)), der: der}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	must0(err)
	return a, b
}

func serial() *big.Int {
	raw := make([]byte, serialBytes)
	_, _ = rand.Read(raw)
	return new(big.Int).SetBytes(raw)
}

// issue makes the tunnel certificate for key: notBefore after that of every earlier one of the
// installation, notAfter 24 hours later, and the SPIFFE ID as the only name, critical.
func (o *Operator) issue(inst *installation, key crypto.PublicKey) (chain [][]byte, notAfter time.Time) {
	notBefore := time.Now().Truncate(time.Second).Add(-backdate)
	if !inst.lastNotBefore.IsZero() {
		if o.cfg.Faults.Has(NotBeforeStalls) {
			notBefore = inst.lastNotBefore
		} else if !notBefore.After(inst.lastNotBefore) {
			notBefore = inst.lastNotBefore.Add(time.Second)
		}
	}
	inst.lastNotBefore = notBefore
	notAfter = notBefore.Add(lifetime)
	if o.cfg.Faults.Has(LongCertificate) {
		notAfter = notBefore.Add(lifetime + time.Hour)
	}
	value := must(tunnelcert.SANValue("spiffe://" + o.cfg.Operator + "/home/" + inst.homeID + "/gateway"))
	template := &x509.Certificate{
		SerialNumber: serial(), NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidSAN, Critical: !o.cfg.Faults.Has(SANNotCritical), Value: value}},
	}
	der := must(x509.CreateCertificate(rand.Reader, template, o.ca.cert, key, o.ca.key))
	inst.tunnelKeys = append(inst.tunnelKeys, key)
	inst.serials = append(inst.serials, template.SerialNumber)
	return [][]byte{der, o.ca.der}, notAfter
}
