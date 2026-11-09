// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

const (
	maxLifetime = 24 * time.Hour
	maxBackdate = 5 * time.Minute
	// minSerialBits is a floor for the serial number, which has to carry 64 random bits; a
	// number of 64 random bits is shorter than 64 bits with a small probability.
	minSerialBits = 48
	// clockSlack allows for the whole seconds of the time of a certificate.
	clockSlack = 2 * time.Second
)

var (
	oidSAN     = asn1.ObjectIdentifier{2, 5, 29, 17}
	emptyName  = []byte{0x30, 0x00}
	wantEKUSet = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
)

// issuedCert is a tunnel certificate of the run with what the checks need to judge it.
type issuedCert struct {
	chain     [][]byte
	notAfter  time.Time
	key       crypto.PublicKey
	homeID    string
	requested time.Time
	received  time.Time
	// earlier is the notBefore of the previous certificate of the installation, if any.
	earlier time.Time
}

// certProblems judges a certificate by RELAY-v0 section 5.4 and returns, for each check of the
// class enrollment about certificates, what is wrong; a check that is fine is not in the map.
func certProblems(c issuedCert, trustDomain string) map[string]string {
	out := map[string]string{}
	if len(c.chain) == 0 || len(c.chain) > tunnelcert.MaxChain {
		out[CheckEnrollCertRules] = fmt.Sprintf("%d certificates in the chain", len(c.chain))
		return out
	}
	leaf, err := x509.ParseCertificate(c.chain[0])
	if err != nil {
		out[CheckEnrollCertRules] = "the certificate cannot be parsed"
		return out
	}
	set := func(id string, msg string) {
		if msg != "" && out[id] == "" {
			out[id] = msg
		}
	}
	set(CheckEnrollCertRules, rulesProblem(leaf, c))
	set(CheckEnrollCertSAN, sanProblem(leaf, "spiffe://"+trustDomain+"/home/"+c.homeID+"/gateway"))
	set(CheckEnrollCertLifetime, lifetimeProblem(leaf, c))
	if !c.earlier.IsZero() && !leaf.NotBefore.After(c.earlier) {
		set(CheckEnrollCertMonotonic, "notBefore is not later than that of the previous certificate of the installation")
	}
	return out
}

func rulesProblem(leaf *x509.Certificate, c issuedCert) string {
	switch {
	case !publicKeyEqual(leaf.PublicKey, c.key):
		return "the public key is not the tunnel key of the request"
	case leaf.IsCA:
		return "cA is true"
	case leaf.KeyUsage != x509.KeyUsageDigitalSignature || !criticalExtension(leaf, asn1.ObjectIdentifier{2, 5, 29, 15}):
		return "the key usage is not digitalSignature alone, critical"
	case !sameSet(leaf.ExtKeyUsage, wantEKUSet):
		return "the extended key usage is not serverAuth and clientAuth"
	case leaf.SerialNumber.BitLen() < minSerialBits:
		return "the serial number is too short for 64 random bits"
	case !leaf.NotAfter.Equal(c.notAfter):
		return "notAfter is not the not_after of the response"
	case len(leaf.UnhandledCriticalExtensions) > 0:
		return "an unknown critical extension"
	}
	return ""
}

func sanProblem(leaf *x509.Certificate, id string) string {
	if !bytes.Equal(leaf.RawSubject, emptyName) {
		return "the subject is not empty"
	}
	want, err := tunnelcert.SANValue(id)
	if err != nil {
		return "the SPIFFE ID of the installation is too long"
	}
	found := 0
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		found++
		if !ext.Critical {
			return "the subject alternative name is not critical"
		}
		if !bytes.Equal(ext.Value, want) {
			return "the subject alternative name is not exactly the SPIFFE ID of the installation"
		}
	}
	if found != 1 {
		return fmt.Sprintf("%d subject alternative name extensions", found)
	}
	return ""
}

func lifetimeProblem(leaf *x509.Certificate, c issuedCert) string {
	switch {
	case !leaf.NotAfter.After(leaf.NotBefore):
		return "notAfter is not after notBefore"
	case leaf.NotAfter.Sub(leaf.NotBefore) > maxLifetime:
		return fmt.Sprintf("the certificate lasts %s, more than 24 hours", leaf.NotAfter.Sub(leaf.NotBefore))
	case leaf.NotBefore.Before(c.requested.Add(-maxBackdate - clockSlack)):
		return "notBefore is more than 5 minutes before issuance"
	case leaf.NotBefore.After(c.received.Add(clockSlack)):
		return "notBefore is later than issuance"
	case !leaf.NotAfter.After(c.received):
		return "notAfter is not in the future"
	}
	return ""
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && k.Equal(b)
}

func criticalExtension(c *x509.Certificate, id asn1.ObjectIdentifier) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(id) {
			return ext.Critical
		}
	}
	return false
}

func sameSet(got, want []x509.ExtKeyUsage) bool {
	for _, u := range got {
		if !slices.Contains(want, u) {
			return false
		}
	}
	for _, u := range want {
		if !slices.Contains(got, u) {
			return false
		}
	}
	return true
}
