// SPDX-License-Identifier: Apache-2.0

// Package tunnelcert checks certificate signing requests and issued tunnel certificates
// (RELAY-v0 section 5.4). It is the reference for the cases in relay/conformance/csr-v0.json
// and relay/conformance/certificate-v0.json, used only by tests.
package tunnelcert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/home-mandate/spec/jws"
)

// MaxChain is the largest number of certificates in a certificate response.
const MaxChain = 4

// MaxLifetime bounds notAfter after notBefore.
const MaxLifetime = 24 * time.Hour

// MaxBackdate bounds how far notBefore lies before issuance.
const MaxBackdate = 5 * time.Minute

// ErrBadCSR is returned for a request that the operator refuses with bad-csr.
var ErrBadCSR = errors.New("tunnelcert: bad-csr")

// ErrInvalid is returned for an issued certificate that breaks a rule.
var ErrInvalid = errors.New("tunnelcert: invalid certificate")

// CheckCSR checks a PKCS #10 request in DER against the installation key and the keys of
// the tunnel certificates issued to the installation before. It returns the key of the
// request.
func CheckCSR(der []byte, installation crypto.PublicKey, earlier []crypto.PublicKey) (crypto.PublicKey, error) {
	// ParseCertificateRequest refuses trailing data and lengths that are not minimal.
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	if err := checkCSRAlgorithm(req); err != nil {
		return nil, err
	}
	// The key is a key in the sense of RELAY-v0 section 5.1: no Ed25519 key of small order,
	// and canonically encoded.
	if jwk, err := jws.MarshalJWK(req.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	} else if _, err := jws.ParseJWK(jwk); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	for _, other := range append([]crypto.PublicKey{installation}, earlier...) {
		if sameKey(req.PublicKey, other) {
			return nil, fmt.Errorf("%w: the key is the installation key or of an earlier tunnel certificate", ErrBadCSR)
		}
	}
	return req.PublicKey, nil
}

func checkCSRAlgorithm(req *x509.CertificateRequest) error {
	switch key := req.PublicKey.(type) {
	case ed25519.PublicKey:
		if req.SignatureAlgorithm == x509.PureEd25519 {
			return nil
		}
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() && req.SignatureAlgorithm == x509.ECDSAWithSHA256 {
			return nil
		}
	}
	return fmt.Errorf("%w: key %s with signature %s", ErrBadCSR, req.PublicKeyAlgorithm, req.SignatureAlgorithm)
}

func sameKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && k.Equal(b)
}

// Expected describes what an issued certificate must match.
type Expected struct {
	// Key is the tunnel key of the request.
	Key crypto.PublicKey
	// TrustDomain and HomeID give the SPIFFE ID.
	TrustDomain, HomeID string
	// NotAfter is not_after of the response.
	NotAfter time.Time
	// RequestedAt is when the request was sent: notBefore is no earlier than 5 minutes
	// before it, and notAfter is after it.
	RequestedAt time.Time
	// ReceivedAt is when the response arrived: notBefore is no later than it, since it is
	// no later than issuance.
	ReceivedAt time.Time
	// EarlierNotBefore is the latest notBefore of the installation's earlier tunnel
	// certificates, zero if there are none.
	EarlierNotBefore time.Time
}

// SPIFFEID returns spiffe://<trust domain>/home/<home ID>/gateway.
func (e Expected) SPIFFEID() string {
	return "spiffe://" + e.TrustDomain + "/home/" + e.HomeID + "/gateway"
}

var (
	oidSAN    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKU     = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidEKU    = asn1.ObjectIdentifier{2, 5, 29, 37}
	emptyName = []byte{0x30, 0x00}
	wantEKU   = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
)

// uriTag is the context-specific tag of uniformResourceIdentifier in GeneralName.
const uriTag = 0x86

// CheckIssued checks the chain of a certificate response: the issued certificate and the
// certificates of its CA.
func CheckIssued(chain [][]byte, want Expected) error {
	if len(chain) == 0 || len(chain) > MaxChain {
		return fmt.Errorf("%w: %d certificates", ErrInvalid, len(chain))
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("%w: certificate %d: %w", ErrInvalid, i, err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	for _, rule := range []func(*x509.Certificate, Expected) error{checkKey, checkSAN, checkTimes, checkUsage} {
		if err := rule(leaf, want); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if len(certs) > 1 {
		if err := checkIssuer(leaf, certs[1], want.TrustDomain); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

func checkKey(c *x509.Certificate, want Expected) error {
	if !sameKey(c.PublicKey, want.Key) {
		return errors.New("the public key is not the tunnel key of the request")
	}
	return nil
}

// SANValue returns the DER of a subject alternative name extension that holds the URI id
// and nothing else.
func SANValue(id string) ([]byte, error) {
	if len(id) > 125 {
		return nil, errors.New("SPIFFE ID too long")
	}
	entry := append([]byte{uriTag, byte(len(id))}, id...)
	return append([]byte{0x30, byte(len(entry))}, entry...), nil
}

// checkSAN compares the raw bytes of the subject alternative name extension with the one
// entry it must hold, and requires an empty subject.
func checkSAN(c *x509.Certificate, want Expected) error {
	if !bytes.Equal(c.RawSubject, emptyName) {
		return errors.New("the subject is not empty")
	}
	value, err := SANValue(want.SPIFFEID())
	if err != nil {
		return err
	}
	found := 0
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		found++
		if !ext.Critical {
			return errors.New("the subject alternative name is not critical")
		}
		if !bytes.Equal(ext.Value, value) {
			return fmt.Errorf("the subject alternative name is not exactly %s", want.SPIFFEID())
		}
	}
	if found != 1 {
		return fmt.Errorf("%d subject alternative name extensions", found)
	}
	return nil
}

func checkTimes(c *x509.Certificate, want Expected) error {
	switch {
	case !c.NotAfter.After(c.NotBefore):
		return errors.New("notAfter is not after notBefore")
	case !c.NotAfter.Equal(want.NotAfter):
		return fmt.Errorf("notAfter %s is not not_after %s", c.NotAfter, want.NotAfter)
	case !c.NotAfter.After(want.RequestedAt):
		return errors.New("notAfter is not in the future")
	case c.NotAfter.Sub(c.NotBefore) > MaxLifetime:
		return errors.New("notAfter is more than 24 hours after notBefore")
	case c.NotBefore.Before(want.RequestedAt.Add(-MaxBackdate)):
		return errors.New("notBefore is more than 5 minutes before issuance")
	case c.NotBefore.After(want.ReceivedAt):
		return errors.New("notBefore is later than issuance")
	case !want.EarlierNotBefore.IsZero() && !c.NotBefore.After(want.EarlierNotBefore):
		return errors.New("notBefore is not later than that of an earlier tunnel certificate")
	}
	return nil
}

// checkUsage: cA=false (no basic constraints extension also means cA=false), key usage
// digitalSignature alone and critical, extended key usage serverAuth and clientAuth and no
// other.
func checkUsage(c *x509.Certificate, _ Expected) error {
	if c.IsCA {
		return errors.New("cA=true")
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("key usage %b is not digitalSignature alone", c.KeyUsage)
	}
	if critical, found := extension(c, oidKU); !found || !critical {
		return errors.New("key usage is missing or not critical")
	}
	if _, found := extension(c, oidEKU); !found {
		return errors.New("no extended key usage")
	}
	// The order does not matter, nor does a usage listed twice.
	if len(c.UnknownExtKeyUsage) > 0 || !slices.Equal(distinct(c.ExtKeyUsage), wantEKU) {
		return errors.New("extended key usage is not serverAuth and clientAuth alone")
	}
	return nil
}

func distinct(in []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// extension reports whether c has the extension oid and whether it is critical.
func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) (critical, found bool) {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Critical, true
		}
	}
	return false, false
}

// checkIssuer: the second certificate is the CA that issued the first; it carries a name
// constraint whose permitted subtree of type URI is the host trust domain.
func checkIssuer(leaf, ca *x509.Certificate, trustDomain string) error {
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the second certificate did not issue the first: %w", err)
	}
	if !slices.Equal(ca.PermittedURIDomains, []string{trustDomain}) {
		return fmt.Errorf("the CA's permitted URI subtrees are %q, not the trust domain", ca.PermittedURIDomains)
	}
	return nil
}

// homeIDAlphabet is lower-case base32, the alphabet of a home ID.
const homeIDAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// homeIDLength is the length of a home ID.
const homeIDLength = 26

// Presented checks a tunnel certificate that a gateway presents to the relay (section 4.1):
// it chains to the tunnel CA in roots, is valid at now, carries the extended key usage
// clientAuth, and its subject alternative name extension holds exactly one URI,
// spiffe://<trust domain>/home/<home ID>/gateway, compared as raw bytes. It returns the
// home ID.
func Presented(chain [][]byte, roots *x509.CertPool, trustDomain string, now time.Time) (string, error) {
	if len(chain) == 0 {
		return "", fmt.Errorf("%w: no certificate", ErrInvalid)
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", fmt.Errorf("%w: certificate %d: %w", ErrInvalid, i, err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := certs[0].Verify(opts); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	// Verify lets a certificate without extended key usage, or with anyExtendedKeyUsage,
	// pass for clientAuth; section 4.1 requires clientAuth itself.
	if !slices.Contains(certs[0].ExtKeyUsage, x509.ExtKeyUsageClientAuth) || slices.Contains(certs[0].ExtKeyUsage, x509.ExtKeyUsageAny) {
		return "", fmt.Errorf("%w: extended key usage without clientAuth", ErrInvalid)
	}
	if !tunnelKey(certs[0].PublicKey) {
		return "", fmt.Errorf("%w: key %s is neither P-256 nor Ed25519", ErrInvalid, certs[0].PublicKeyAlgorithm)
	}
	return homeIDOf(certs[0], trustDomain)
}

// tunnelKey reports whether key is ECDSA P-256 or Ed25519 (section 4.2).
func tunnelKey(key crypto.PublicKey) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return true
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256()
	}
	return false
}

// homeIDOf reads the home ID from the raw subject alternative name extension.
func homeIDOf(c *x509.Certificate, trustDomain string) (string, error) {
	var value []byte
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidSAN) {
			value = ext.Value
		}
	}
	prefix, suffix := "spiffe://"+trustDomain+"/home/", "/gateway"
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(value, &names)
	if err != nil || len(rest) != 0 || len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != 6 {
		return "", fmt.Errorf("%w: the subject alternative name is not one URI", ErrInvalid)
	}
	id := string(names[0].Bytes)
	if len(id) != len(prefix)+homeIDLength+len(suffix) || id[:len(prefix)] != prefix || id[len(id)-len(suffix):] != suffix {
		return "", fmt.Errorf("%w: URI %q is not a SPIFFE ID of a gateway of this trust domain", ErrInvalid, id)
	}
	home := id[len(prefix) : len(prefix)+homeIDLength]
	for _, ch := range home {
		if !strings.ContainsRune(homeIDAlphabet, ch) {
			return "", fmt.Errorf("%w: home ID %q", ErrInvalid, home)
		}
	}
	want, err := SANValue(id)
	if err != nil || !bytes.Equal(value, want) {
		return "", fmt.Errorf("%w: the subject alternative name is not in DER", ErrInvalid)
	}
	return home, nil
}
