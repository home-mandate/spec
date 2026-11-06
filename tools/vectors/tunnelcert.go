// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"
)

// relayCSRDescription is the description of relay/conformance/csr-v0.json.
const relayCSRDescription = "Certificate signing requests for tunnel certificates of the Relay Specification v0 (draft), RELAY-v0.md section 5.4. " +
	"Each case: csr as in the payload of a certificate request (PKCS #10 in DER, base64url without padding), the installation key, " +
	"the keys of the tunnel certificates the operator issued to the installation before, and whether the operator accepts the request " +
	"or refuses it with bad-csr. Every csr is valid against $defs/der of relay/schema/enrollment-v0.schema.json; one that is not " +
	"is malformed (section 5.1 step 6), not bad-csr. The keys are test keys; their private parts are in " +
	"relay/conformance/keys/test-keys.private.json. Generated with go run ./tools/vectors relay-csr."

// relayCertificateDescription is the description of relay/conformance/certificate-v0.json.
const relayCertificateDescription = "Tunnel certificates of the Relay Specification v0 (draft), RELAY-v0.md section 5.4, " +
	"as the chain of a certificate response. Each case: chain (DER, base64url without padding, the issued certificate first), " +
	"not_after of the response, the tunnel key of the request, trust_domain and home_id of the installation, requested_at " +
	"(when the request was sent), received_at (when the response arrived), earlier_not_before (the latest notBefore of the tunnel certificates issued to the installation before, " +
	"or null), and whether the certificate is valid. Valid: one to four certificates; the issued one has the tunnel key; " +
	"its subject alternative name extension is critical and is byte for byte one URI, spiffe://<trust_domain>/home/<home_id>/gateway; " +
	"its subject is empty; notAfter equals not_after, is after requested_at and at most 24 hours after notBefore; notBefore is no earlier " +
	"than 5 minutes before requested_at, no later than received_at and later than earlier_not_before (issuance lies between the two times, " +
	"so a notBefore outside these bounds breaks the rule of 5 minutes before issuance or of no later than issuance); cA=false (also without a basic constraints extension); " +
	"key usage digitalSignature alone and critical; extended key usage serverAuth and clientAuth and no other. Where the chain holds " +
	"a second certificate, it issued the first and carries a name constraint whose permitted URI subtree is trust_domain alone. " +
	"Whether the serial number has 64 random bits cannot be seen in one certificate. The keys are test keys; their private parts are " +
	"in relay/conformance/keys/test-keys.private.json. Generated with go run ./tools/vectors relay-certificate."

// relayCSRKids and relayCertKids are the test keys of the cases.
var (
	relayCSRKids  = []string{"relay-installation", "relay-other", "relay-p256", "relay-tunnel", "relay-tunnel-old", "relay-tunnel-p256", "relay-p384", "relay-rsa"}
	relayCertKids = []string{"relay-other", "relay-tunnel", "relay-tunnel-old", "relay-tunnel-p256", "relay-tunnel-ca"}
)

const (
	relayTrustDomain = "relay-operator.example"
	relayHomeID      = "k7q2xwmpd4hj3n6rt5vbyc2ezu"
	relayOtherHomeID = "m3n4p5q6r7s2t3u4v5w6x7y2za"
)

// maxTunnelLifetime and maxTunnelBackdate are the limits of section 5.4.
const (
	maxTunnelLifetime = 24 * time.Hour
	maxTunnelBackdate = 5 * time.Minute
)

// relayAt is requested_at of the certificate cases; relayEarlier is their usual earlier
// notBefore.
var (
	relayAt      = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	relayEarlier = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	// relayReceived is received_at, when the response arrived.
	relayReceived = relayAt.Add(2 * time.Second)
)

// relayCSRCase is a case of relay/conformance/csr-v0.json.
type relayCSRCase struct {
	ID              string            `json:"id"`
	CSR             string            `json:"csr"`
	InstallationKey json.RawMessage   `json:"installation_key"`
	EarlierKeys     []json.RawMessage `json:"earlier_keys"`
	Expected        string            `json:"expected"`
	Why             string            `json:"why"`
}

// relayCertificateCase is a case of relay/conformance/certificate-v0.json.
type relayCertificateCase struct {
	ID               string          `json:"id"`
	Chain            []string        `json:"chain"`
	NotAfter         string          `json:"not_after"`
	TunnelKey        json.RawMessage `json:"tunnel_key"`
	TrustDomain      string          `json:"trust_domain"`
	HomeID           string          `json:"home_id"`
	RequestedAt      string          `json:"requested_at"`
	ReceivedAt       string          `json:"received_at"`
	EarlierNotBefore *string         `json:"earlier_not_before"`
	Expected         string          `json:"expected"`
	Why              string          `json:"why"`
}

func loadSigners(dir, path string, kids []string) (relaySigners, error) {
	signers := relaySigners{}
	for _, kid := range kids {
		key, err := privateKey(resolve(dir, path), kid)
		if err != nil {
			return nil, err
		}
		signers[kid] = key
	}
	return signers, nil
}

func requireSigners(signers relaySigners, kids []string) error {
	for _, kid := range kids {
		if signers[kid] == nil {
			return fmt.Errorf("no key %q", kid)
		}
	}
	return nil
}

func runRelayCSR(args []string, dir string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: vectors relay-csr <private JWK Set>")
	}
	signers, err := loadSigners(dir, args[0], relayCSRKids)
	if err != nil {
		return err
	}
	cases, err := relayCSRCases(signers)
	if err != nil {
		return err
	}
	return writeCases(stdout, relayCSRDescription, cases)
}

func runRelayCertificate(args []string, dir string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: vectors relay-certificate <private JWK Set>")
	}
	signers, err := loadSigners(dir, args[0], relayCertKids)
	if err != nil {
		return err
	}
	cases, err := relayCertificateCases(signers)
	if err != nil {
		return err
	}
	return writeCases(stdout, relayCertificateDescription, cases)
}

// makeCSR signs a request; without a random source, ECDSA signatures are deterministic
// (RFC 6979), so that regenerating the cases does not change them.
func makeCSR(template *x509.CertificateRequest, key any) ([]byte, error) {
	return x509.CreateCertificateRequest(nil, template, key)
}

var (
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// resign replaces the signature algorithm and signature of a request.
func resign(der []byte, alg asn1.ObjectIdentifier, signer any) ([]byte, error) {
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	tbs := req.RawTBSCertificateRequest
	var sig []byte
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(key, tbs)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(tbs)
		if sig, err = key.Sign(nil, digest[:], crypto.SHA256); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key %T", signer)
	}
	return asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: alg}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

// longFormLength writes the outer length of a DER element with one more length byte than
// needed: valid BER, not DER.
func longFormLength(der []byte) ([]byte, error) {
	switch {
	case len(der) < 3:
		return nil, errors.New("too short")
	case der[1] < 0x80:
		return append([]byte{der[0], 0x81, der[1]}, der[2:]...), nil
	case der[1] == 0x81:
		return append([]byte{der[0], 0x82, 0x00}, der[2:]...), nil
	}
	return nil, errors.New("outer length of more than one byte")
}

type relayCSRSpec struct {
	id, installation, expected, why string
	earlier                         []string
	build                           func() ([]byte, error)
}

func relayCSRCases(signers relaySigners) ([]relayCSRCase, error) {
	if err := requireSigners(signers, relayCSRKids); err != nil {
		return nil, err
	}
	specs, err := relayCSRSpecs(signers)
	if err != nil {
		return nil, err
	}
	jwk := func(kid string) (json.RawMessage, error) {
		text, err := publicJWKText(signers[kid])
		return json.RawMessage(text), err
	}
	cases := make([]relayCSRCase, 0, len(specs))
	for _, s := range specs {
		der, err := s.build()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.id, err)
		}
		inst, err := jwk(s.installation)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.id, err)
		}
		earlier := []json.RawMessage{}
		for _, kid := range s.earlier {
			key, err := jwk(kid)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", s.id, err)
			}
			earlier = append(earlier, key)
		}
		cases = append(cases, relayCSRCase{ID: s.id, CSR: relayB64.EncodeToString(der), InstallationKey: inst, EarlierKeys: earlier, Expected: s.expected, Why: s.why})
	}
	return cases, nil
}

func relayCSRSpecs(signers relaySigners) ([]relayCSRSpec, error) {
	csr := func(template *x509.CertificateRequest, kid string) func() ([]byte, error) {
		return func() ([]byte, error) { return makeCSR(template, signers[kid]) }
	}
	plain := func(kid string) func() ([]byte, error) { return csr(&x509.CertificateRequest{}, kid) }
	edit := func(base func() ([]byte, error), change func([]byte) ([]byte, error)) func() ([]byte, error) {
		return func() ([]byte, error) {
			der, err := base()
			if err != nil {
				return nil, err
			}
			return change(der)
		}
	}
	requested, err := url.Parse(spiffeID(relayTrustDomain, relayHomeID))
	if err != nil {
		return nil, err
	}
	withNames := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "gateway", Organization: []string{"Household"}},
		DNSNames: []string{relayHomeID + ".homes.example.net"},
		URIs:     []*url.URL{requested},
	}
	tunnelKey, ok := signers["relay-tunnel"].(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("relay-tunnel is not Ed25519")
	}
	cert, err := selfSigned(tunnelKey)
	if err != nil {
		return nil, err
	}
	old := []string{"relay-tunnel-old"}
	inst := "relay-installation"
	return []relayCSRSpec{
		{id: "c01", installation: inst, build: plain("relay-tunnel"), expected: "accepted", why: "Ed25519 key, signed with Ed25519, empty subject; the first tunnel certificate of the installation"},
		{id: "c02", installation: inst, earlier: old, build: plain("relay-tunnel-p256"), expected: "accepted", why: "P-256 key, signed with ECDSA with SHA-256"},
		{id: "c03", installation: inst, earlier: old, build: csr(withNames, "relay-tunnel"), expected: "accepted", why: "subject and requested names are ignored"},
		{id: "c04", installation: inst, earlier: old, build: edit(plain("relay-tunnel"), func(d []byte) ([]byte, error) {
			out := append([]byte{}, d...)
			out[len(out)-1] ^= 0x01
			return out, nil
		}), expected: "bad-csr", why: "signature does not verify: its last byte changed"},
		{id: "c05", installation: inst, earlier: old, build: edit(plain("relay-tunnel"), func(d []byte) ([]byte, error) {
			return resign(d, oidEd25519, signers["relay-other"])
		}), expected: "bad-csr", why: "signed by another key than the one it contains"},
		{id: "c06", installation: inst, earlier: old, build: plain("relay-p384"), expected: "bad-csr", why: "P-384 key, signed with ECDSA with SHA-384"},
		{id: "c07", installation: inst, earlier: old, build: csr(&x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}, "relay-p384"), expected: "bad-csr", why: "P-384 key, signed with ECDSA with SHA-256"},
		{id: "c08", installation: inst, earlier: old, build: csr(&x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA384}, "relay-tunnel-p256"), expected: "bad-csr", why: "P-256 key, signed with ECDSA with SHA-384"},
		{id: "c09", installation: inst, earlier: old, build: edit(plain("relay-tunnel"), func(d []byte) ([]byte, error) {
			return resign(d, oidECDSASHA256, signers["relay-tunnel"])
		}), expected: "bad-csr", why: "Ed25519 key and signature, but the signature algorithm says ECDSA with SHA-256"},
		{id: "c10", installation: inst, earlier: old, build: plain("relay-installation"), expected: "bad-csr", why: "the key is the installation key"},
		{id: "c11", installation: inst, earlier: []string{"relay-tunnel-old", "relay-tunnel"}, build: plain("relay-tunnel"), expected: "bad-csr", why: "the key is that of an earlier tunnel certificate"},
		{id: "c12", installation: "relay-p256", build: plain("relay-p256"), expected: "bad-csr", why: "the P-256 key is the installation key"},
		{id: "c13", installation: inst, earlier: old, build: edit(plain("relay-tunnel"), func(d []byte) ([]byte, error) {
			return append(append([]byte{}, d...), 0x00), nil
		}), expected: "bad-csr", why: "a byte after the request"},
		{id: "c14", installation: inst, earlier: old, build: edit(plain("relay-tunnel"), longFormLength), expected: "bad-csr", why: "outer length in long form where the short form suffices: BER, not DER"},
		{id: "c15", installation: inst, earlier: old, build: func() ([]byte, error) { return cert, nil }, expected: "bad-csr", why: "a certificate, not a request"},
		{id: "c16", installation: inst, earlier: old, build: func() ([]byte, error) { return make([]byte, 60), nil }, expected: "bad-csr", why: "60 zero bytes: not DER"},
		{id: "c17", installation: inst, earlier: old, build: plain("relay-rsa"), expected: "bad-csr", why: "RSA key of 2048 bits, signed with RSA with SHA-256"},
		{id: "c18", installation: inst, earlier: old, build: func() ([]byte, error) { return makeCSR(&x509.CertificateRequest{}, smallOrderSigner{}) }, expected: "bad-csr", why: "Ed25519 key of small order (the neutral point), with a signature that verifies without any private key (Section 5.1)"},
	}, nil
}

// smallOrderSigner has the neutral point as its Ed25519 key. R = neutral point and S = 0
// verify for every message under it, so the signature needs no private key.
type smallOrderSigner struct{}

func (smallOrderSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(append([]byte{0x01}, make([]byte, 31)...))
}

func (smallOrderSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return append([]byte{0x01}, make([]byte, 63)...), nil
}

// selfSigned is a certificate for c15.
func selfSigned(key ed25519.PrivateKey) ([]byte, error) {
	t := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: relayAt, NotAfter: relayAt.Add(time.Hour)}
	return x509.CreateCertificate(nil, t, t, key.Public(), key)
}

var (
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKU  = asn1.ObjectIdentifier{2, 5, 29, 15}
	// kuDigitalSignature is the DER of key usage digitalSignature.
	kuDigitalSignature = []byte{0x03, 0x02, 0x07, 0x80}
)

func sanExtension(id string, critical bool) (pkix.Extension, error) {
	// GeneralNames with one uniformResourceIdentifier [6] IA5String.
	value, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(id)}})
	return pkix.Extension{Id: oidSAN, Critical: critical, Value: value}, err
}

func spiffeID(trustDomain, homeID string) string {
	return "spiffe://" + trustDomain + "/home/" + homeID + "/gateway"
}

// leafSpec describes an issued certificate by its differences from a valid one.
type leafSpec struct {
	key       string
	notBefore time.Time
	lifetime  time.Duration
	edit      func(*x509.Certificate) error
}

// issue creates a tunnel certificate signed by the tunnel CA.
func issue(id string, s leafSpec, signers relaySigners, ca *x509.Certificate) ([]byte, time.Time, error) {
	nb := s.notBefore
	if nb.IsZero() {
		nb = relayAt.Add(-time.Minute)
	}
	lifetime := s.lifetime
	if lifetime == 0 {
		lifetime = maxTunnelLifetime
	}
	san, err := sanExtension(spiffeID(relayTrustDomain, relayHomeID), true)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial := sha256.Sum256([]byte("relay-certificate " + id))
	t := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial[:16]),
		NotBefore:             nb,
		NotAfter:              nb.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{san},
	}
	if s.edit != nil {
		if err := s.edit(t); err != nil {
			return nil, time.Time{}, err
		}
	}
	key := s.key
	if key == "" {
		key = "relay-tunnel"
	}
	signer, ok := signers[key].(crypto.Signer)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("key %q cannot sign", key)
	}
	public := signer.Public()
	der, err := x509.CreateCertificate(nil, t, ca, public, signers["relay-tunnel-ca"])
	return der, t.NotAfter, err
}

// tunnelCA is the self-signed certificate of a tunnel CA with key kid and the permitted URI
// subtrees.
func tunnelCA(signers relaySigners, kid string, permitted []string) (*x509.Certificate, []byte, error) {
	key, ok := signers[kid].(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key %q is not Ed25519", kid)
	}
	serial := sha256.Sum256([]byte(fmt.Sprintf("relay-certificate CA %s %q", kid, permitted)))
	t := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial[:16]),
		Subject:               pkix.Name{CommonName: "Tunnel CA (test)"},
		NotBefore:             relayAt.Add(-30 * 24 * time.Hour),
		NotAfter:              relayAt.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PermittedURIDomains:   permitted,
	}
	der, err := x509.CreateCertificate(nil, t, t, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, der, err
}

type relayCertSpec struct {
	id, expected, why string
	leaf              leafSpec
	// chain builds the chain from the issued certificate and the CA certificate; nil means
	// both.
	chain func(leaf, ca []byte) [][]byte
	// caKid and caPermitted change the CA certificate in the chain; the issued certificate
	// is always signed by relay-tunnel-ca.
	caKid       string
	caPermitted []string
	notAfter    time.Duration
	tunnelKey   string
	earlier     *time.Time
	noEarlier   bool
}

func relayCertificateCases(signers relaySigners) ([]relayCertificateCase, error) {
	if err := requireSigners(signers, relayCertKids); err != nil {
		return nil, err
	}
	specs, err := relayCertSpecs()
	if err != nil {
		return nil, err
	}
	signing, _, err := tunnelCA(signers, "relay-tunnel-ca", []string{relayTrustDomain})
	if err != nil {
		return nil, err
	}
	cases := make([]relayCertificateCase, 0, len(specs))
	for _, s := range specs {
		c, err := buildCertificateCase(s, signers, signing)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.id, err)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func relayCertSpecs() ([]relayCertSpec, error) {
	edit := func(f func(*x509.Certificate)) func(*x509.Certificate) error {
		return func(c *x509.Certificate) error { f(c); return nil }
	}
	withSAN := func(id string, critical bool, more ...pkix.Extension) func(*x509.Certificate) error {
		return func(c *x509.Certificate) error {
			ext, err := sanExtension(id, critical)
			c.ExtraExtensions = append([]pkix.Extension{ext}, more...)
			return err
		}
	}
	id := spiffeID(relayTrustDomain, relayHomeID)
	uriAndDNS, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(id)},
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(relayHomeID + ".homes.example.net")},
	})
	if err != nil {
		return nil, err
	}
	san, err := sanExtension(id, true)
	if err != nil {
		return nil, err
	}
	alone := func(leaf, _ []byte) [][]byte { return [][]byte{leaf} }
	nb := relayAt.Add(-time.Minute)
	justBefore := nb.Add(-time.Second)
	return []relayCertSpec{
		{id: "t01", expected: "valid", why: "Ed25519 tunnel key, with the issuing CA in the chain"},
		{id: "t02", leaf: leafSpec{key: "relay-tunnel-p256"}, tunnelKey: "relay-tunnel-p256", chain: alone, noEarlier: true, expected: "valid", why: "P-256 tunnel key, the issued certificate alone; the first tunnel certificate of the installation"},
		{id: "t03", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.BasicConstraintsValid = false })}, expected: "valid", why: "no basic constraints extension: cA=false"},
		{id: "t04", leaf: leafSpec{notBefore: relayAt.Add(-maxTunnelBackdate)}, expected: "valid", why: "notBefore exactly 5 minutes before the request"},
		{id: "t05", leaf: leafSpec{lifetime: maxTunnelLifetime + time.Second}, expected: "invalid", why: "notAfter 24 hours and 1 second after notBefore"},
		{id: "t06", leaf: leafSpec{notBefore: relayAt.Add(-maxTunnelBackdate - time.Second)}, expected: "invalid", why: "notBefore 5 minutes and 1 second before the request"},
		{id: "t07", earlier: &nb, expected: "invalid", why: "notBefore equal to that of an earlier tunnel certificate, not later"},
		{id: "t08", earlier: &justBefore, expected: "valid", why: "notBefore 1 second after that of an earlier tunnel certificate"},
		{id: "t09", notAfter: time.Second, expected: "invalid", why: "not_after of the response differs from notAfter"},
		{id: "t10", leaf: leafSpec{lifetime: time.Minute}, expected: "invalid", why: "notAfter is the time of the request: not in the future"},
		{id: "t11", leaf: leafSpec{edit: withSAN(id, false)}, expected: "invalid", why: "subject alternative name not critical"},
		{id: "t12", leaf: leafSpec{edit: edit(func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Critical: true, Value: uriAndDNS}}
		})}, expected: "invalid", why: "subject alternative name with the URI and a DNS name"},
		{id: "t13", leaf: leafSpec{edit: withSAN(spiffeID(relayTrustDomain, relayOtherHomeID), true)}, expected: "invalid", why: "SPIFFE ID of another home ID"},
		{id: "t14", leaf: leafSpec{edit: withSAN("SPIFFE://"+id[len("spiffe://"):], true)}, expected: "invalid", why: "scheme in upper case: equal as a parsed URI, not byte for byte"},
		{id: "t15", leaf: leafSpec{edit: withSAN(id+"?", true)}, expected: "invalid", why: "SPIFFE ID with an empty query: equal once a parser drops it, not byte for byte"},
		{id: "t16", leaf: leafSpec{edit: withSAN(spiffeID("other-operator.example", relayHomeID), true)}, expected: "invalid", why: "SPIFFE ID of another trust domain"},
		{id: "t17", leaf: leafSpec{edit: withSAN(id, true, san)}, expected: "invalid", why: "two subject alternative name extensions"},
		{id: "t18", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "gateway"} })}, expected: "invalid", why: "subject not empty"},
		{id: "t19", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.IsCA = true })}, expected: "invalid", why: "cA=true"},
		{id: "t20", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment })}, expected: "invalid", why: "key usage digitalSignature and keyEncipherment"},
		{id: "t21", leaf: leafSpec{edit: edit(func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oidKU, Critical: false, Value: kuDigitalSignature})
		})}, expected: "invalid", why: "key usage not critical"},
		{id: "t22", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.KeyUsage = 0 })}, expected: "invalid", why: "no key usage"},
		{id: "t23", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })}, expected: "invalid", why: "extended key usage clientAuth alone"},
		{id: "t24", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) })}, expected: "invalid", why: "extended key usage codeSigning besides serverAuth and clientAuth"},
		{id: "t25", leaf: leafSpec{edit: edit(func(c *x509.Certificate) { c.ExtKeyUsage = nil })}, expected: "invalid", why: "no extended key usage"},
		{id: "t26", leaf: leafSpec{key: "relay-tunnel-old"}, expected: "invalid", why: "the certificate is for another key than the tunnel key of the request"},
		{id: "t27", chain: func(leaf, ca []byte) [][]byte { return [][]byte{leaf, ca, ca, ca, ca} }, expected: "invalid", why: "five certificates"},
		{id: "t28", caKid: "relay-other", expected: "invalid", why: "the second certificate is a CA that did not issue the first"},
		{id: "t29", caPermitted: []string{}, expected: "invalid", why: "the CA has no name constraint"},
		{id: "t30", caPermitted: []string{"other-operator.example"}, expected: "invalid", why: "the CA's permitted URI subtree is another host"},
		{id: "t31", caPermitted: []string{relayTrustDomain, "other-operator.example"}, expected: "invalid", why: "the CA's permitted URI subtrees include another host"},
		{id: "t32", chain: func(leaf, _ []byte) [][]byte { return [][]byte{append(append([]byte{}, leaf...), 0x00)} }, expected: "invalid", why: "a byte after the issued certificate"},
		{id: "t33", leaf: leafSpec{notBefore: relayAt.Add(2 * time.Hour), lifetime: -time.Hour}, expected: "invalid", why: "notAfter before notBefore"},
		{id: "t34", leaf: leafSpec{notBefore: relayAt.Add(time.Hour)}, expected: "invalid", why: "notBefore one hour after the request: later than issuance"},
		{id: "t35", leaf: leafSpec{notBefore: relayReceived}, expected: "valid", why: "notBefore when the response arrived: no later than issuance"},
		{id: "t36", leaf: leafSpec{edit: edit(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		})}, expected: "valid", why: "extended key usage in another order and with clientAuth twice: still serverAuth and clientAuth and no other"},
	}, nil
}

func buildCertificateCase(s relayCertSpec, signers relaySigners, signing *x509.Certificate) (relayCertificateCase, error) {
	caKid := s.caKid
	if caKid == "" {
		caKid = "relay-tunnel-ca"
	}
	permitted := s.caPermitted
	if permitted == nil {
		permitted = []string{relayTrustDomain}
	}
	_, caDER, err := tunnelCA(signers, caKid, permitted)
	if err != nil {
		return relayCertificateCase{}, err
	}
	leaf, notAfter, err := issue(s.id, s.leaf, signers, signing)
	if err != nil {
		return relayCertificateCase{}, err
	}
	chain := [][]byte{leaf, caDER}
	if s.chain != nil {
		chain = s.chain(leaf, caDER)
	}
	tunnelKey := s.tunnelKey
	if tunnelKey == "" {
		tunnelKey = "relay-tunnel"
	}
	key, err := publicJWKText(signers[tunnelKey])
	if err != nil {
		return relayCertificateCase{}, err
	}
	var earlier *string
	if !s.noEarlier {
		at := relayEarlier
		if s.earlier != nil {
			at = *s.earlier
		}
		text := at.Format(time.RFC3339)
		earlier = &text
	}
	encoded := make([]string, len(chain))
	for i, der := range chain {
		encoded[i] = relayB64.EncodeToString(der)
	}
	return relayCertificateCase{
		ID: s.id, Chain: encoded, NotAfter: notAfter.Add(s.notAfter).Format(time.RFC3339), TunnelKey: json.RawMessage(key),
		TrustDomain: relayTrustDomain, HomeID: relayHomeID, RequestedAt: relayAt.Format(time.RFC3339),
		ReceivedAt: relayReceived.Format(time.RFC3339),
		EarlierNotBefore: earlier, Expected: s.expected, Why: s.why,
	}, nil
}
