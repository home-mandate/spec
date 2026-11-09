// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

type certOpts struct {
	isCA        bool
	keyUsage    x509.KeyUsage
	ekus        []x509.ExtKeyUsage
	serialBits  int
	hours       int
	subject     string
	san         string
	sanNotCrit  bool
	otherKey    bool
	notAfterOff time.Duration
	back        time.Duration
}

func goodOpts() certOpts {
	return certOpts{keyUsage: x509.KeyUsageDigitalSignature, ekus: wantEKUSet, serialBits: 120, hours: 24,
		san: "spiffe://op.example.net/home/abcdefghijklmnopqrstuvwxyz/gateway", back: 4 * time.Minute}
}

// build makes a certificate of the options for a tunnel key and the issuedCert that describes it.
func build(t *testing.T, o certOpts) issuedCert {
	t.Helper()
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tunnelPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if !o.otherKey {
		tunnelPub = pub
	}
	notBefore := time.Now().Add(-o.back).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), uint(o.serialBits)), NotBefore: notBefore,
		NotAfter: notBefore.Add(time.Duration(o.hours) * time.Hour), IsCA: o.isCA, BasicConstraintsValid: true,
		KeyUsage: o.keyUsage, ExtKeyUsage: o.ekus,
	}
	if o.subject != "" {
		template.Subject = pkix.Name{CommonName: o.subject}
	}
	if o.san != "" {
		value, _ := tunnelcert.SANValue(o.san)
		template.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Critical: !o.sanNotCrit, Value: value}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCert{chain: [][]byte{der, caDER}, notAfter: template.NotAfter.Add(o.notAfterOff), key: tunnelPub, homeID: "abcdefghijklmnopqrstuvwxyz",
		requested: time.Now().Add(-time.Second), received: time.Now()}
}

func TestCertProblems(t *testing.T) {
	edit := func(f func(*certOpts)) certOpts { o := goodOpts(); f(&o); return o }
	for name, tt := range map[string]struct {
		opts certOpts
		want []string
	}{
		"good":             {goodOpts(), nil},
		"other key":        {edit(func(o *certOpts) { o.otherKey = true }), []string{CheckEnrollCertRules}},
		"cA":               {edit(func(o *certOpts) { o.isCA = true }), []string{CheckEnrollCertRules}},
		"key usage":        {edit(func(o *certOpts) { o.keyUsage |= x509.KeyUsageKeyEncipherment }), []string{CheckEnrollCertRules}},
		"no key usage":     {edit(func(o *certOpts) { o.keyUsage = 0 }), []string{CheckEnrollCertRules}},
		"missing EKU":      {edit(func(o *certOpts) { o.ekus = wantEKUSet[:1] }), []string{CheckEnrollCertRules}},
		"extra EKU":        {edit(func(o *certOpts) { o.ekus = append([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, wantEKUSet...) }), []string{CheckEnrollCertRules}},
		"short serial":     {edit(func(o *certOpts) { o.serialBits = 20 }), []string{CheckEnrollCertRules}},
		"not_after":        {edit(func(o *certOpts) { o.notAfterOff = time.Hour }), []string{CheckEnrollCertRules}},
		"subject":          {edit(func(o *certOpts) { o.subject = "x" }), []string{CheckEnrollCertSAN}},
		"no SAN":           {edit(func(o *certOpts) { o.san = "" }), []string{CheckEnrollCertSAN}},
		"SAN not exact":    {edit(func(o *certOpts) { o.san = "spiffe://op.example.net/home/other/gateway" }), []string{CheckEnrollCertSAN}},
		"SAN not critical": {edit(func(o *certOpts) { o.sanNotCrit = true }), []string{CheckEnrollCertSAN}},
		"long":             {edit(func(o *certOpts) { o.hours = 25 }), []string{CheckEnrollCertLifetime}},
		"backdated":        {edit(func(o *certOpts) { o.back = 10 * time.Minute }), []string{CheckEnrollCertLifetime}},
		"future":           {edit(func(o *certOpts) { o.back = -time.Hour }), []string{CheckEnrollCertLifetime}},
	} {
		got := certProblems(build(t, tt.opts), "op.example.net")
		if len(got) != len(tt.want) {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
			continue
		}
		for _, id := range tt.want {
			if got[id] == "" {
				t.Errorf("%s: no problem for %s in %v", name, id, got)
			}
		}
	}
}

func TestCertProblemsMonotonicAndBrokenChains(t *testing.T) {
	c := build(t, goodOpts())
	leaf := mustParse(t, c)
	c.earlier = leaf.NotBefore
	if got := certProblems(c, "op.example.net"); got[CheckEnrollCertMonotonic] == "" {
		t.Errorf("equal notBefore: %v", got)
	}
	c.earlier = leaf.NotBefore.Add(-time.Second)
	if got := certProblems(c, "op.example.net"); len(got) != 0 {
		t.Errorf("rising notBefore: %v", got)
	}
	if got := certProblems(issuedCert{}, "op.example.net"); got[CheckEnrollCertRules] == "" {
		t.Error("empty chain")
	}
	if got := certProblems(issuedCert{chain: make([][]byte, 5)}, "op.example.net"); got[CheckEnrollCertRules] == "" {
		t.Error("long chain")
	}
	if got := certProblems(issuedCert{chain: [][]byte{[]byte("junk")}}, "op.example.net"); got[CheckEnrollCertRules] == "" {
		t.Error("junk")
	}
	if p := sanProblem(leaf, "spiffe://"+string(make([]byte, 200))); p == "" {
		t.Error("an ID that is too long")
	}
	if publicKeyEqual(nil, nil) || !criticalExtension(leaf, oidSAN) || criticalExtension(leaf, oidSAN[:2]) {
		t.Error("helpers")
	}
}

func mustParse(t *testing.T, c issuedCert) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.chain[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
