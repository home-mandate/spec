// SPDX-License-Identifier: Apache-2.0

package tunnelcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestSANValueRefusesALongID(t *testing.T) {
	if _, err := SANValue(strings.Repeat("a", 126)); err == nil {
		t.Error("SANValue accepted 126 bytes")
	}
	if v, err := SANValue(strings.Repeat("a", 125)); err != nil || len(v) != 129 {
		t.Errorf("SANValue(125 bytes) = %d bytes, %v", len(v), err)
	}
}

func TestHomeIDOfRefusesWhatIsNotTheSPIFFEIDOfAGateway(t *testing.T) {
	const td = "relay-operator.example"
	der := func(raw string) []byte {
		v, err := SANValue(raw)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	valid := der("spiffe://" + td + "/home/k7q2xwmpd4hj3n6rt5vbyc2ezu/gateway")
	cases := map[string][]byte{
		"no extension":       nil,
		"not DER":            {0x30, 0x03, 0x86, 0x01},
		"DNS name":           {0x30, 0x03, 0x82, 0x01, 'a'},
		"other path":         der("spiffe://" + td + "/home/k7q2xwmpd4hj3n6rt5vbyc2ezu/agent"),
		"home ID upper case": der("spiffe://" + td + "/home/K7Q2XWMPD4HJ3N6RT5VBYC2EZU/gateway"),
		"home ID with 1":     der("spiffe://" + td + "/home/k7q2xwmpd4hj3n6rt5vbyc2ez1/gateway"),
		"home ID too short":  der("spiffe://" + td + "/home/k7q2xwmpd4hj3n6rt5vbyc2e/gateway"),
		"long-form length":   append([]byte{0x30, 0x81, valid[1]}, valid[2:]...),
	}
	for name, value := range cases {
		c := &x509.Certificate{}
		if value != nil {
			c.Extensions = []pkix.Extension{{Id: oidSAN, Value: value}}
		}
		if _, err := homeIDOf(c, td); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSAN, Value: valid}}}
	if home, err := homeIDOf(c, td); err != nil || home != "k7q2xwmpd4hj3n6rt5vbyc2ezu" {
		t.Errorf("homeIDOf = %q, %v", home, err)
	}
}
