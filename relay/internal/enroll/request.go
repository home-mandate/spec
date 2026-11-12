// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"crypto/rand"
	"encoding/json"
	"strings"
)

// Defect is a deliberate defect of the spelling of a request (RELAY-v0 section 5.1, step 1).
// An operator answers every one of them with malformed.
type Defect int

// Defects.
const (
	// NoDefect builds a regular request.
	NoDefect Defect = iota
	// ExtraHeaderMember adds a member to the protected header.
	ExtraHeaderMember
	// PrivateJWK adds the private part d to the jwk (an installation key is public only).
	PrivateJWK
	// DuplicateMember repeats url in the protected header.
	DuplicateMember
	// HighS gives an ES256 signature the higher S.
	HighS
	// PaddedSignature spells the signature with padding.
	PaddedSignature
	// ShortNonce uses a nonce of 8 bytes.
	ShortNonce
	// MemberCase spells a member of the header with a capital.
	MemberCase
	// ArrayPayload sends a JSON array as payload.
	ArrayPayload
	// DuplicatePayloadMember repeats a member of the payload.
	DuplicatePayloadMember
	// UnknownAlg names the algorithm none.
	UnknownAlg
	// KidAndJWK carries both a kid and a jwk.
	KidAndJWK
	// MissingURL leaves the url out of the header.
	MissingURL
	// PaddedPayload spells the payload with padding.
	PaddedPayload
)

// Spec describes a request. The zero value of an optional field builds the regular request.
type Spec struct {
	// Signer signs the request.
	Signer *Signer
	// SignWith, if set, signs instead of Signer: the header names Signer's key and
	// algorithm, the signature is of another key (a bad signature with a good spelling).
	SignWith *Signer
	// Kid is the installation URL; empty for a request with a jwk.
	Kid string
	// JWK says that the header carries the public key of Signer (a pairing request).
	JWK bool
	// Nonce and URL go into the header.
	Nonce, URL string
	// Alg overrides the algorithm of the header.
	Alg string
	// Payload is the JSON text of the payload; empty for a read.
	Payload string
	// Defect is a deliberate defect.
	Defect Defect
}

type member struct{ name, value string }

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// header returns the members of the protected header, in the order alg, nonce, url, jwk or kid.
func (s Spec) header() []member {
	alg := s.Alg
	if alg == "" {
		alg = s.Signer.Alg()
	}
	nonce := s.Nonce
	if s.Defect == ShortNonce {
		nonce = B64(make([]byte, 8))
	}
	members := []member{{"alg", quote(alg)}, {"nonce", quote(nonce)}, {"url", quote(s.URL)}}
	if s.JWK {
		jwk := s.Signer.JWK()
		if s.Defect == PrivateJWK {
			jwk = strings.TrimSuffix(jwk, "}") + `,"d":"` + B64(make([]byte, 32)) + `"}`
		}
		members = append(members, member{"jwk", jwk})
	}
	if s.Kid != "" {
		members = append(members, member{"kid", quote(s.Kid)})
	}
	return s.mutate(members)
}

func (s Spec) mutate(members []member) []member {
	switch s.Defect {
	case ExtraHeaderMember:
		members = append(members, member{"extra", "1"})
	case DuplicateMember:
		members = append(members, member{"url", quote(s.URL)})
	case MemberCase:
		members[0].name = "Alg"
	case UnknownAlg:
		members[0].value = quote("none")
	case KidAndJWK:
		members = append(members, member{"jwk", s.Signer.JWK()})
	case MissingURL:
		members = append(members[:2], members[3:]...)
	}
	return members
}

func render(members []member) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(m.name) + ":" + m.value)
	}
	b.WriteByte('}')
	return b.String()
}

func (s Spec) payload() string {
	switch s.Defect {
	case ArrayPayload:
		return "[]"
	case DuplicatePayloadMember:
		return `{"own_domain":null,"own_domain":null}`
	}
	return s.Payload
}

// Compact builds the request as a JWS in compact serialization.
func (s Spec) Compact() string {
	head := B64([]byte(render(s.header())))
	payload := B64([]byte(s.payload()))
	if s.Defect == PaddedPayload {
		payload += "="
	}
	signer := s.Signer
	if s.SignWith != nil {
		signer = s.SignWith
	}
	sig := signer.Sign([]byte(head + "." + payload))
	if s.Defect == HighS && signer.Alg() == AlgES256 {
		sig = highS(sig)
	}
	encoded := B64(sig)
	if s.Defect == PaddedSignature {
		encoded += "="
	}
	return head + "." + payload + "." + encoded
}

// RandomToken returns n random bytes, base64url: a nonce the operator never issued, or a
// name that no installation has.
func RandomToken(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return B64(raw)
}
