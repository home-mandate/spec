// SPDX-License-Identifier: Apache-2.0

// Package dpop checks the claims of a DPoP proof (RFC 9449) against the request it came with,
// as SPEC-v0 section 11.7 item 6 states them. It checks the cases of conformance/origin-v0.json
// that have a proof; the signature of the proof is outside its scope. It is not part of the
// public API.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/home-mandate/spec/internal/origin"
)

// The window of iat around the time a request was received, in seconds (SPEC-v0 section 11.7
// item 6).
const (
	MaxAge    = 60
	MaxAhead  = 10
	proofType = "dpop+jwt"
)

// ErrInvalid means the proof is not valid for the request.
var ErrInvalid = errors.New("dpop: invalid proof")

// Proof holds the members of a proof that the check needs.
type Proof struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	JKT string  `json:"jkt"` // RFC 7638 thumbprint of the proof's key
	HTM string  `json:"htm"`
	HTU string  `json:"htu"`
	IAT int64   `json:"iat"`
	JTI string  `json:"jti"`
	ATH *string `json:"ath"`
}

// Request is the request a proof came with.
type Request struct {
	Method      string  `json:"method"`
	URL         string  `json:"url"` // built from the public origin
	Received    int64   `json:"received"`
	AccessToken *string `json:"access_token"`
	BoundJKT    *string `json:"bound_jkt"` // the key the access token is bound to
	DPoPJKT     *string `json:"dpop_jkt"`  // of the authorization request, at the token endpoint
}

// Memory is what the implementation remembers of earlier proofs.
type Memory struct {
	// Seen reports whether a jti was accepted before within the window.
	Seen func(jti string) bool
	// Started is the start of a process whose memory of jti values does not survive a
	// restart; nil if it does.
	Started *int64
}

// algorithms are the algorithms the reference offers for proofs.
var algorithms = map[string]bool{"ES256": true}

type rule struct {
	name  string
	check func(Proof, Request, Memory) error
}

var checks = []rule{
	{"typ", func(p Proof, _ Request, _ Memory) error {
		return want(p.Typ == proofType, "typ %q is not %s", p.Typ, proofType)
	}},
	{"alg", func(p Proof, _ Request, _ Memory) error {
		return want(algorithms[p.Alg], "alg %q is not offered", p.Alg)
	}},
	{"htm", func(p Proof, r Request, _ Memory) error {
		return want(p.HTM == r.Method, "htm %q is not the method %q", p.HTM, r.Method)
	}},
	{"htu", func(p Proof, r Request, _ Memory) error {
		return want(origin.HTUMatches(p.HTU, r.URL), "htu does not match the request")
	}},
	{"iat", func(p Proof, r Request, _ Memory) error {
		return want(p.IAT >= r.Received-MaxAge && p.IAT <= r.Received+MaxAhead, "iat outside the window")
	}},
	{"jti", func(p Proof, _ Request, m Memory) error {
		return want(p.JTI != "" && (m.Seen == nil || !m.Seen(p.JTI)), "jti was accepted before")
	}},
	{"restart", func(p Proof, _ Request, m Memory) error {
		return want(m.Started == nil || p.IAT > *m.Started+MaxAhead, "iat not later than the start of the process plus the time a proof may lie ahead")
	}},
	{"ath", func(p Proof, r Request, _ Memory) error {
		if r.AccessToken == nil {
			return nil
		}
		sum := sha256.Sum256([]byte(*r.AccessToken))
		return want(p.ATH != nil && *p.ATH == base64.RawURLEncoding.EncodeToString(sum[:]), "ath is not the hash of the access token")
	}},
	{"bound key", func(p Proof, r Request, _ Memory) error {
		if r.AccessToken == nil {
			return nil
		}
		return want(r.BoundJKT != nil && *r.BoundJKT == p.JKT, "the token is bound to another key")
	}},
	{"dpop_jkt", func(p Proof, r Request, _ Memory) error {
		return want(r.DPoPJKT == nil || *r.DPoPJKT == p.JKT, "the key is not the dpop_jkt of the authorization request")
	}},
}

func want(ok bool, format string, args ...any) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Check reports whether the proof is valid for the request; the error says the first rule
// it breaks.
func Check(p Proof, r Request, m Memory) error {
	return checkWithout("", p, r, m)
}

func checkWithout(skip string, p Proof, r Request, m Memory) error {
	for _, c := range checks {
		if c.name == skip {
			continue
		}
		if err := c.check(p, r, m); err != nil {
			return err
		}
	}
	return nil
}

func rules() []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.name
	}
	return out
}
