// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/home-mandate/spec/jws"
)

// relayJWSDescription is the description of relay/conformance/jws-v0.json.
const relayJWSDescription = "Requests of the Relay Specification v0 (draft), RELAY-v0.md sections 5.1 and 5.5. " +
	"Each case: a compact JWS, of kind request (the body of a POST to the enrollment endpoint) or key-change " +
	"(the inner JWS of a key change); the public key that verifies it, or null when the header carries it as jwk; " +
	"the URL it was sent to; and the result: valid, malformed or bad-signature (the errors of section 5.1). " +
	"A case is malformed if its header, its spelling or its url is wrong, also if its signature would verify; " +
	"bad-signature only if everything else is right. The payloads are only checked for I-JSON and for being " +
	"an object (or, for a request, empty), not against their schema. The keys are test keys; their private " +
	"parts are in relay/conformance/keys/test-keys.private.json. Generated with go run ./tools/vectors relay-jws."

const (
	relayNonce    = "oFvnlFP1wIhRlYS2jTaXbA"
	relayPair     = "https://relay-operator.example/enroll/pair"
	relayKeyURL   = "https://relay-operator.example/enroll/key-change"
	relayInstall  = "https://relay-operator.example/enroll/installation/k7q2xwmpd4hj3n6rt5vbyc2ezu"
	relayCertURL  = relayInstall + "/certificate"
	relayPairBody = `{"code":"ABCDEFGHIJKLMNOP"}`
	relayCSRBody  = `{"csr":"MIIB"}`
)

// relayJWSCase is a case of relay/conformance/jws-v0.json.
type relayJWSCase struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	JWS      string          `json:"jws"`
	Key      json.RawMessage `json:"key"`
	URL      string          `json:"url"`
	Expected string          `json:"expected"`
	Why      string          `json:"why"`
	// ES256 signatures are not deterministic: such a case changes on every run.
	random bool
}

// relaySigners are the test keys by kid.
type relaySigners map[string]any

// relayKids are the test keys of the cases.
var relayKids = []string{"relay-installation", "relay-other", "relay-new", "relay-p256"}

func runRelayJWS(args []string, dir string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: vectors relay-jws <private JWK Set>")
	}
	signers := relaySigners{}
	for _, kid := range relayKids {
		key, err := privateKey(resolve(dir, args[0]), kid)
		if err != nil {
			return err
		}
		signers[kid] = key
	}
	cases, err := relayJWSCases(signers)
	if err != nil {
		return err
	}
	return writeCases(stdout, relayJWSDescription, cases)
}

// writeCases writes a conformance file with one case per line.
func writeCases(w io.Writer, description string, cases []relayJWSCase) error {
	var buf bytes.Buffer
	desc, err := marshalNoEscape(description)
	if err != nil {
		return err
	}
	buf.WriteString("{\n  \"description\": " + desc + ",\n  \"cases\": [\n")
	for i, c := range cases {
		line, err := marshalNoEscape(c)
		if err != nil {
			return err
		}
		buf.WriteString("    " + line)
		if i < len(cases)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("  ]\n}\n")
	_, err = w.Write(buf.Bytes())
	return err
}

func marshalNoEscape(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

var relayB64 = base64.RawURLEncoding

// rawRelayJWS signs a header given as JSON text over payload.
func rawRelayJWS(head, payload string, signer any) (string, error) {
	encoded := relayB64.EncodeToString([]byte(head)) + "." + relayB64.EncodeToString([]byte(payload))
	input := []byte(encoded)
	var sig []byte
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(key, input)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return "", err
		}
		n := elliptic.P256().Params().N
		if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			s.Sub(n, s)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	default:
		return "", fmt.Errorf("unsupported key %T", signer)
	}
	return encoded + "." + relayB64.EncodeToString(sig), nil
}

func publicJWKText(signer any) (string, error) {
	var public any
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		public = key.Public()
	case *ecdsa.PrivateKey:
		public = key.Public()
	}
	data, err := jws.MarshalJWK(public)
	if err != nil {
		return "", fmt.Errorf("test key: %w", err)
	}
	return string(data), nil
}

// segments replaces the segments of a compact JWS.
func segments(compact string, edit func(parts []string) []string) string {
	return strings.Join(edit(strings.Split(compact, ".")), ".")
}

// highS replaces s of an ES256 signature by n - s.
func highS(compact string) string {
	return segments(compact, func(p []string) []string {
		sig, _ := relayB64.DecodeString(p[2])
		n := elliptic.P256().Params().N
		s := new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:]))
		p[2] = relayB64.EncodeToString(append(sig[:32:32], s.FillBytes(make([]byte, 32))...))
		return p
	})
}

// ed25519Order is L (RFC 8032).
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// largeS replaces S of an EdDSA signature by S + L, which lenient libraries reduce.
func largeS(compact string) string {
	return segments(compact, func(p []string) []string {
		sig, _ := relayB64.DecodeString(p[2])
		le := sig[32:]
		be := make([]byte, 32)
		for i, b := range le {
			be[31-i] = b
		}
		sum := new(big.Int).Add(new(big.Int).SetBytes(be), ed25519Order).FillBytes(make([]byte, 32))
		out := append([]byte{}, sig[:32]...)
		for i := range sum {
			out = append(out, sum[31-i])
		}
		p[2] = relayB64.EncodeToString(out)
		return p
	})
}

// relayCaseSpec describes a case before it is signed.
type relayCaseSpec struct {
	id, kind, head, payload, signer, key, url, expected, why string
	edit                                                     func(string) string
}

func relayJWSCases(signers relaySigners) ([]relayJWSCase, error) {
	jwk := map[string]string{}
	for _, kid := range relayKids {
		text, err := publicJWKText(signers[kid])
		if err != nil {
			return nil, err
		}
		jwk[kid] = text
	}
	inst, other, newKey, p256 := jwk["relay-installation"], jwk["relay-other"], jwk["relay-new"], jwk["relay-p256"]
	pair := func(alg, key string) string {
		return `{"alg":"` + alg + `","nonce":"` + relayNonce + `","url":"` + relayPair + `","jwk":` + key + `}`
	}
	kid := func(alg, url string) string {
		return `{"alg":"` + alg + `","nonce":"` + relayNonce + `","url":"` + url + `","kid":"` + relayInstall + `"}`
	}
	cert := kid("EdDSA", relayCertURL)
	withMember := func(head, member string) string { return strings.TrimSuffix(head, "}") + "," + member + "}" }
	replace := func(head, old, new string) string { return strings.Replace(head, old, new, 1) }
	change := func(alg, key, url string) string {
		return `{"alg":"` + alg + `","jwk":` + key + `,"url":"` + url + `"}`
	}
	changeBody := `{"installation":"` + relayInstall + `","old_key":` + inst + `}`
	const smallOrder = `{"kty":"OKP","crv":"Ed25519","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	// x of relay-installation with the last character one higher: trailing bits that are not zero.
	instX := inst[strings.Index(inst, `"x":"`)+5 : len(inst)-2]
	nonCanonicalX := replace(inst, instX, instX[:42]+string(instX[42]+1))
	request, keyChange := "request", "key-change"
	specs := []relayCaseSpec{
		{id: "r01", kind: request, head: pair("EdDSA", inst), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "valid", why: "pairing request, Ed25519 key in jwk"},
		{id: "r02", kind: request, head: pair("ES256", p256), payload: relayPairBody, signer: "relay-p256", url: relayPair, expected: "valid", why: "pairing request, P-256 key in jwk"},
		{id: "r03", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "valid", why: "request with kid, Ed25519"},
		{id: "r04", kind: request, head: kid("ES256", relayCertURL), payload: relayCSRBody, signer: "relay-p256", key: "relay-p256", url: relayCertURL, expected: "valid", why: "request with kid, ES256"},
		{id: "r05", kind: request, head: kid("EdDSA", relayInstall), payload: "", signer: "relay-installation", key: "relay-installation", url: relayInstall, expected: "valid", why: "POST-as-GET: empty payload segment"},
		{id: "r06", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayInstall, expected: "malformed", why: "url is not the URL the request was sent to"},
		{id: "r07", kind: request, head: cert, payload: relayCSRBody, signer: "relay-other", key: "relay-installation", url: relayCertURL, expected: "bad-signature", why: "signed by another key than the installation key"},
		{id: "r08", kind: request, head: pair("EdDSA", inst), payload: relayPairBody, signer: "relay-other", url: relayPair, expected: "bad-signature", why: "pairing request not signed by the key in jwk"},
		{id: "r09", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "bad-signature", why: "payload changed after signing",
			edit: func(c string) string {
				return segments(c, func(p []string) []string { p[1] = relayB64.EncodeToString([]byte(`{"csr":"MIIC"}`)); return p })
			}},
		{id: "r10", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "bad-signature", why: "signature over the payload, payload segment left empty (detached): the signature does not cover an empty payload",
			edit: func(c string) string { return segments(c, func(p []string) []string { p[1] = ""; return p }) }},
		{id: "r11", kind: request, head: withMember(cert, `"jwk":`+inst), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "both jwk and kid"},
		{id: "r12", kind: request, head: `{"alg":"EdDSA","nonce":"` + relayNonce + `","url":"` + relayCertURL + `"}`, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "neither jwk nor kid"},
		{id: "r13", kind: request, head: withMember(cert, `"crit":["exp"],"exp":1`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "header member crit"},
		{id: "r14", kind: request, head: withMember(cert, `"b64":false`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "header member b64"},
		{id: "r15", kind: request, head: withMember(cert, `"typ":"JOSE"`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "header member typ: no other member"},
		{id: "r16", kind: request, head: withMember(cert, `"kid":"`+relayInstall+`"`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "kid twice in the header (I-JSON)"},
		{id: "r17", kind: request, head: cert, payload: `{"csr":"MIIB","csr":"MIIC"}`, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "member twice in the payload (I-JSON)"},
		{id: "r18", kind: request, head: replace(cert, `"url"`, `"URL"`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "member names are case-sensitive: URL is not url"},
		{id: "r19", kind: request, head: replace(cert, "EdDSA", "none"), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "alg none"},
		{id: "r20", kind: request, head: replace(cert, "EdDSA", "Ed25519"), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "alg Ed25519 is not EdDSA"},
		{id: "r21", kind: request, head: pair("ES256", inst), payload: relayPairBody, signer: "relay-p256", url: relayPair, expected: "malformed", why: "alg ES256 with an OKP key in jwk"},
		{id: "r22", kind: request, head: pair("EdDSA", p256), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "alg EdDSA with an EC key in jwk"},
		{id: "r23", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-p256", url: relayCertURL, expected: "malformed", why: "alg EdDSA, but kid names a P-256 key"},
		{id: "r24", kind: request, head: kid("ES256", relayCertURL), payload: relayCSRBody, signer: "relay-p256", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "alg ES256, but kid names an Ed25519 key"},
		{id: "r25", kind: request, head: pair("EdDSA", replace(inst, "}", `,"d":"kqp3TCBdBF47A_Rn-K_uOqQ0l49q27SgqgfbaVI4Ns4"}`)), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "jwk with its private part d"},
		{id: "r26", kind: request, head: pair("EdDSA", replace(inst, "}", `,"kid":"relay-installation"}`)), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "jwk with kid: no member beyond kty, crv, x (and y)"},
		{id: "r27", kind: request, head: pair("EdDSA", replace(inst, "}", `,"use":"sig"}`)), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "jwk with use"},
		{id: "r28", kind: request, head: pair("ES256", p256[:strings.Index(p256, `,"y"`)]+"}"), payload: relayPairBody, signer: "relay-p256", url: relayPair, expected: "malformed", why: "EC jwk without y"},
		{id: "r29", kind: request, head: pair("EdDSA", smallOrder), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "jwk is an Ed25519 point of small order (SPEC-v0 section 7.1)"},
		{id: "r30", kind: request, head: pair("EdDSA", nonCanonicalX), payload: relayPairBody, signer: "relay-installation", url: relayPair, expected: "malformed", why: "x of jwk with trailing bits that are not zero"},
		{id: "r31", kind: request, head: replace(cert, relayNonce, relayNonce[:21]), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "nonce of 21 characters: fewer than 128 bits"},
		{id: "r32", kind: request, head: replace(cert, relayNonce, relayNonce[:21]+"B"), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "nonce with trailing bits that are not zero: not base64url of any value"},
		{id: "r33", kind: request, head: replace(cert, relayNonce, "oFvnlFP1wIhRlYS2jTaXbA+"), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "nonce with a character outside base64url"},
		{id: "r34", kind: request, head: replace(cert, `"nonce":"`+relayNonce+`",`, ""), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "no nonce"},
		{id: "r35", kind: request, head: replace(cert, `"nonce":"`+relayNonce+`"`, `"nonce":null`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "nonce null"},
		{id: "r36", kind: request, head: replace(cert, `"url":"https:`, `"url":"http:`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: "http://relay-operator.example/enroll/installation/k7q2xwmpd4hj3n6rt5vbyc2ezu/certificate", expected: "malformed", why: "url is not an HTTPS URL"},
		{id: "r37", kind: request, head: replace(cert, relayInstall+`"}`, `installation-1"}`), payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "kid is not an installation URL"},
		{id: "r38", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "line feed in the header segment",
			edit: func(c string) string { return c[:8] + "\n" + c[8:] }},
		{id: "r39", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "padding on the payload segment",
			edit: func(c string) string { return segments(c, func(p []string) []string { p[1] += "="; return p }) }},
		{id: "r40", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "signature segment with trailing bits that are not zero",
			edit: func(c string) string {
				return segments(c, func(p []string) []string { p[2] = p[2][:85] + string(nonZeroTail(p[2][85])); return p })
			}},
		{id: "r41", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "signature in the standard base64 alphabet",
			edit: func(c string) string {
				return segments(c, func(p []string) []string {
					p[2] = strings.NewReplacer("-", "+", "_", "/").Replace(p[2]) + "/"
					return p
				})
			}},
		{id: "r42", kind: request, head: kid("ES256", relayCertURL), payload: relayCSRBody, signer: "relay-p256", key: "relay-p256", url: relayCertURL, expected: "malformed", why: "ES256 signature with the higher s, which verifies as well", edit: highS},
		{id: "r43", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "EdDSA signature with S + L, which lenient libraries accept", edit: largeS},
		{id: "r44", kind: request, head: cert, payload: `["csr"]`, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "payload is not a JSON object"},
		{id: "r45", kind: request, head: `["EdDSA"]`, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "header is not a JSON object"},
		{id: "r46", kind: request, head: cert, payload: relayCSRBody, signer: "relay-installation", key: "relay-installation", url: relayCertURL, expected: "malformed", why: "two segments",
			edit: func(c string) string { return c[:strings.LastIndex(c, ".")] }},
		{id: "r47", kind: request, head: pair("EdDSA", inst), payload: "", signer: "relay-installation", url: relayPair, expected: "valid", why: "pairing request with an empty payload: the payload is checked after the signature (step 6)"},

		{id: "k01", kind: keyChange, head: change("EdDSA", newKey, relayKeyURL), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "valid", why: "inner JWS signed with the new Ed25519 key"},
		{id: "k02", kind: keyChange, head: change("ES256", p256, relayKeyURL), payload: changeBody, signer: "relay-p256", url: relayKeyURL, expected: "valid", why: "inner JWS signed with a new P-256 key"},
		{id: "k03", kind: keyChange, head: change("EdDSA", newKey, relayKeyURL), payload: changeBody, signer: "relay-installation", url: relayKeyURL, expected: "bad-signature", why: "signed with the old key, not with the new key in jwk"},
		{id: "k04", kind: keyChange, head: change("EdDSA", newKey, relayPair), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "url is not the URL of key_change"},
		{id: "k05", kind: keyChange, head: withMember(change("EdDSA", newKey, relayKeyURL), `"nonce":"`+relayNonce+`"`), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "inner header with a nonce"},
		{id: "k06", kind: keyChange, head: `{"alg":"EdDSA","kid":"` + relayInstall + `","url":"` + relayKeyURL + `"}`, payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "inner header with kid instead of jwk"},
		{id: "k07", kind: keyChange, head: withMember(change("EdDSA", newKey, relayKeyURL), `"kid":"`+relayInstall+`"`), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "inner header with kid besides jwk"},
		{id: "k08", kind: keyChange, head: change("ES256", newKey, relayKeyURL), payload: changeBody, signer: "relay-p256", url: relayKeyURL, expected: "malformed", why: "alg ES256 with an OKP key in jwk"},
		{id: "k09", kind: keyChange, head: change("EdDSA", replace(newKey, "}", `,"d":"p7_aTVVmXEX-06etlTq-z-tbSlQtbHAbFEplzc4ly-8"}`), relayKeyURL), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "jwk with its private part d"},
		{id: "k10", kind: keyChange, head: withMember(change("EdDSA", newKey, relayKeyURL), `"crit":["b64"],"b64":false`), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "inner header with crit and b64"},
		{id: "k11", kind: keyChange, head: change("EdDSA", newKey, relayKeyURL), payload: "", signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "inner JWS without payload"},
		{id: "k12", kind: keyChange, head: change("EdDSA", newKey, relayKeyURL), payload: `{"installation":"` + relayInstall + `","installation":"` + relayInstall + `"}`, signer: "relay-new", url: relayKeyURL, expected: "malformed", why: "member twice in the payload (I-JSON)"},
		{id: "k13", kind: keyChange, head: change("ES256", p256, relayKeyURL), payload: changeBody, signer: "relay-p256", url: relayKeyURL, expected: "malformed", why: "ES256 signature with the higher s", edit: highS},
		{id: "k14", kind: keyChange, head: change("EdDSA", other, relayKeyURL), payload: changeBody, signer: "relay-new", url: relayKeyURL, expected: "bad-signature", why: "jwk names another key than the one that signed"},
	}
	cases := make([]relayJWSCase, 0, len(specs))
	for _, s := range specs {
		signer, ok := signers[s.signer]
		if !ok {
			return nil, fmt.Errorf("%s: no key %q", s.id, s.signer)
		}
		compact, err := rawRelayJWS(s.head, s.payload, signer)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.id, err)
		}
		if s.edit != nil {
			compact = s.edit(compact)
		}
		key := json.RawMessage("null")
		if s.key != "" {
			key = json.RawMessage(jwk[s.key])
		}
		_, random := signer.(*ecdsa.PrivateKey)
		cases = append(cases, relayJWSCase{ID: s.id, Kind: s.kind, JWS: compact, Key: key, URL: s.url, Expected: s.expected, Why: s.why, random: random})
	}
	return cases, nil
}

// nonZeroTail returns a base64url character that differs from c only in its lowest bits.
func nonZeroTail(c byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, c)
	return alphabet[i|1]
}
