// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

const (
	testNonce    = "oFvnlFP1wIhRlYS2jTaXbA"
	testPair     = "https://relay-operator.example/enroll/pair"
	testKeyURL   = "https://relay-operator.example/enroll/key-change"
	testInstall  = "https://relay-operator.example/enroll/installation/k7q2xwmpd4hj3n6rt5vbyc2ezu"
	testCertURL  = testInstall + "/certificate"
	testPayload  = `{"code":"ABCD-EFGH-IJKL-MNOP"}`
	testKCChange = `{"installation":"` + testInstall + `","old_key":{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `"}}`
)

func jwkOf(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	data, err := MarshalJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// rawSign signs a header given as JSON text, so that tests can build headers SignRequest refuses.
func rawSign(t *testing.T, head, payload string, signer any) string {
	t.Helper()
	alg, _, err := signerAlg(signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded := b64.EncodeToString([]byte(head))
	sig, err := signInput(alg, signer, signingInput(encoded, []byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	return encoded + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

func TestSignAndVerifyRequest(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	for name, tt := range map[string]struct {
		h       RequestHeader
		payload string
		signer  any
		key     crypto.PublicKey
	}{
		"pairing Ed25519": {RequestHeader{Nonce: testNonce, URL: testPair, JWK: ed.Public()}, testPayload, ed, nil},
		"pairing ES256":   {RequestHeader{Alg: AlgES256, Nonce: testNonce, URL: testPair, JWK: ec.Public()}, testPayload, ec, ec.Public()},
		"kid Ed25519":     {RequestHeader{Alg: AlgEdDSA, Nonce: testNonce, URL: testCertURL, Kid: testInstall}, testPayload, ed, ed.Public()},
		"kid ES256":       {RequestHeader{Nonce: testNonce, URL: testCertURL, Kid: testInstall}, `{}`, ec, ec.Public()},
		"POST-as-GET":     {RequestHeader{Nonce: testNonce, URL: testInstall, Kid: testInstall}, "", ed, ed.Public()},
	} {
		compact, err := SignRequest([]byte(tt.payload), tt.h, tt.signer)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if parts := strings.Split(compact, "."); len(parts) != 3 || (tt.payload == "") != (parts[1] == "") {
			t.Fatalf("%s: %q", name, compact)
		}
		h, payload, err := VerifyRequest(compact, tt.key)
		if err != nil || string(payload) != tt.payload || h.Nonce != testNonce || h.URL != tt.h.URL || h.Kid != tt.h.Kid {
			t.Errorf("%s: VerifyRequest = %+v, %q, %v", name, h, payload, err)
		}
		if (h.JWK == nil) != (tt.h.JWK == nil) || (h.JWK != nil && !sameKey(h.JWK, tt.h.JWK)) {
			t.Errorf("%s: jwk = %v", name, h.JWK)
		}
		parsed, _, err := ParseRequest(compact)
		if err != nil || parsed.Alg != h.Alg {
			t.Errorf("%s: ParseRequest = %+v, %v", name, parsed, err)
		}
	}
}

func TestVerifyRequestDistinguishesMalformedFromBadSignature(t *testing.T) {
	ed, other, ec := rfcKey(t), ed25519.NewKeyFromSeed(make([]byte, 32)), ecKey(t)
	edJWK, ecJWK := jwkOf(t, ed.Public()), jwkOf(t, ec.Public())
	pair := func(members string) string {
		return `{"alg":"EdDSA","nonce":"` + testNonce + `","url":"` + testPair + `"` + members + `}`
	}
	kid := func(members string) string {
		return `{"alg":"EdDSA","nonce":"` + testNonce + `","url":"` + testCertURL + `","kid":"` + testInstall + `"` + members + `}`
	}
	good := rawSign(t, kid(""), testPayload, ed)
	parts := strings.Split(good, ".")
	for name, tt := range map[string]struct {
		compact string
		key     crypto.PublicKey
		want    error
		reason  string // a part of the message that names the defect
	}{
		"signed by another key":      {rawSign(t, kid(""), testPayload, other), ed.Public(), ErrSignature, "signature does not verify"},
		"payload changed":            {parts[0] + "." + b64.EncodeToString([]byte(`{"code":"X"}`)) + "." + parts[2], ed.Public(), ErrSignature, "signature does not verify"},
		"pairing signed by another":  {rawSign(t, pair(`,"jwk":`+edJWK), testPayload, other), nil, ErrSignature, "signature does not verify"},
		"kid without key":            {good, nil, ErrKey, "<nil>"},
		"key other than jwk":         {rawSign(t, pair(`,"jwk":`+edJWK), testPayload, ed), other.Public(), ErrKey, "key is not the jwk"},
		"unsupported key":            {good, "key", ErrKey, "string"},
		"ES256 for an Ed25519 key":   {rawSign(t, strings.Replace(kid(""), "EdDSA", "ES256", 1), testPayload, ec), ed.Public(), ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"EdDSA for a P-256 key":      {good, ec.Public(), ErrMalformed, "algorithm EdDSA for a ES256 key"},
		"ES256 with an OKP jwk":      {rawSign(t, strings.Replace(pair(`,"jwk":`+edJWK), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"EdDSA with an EC jwk":       {rawSign(t, pair(`,"jwk":`+ecJWK), testPayload, ed), nil, ErrMalformed, "algorithm EdDSA for a ES256 key"},
		"both jwk and kid":           {rawSign(t, kid(`,"jwk":`+edJWK), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"neither jwk nor kid":        {rawSign(t, pair(""), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"crit":                       {rawSign(t, kid(`,"crit":["b64"]`), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"b64":                        {rawSign(t, kid(`,"b64":false`), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"duplicate member":           {rawSign(t, kid(`,"kid":"`+testInstall+`"`), testPayload, ed), ed.Public(), ErrMalformed, `header: malformed JSON: duplicate key "kid"`},
		"upper-case member":          {rawSign(t, strings.Replace(kid(""), `"url"`, `"URL"`, 1), testPayload, ed), ed.Public(), ErrMalformed, "url must be a string"},
		"jwk with d":                 {rawSign(t, pair(`,"jwk":`+strings.Replace(edJWK, `}`, `,"d":"`+rfc8037Seed+`"}`, 1)), testPayload, ed), nil, ErrMalformed, "members other than"},
		"jwk with kid":               {rawSign(t, pair(`,"jwk":`+strings.Replace(edJWK, `}`, `,"kid":"k"}`, 1)), testPayload, ed), nil, ErrMalformed, "members other than"},
		"jwk not an object":          {rawSign(t, pair(`,"jwk":"`+rfc8037Public+`"`), testPayload, ed), nil, ErrMalformed, "jwk: not a JSON object"},
		"jwk without kty":            {rawSign(t, pair(`,"jwk":{"crv":"Ed25519","x":"`+rfc8037Public+`","y":"x"}`), testPayload, ed), nil, ErrMalformed, "kty must be a string"},
		"jwk crv null":               {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":null,"x":"`+rfc8037Public+`"}`), testPayload, ed), nil, ErrMalformed, "crv must be a string"},
		"jwk short x":                {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQAB"}`), testPayload, ed), nil, ErrMalformed, "x is not 32 bytes"},
		"jwk RSA":                    {rawSign(t, pair(`,"jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}`), testPayload, ed), nil, ErrMalformed, "crv must be a string"},
		"jwk EC without y":           {rawSign(t, strings.Replace(pair(`,"jwk":{"kty":"EC","crv":"P-256","x":"`+rfc8037Public+`"}`), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "members other than"},
		"jwk P-256 off the curve":    {rawSign(t, strings.Replace(pair(`,"jwk":`+offCurve(t, ecJWK)), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "not on curve"},
		"jwk small order":            {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), testPayload, ed), nil, ErrMalformed, "small order"},
		"alg none":                   {rawSign(t, strings.Replace(kid(""), "EdDSA", "none", 1), testPayload, ed), ed.Public(), ErrMalformed, `algorithm "none"`},
		"alg null":                   {rawSign(t, strings.Replace(kid(""), `"EdDSA"`, "null", 1), testPayload, ed), ed.Public(), ErrMalformed, "alg must be a string"},
		"nonce too short":            {rawSign(t, strings.Replace(kid(""), testNonce, testNonce[:21], 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce not base64url":        {rawSign(t, strings.Replace(kid(""), testNonce, strings.Repeat("+", 22), 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce not canonical":        {rawSign(t, strings.Replace(kid(""), testNonce, testNonce[:21]+"B", 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce too long":             {rawSign(t, strings.Replace(kid(""), testNonce, strings.Repeat("A", 132), 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce a number":             {rawSign(t, strings.Replace(kid(""), `"`+testNonce+`"`, "1", 1), testPayload, ed), ed.Public(), ErrMalformed, "nonce must be a string"},
		"url over http":              {rawSign(t, strings.Replace(kid(""), `"url":"https`, `"url":"http`, 1), testPayload, ed), ed.Public(), ErrMalformed, `url "http://`},
		"kid with query":             {rawSign(t, strings.Replace(kid(""), testInstall+`"`, testInstall+`?a"`, 1), testPayload, ed), ed.Public(), ErrMalformed, `kid "https://`},
		"header an array":            {rawSign(t, `[]`, testPayload, ed), ed.Public(), ErrMalformed, "header is not a JSON object"},
		"header null":                {rawSign(t, `null`, testPayload, ed), ed.Public(), ErrMalformed, "header is not a JSON object"},
		"header duplicate in I-JSON": {rawSign(t, kid(`,"alg":"EdDSA"`), testPayload, ed), ed.Public(), ErrMalformed, `header: malformed JSON: duplicate key "alg"`},
		"payload not an object":      {rawSign(t, kid(""), `[1]`, ed), ed.Public(), ErrMalformed, "payload is not a JSON object"},
		"payload null":               {rawSign(t, kid(""), `null`, ed), ed.Public(), ErrMalformed, "payload is not a JSON object"},
		"payload duplicate member":   {rawSign(t, kid(""), `{"a":1,"a":2}`, ed), ed.Public(), ErrMalformed, `payload: malformed JSON: duplicate key "a"`},
		"payload padded":             {parts[0] + "." + parts[1] + "=." + parts[2], ed.Public(), ErrMalformed, "payload: illegal base64"},
		"header with line feed":      {parts[0][:4] + "\n" + parts[0][4:] + "." + parts[1] + "." + parts[2], ed.Public(), ErrMalformed, "header: not canonical base64url"},
		"signature not base64url":    {parts[0] + "." + parts[1] + ".!!", ed.Public(), ErrMalformed, "signature: illegal base64"},
		"signature short":            {parts[0] + "." + parts[1] + "." + parts[2][:40], ed.Public(), ErrMalformed, "signature of 30 bytes"},
		"signature empty":            {parts[0] + "." + parts[1] + ".", ed.Public(), ErrMalformed, "signature of 0 bytes"},
		"two segments":               {parts[0] + "." + parts[1], ed.Public(), ErrMalformed, "not a compact JWS"},
	} {
		_, _, err := VerifyRequest(tt.compact, tt.key)
		if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: err = %v, want %v with %q", name, err, tt.want, tt.reason)
		}
		for _, other := range []error{ErrMalformed, ErrSignature, ErrKey} {
			if other != tt.want && errors.Is(err, other) {
				t.Errorf("%s: err = %v is also %v", name, err, other)
			}
		}
	}
}

// TestSignatureSpellingIsMalformed: a signature that breaks the spelling rules is
// malformed before it is checked (RELAY-v0 section 5.1 step 1), even if a lenient
// library would accept it. Each fixture verifies before it is changed.
func TestSignatureSpellingIsMalformed(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	head := `{"alg":"ES256","nonce":"` + testNonce + `","url":"` + testCertURL + `","kid":"` + testInstall + `"}`
	compact := rawSign(t, head, testPayload, ec)
	if _, _, err := VerifyRequest(compact, ec.Public()); err != nil {
		t.Fatalf("ES256 fixture: %v", err)
	}
	parts := strings.Split(compact, ".")
	sig, _ := b64.DecodeString(parts[2])
	n := elliptic.P256().Params().N
	high := append(sig[:32:32], new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:])).FillBytes(make([]byte, 32))...)
	if _, _, err := VerifyRequest(parts[0]+"."+parts[1]+"."+b64.EncodeToString(high), ec.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "higher s") {
		t.Errorf("high s: %v, want ErrMalformed for the higher s", err)
	}

	edCompact := rawSign(t, strings.Replace(head, "ES256", "EdDSA", 1), testPayload, ed)
	if _, _, err := VerifyRequest(edCompact, ed.Public()); err != nil {
		t.Fatalf("EdDSA fixture: %v", err)
	}
	parts = strings.Split(edCompact, ".")
	sig, _ = b64.DecodeString(parts[2])
	// S + L verifies in libraries that reduce S.
	s := make([]byte, 32)
	for i, b := range sig[32:] {
		s[31-i] = b
	}
	sum := new(big.Int).Add(new(big.Int).SetBytes(s), ed25519Order).FillBytes(make([]byte, 32))
	large := append([]byte{}, sig[:32]...)
	for i := range sum {
		large = append(large, sum[31-i])
	}
	if _, _, err := VerifyRequest(parts[0]+"."+parts[1]+"."+b64.EncodeToString(large), ed.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "EdDSA signature not canonical") {
		t.Errorf("S >= L: %v, want ErrMalformed for a non-canonical signature", err)
	}
	// R with y = p + 1, not canonical.
	badR := append([]byte{0xee}, append(bytesOf(0xff, 30), 0x7f)...)
	if _, _, err := VerifyRequest(parts[0]+"."+parts[1]+"."+b64.EncodeToString(append(badR, sig[32:]...)), ed.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "EdDSA signature not canonical") {
		t.Errorf("non-canonical R: %v, want ErrMalformed for a non-canonical signature", err)
	}
}

// offCurve returns a P-256 jwk whose y is changed in its lowest bit, so that the point is
// not on the curve.
func offCurve(t *testing.T, ecJWK string) string {
	t.Helper()
	var k struct{ Kty, Crv, X, Y string }
	if err := json.Unmarshal([]byte(ecJWK), &k); err != nil {
		t.Fatal(err)
	}
	y, err := b64.DecodeString(k.Y)
	if err != nil {
		t.Fatal(err)
	}
	y[len(y)-1] ^= 1
	return `{"kty":"EC","crv":"P-256","x":"` + k.X + `","y":"` + b64.EncodeToString(y) + `"}`
}

// TestRequestErrorsQuoteOnlyAPrefix: an error quotes at most maxQuotedBytes of a value
// that the sender chose.
func TestRequestErrorsQuoteOnlyAPrefix(t *testing.T) {
	ed := rfcKey(t)
	long := strings.Repeat("A", maxNonceChars+4)
	kid := `{"alg":"EdDSA","nonce":"` + testNonce + `","url":"` + testCertURL + `","kid":"` + testInstall + `"}`
	for name, head := range map[string]string{
		"nonce": strings.Replace(kid, testNonce, long, 1),
		"url":   strings.Replace(kid, testCertURL, "http://"+long, 1),
		"kid":   strings.Replace(kid, `"kid":"`+testInstall, `"kid":"https://`+strings.ToLower(long)+"/", 1),
		"alg":   strings.Replace(kid, "EdDSA", long, 1),
	} {
		_, _, err := VerifyRequest(rawSign(t, head, testPayload, ed), ed.Public())
		if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "...") {
			t.Errorf("%s: err = %v, want ErrMalformed naming %s with a cut value", name, err, name)
		}
		if strings.Contains(err.Error(), long[:maxQuotedBytes+1]) || strings.Contains(err.Error(), strings.ToLower(long[:maxQuotedBytes+1])) {
			t.Errorf("%s: err quotes more than %d bytes: %v", name, maxQuotedBytes, err)
		}
	}
	if got := quote("short"); got != `"short"` {
		t.Errorf("quote(short) = %s", got)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSignRequestRejects(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ok := RequestHeader{Nonce: testNonce, URL: testCertURL, Kid: testInstall}
	for name, tt := range map[string]struct {
		h       RequestHeader
		payload string
		signer  any
		want    error
	}{
		"no key":            {ok, testPayload, "key", ErrKey},
		"P-384":             {ok, testPayload, p384, ErrKey},
		"short Ed25519 key": {ok, testPayload, ed[:32], ErrKey},
		"alg of other type": {RequestHeader{Alg: AlgES256, Nonce: testNonce, URL: testCertURL, Kid: testInstall}, testPayload, ed, ErrKey},
		"jwk of other key":  {RequestHeader{Nonce: testNonce, URL: testPair, JWK: ec.Public()}, testPayload, ed, ErrKey},
		"both":              {RequestHeader{Nonce: testNonce, URL: testPair, JWK: ed.Public(), Kid: testInstall}, testPayload, ed, ErrMalformed},
		"neither":           {RequestHeader{Nonce: testNonce, URL: testPair}, testPayload, ed, ErrMalformed},
		"bad kid":           {RequestHeader{Nonce: testNonce, URL: testCertURL, Kid: "inst-1"}, testPayload, ed, ErrMalformed},
		"bad nonce":         {RequestHeader{Nonce: "abc", URL: testCertURL, Kid: testInstall}, testPayload, ed, ErrMalformed},
		"bad url":           {RequestHeader{Nonce: testNonce, URL: "https://Relay.example/", Kid: testInstall}, testPayload, ed, ErrMalformed},
		"payload array":     {ok, `[]`, ed, ErrMalformed},
		"payload duplicate": {ok, `{"a":1,"a":1}`, ed, ErrMalformed},
	} {
		if _, err := SignRequest([]byte(tt.payload), tt.h, tt.signer); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
	}
}

func TestKeyChange(t *testing.T) {
	newKey, oldKey, ec := ed25519.NewKeyFromSeed(bytesOf(7, 32)), rfcKey(t), ecKey(t)
	for name, signer := range map[string]any{"Ed25519": newKey, "P-256": ec} {
		compact, err := SignKeyChange([]byte(testKCChange), KeyChangeHeader{URL: testKeyURL}, signer)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h, payload, err := VerifyKeyChange(compact)
		_, public, _ := signerAlg(signer)
		if err != nil || h.URL != testKeyURL || !sameKey(h.JWK, public) || string(payload) != testKCChange {
			t.Errorf("%s: VerifyKeyChange = %+v, %q, %v", name, h, payload, err)
		}
		if _, _, err := ParseKeyChange(compact); err != nil {
			t.Errorf("%s: ParseKeyChange: %v", name, err)
		}
	}
	newJWK := jwkOf(t, newKey.Public())
	head := `{"alg":"EdDSA","jwk":` + newJWK + `,"url":"` + testKeyURL + `"}`
	good := rawSign(t, head, testKCChange, newKey)
	parts := strings.Split(good, ".")
	for name, tt := range map[string]struct {
		compact string
		want    error
		reason  string
	}{
		"signed by the old key": {rawSign(t, head, testKCChange, oldKey), ErrSignature, "signature does not verify"},
		"with nonce":            {rawSign(t, strings.Replace(head, `{`, `{"nonce":"`+testNonce+`",`, 1), testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"with kid":              {rawSign(t, strings.Replace(head, `{`, `{"kid":"`+testInstall+`",`, 1), testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"without jwk":           {rawSign(t, `{"alg":"EdDSA","kid":"`+testInstall+`","url":"`+testKeyURL+`"}`, testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"without url":           {rawSign(t, `{"alg":"EdDSA","jwk":`+newJWK+`}`, testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"bad url":               {rawSign(t, strings.Replace(head, "https", "http", 1), testKCChange, newKey), ErrMalformed, `url "http://`},
		"alg ES256":             {rawSign(t, strings.Replace(head, "EdDSA", "ES256", 1), testKCChange, ec), ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"alg missing":           {rawSign(t, `{"jwk":`+newJWK+`,"url":"`+testKeyURL+`","x":1}`, testKCChange, newKey), ErrMalformed, "alg must be a string"},
		"empty payload":         {rawSign(t, head, "", newKey), ErrMalformed, "no payload"},
		"payload array":         {rawSign(t, head, "[]", newKey), ErrMalformed, "payload is not a JSON object"},
		"padded signature":      {good + "=", ErrMalformed, "signature: illegal base64"},
		"two segments":          {parts[0] + "." + parts[1], ErrMalformed, "not a compact JWS"},
		"too long":              {parts[0] + "." + strings.Repeat("A", maxKeyChangeBytes) + "." + parts[2], ErrMalformed, "larger than"},
	} {
		if _, _, err := VerifyKeyChange(tt.compact); !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: err = %v, want %v with %q", name, err, tt.want, tt.reason)
		}
	}
	for name, tt := range map[string]struct {
		h       KeyChangeHeader
		payload string
		signer  any
		want    error
	}{
		"no key":            {KeyChangeHeader{URL: testKeyURL}, testKCChange, nil, ErrKey},
		"short Ed25519 key": {KeyChangeHeader{URL: testKeyURL}, testKCChange, newKey[:63], ErrKey},
		"alg mismatch":      {KeyChangeHeader{Alg: AlgES256, URL: testKeyURL}, testKCChange, newKey, ErrKey},
		"jwk mismatch":      {KeyChangeHeader{JWK: oldKey.Public(), URL: testKeyURL}, testKCChange, newKey, ErrKey},
		"bad url":           {KeyChangeHeader{URL: "https://x"}, testKCChange, newKey, ErrMalformed},
		"empty payload":     {KeyChangeHeader{URL: testKeyURL}, "", newKey, ErrMalformed},
		"too long":          {KeyChangeHeader{URL: testKeyURL}, `{"a":"` + strings.Repeat("x", maxKeyChangeBytes) + `"}`, newKey, ErrMalformed},
	} {
		_, err := SignKeyChange([]byte(tt.payload), tt.h, tt.signer)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
		for _, other := range []error{ErrMalformed, ErrSignature, ErrKey} {
			if other != tt.want && errors.Is(err, other) {
				t.Errorf("%s: err = %v is also %v", name, err, other)
			}
		}
	}
}

func TestParseJWKAndMarshalJWK(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	for _, key := range []crypto.PublicKey{ed.Public(), ec.Public()} {
		data, err := MarshalJWK(key)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]any
		if err := json.Unmarshal(data, &members); err != nil || members["kid"] != nil {
			t.Errorf("MarshalJWK = %s", data)
		}
		back, err := ParseJWK(data)
		if err != nil || !sameKey(back, key) {
			t.Errorf("ParseJWK(%s) = %v, %v", data, back, err)
		}
	}
	var none *ecdsa.PublicKey
	for _, key := range []crypto.PublicKey{nil, "key", none, ed25519.PublicKey(make([]byte, 31))} {
		if _, err := MarshalJWK(key); !errors.Is(err, ErrKey) {
			t.Errorf("MarshalJWK(%v) = %v, want ErrKey", key, err)
		}
	}
	for name, tt := range map[string]struct{ doc, reason string }{
		"duplicate x": {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","x":"` + rfc8037Public + `"}`, "duplicate key"},
		"with kid":    {`{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + rfc8037Public + `"}`, "members other than"},
		"with d":      {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","d":"` + rfc8037Seed + `"}`, "members other than"},
		"upper X":     {`{"kty":"OKP","crv":"Ed25519","X":"` + rfc8037Public + `"}`, "x must be a string"},
		"OKP with y":  {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `","y":"` + rfc8037Public + `"}`, "members other than"},
		"EC short y":  {`{"kty":"EC","crv":"P-256","x":"` + rfc8037Public + `","y":"AQAB"}`, "y is not 32 bytes"},
		"x padded":    {`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public[:42] + `="}`, "illegal base64"},
		"not JSON":    {`nope`, "malformed JSON"},
		"null":        {`null`, "not a JSON object"},
	} {
		if _, err := ParseJWK([]byte(tt.doc)); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: ParseJWK = %v, want ErrKey with %q", name, err, tt.reason)
		}
	}
}
