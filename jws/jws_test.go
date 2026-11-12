// SPDX-License-Identifier: Apache-2.0

package jws

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
)

// Test vector of RFC 8037 appendix A.4.
const (
	rfc8037Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037Public    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Header    = "eyJhbGciOiJFZERTQSJ9"
	rfc8037Payload   = "Example of Ed25519 signing"
	rfc8037Signature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func rfcKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestEd25519MatchesRFC8037(t *testing.T) {
	key := rfcKey(t)
	if got := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)); got != rfc8037Public {
		t.Fatalf("public key = %s", got)
	}
	input := rfc8037Header + "." + base64.RawURLEncoding.EncodeToString([]byte(rfc8037Payload))
	sig, err := signInput(AlgEdDSA, key, []byte(input))
	if err != nil || base64.RawURLEncoding.EncodeToString(sig) != rfc8037Signature {
		t.Errorf("signature = %s, %v", base64.RawURLEncoding.EncodeToString(sig), err)
	}
	if !verifyInput(AlgEdDSA, key.Public(), []byte(input), sig) {
		t.Error("RFC 8037 signature does not verify")
	}
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignAndVerifyDetached(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	keys := Keys{"ed-1": ed.Public(), "ec-1": ec.Public()}
	payload := []byte(`{"a":1}`)
	for kid, signer := range map[string]any{"ed-1": ed, "ec-1": ec} {
		detached, err := SignDetached(payload, kid, signer)
		if err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
		parts := strings.Split(detached, ".")
		if len(parts) != 3 || parts[1] != "" {
			t.Fatalf("%s: %q is not a detached JWS", kid, detached)
		}
		gotKid, err := VerifyDetached(detached, payload, keys)
		if err != nil || gotKid != kid {
			t.Errorf("%s: VerifyDetached = %q, %v", kid, gotKid, err)
		}
		if _, err := VerifyDetached(detached, []byte(`{"a":2}`), keys); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: changed payload: %v, want ErrSignature", kid, err)
		}
	}
}

func TestSignAndVerifyCompact(t *testing.T) {
	ed := rfcKey(t)
	keys := Keys{"ed-1": ed.Public()}
	compact, err := Sign([]byte(`{"a":1}`), "ed-1", ed)
	if err != nil {
		t.Fatal(err)
	}
	payload, kid, err := Verify(compact, keys)
	if err != nil || string(payload) != `{"a":1}` || kid != "ed-1" {
		t.Errorf("Verify = %q, %q, %v", payload, kid, err)
	}
	// Deterministic for Ed25519: the same input gives the same JWS.
	again, _ := Sign([]byte(`{"a":1}`), "ed-1", ed)
	if again != compact {
		t.Error("Ed25519 JWS is not deterministic")
	}
}

func header(t *testing.T, json string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

func TestVerifyRejects(t *testing.T) {
	ed, other, ec := rfcKey(t), ed25519.NewKeyFromSeed(make([]byte, 32)), ecKey(t)
	keys := Keys{"ed-1": ed.Public(), "ec-1": ec.Public()}
	payload := []byte(`{"a":1}`)
	good, _ := SignDetached(payload, "ed-1", ed)
	sig := good[strings.LastIndex(good, ".")+1:]
	wrongKey, _ := SignDetached(payload, "ed-1", other)
	ecAsEd, _ := SignDetached(payload, "ec-1", ed) // kid of the EC key, signed with Ed25519
	for name, jws := range map[string]string{
		"empty":                "",
		"two parts":            "a.b",
		"four parts":           "a..b.c",
		"payload not detached": header(t, `{"alg":"EdDSA","kid":"ed-1"}`) + ".e30." + sig,
		"alg none":             header(t, `{"alg":"none","kid":"ed-1"}`) + "..",
		"alg HS256":            header(t, `{"alg":"HS256","kid":"ed-1"}`) + ".." + sig,
		"alg missing":          header(t, `{"kid":"ed-1"}`) + ".." + sig,
		"kid missing":          header(t, `{"alg":"EdDSA"}`) + ".." + sig,
		"unknown kid":          header(t, `{"alg":"EdDSA","kid":"ed-2"}`) + ".." + sig,
		"crit header":          header(t, `{"alg":"EdDSA","kid":"ed-1","crit":["x"],"x":1}`) + ".." + sig,
		"b64 header":           header(t, `{"alg":"EdDSA","kid":"ed-1","b64":false}`) + ".." + sig,
		"jwk header":           header(t, `{"alg":"EdDSA","kid":"ed-1","jwk":{}}`) + ".." + sig,
		"duplicate header":     header(t, `{"alg":"none","alg":"EdDSA","kid":"ed-1"}`) + ".." + sig,
		"header not JSON":      header(t, `nope`) + ".." + sig,
		"header not base64":    "!!!.." + sig,
		"padded header":        header(t, `{"alg":"EdDSA","kid":"ed-1"}`) + "=.." + sig,
		"signature not base64": good[:strings.LastIndex(good, ".")+1] + "!!!",
		"short signature":      good[:len(good)-4],
		"header changed":       header(t, `{"kid":"ed-1","alg":"EdDSA"}`) + ".." + sig,
		"wrong key":            wrongKey,
		"alg does not fit key": ecAsEd,
		"too long":             good + strings.Repeat("A", maxCompactBytes),
	} {
		if _, err := VerifyDetached(jws, payload, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := Verify(good, keys); err == nil {
		t.Error("Verify accepted a detached JWS")
	}
	if _, _, err := Verify("a.b", keys); err == nil {
		t.Error("Verify accepted two parts")
	}
	if _, _, err := Verify(header(t, `{"alg":"EdDSA","kid":"ed-1"}`)+".!!."+sig, keys); err == nil {
		t.Error("Verify accepted a payload that is not base64url")
	}
}

func TestSignRejects(t *testing.T) {
	ed := rfcKey(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignDetached([]byte("x"), "bad kid", ed); err == nil {
		t.Error("kid with a space accepted")
	}
	if _, err := SignDetached([]byte("x"), "", ed); err == nil {
		t.Error("empty kid accepted")
	}
	if _, err := SignDetached([]byte("x"), "k", p384); err == nil {
		t.Error("P-384 key accepted")
	}
	if _, err := SignDetached([]byte("x"), "k", "not a key"); err == nil {
		t.Error("unsupported key type accepted")
	}
}

func TestParseJWKS(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	set, err := MarshalJWKS(Keys{"ed-1": ed.Public(), "ec-1": ec.Public()})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(set)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ParseJWKS = %v, %v", keys, err)
	}
	payload := []byte("x")
	for kid, signer := range map[string]any{"ed-1": ed, "ec-1": ec} {
		detached, _ := SignDetached(payload, kid, signer)
		if _, err := VerifyDetached(detached, payload, keys); err != nil {
			t.Errorf("%s: key from the set does not verify: %v", kid, err)
		}
	}
	okp := `{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + rfc8037Public + `"}`
	for name, doc := range map[string]string{
		"not JSON":       `nope`,
		"no keys":        `{"keys":[]}`,
		"private key":    `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + rfc8037Public + `","d":"` + rfc8037Seed + `"}]}`,
		"duplicate kid":  `{"keys":[` + okp + `,` + okp + `]}`,
		"no kid":         `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `"}]}`,
		"bad kid":        `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a b","x":"` + rfc8037Public + `"}]}`,
		"unknown kty":    `{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`,
		"unknown curve":  `{"keys":[{"kty":"OKP","crv":"Ed448","kid":"k","x":"` + rfc8037Public + `"}]}`,
		"short x":        `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AQAB"}]}`,
		"x not base64":   `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"!!"}]}`,
		"EC wrong curve": `{"keys":[{"kty":"EC","crv":"P-384","kid":"k","x":"AQAB","y":"AQAB"}]}`,
		"EC off curve":   `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + rfc8037Public + `","y":"` + rfc8037Public + `"}]}`,
		"EC y missing":   `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + rfc8037Public + `"}]}`,
	} {
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := MarshalJWKS(Keys{"k": "not a key"}); err == nil {
		t.Error("MarshalJWKS accepted an unsupported key")
	}
}

// TestSegmentsMustBeCanonicalBase64URL: Go's base64 decoder skips line breaks, so the
// segments are checked before decoding. One signed object has exactly one string.
func TestSegmentsMustBeCanonicalBase64URL(t *testing.T) {
	ed := rfcKey(t)
	keys := Keys{"ed-1": ed.Public()}
	payload := []byte(`{"a":1}`)
	compact, _ := Sign(payload, "ed-1", ed)
	detached, _ := SignDetached(payload, "ed-1", ed)
	parts := strings.Split(compact, ".")
	for name, altered := range map[string]string{
		"line feed in payload":       parts[0] + "." + parts[1][:4] + "\n" + parts[1][4:] + "." + parts[2],
		"carriage return in payload": parts[0] + "." + parts[1][:4] + "\r" + parts[1][4:] + "." + parts[2],
		"line feed in signature":     parts[0] + "." + parts[1] + "." + parts[2][:8] + "\n" + parts[2][8:],
		"line feed in header":        parts[0][:4] + "\n" + parts[0][4:] + "." + parts[1] + "." + parts[2],
		"padding on payload":         parts[0] + "." + parts[1] + "=." + parts[2],
		"standard alphabet":          parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+",
		"space in signature":         parts[0] + "." + parts[1] + "." + parts[2] + " ",
	} {
		if _, _, err := Verify(altered, keys); err == nil {
			t.Errorf("%s: Verify accepted", name)
		}
	}
	sig := detached[strings.LastIndex(detached, ".")+1:]
	if _, err := VerifyDetached(parts[0]+".."+sig[:8]+"\n"+sig[8:], payload, keys); err == nil {
		t.Error("line feed in a detached signature: accepted")
	}
	// Trailing bits that are not zero decode to the same bytes in lenient decoders.
	last := sig[len(sig)-1]
	if other := string(rune(last + 1)); other != "" {
		if _, err := VerifyDetached(parts[0]+".."+sig[:len(sig)-1]+other, payload, keys); err == nil {
			t.Error("signature with other trailing bits: accepted")
		}
	}
}

func TestParseJWKSRejectsDuplicateMembers(t *testing.T) {
	doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","kid":"k2","x":"` + rfc8037Public + `"}]}`
	if _, err := ParseJWKS([]byte(doc)); err == nil {
		t.Error("JWK with a duplicate member accepted")
	}
}

func TestHeaderMemberNamesAreCaseSensitive(t *testing.T) {
	ed := rfcKey(t)
	keys := Keys{"ed-1": ed.Public()}
	payload := []byte("x")
	for _, head := range []string{`{"ALG":"EdDSA","KID":"ed-1"}`, `{"alg":"EdDSA","Kid":"ed-1"}`, `{"alg":"EdDSA","kid":"ed-1","Alg":"EdDSA"}`} {
		encoded := header(t, head)
		sig, err := signInput(AlgEdDSA, ed, signingInput(encoded, payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyDetached(encoded+".."+b64.EncodeToString(sig), payload, keys); err == nil {
			t.Errorf("header %s accepted", head)
		}
	}
}

// TestES256RequiresLowS: for every ES256 signature (r, s) the pair (r, n-s) verifies as
// well. Only the lower s is accepted, so that a signature has one form.
func TestES256RequiresLowS(t *testing.T) {
	ec := ecKey(t)
	keys := Keys{"ec-1": ec.Public()}
	payload := []byte("x")
	n := elliptic.P256().Params().N
	for range 8 {
		detached, err := SignDetached(payload, "ec-1", ec)
		if err != nil {
			t.Fatal(err)
		}
		head, sigText := detached[:strings.Index(detached, ".")], detached[strings.LastIndex(detached, ".")+1:]
		sig, _ := b64.DecodeString(sigText)
		s := new(big.Int).SetBytes(sig[32:])
		if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			t.Fatal("SignDetached produced a high s")
		}
		high := append([]byte{}, sig[:32]...)
		high = append(high, new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))...)
		if _, err := VerifyDetached(head+".."+b64.EncodeToString(high), payload, keys); err == nil {
			t.Fatal("signature with the high s accepted")
		}
	}
}

func TestParseJWKSRejectsNonCanonicalEd25519Key(t *testing.T) {
	// y = p + 1 encodes the identity non-canonically (RFC 8032 section 5.1.3).
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	be := new(big.Int).Add(p, big.NewInt(1)).FillBytes(make([]byte, 32))
	le := make([]byte, 32)
	for i := range be {
		le[31-i] = be[i]
	}
	set := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + base64.RawURLEncoding.EncodeToString(le) + `"}]}`
	if _, err := ParseJWKS([]byte(set)); !errors.Is(err, ErrKey) {
		t.Fatalf("non-canonical key: err = %v, want ErrKey", err)
	}
	canonical := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + rfc8037Public + `"}]}`
	if _, err := ParseJWKS([]byte(canonical)); err != nil {
		t.Fatalf("canonical key: %v", err)
	}
}

func TestParseJWKSKeepsAcceptingNoncharactersInUnknownMembers(t *testing.T) {
	data, err := os.ReadFile("../conformance/keys/test-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	marked := bytes.Replace(data, []byte(`{`), []byte(`{"comment":"￿",`), 1)
	if _, err := ParseJWKS(marked); err != nil {
		t.Errorf("ParseJWKS = %v", err)
	}
}

const (
	testGood = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	testAtk  = "sD-Dp3g_YEAOY2QXevVAJ4llHJDBwzeaX1KSlYH_YyU"
)

func okp(members string) []byte {
	return []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k",` + members + `}]}`)
}

func TestParseJWKSReadsMemberNamesExactly(t *testing.T) {
	keys, err := ParseJWKS(okp(`"x":"` + testGood + `","X":"` + testAtk + `"`))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := b64.DecodeString(testGood)
	if got := keys["k"].(ed25519.PublicKey); !bytes.Equal(got, want) {
		t.Errorf("key = %x, want the one under x", got)
	}
	for name, set := range map[string]string{
		"upper keys only": `{"KEYS":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + testGood + `"}]}`,
		"upper kty only":  `{"keys":[{"KTY":"OKP","crv":"Ed25519","kid":"k","x":"` + testGood + `"}]}`,
		"upper crv only":  `{"keys":[{"kty":"OKP","CRV":"Ed25519","kid":"k","x":"` + testGood + `"}]}`,
		"upper kid only":  `{"keys":[{"kty":"OKP","crv":"Ed25519","KID":"k","x":"` + testGood + `"}]}`,
		"upper x only":    `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","X":"` + testGood + `"}]}`,
		"RSA with KTY":    `{"keys":[{"kty":"RSA","KTY":"OKP","crv":"Ed25519","kid":"k","x":"` + testGood + `"}]}`,
	} {
		if _, err := ParseJWKS([]byte(set)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	both := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + testGood + `"}],"KEYS":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + testAtk + `"}]}`
	keys, err = ParseJWKS([]byte(both))
	if err != nil {
		t.Fatal(err)
	}
	if got := keys["k"].(ed25519.PublicKey); !bytes.Equal(got, want) {
		t.Errorf("key = %x, want the one under keys", got)
	}
	// The upper-case D is an unknown member, like any other (RFC 7517 section 4).
	if _, err := ParseJWKS(okp(`"x":"` + testGood + `","D":"x"`)); err != nil {
		t.Errorf("unknown member D: %v", err)
	}
}

func TestParseJWKSRejectsMalformedMembers(t *testing.T) {
	for name, set := range map[string]string{
		"keys not an array": `{"keys":{}}`,
		"key not an object": `{"keys":[1]}`,
		"key is null":       `{"keys":[null]}`,
		"x not a string":    string(okp(`"x":1`)),
		"kid not a string":  `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":1,"x":"` + testGood + `"}]}`,
		"y not a string":    `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + testGood + `","y":1}]}`,
		"line feed in x":    string(okp(`"x":"` + testGood[:12] + `\n` + testGood[12:] + `"`)),
		"carriage return":   string(okp(`"x":"` + testGood + `\r\n"`)),
		"d is empty":        string(okp(`"x":"` + testGood + `","d":""`)),
		"d is null":         string(okp(`"x":"` + testGood + `","d":null`)),
		"d is not a string": string(okp(`"x":"` + testGood + `","d":1`)),
		"d has a value":     string(okp(`"x":"` + testGood + `","d":"` + testGood + `"`)),
		"no keys member":    `{}`,
		"keys is null":      `{"keys":null}`,
		"not an object":     `[]`,
	} {
		if _, err := ParseJWKS([]byte(set)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSmallOrderEd25519KeysAreRejected(t *testing.T) {
	input := []byte("any message")
	for _, encoded := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	} {
		key, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseJWKS(okp(`"x":"` + b64.EncodeToString(key) + `"`)); err == nil {
			t.Errorf("ParseJWKS accepted %s", encoded)
		}
		// Keys built directly, without a key set, are checked as well. R is the identity,
		// S = 0: for the identity this verifies for every message.
		sig := append(bytes.Clone(key[:0:0]), make([]byte, ed25519.SignatureSize)...)
		sig[0] = 1
		if verifyInput(AlgEdDSA, ed25519.PublicKey(key), input, sig) {
			t.Errorf("verifyInput accepted the key %s", encoded)
		}
	}
	// The aliases with y >= p, built directly.
	for _, encoded := range []string{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1, the identity
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p, order 4
	} {
		key, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, ed25519.SignatureSize)
		sig[0] = 1
		if verifyInput(AlgEdDSA, ed25519.PublicKey(key), input, sig) {
			t.Errorf("verifyInput accepted the alias %s", encoded)
		}
	}
	if verifyInput(AlgEdDSA, ed25519.PublicKey(make([]byte, 31)), input, make([]byte, ed25519.SignatureSize)) {
		t.Error("verifyInput accepted a key of the wrong length")
	}
}

func TestSmallOrderIdentityWouldVerifyWithoutTheCheck(t *testing.T) {
	// Guards the test above: the signature it uses does verify in the standard library.
	key, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1
	if !ed25519.Verify(ed25519.PublicKey(key), []byte("any message"), sig) {
		t.Fatal("the standard library no longer accepts this signature; the check may be obsolete")
	}
}

func TestSmallOrderKeyIsRejectedForDetachedSignatures(t *testing.T) {
	// The path of an audit checkpoint, with keys built without a key set.
	key, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	head := b64.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k"}`))
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1
	detached := head + ".." + b64.EncodeToString(sig)
	if _, err := VerifyDetached(detached, []byte("any payload"), Keys{"k": ed25519.PublicKey(key)}); !errors.Is(err, ErrSignature) {
		t.Errorf("VerifyDetached = %v, want ErrSignature", err)
	}
}

func TestMarshalJWKSRefusesWhatParseJWKSRefuses(t *testing.T) {
	weak, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	var none *ecdsa.PublicKey
	for name, key := range map[string]crypto.PublicKey{
		"small order":  ed25519.PublicKey(weak),
		"wrong length": ed25519.PublicKey(make([]byte, 31)),
		"nil P-256":    none,
	} {
		if _, err := MarshalJWKS(Keys{"k": key}); !errors.Is(err, ErrKey) {
			t.Errorf("%s: MarshalJWKS = %v, want ErrKey", name, err)
		}
	}
}

// TestSignRejectsUnusableKeys: a private key that cannot sign gives ErrKey, never a panic
// (issue #143).
func TestSignRejectsUnusableKeys(t *testing.T) {
	ec, other := ecKey(t), ecKey(t)
	p256 := func(d *big.Int, public ecdsa.PublicKey) *ecdsa.PrivateKey {
		return &ecdsa.PrivateKey{PublicKey: public, D: d}
	}
	signers := map[string]any{
		"P-256 without D":         p256(nil, ec.PublicKey),
		"P-256 without X and Y":   p256(ec.D, ecdsa.PublicKey{Curve: elliptic.P256()}),
		"P-256 with D zero":       p256(big.NewInt(0), ec.PublicKey),
		"P-256 with D too large":  p256(new(big.Int).Lsh(big.NewInt(1), 300), ec.PublicKey),
		"P-256 with D of another": p256(other.D, ec.PublicKey),
		"Ed25519 of 0 bytes":      ed25519.PrivateKey{},
		"Ed25519 of 32 bytes":     ed25519.PrivateKey(make([]byte, ed25519.SeedSize)),
		"Ed25519 of 63 bytes":     ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize-1)),
		"Ed25519 of 65 bytes":     ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize+1)),
		"nil ECDSA key":           (*ecdsa.PrivateKey)(nil),
		"ECDSA without curve":     &ecdsa.PrivateKey{},
		"nil Ed25519 key":         ed25519.PrivateKey(nil),
		"nil":                     nil,
	}
	for name, signer := range signers {
		calls := map[string]func() error{
			"Sign":          func() error { _, err := Sign([]byte("x"), "k", signer); return err },
			"SignDetached":  func() error { _, err := SignDetached([]byte("x"), "k", signer); return err },
			"SignRequest":   func() error { _, err := SignRequest(nil, RequestHeader{Kid: "k"}, signer); return err },
			"SignKeyChange": func() error { _, err := SignKeyChange([]byte("{}"), KeyChangeHeader{}, signer); return err },
		}
		for call, f := range calls {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s with %s panics: %v", call, name, r)
					}
				}()
				if err := f(); !errors.Is(err, ErrKey) {
					t.Errorf("%s with %s: err = %v, want ErrKey", call, name, err)
				}
			}()
		}
	}
}

// TestErrorsQuoteOnlyAPrefix: an error of Sign, Verify or ParseJWKS quotes at most
// maxQuotedBytes of a value it did not accept, so that input cannot fill logs (issue #143).
func TestErrorsQuoteOnlyAPrefix(t *testing.T) {
	ed := rfcKey(t)
	keys := Keys{"ed-1": ed.Public()}
	long := strings.Repeat("A", 5000)
	control := strings.Repeat(`\u0001`, 5000) // every byte quotes to \x01, four bytes
	errs := map[string]func() error{
		"Sign kid": func() error { _, err := SignDetached([]byte("x"), long, ed); return err },
		"Verify alg": func() error {
			_, err := VerifyDetached(header(t, `{"alg":"`+long+`","kid":"ed-1"}`)+"..AA", nil, keys)
			return err
		},
		"Verify kid": func() error {
			_, err := VerifyDetached(header(t, `{"alg":"EdDSA","kid":"`+long+`"}`)+"..AA", nil, keys)
			return err
		},
		"Verify dup key": func() error {
			_, err := VerifyDetached(header(t, `{"`+long+`":1,"`+long+`":2}`)+"..AA", nil, keys)
			return err
		},
		"ParseJWKS kid": func() error {
			_, err := ParseJWKS([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + long + `","x":"AA"}]}`))
			return err
		},
		"ParseJWKS kty": func() error {
			_, err := ParseJWKS([]byte(`{"keys":[{"kty":"` + long + `","kid":"k","x":"AA"}]}`))
			return err
		},
		"ParseJWKS dup": func() error {
			_, err := ParseJWKS([]byte(`{"keys":[{"` + long + `":1,"` + long + `":2}]}`))
			return err
		},
		"SignRequest alg":   func() error { _, err := SignRequest(nil, RequestHeader{Alg: long, Kid: "k"}, ed); return err },
		"SignKeyChange alg": func() error { _, err := SignKeyChange([]byte("{}"), KeyChangeHeader{Alg: long}, ed); return err },
		"ParseJWKS kty and crv of control characters": func() error {
			_, err := ParseJWKS([]byte(`{"keys":[{"kty":"` + control + `","crv":"` + control + `","kid":"k","x":"AA"}]}`))
			return err
		},
	}
	for name, f := range errs {
		err := f()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), long[:maxQuotedBytes+1]) || !strings.Contains(err.Error(), `"...`) {
			t.Errorf("%s: err does not quote a cut value: %.200s", name, err)
		}
		if len(err.Error()) > maxErrorBytes {
			t.Errorf("%s: err of %d bytes: %.200s", name, len(err.Error()), err)
		}
	}
}
