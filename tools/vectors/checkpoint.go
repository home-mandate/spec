// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"

	"github.com/home-mandate/spec/audit"
	"github.com/home-mandate/spec/evaluator"
	"github.com/home-mandate/spec/jws"
)

type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	D   string `json:"d"`
	// N, E, P and Q are set for RSA keys only.
	N string `json:"n"`
	E string `json:"e"`
	P string `json:"p"`
	Q string `json:"q"`
}

// rsaKey builds an RSA key of a test key set; it serves only for a request that is refused.
func rsaKey(k privateJWK, d []byte) (*rsa.PrivateKey, error) {
	var ints []*big.Int
	for _, s := range []string{k.N, k.E, k.P, k.Q} {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("key %q: RSA member", k.Kid)
		}
		ints = append(ints, new(big.Int).SetBytes(b))
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: ints[0], E: int(ints[1].Int64())},
		D:         new(big.Int).SetBytes(d),
		Primes:    []*big.Int{ints[2], ints[3]},
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("key %q: %w", k.Kid, err)
	}
	key.Precompute()
	return key, nil
}

// runCheckpoint prints the signature of a checkpoint (SPEC-v0 section 9.5), signed
// with a test key from a JWK Set that contains private keys.
func runCheckpoint(args []string, dir string, stdout io.Writer) error {
	if len(args) != 6 {
		return errors.New("usage: vectors checkpoint <private JWK Set> <kid> <log ID> <seq> <digest> <recorded_at of the checkpoint entry>")
	}
	signer, err := privateKey(resolve(dir, args[0]), args[1])
	if err != nil {
		return err
	}
	seq, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil {
		return fmt.Errorf("seq: %w", err)
	}
	signature, err := audit.SignCheckpoint(args[2], seq, args[4], args[5], args[1], signer)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, signature)
	return err
}

func resolve(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func privateKey(path, kid string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys: %w", err)
	}
	var set struct {
		Keys []privateJWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		d, err := base64.RawURLEncoding.DecodeString(k.D)
		if err != nil || len(d) == 0 {
			return nil, fmt.Errorf("key %q has no private part", kid)
		}
		switch {
		case k.Kty == "OKP" && k.Crv == "Ed25519" && len(d) == ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(d), nil
		case k.Kty == "EC" && k.Crv == "P-256":
			return ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		case k.Kty == "EC" && k.Crv == "P-384":
			return ecdsa.ParseRawPrivateKey(elliptic.P384(), d)
		case k.Kty == "RSA":
			return rsaKey(k, d)
		}
		return nil, fmt.Errorf("key %q: unsupported type", kid)
	}
	return nil, fmt.Errorf("key %q not found", kid)
}

// runSign prints a compact JWS over a file, signed with a test key: over its canonical
// form (SPEC-v0 section 7) or, with -raw, over its bytes as they are, for cases about
// payloads that are not canonical.
func runSign(args []string, dir string, stdout io.Writer) error {
	raw := len(args) > 0 && args[0] == "-raw"
	if raw {
		args = args[1:]
	}
	if len(args) != 3 {
		return errors.New("usage: vectors sign [-raw] <private JWK Set> <kid> <file>")
	}
	signer, err := privateKey(resolve(dir, args[0]), args[1])
	if err != nil {
		return err
	}
	payload, err := os.ReadFile(resolve(dir, args[2]))
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if !raw {
		if payload, err = evaluator.Canonical(payload); err != nil {
			return err
		}
	}
	compact, err := jws.Sign(payload, args[1], signer)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, compact)
	return err
}
