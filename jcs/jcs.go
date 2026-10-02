// SPDX-License-Identifier: Apache-2.0

// Package jcs implements the JSON Canonicalization Scheme (RFC 8785) for the subset
// mandate-spec uses, and the digests of SPEC-v0 sections 3.2 and 9.4.
package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf16"
)

// maxExactInteger is 2^53; above it, integers are no longer exact in IEEE 754.
const maxExactInteger = 1 << 53

// Digest returns "sha256:" + hex(SHA-256(JCS(v))) according to SPEC-v0 sections 3.2
// and 9.4. v is a value decoded with json.Number for numbers.
func Digest(v any) (string, error) {
	canonical, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Canonicalize returns v in the canonical form according to RFC 8785 (JCS). It supports
// the subset used by mandates and audit log entries: null, booleans, strings,
// integers as json.Number, arrays and objects.
func Canonicalize(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		writeCanonicalString(b, x)
	case json.Number:
		n, err := canonicalNumber(x)
		if err != nil {
			return err
		}
		b.WriteString(n)
	case []any:
		return writeCanonicalArray(b, x)
	case map[string]any:
		return writeCanonicalObject(b, x)
	default:
		return fmt.Errorf("canonical JSON: unsupported type %T", v)
	}
	return nil
}

func writeCanonicalArray(b *bytes.Buffer, items []any) error {
	b.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeCanonical(b, item); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

func writeCanonicalObject(b *bytes.Buffer, object map[string]any) error {
	keys := make([]string, 0, len(object))
	for k := range object {
		keys = append(keys, k)
	}
	// RFC 8785 section 3.2.3: sort by UTF-16 code units.
	slices.SortFunc(keys, func(a, c string) int {
		return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(c)))
	})
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeCanonicalString(b, k)
		b.WriteByte(':')
		if err := writeCanonical(b, object[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// canonicalNumber accepts only integers in the exactly representable range. For them,
// the RFC 8785 number serialization equals decimal notation without an exponent.
func canonicalNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return "", fmt.Errorf("canonical JSON: invalid number %q", n)
	}
	if f != math.Trunc(f) || math.Abs(f) >= maxExactInteger {
		return "", fmt.Errorf("canonical JSON: unsupported number %q", n)
	}
	return strconv.FormatInt(int64(f), 10), nil
}

// writeCanonicalString escapes according to RFC 8785 section 3.2.2.2: only quotation mark,
// backslash and control characters below U+0020; everything else stays UTF-8.
func writeCanonicalString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
