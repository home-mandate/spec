// SPDX-License-Identifier: Apache-2.0

package evaluator

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

// maxExactInteger ist 2^53; darüber sind ganze Zahlen in IEEE 754 nicht mehr exakt.
const maxExactInteger = 1 << 53

// digestOf liefert den Fingerabdruck nach SPEC-v0 Abschnitt 3.2.
func digestOf(v any) (string, error) {
	canonical, err := canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// canonicalize schreibt v in der kanonischen Form nach RFC 8785 (JCS). Unterstützt wird
// die Teilmenge, die Mandate und Protokolleinträge nutzen: null, Wahrheitswerte,
// Zeichenketten, ganze Zahlen als json.Number, Listen und Objekte.
func canonicalize(v any) ([]byte, error) {
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
	// RFC 8785 Abschnitt 3.2.3: Sortierung nach UTF-16-Codeeinheiten.
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

// canonicalNumber akzeptiert nur ganze Zahlen im exakt darstellbaren Bereich. Für sie
// entspricht die Zahlendarstellung von RFC 8785 der dezimalen Schreibweise ohne Exponent.
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

// writeCanonicalString maskiert nach RFC 8785 Abschnitt 3.2.2.2: nur Anführungszeichen,
// Backslash und Steuerzeichen unter U+0020; alles andere bleibt UTF-8.
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
