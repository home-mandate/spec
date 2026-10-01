// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxNestingDepth limits nesting; valid mandates need no more than 5 levels.
const maxNestingDepth = 32

// checkJSONStructure checks what the schema validator and encoding/json do not
// (SPEC-v0 section 3.1 item 1): exactly one JSON value, valid UTF-8, no lone
// surrogates, no duplicate keys, bounded depth.
func checkJSONStructure(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrMalformed)
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}
	return checkTokens(data)
}

type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

func checkTokens(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []jsonFrame
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		if len(stack) == 0 {
			values++
			if values > 1 {
				return fmt.Errorf("%w: data after the first JSON value", ErrMalformed)
			}
		}
		stack, err = applyToken(stack, tok)
		if err != nil {
			return err
		}
	}
	if values == 0 {
		return fmt.Errorf("%w: empty input", ErrMalformed)
	}
	if len(stack) != 0 {
		return fmt.Errorf("%w: unexpected end of input", ErrMalformed)
	}
	return nil
}

func applyToken(stack []jsonFrame, tok json.Token) ([]jsonFrame, error) {
	if delim, ok := tok.(json.Delim); ok && (delim == '}' || delim == ']') {
		return stack[:len(stack)-1], nil
	}
	if len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.object && top.expectKey {
			key, _ := tok.(string) // The decoder guarantees a string in key position.
			if _, dup := top.keys[key]; dup {
				return nil, fmt.Errorf("%w: duplicate key %q", ErrMalformed, key)
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			return stack, nil
		}
		if top.object {
			top.expectKey = true // a key follows again after this value
		}
	}
	if delim, ok := tok.(json.Delim); ok {
		if len(stack) >= maxNestingDepth {
			return nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, maxNestingDepth)
		}
		frame := jsonFrame{object: delim == '{'}
		if frame.object {
			frame.expectKey = true
			frame.keys = make(map[string]struct{})
		}
		stack = append(stack, frame)
	}
	return stack, nil
}

// checkSurrogates rejects escape sequences for lone UTF-16 surrogates. encoding/json
// would silently replace them with U+FFFD, so different inputs would have the same
// digest. Syntax errors are left to checkTokens.
func checkSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' || i+1 >= len(data) {
			continue
		}
		if data[i+1] != 'u' {
			i++ // skip the escaped character, e.g. \" or \\
			continue
		}
		unit, ok := hex4(data, i+2)
		if !ok {
			continue
		}
		i += 5
		switch {
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return fmt.Errorf("%w: unpaired low surrogate", ErrMalformed)
		case unit >= 0xD800 && unit <= 0xDBFF:
			next := i + 1
			if next+1 >= len(data) || data[next] != '\\' || data[next+1] != 'u' {
				return fmt.Errorf("%w: unpaired high surrogate", ErrMalformed)
			}
			low, ok := hex4(data, next+2)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return fmt.Errorf("%w: unpaired high surrogate", ErrMalformed)
			}
			i = next + 5
		}
	}
	return nil
}

func hex4(data []byte, pos int) (uint64, bool) {
	if pos+4 > len(data) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(data[pos:pos+4]), 16, 16)
	return v, err == nil
}
