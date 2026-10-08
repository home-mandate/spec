// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/internal/ijson"
	"github.com/home-mandate/spec/jcs"
	"github.com/home-mandate/spec/schema"
)

// MaxMandateBytes is the size limit from SPEC-v0 section 3.1 item 5.
const MaxMandateBytes = 256 << 10

// Error kinds returned by Parse; check them with errors.Is. The underlying cause stays
// wrapped as well and is reachable with errors.As.
var (
	ErrTooLarge  = errors.New("evaluator: mandate too large")
	ErrMalformed = errors.New("evaluator: malformed mandate JSON")
	ErrSchema    = errors.New("evaluator: mandate violates schema")
	ErrSemantic  = errors.New("evaluator: mandate violates SPEC-v0 section 3.1")
)

// mandateSchema compiles the embedded schema once. Formats are asserted
// (SPEC-v0 section 3.1 item 0), not merely treated as annotations.
var mandateSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Mandate()))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(schema.MandateID, doc); err != nil {
		return nil, err
	}
	return c.Compile(schema.MandateID)
})

// Parse checks data according to SPEC-v0 section 3.1 and returns the valid mandate with
// its digest (section 3.2). On any error the mandate is nil. The mandate holds no
// reference to data.
func Parse(data []byte) (*Mandate, error) {
	if len(data) > MaxMandateBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(data), MaxMandateBytes)
	}
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	compiled, err := mandateSchema()
	if err != nil {
		return nil, fmt.Errorf("evaluator: load schema: %w", err)
	}
	if err := compiled.Validate(instance); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	var raw rawMandate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	digest, err := jcs.Digest(instance)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	return buildMandate(raw, digest)
}
