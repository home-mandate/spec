// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/mandate-spec/mandate-spec/schema"
)

// MaxMandateBytes ist die Größengrenze aus SPEC-v0 Abschnitt 3.1 Nr. 5.
const MaxMandateBytes = 256 << 10

// Fehlerarten von Parse; mit errors.Is prüfbar. Die Ursache bleibt ebenfalls verpackt
// und ist mit errors.As erreichbar.
var (
	ErrTooLarge  = errors.New("evaluator: mandate too large")
	ErrMalformed = errors.New("evaluator: malformed mandate JSON")
	ErrSchema    = errors.New("evaluator: mandate violates schema")
	ErrSemantic  = errors.New("evaluator: mandate violates SPEC-v0 section 3.1")
)

// mandateSchema kompiliert das eingebettete Schema einmal. Formate werden geprüft
// (SPEC-v0 Abschnitt 3.1 Nr. 0), nicht nur als Anmerkung behandelt.
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

// Parse prüft data nach SPEC-v0 Abschnitt 3.1 und liefert das gültige Mandat mit seinem
// Fingerabdruck (Abschnitt 3.2). Bei jedem Fehler ist das Mandat nil. Das Mandat hält
// keine Referenz auf data.
func Parse(data []byte) (*Mandate, error) {
	if len(data) > MaxMandateBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(data), MaxMandateBytes)
	}
	if err := checkJSONStructure(data); err != nil {
		return nil, err
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
	digest, err := digestOf(instance)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	return buildMandate(raw, digest)
}
