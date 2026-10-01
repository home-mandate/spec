// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	mandatespec "github.com/mandate-spec/mandate-spec"
)

// MaxMandateBytes ist die größte Eingabe, die Parse annimmt. 200 Regeln brauchen weit weniger.
const MaxMandateBytes = 256 << 10

// Fehlerarten von Parse; mit errors.Is prüfbar.
var (
	ErrTooLarge  = errors.New("evaluator: mandate too large")
	ErrMalformed = errors.New("evaluator: malformed mandate JSON")
	ErrSchema    = errors.New("evaluator: mandate violates schema")
	ErrSemantic  = errors.New("evaluator: mandate violates SPEC-v0 section 3.1")
)

const mandateSchemaURL = "https://mandate-spec.org/mandate/v0/mandate.schema.json"

// mandateSchema kompiliert das eingebettete Schema einmal. Formate werden geprüft
// (SPEC-v0 Abschnitt 3.1 Nr. 0), nicht nur als Anmerkung behandelt.
var mandateSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	data, err := fs.ReadFile(mandatespec.FS(), mandatespec.MandateSchemaPath)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(mandateSchemaURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(mandateSchemaURL)
})

// Parse prüft data nach SPEC-v0 Abschnitt 3.1 und liefert das gültige Mandat mit seinem
// Fingerabdruck (Abschnitt 3.2). Bei jedem Fehler ist das Mandat nil.
func Parse(data []byte) (*Mandate, error) {
	if len(data) > MaxMandateBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(data), MaxMandateBytes)
	}
	if err := checkJSONStructure(data); err != nil {
		return nil, err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	schema, err := mandateSchema()
	if err != nil {
		return nil, fmt.Errorf("evaluator: load schema: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	var raw rawMandate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	digest, err := digestOf(instance)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	return buildMandate(raw, digest)
}
