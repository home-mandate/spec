// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/relay"
)

const enrollmentSchemaID = "https://home-mandate.org/relay-enrollment/v0/enrollment.schema.json"

var (
	enrollSchemas   = map[string]*jsonschema.Schema{}
	enrollSchemasMu sync.Mutex
)

// enrollmentDef returns the definition def of the enrollment schema.
func enrollmentDef(def string) *jsonschema.Schema {
	enrollSchemasMu.Lock()
	defer enrollSchemasMu.Unlock()
	if s, ok := enrollSchemas[def]; ok {
		return s
	}
	c := jsonschema.NewCompiler()
	for id, path := range map[string]string{metadataSchema: relay.MetadataSchemaPath, enrollmentSchemaID: relay.EnrollmentSchemaPath} {
		doc := must(jsonschema.UnmarshalJSON(bytes.NewReader(must(relayFile(path)))))
		must0(c.AddResource(id, doc))
	}
	s := must(c.Compile(enrollmentSchemaID + "#/$defs/" + def))
	enrollSchemas[def] = s
	return s
}

// schemaProblem returns "" if the body is valid against the definition, else the places of
// the violations.
func schemaProblem(def string, body []byte) string {
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return def + " is not JSON"
	}
	err = enrollmentDef(def).Validate(instance)
	if err == nil {
		return ""
	}
	violation, _ := err.(*jsonschema.ValidationError)
	return def + " violates the schema at " + strings.Join(locations(violation), ", ")
}
