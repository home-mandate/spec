// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"encoding/json"
	"testing"

	"github.com/mandate-spec/mandate-spec/schema"
)

func TestSchemasDeclareTheirIDs(t *testing.T) {
	for name, tt := range map[string]struct {
		data func() []byte
		id   string
	}{
		"mandate": {schema.Mandate, schema.MandateID},
		"audit":   {schema.Audit, schema.AuditID},
	} {
		var doc struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(tt.data(), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc.ID != tt.id {
			t.Errorf("%s: $id = %q, want %q", name, doc.ID, tt.id)
		}
	}
}

func TestSchemasAreCopies(t *testing.T) {
	first := schema.Mandate()
	first[0] = 'X'
	if schema.Mandate()[0] == 'X' {
		t.Error("Mandate() returned shared bytes")
	}
	audit := schema.Audit()
	audit[0] = 'X'
	if schema.Audit()[0] == 'X' {
		t.Error("Audit() returned shared bytes")
	}
}
