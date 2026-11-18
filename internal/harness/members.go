// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// exactMembers checks a request line against the protocol before it is decoded: every member
// name is spelled exactly as the protocol defines it, and no member occurs twice in an
// object. encoding/json alone matches names without regard to case and keeps the last of a
// repeated member (SPEC-v0 section 10.2). What the protocol carries as raw JSON, such as the
// parameters of a request, is passed on unchecked: its content is what a case is about.
func exactMembers(line []byte) error {
	return membersOf(line, reflect.TypeFor[Request](), false)
}

// responseMembers are the members of the response to each operation (SPEC-v0 section 10.2).
var responseMembers = map[string][]string{
	OpCapabilities: {"name", "version", "ops"},
	OpValidate:     {"valid", "digest"},
	OpEvaluate:     {"decision", "reason", "rule_id", "approval_timeout", "approvers", "mandate_digest", "enforced", "confirm", "limited_rules"},
	OpSelect:       {"decision", "reason", "rule_id", "approval_timeout", "approvers", "mandate_digest", "enforced", "confirm", "selected", "limited_rules"},
	OpSuccession:   {"accept", "confirm"},
	OpVerifySigned: {"valid", "digest"},
	OpVerifyAudit: {"valid", "entries", "broken_at", "anchored", "integrity_broken_at", "conformance_broken_at",
		"unknown_version_at", "checkpoint_gap_at"},
	OpEntryDigest: {"digest"},
}

// exactResponse checks a response line of the process binding to an operation as
// exactMembers checks a request: a member the operation does not define, a name in another
// case, a member that occurs twice or is null fails the case, and error stands alone (SPEC-v0
// section 10.2).
func exactResponse(line []byte, op string) error {
	if err := membersOf(line, reflect.TypeFor[Response](), false); err != nil {
		return err
	}
	allowed := responseMembers[op]
	var names []string
	err := eachMember(line, func(name string, value []byte) error {
		if string(bytes.TrimSpace(value)) == "null" {
			return fmt.Errorf("harness: member %q is null", name)
		}
		if name != "error" && !slices.Contains(allowed, name) {
			return fmt.Errorf("harness: member %q is not one of the response to %s", name, op)
		}
		names = append(names, name)
		return nil
	})
	if err == nil && slices.Contains(names, "error") && len(names) > 1 {
		return errors.New("harness: error with other members")
	}
	return err
}

// exactNames checks a response of another protocol, such as AuthZEN, that may carry members
// this tool does not read: those are allowed, but a member it reads must be spelled exactly
// and occur once.
func exactNames(raw []byte, t reflect.Type) error {
	return membersOf(raw, t, true)
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// membersOf reports a member of raw that t does not define or that occurs twice, at any
// depth. Values of the wrong JSON type are left to the decoder, which reports them.
func membersOf(raw []byte, t reflect.Type, allowUnknown bool) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		fields := fieldsOf(t)
		return eachMember(raw, func(name string, value []byte) error {
			field, ok := fields[name]
			if !ok {
				if allowUnknown && !sameButCase(fields, name) {
					return nil
				}
				return fmt.Errorf("harness: unknown member %q", name)
			}
			return membersOf(value, field, allowUnknown)
		})
	case reflect.Map:
		return eachMember(raw, func(_ string, value []byte) error { return membersOf(value, t.Elem(), allowUnknown) })
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil
		}
		for _, item := range items {
			if err := membersOf(item, t.Elem(), allowUnknown); err != nil {
				return err
			}
		}
	}
	return nil
}

// eachMember calls f for each member of the JSON object raw, in order, and reports a name that
// occurs twice. A value that is not an object is left to the decoder.
func eachMember(raw []byte, f func(name string, value []byte) error) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		// Inside an object, encoding/json gives a member name as a string or an error.
		name, _ := tok.(string)
		if seen[name] {
			return fmt.Errorf("harness: member %q twice", name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		if err := f(name, value); err != nil {
			return err
		}
	}
	return nil
}

// sameButCase reports whether name differs from a field's name only in case, which
// encoding/json would match.
func sameButCase(fields map[string]reflect.Type, name string) bool {
	for f := range fields {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}

// fieldsOf maps the JSON names of a struct's fields to their types.
func fieldsOf(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = f.Type
	}
	return fields
}
