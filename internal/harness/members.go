// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// exactMembers checks a request line against the protocol before it is decoded: every member
// name is spelled exactly as the protocol defines it, and no member occurs twice in an
// object. encoding/json alone matches names without regard to case and keeps the last of a
// repeated member (SPEC-v0 section 10.2). What the protocol carries as raw JSON, such as a key
// set, is passed on unchecked: its content is what a case is about.
func exactMembers(line []byte) error {
	return membersOf(line, reflect.TypeFor[Request]())
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// membersOf reports a member of raw that t does not define or that occurs twice, at any
// depth. Values of the wrong JSON type are left to the decoder, which reports them.
func membersOf(raw []byte, t reflect.Type) error {
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
				return fmt.Errorf("harness: unknown member %q", name)
			}
			return membersOf(value, field)
		})
	case reflect.Map:
		return eachMember(raw, func(_ string, value []byte) error { return membersOf(value, t.Elem()) })
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil
		}
		for _, item := range items {
			if err := membersOf(item, t.Elem()); err != nil {
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
