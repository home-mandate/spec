// SPDX-License-Identifier: Apache-2.0

// Package rfc3339 reads timestamps by the grammar of RFC 3339. time.Parse alone also
// accepts a comma before the fraction, a one-digit hour and an offset of 24 hours or 60
// minutes.
package rfc3339

import (
	"fmt"
	"regexp"
	"time"
)

var form = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// Parse reads a timestamp with an offset. The narrower rules for the fields of a document
// (SPEC-v0 section 3.1 item 0) are the schema's.
func Parse(s string) (time.Time, error) {
	if !form.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q is no RFC 3339 timestamp", s)
	}
	return time.Parse(time.RFC3339, s)
}
