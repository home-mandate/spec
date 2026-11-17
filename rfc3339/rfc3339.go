// SPDX-License-Identifier: Apache-2.0

// Package rfc3339 reads timestamps by the grammar of RFC 3339 and the narrower rules of
// SPEC-v0 section 3.1 item 0. time.Parse alone also accepts a comma before the fraction, a
// one-digit hour and an offset of 24 hours or 60 minutes.
package rfc3339

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var form = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// Parse reads a timestamp with an offset by the rules of SPEC-v0 section 3.1 item 0, which
// apply to the fields of a document and to the point in time of a request alike: the
// grammar of RFC 3339 with an upper-case T and Z, at most 9 fractional digits, no leap
// second, not in the year 0000 and not with the offset -00:00.
func Parse(s string) (time.Time, error) {
	if !form.MatchString(s) || strings.HasPrefix(s, "0000") || strings.HasSuffix(s, "-00:00") {
		return time.Time{}, fmt.Errorf("%q is no RFC 3339 timestamp by SPEC-v0 section 3.1 item 0", s)
	}
	return time.Parse(time.RFC3339, s)
}
