// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// maxText is how many characters of a text from the operator reach a report.
	maxText = 200
	// maxFailures is how many failures a report lists.
	maxFailures = 200
)

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// esc quotes a text from the operator for output: cut to maxText characters, in ASCII, with
// the control, format and non-ASCII characters escaped. A line break or a U+202E in it cannot
// start a line of its own or reorder the text around it.
func esc(s string) string {
	return strconv.QuoteToASCII(truncate(s, maxText))
}

// clean is the last line of defence for every text of a report: cut to maxText characters,
// and everything but printable ASCII escaped. Texts of the tool pass unchanged.
func clean(s string) string {
	var b strings.Builder
	for _, r := range truncate(s, maxText) {
		switch {
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}
