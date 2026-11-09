// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"strings"
	"testing"
	"unicode/utf8"
)

const hostile = "line\n::error::boom‮evil\x00\x1b[31m \U0001F600 \xff"

func TestEscQuotesEverythingNotPrintableASCII(t *testing.T) {
	got := esc(hostile)
	for _, r := range got {
		if r < 0x20 || r >= 0x7f {
			t.Fatalf("esc left %U in %q", r, got)
		}
	}
	if !strings.HasPrefix(got, `"`) || strings.Contains(got, "\n") {
		t.Errorf("esc = %s", got)
	}
}

func TestCleanEscapesAndCuts(t *testing.T) {
	if got := clean("plain text 123"); got != "plain text 123" {
		t.Errorf("clean changed a plain text: %q", got)
	}
	got := clean(hostile)
	for i := 0; i < len(got); i++ {
		if got[i] < 0x20 || got[i] >= 0x7f {
			t.Fatalf("clean left byte %#x in %q", got[i], got)
		}
	}
	for _, want := range []string{"\\u000a", "\\u202e", "\\U0001f600", "\\ufffd"} {
		if !strings.Contains(got, want) {
			t.Errorf("clean(%q) = %s, missing %s", hostile, got, want)
		}
	}
	long := strings.Repeat("é", 500)
	if n := utf8.RuneCountInString(truncate(long, maxText)); n != maxText {
		t.Errorf("truncate left %d characters", n)
	}
	if n := len(clean(strings.Repeat("a", 500))); n != maxText {
		t.Errorf("clean left %d characters", n)
	}
}
