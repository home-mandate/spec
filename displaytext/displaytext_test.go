// SPDX-License-Identifier: Apache-2.0

package displaytext_test

import (
	"errors"
	"testing"

	"github.com/mandate-spec/mandate-spec/displaytext"
)

func TestCheckAcceptsOrdinaryNames(t *testing.T) {
	for name, s := range map[string]string{
		"ascii":                "Voice Assistant",
		"german":               "Küchen-Assistent",
		"inner no-break space": "Voice\u00a0Assistant",
		"persian with ZWNJ":    "می\u200cخواهم",
		"hindi with ZWJ":       "क्\u200dष",
		"emoji ZWJ sequence":   "👨\u200d👩\u200d👧",
		"emoji presentation":   "❤\ufe0f home",
		"cjk":                  "音声アシスタント",
		"combining mark":       "é",
		"single letter":        "A",
	} {
		if err := displaytext.Check(s); err != nil {
			t.Errorf("%s: Check(%q) = %v", name, s, err)
		}
	}
}

func TestCheckRejectsMisleadingText(t *testing.T) {
	for name, s := range map[string]string{
		"control character":          "a\u0007b",
		"line feed":                  "a\nb",
		"NUL":                        "a\u0000b",
		"bidi override":              "a\u202egnp.exe",
		"bidi isolate":               "a\u2066b",
		"zero width space":           "a\u200bb",
		"soft hyphen":                "a\u00adb",
		"line separator":             "a\u2028b",
		"paragraph separator":        "a\u2029b",
		"byte order mark":            string(rune(0xfeff)) + "a",
		"hangul filler":              "\u3164",
		"private use":                "a\ue000b",
		"private use plane 15":       "a\U000f0000b",
		"tag character":              "A\U000e0041",
		"leading space":              " a",
		"trailing space":             "a ",
		"only spaces":                "   ",
		"only no-break space":        "\u00a0",
		"trailing ideographic space": "a\u3000",
		"leading ZWJ":                "\u200da",
		"trailing ZWNJ":              "a\u200c",
		"two joiners in a row":       "a\u200d\u200cb",
		"only a joiner":              "\u200d",
		"empty":                      "",
		"invalid UTF-8":              "a\xffb",
	} {
		if err := displaytext.Check(s); !errors.Is(err, displaytext.ErrMisleading) {
			t.Errorf("%s: Check(%q) = %v, want ErrMisleading", name, s, err)
		}
	}
}

func TestUnicodeVersionIsPinned(t *testing.T) {
	if got := displaytext.UnicodeVersion(); got != "17.0.0" {
		t.Errorf("UnicodeVersion() = %q, want 17.0.0", got)
	}
}
