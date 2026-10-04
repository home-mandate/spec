// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testUnicodeData = `0000;<control>;Cc;0;BN;;;;;N;NULL;;;;
0001;<control>;Cc;0;BN;;;;;N;START OF HEADING;;;;
0020;SPACE;Zs;0;WS;;;;;N;;;;;
0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;
00AD;SOFT HYPHEN;Cf;0;BN;;;;;N;;;;;
200C;ZERO WIDTH NON-JOINER;Cf;0;BN;;;;;N;;;;;
200D;ZERO WIDTH JOINER;Cf;0;BN;;;;;N;;;;;
200E;LEFT-TO-RIGHT MARK;Cf;0;L;;;;;N;;;;;
2028;LINE SEPARATOR;Zl;0;WS;;;;;N;;;;;
2029;PARAGRAPH SEPARATOR;Zp;0;B;;;;;N;;;;;
3164;HANGUL FILLER;Lo;0;L;;;;;N;;;;;
D800;<Non Private Use High Surrogate, First>;Cs;0;L;;;;;N;;;;;
DB7F;<Non Private Use High Surrogate, Last>;Cs;0;L;;;;;N;;;;;
E000;<Private Use, First>;Co;0;L;;;;;N;;;;;
F8FF;<Private Use, Last>;Co;0;L;;;;;N;;;;;
0301;COMBINING ACUTE ACCENT;Mn;230;NSM;;;;;N;NON-SPACING ACUTE;;;;
2800;BRAILLE PATTERN BLANK;So;0;L;;;;;N;;;;;
FE0F;VARIATION SELECTOR-16;Mn;0;NSM;;;;;N;;;;;
`

const testDerivedCoreProperties = `# DerivedCoreProperties-17.0.0.txt
00AD          ; Default_Ignorable_Code_Point # Cf       SOFT HYPHEN
200B..200F    ; Default_Ignorable_Code_Point # Cf   [5] ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
3164          ; Default_Ignorable_Code_Point # Lo       HANGUL FILLER
FE00..FE0F    ; Default_Ignorable_Code_Point # Mn  [16] VARIATION SELECTOR-1..VARIATION SELECTOR-16
0041          ; Alphabetic # Lu       LATIN CAPITAL LETTER A
`

const testPropList = `# PropList-17.0.0.txt
0009..000D    ; White_Space # Cc   [5] <control-0009>..<control-000D>
0020          ; White_Space # Zs       SPACE
2028          ; White_Space # Zl       LINE SEPARATOR
00A0          ; White_Space # Zs       NO-BREAK SPACE
FE00..FE0F    ; Variation_Selector # Mn  [16] VARIATION SELECTOR-1..VARIATION SELECTOR-16
FDD0..FDEF    ; Noncharacter_Code_Point # Cn  [32] <noncharacter-FDD0>..<noncharacter-FDEF>
`

func writeUCD(t *testing.T, unicodeData, derived, propList string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"UnicodeData.txt": unicodeData, "DerivedCoreProperties.txt": derived, "PropList.txt": propList,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCodepointsDerivesTheListFromTheUCD(t *testing.T) {
	ucd := writeUCD(t, testUnicodeData, testDerivedCoreProperties, testPropList)
	out, err := runTool(t, ".", "", "codepoints", ucd)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Description    string   `json:"description"`
		UnicodeVersion string   `json:"unicode_version"`
		Forbidden      [][2]int `json:"forbidden"`
		Joiners        []int    `json:"joiners"`
		NotFirst       [][2]int `json:"not_first"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if got.UnicodeVersion != "17.0.0" || got.Description == "" {
		t.Errorf("version %q, description %q", got.UnicodeVersion, got.Description)
	}
	// Cc 0-1 and the white space 9-D, no-break space, soft hyphen, 200B and 200E-200F (200C
	// and 200D are joiners), Zl and Zp, braille blank, Hangul filler, surrogates, private
	// use, noncharacters, object replacement; the space and the variation selectors are exempt.
	wantForbidden := [][2]int{{0x0, 0x1}, {0x9, 0xD}, {0xA0, 0xA0}, {0xAD, 0xAD}, {0x200B, 0x200B}, {0x200E, 0x200F},
		{0x2028, 0x2029}, {0x2800, 0x2800}, {0x3164, 0x3164}, {0xD800, 0xDB7F}, {0xE000, 0xF8FF}, {0xFDD0, 0xFDEF}, {0xFFFC, 0xFFFC}}
	if !reflect.DeepEqual(got.Forbidden, wantForbidden) {
		t.Errorf("forbidden = %x\nwant        %x", got.Forbidden, wantForbidden)
	}
	if !reflect.DeepEqual(got.Joiners, []int{0x200C, 0x200D}) {
		t.Errorf("joiners = %x", got.Joiners)
	}
	if want := [][2]int{{0x301, 0x301}, {0xFE00, 0xFE0F}}; !reflect.DeepEqual(got.NotFirst, want) {
		t.Errorf("not_first = %x, want %x", got.NotFirst, want)
	}
}

func TestCodepointsRejectsBrokenUCD(t *testing.T) {
	for name, files := range map[string][3]string{
		"no version":         {testUnicodeData, "no header\n", testPropList},
		"bad code point":     {"ZZZZ;X;Cc;\n", testDerivedCoreProperties, testPropList},
		"too few fields":     {"0000;X\n", testDerivedCoreProperties, testPropList},
		"first without last": {"E000;<Private Use, First>;Co;\n", testDerivedCoreProperties, testPropList},
		"bad range":          {testUnicodeData, testDerivedCoreProperties, "# x\n0020..ZZ ; White_Space\n"},
		"range without name": {testUnicodeData, "# DerivedCoreProperties-17.0.0.txt\n00AD\n", testPropList},
	} {
		ucd := writeUCD(t, files[0], files[1], files[2])
		if _, err := runTool(t, ".", "", "codepoints", ucd); err == nil {
			t.Errorf("%s: codepoints accepted the input", name)
		}
	}
	if _, err := runTool(t, ".", "", "codepoints"); err == nil {
		t.Error("codepoints accepted a call without a directory")
	}
	if _, err := runTool(t, ".", "", "codepoints", t.TempDir()); err == nil || !strings.Contains(err.Error(), "UnicodeData.txt") {
		t.Errorf("codepoints with an empty directory: %v", err)
	}
}
