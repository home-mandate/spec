// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/home-mandate/spec/audit"
)

// entryWith is a valid first entry whose entity_id is the given JSON string content.
func entryWith(entityID string) []byte {
	return []byte(`{"agent":{"client_id":"hm-client:voice-7c21e9a4"},"evaluation":{"decision":"deny","reason":"invalid_request","rule_id":null},` +
		`"event":"decision","id":"01a0f64c-7140-7001-9007-0000a2130001","mandate":{"id":"m-voice-assistant","digest":"sha256:` + strings.Repeat("1", 64) + `"},` +
		`"prev":null,"principal":"household:hm-7f3a","recorded_at":"2026-10-01T09:01:00+02:00","request":{"time":"2026-10-12T19:00:00+02:00",` +
		`"timezone":"Europe/Berlin","resource":{"entity_id":"` + entityID + `"},"action":"turn_on"},"result":{"status":"denied","denied_by":"mandate"},"seq":1,"type":"https://home-mandate.org/audit/v0"}`)
}

func TestVerifyKeepsAcceptingNoncharactersInExistingLogs(t *testing.T) {
	const escape = `\` + "u"
	for name, id := range map[string]string{
		"plain":   "light.kitchen",
		"escaped": "light." + escape + "ffff",
		"raw":     "light.￿",
		"plane 1": "light." + escape + "d83f" + escape + "dfff",
	} {
		t.Run(name, func(t *testing.T) {
			r, err := audit.Verify([][]byte{entryWith(id)})
			if err != nil || !r.Valid || r.Entries != 1 {
				t.Errorf("Verify = %+v, %v, want a valid log of 1 entry", r, err)
			}
			if _, err := audit.Digest(entryWith(id)); err != nil {
				t.Errorf("Digest = %v", err)
			}
		})
	}
}

func TestSpellingsOfANoncharacterHaveOneDigest(t *testing.T) {
	escaped, err := audit.Digest(entryWith("light." + `\` + "uffff"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := audit.Digest(entryWith("light.￿"))
	if err != nil {
		t.Fatal(err)
	}
	if escaped != raw {
		t.Errorf("digests differ: %s, %s", escaped, raw)
	}
}

func TestVerifyStillRejectsWhatNoCorrectionCovers(t *testing.T) {
	for name, entry := range map[string][]byte{
		"lone surrogate": entryWith("light." + `\` + "ud800"),
		"duplicate key":  bytes.Replace(entryWith("light.kitchen"), []byte(`"seq":1`), []byte(`"seq":1,"seq":1`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := audit.Verify([][]byte{entry})
			if err != nil || r.Valid {
				t.Errorf("Verify = %+v, %v, want an invalid log", r, err)
			}
		})
	}
}

func TestCheckNewAppliesTheStrictRule(t *testing.T) {
	if err := audit.CheckNew(entryWith("light.kitchen")); err != nil {
		t.Errorf("plain entry: %v", err)
	}
	for name, id := range map[string]string{
		"noncharacter":   "light." + `\` + "uffff",
		"raw":            "light.﷐",
		"lone surrogate": "light." + `\` + "ud800",
	} {
		t.Run(name, func(t *testing.T) {
			if err := audit.CheckNew(entryWith(id)); !errors.Is(err, audit.ErrMalformed) {
				t.Errorf("CheckNew = %v, want ErrMalformed", err)
			}
		})
	}
	if err := audit.CheckNew(append(entryWith("light.kitchen"), bytes.Repeat([]byte(" "), audit.MaxEntryBytes)...)); !errors.Is(err, audit.ErrMalformed) {
		t.Errorf("oversized entry: %v, want ErrMalformed", err)
	}
}
