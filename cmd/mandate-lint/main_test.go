// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safe = `{"type":"https://home-mandate.org/mandate/v0","id":"m-test","principal":"household:t",` +
	`"agent":{"client_id":"hm-client:test-0001","display_name":"Test"},` +
	`"rules":[{"id":"r-1","resource":{"category":"light"},"actions":["turn_on"],"decision":"allow"}],` +
	`"default":"deny","approval":{"timeout":"PT2M","approvers":["a-1"]},"limits":{"max_actions_per_hour":10},` +
	`"valid_from":"2026-01-01T00:00:00+01:00","created_by":"a-1","created_at":"2025-12-31T12:00:00+01:00"}`

var broad = strings.Replace(safe, `"actions":["turn_on"]`, `"actions":["*"]`, 1)

func TestExitStatusAndOutput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct {
		args   []string
		stdin  string
		status int
		out    string
	}{
		"safe from stdin":      {nil, safe, 0, ""},
		"broad from a file":    {[]string{write("broad.json", broad)}, "", 1, "every_action: rule r-1"},
		"two files, one broad": {[]string{write("a.json", safe), write("b.json", broad)}, "", 1, "b.json"},
		"json":                 {[]string{"-json", write("c.json", broad)}, "", 1, `"code":"every_action"`},
		"invalid mandate":      {nil, `{}`, 2, ""},
		"missing file":         {[]string{filepath.Join(dir, "none.json")}, "", 2, ""},
		"unknown flag":         {[]string{"-nope"}, "", 2, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tc.args, strings.NewReader(tc.stdin), &out, &errOut); got != tc.status {
				t.Errorf("status = %d, want %d (stderr %q)", got, tc.status, errOut.String())
			}
			if !strings.Contains(out.String(), tc.out) {
				t.Errorf("stdout = %q, want %q", out.String(), tc.out)
			}
		})
	}
}
