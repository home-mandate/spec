// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const goodCode = "ABCD-EFGH-IJKL-MNOP"

func TestValidDomain(t *testing.T) {
	for s, want := range map[string]bool{
		"op.example.net": true, "a.b": true, "Op.example.net": false, "example": false, "a..b": false,
		"op.example.net:443": false, "op.example.net/x": false, "127.0.0.1": false, "": false,
		"-a.example": false, strings.Repeat("a", 250) + ".example": false,
	} {
		if got := ValidDomain(s); got != want {
			t.Errorf("ValidDomain(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		goodCode: "ABCDEFGHIJKLMNOP", "abcdefghijklmnop": "ABCDEFGHIJKLMNOP", "abcd-efgh-ijkl-mn27": "ABCDEFGHIJKLMN27",
	} {
		if got, err := NormalizeCode(in); err != nil || got != want {
			t.Errorf("NormalizeCode(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ABCD", "ABCD-EFGH-IJKL-MNO1", "ABCD-EFGH-IJKL-MNOPQ", "ABCD-EFGH-IJKL-MNO\n"} {
		_, err := NormalizeCode(in)
		if !errors.Is(err, ErrUsage) {
			t.Errorf("NormalizeCode(%q) = %v", in, err)
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Errorf("the error repeats the code: %v", err)
		}
	}
}

func TestValidate(t *testing.T) {
	good := Settings{Operator: "op.example.net"}
	for name, tt := range map[string]struct {
		s  Settings
		ok bool
	}{
		"minimal":                            {good, true},
		"two codes":                          {Settings{Operator: good.Operator, Codes: []string{goodCode, "AAAA-BBBB-CCCC-DDDD"}}, true},
		"three codes":                        {Settings{Operator: good.Operator, Codes: []string{goodCode, "AAAA-BBBB-CCCC-DDDD", "EEEE-FFFF-GGGG-HHHH"}}, false},
		"same code twice":                    {Settings{Operator: good.Operator, Codes: []string{goodCode, "abcdefghijklmnop"}}, false},
		"bad code":                           {Settings{Operator: good.Operator, Codes: []string{"nope"}}, false},
		"no operator":                        {Settings{}, false},
		"upper-case operator":                {Settings{Operator: "OP.example.net"}, false},
		"unknown class":                      {Settings{Operator: good.Operator, Classes: []string{"nope"}}, false},
		"own domain with hook":               {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSHook: "./hook"}, true},
		"own domain manual":                  {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSManual: true}, true},
		"own domain alone":                   {Settings{Operator: good.Operator, OwnDomain: "x.test.example"}, false},
		"bad own domain":                     {Settings{Operator: good.Operator, OwnDomain: "X", DNSManual: true}, false},
		"hook without domain":                {Settings{Operator: good.Operator, DNSHook: "./hook"}, false},
		"manual without domain":              {Settings{Operator: good.Operator, DNSManual: true}, false},
		"hook and manual":                    {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSHook: "h", DNSManual: true}, false},
		"hook like a flag":                   {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSHook: "-rf"}, false},
		"hook of white space":                {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSHook: " \t "}, false},
		"hook like a flag after white space": {Settings{Operator: good.Operator, OwnDomain: "x.test.example", DNSHook: "  -rf"}, false},
		"negative timeout":                   {Settings{Operator: good.Operator, Timeout: -time.Second}, false},
		"timeout too long":                   {Settings{Operator: good.Operator, Timeout: MaxTimeout + time.Second}, false},
		"timeout at the limit":               {Settings{Operator: good.Operator, Timeout: MaxTimeout}, true},
		"cleanup":                            {Settings{CleanupPath: "s.json", DNSHook: "./hook"}, true},
		"cleanup with operator":              {Settings{CleanupPath: "s.json", Operator: good.Operator}, false},
		"cleanup with codes":                 {Settings{CleanupPath: "s.json", Codes: []string{goodCode}}, false},
	} {
		got, err := tt.s.Validate()
		if (err == nil) != tt.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrUsage) {
			t.Errorf("%s: %v is no ErrUsage", name, err)
		}
		if err == nil && got.Timeout == 0 {
			t.Errorf("%s: no default timeout", name)
		}
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	got, err := Settings{Operator: "op.example.net", Codes: []string{goodCode}, Classes: []string{"relay", "metadata", "relay"}}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Classes, []string{"metadata", "relay"}) || got.Codes[0] != "ABCDEFGHIJKLMNOP" || got.Timeout != MaxTimeout {
		t.Errorf("got %+v", got)
	}
	all, _ := Settings{Operator: "op.example.net"}.Validate()
	if !slices.Equal(all.Classes, AllClasses) {
		t.Errorf("default classes %v", all.Classes)
	}
	all.Classes[0] = "changed"
	if AllClasses[0] != ClassMetadata {
		t.Error("AllClasses was changed through the settings")
	}
}
