// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/refop"
)

func caaAnswer(values ...string) dnsq.Answer {
	var a dnsq.Answer
	for _, v := range values {
		tag, value, _ := strings.Cut(v, " ")
		a.Records = append(a.Records, dnsq.Record{Type: dnsq.TypeCAA, CAA: dnsq.CAA{Tag: tag, Value: value}})
	}
	return a
}

func TestCAAJudges(t *testing.T) {
	acct := "https://acme.example/acct/1"
	good := `letsencrypt.org; accounturi=` + acct + `; validationmethods=dns-01`
	judgeAcct := judgeAccount("letsencrypt.org", acct)
	for name, tt := range map[string]struct {
		judge func(dnsq.Answer) string
		in    dnsq.Answer
		ok    bool
	}{
		"apex good":             {judgeApex, caaAnswer("issue ;", "issuewild ;", "iodef mailto:x@example.org"), true},
		"apex no issuewild":     {judgeApex, caaAnswer("issue ;"), false},
		"apex CA":               {judgeApex, caaAnswer("issue ca.example", "issuewild ;"), false},
		"apex two issue":        {judgeApex, caaAnswer("issue ;", "issue ;", "issuewild ;"), false},
		"apex wild CA":          {judgeApex, caaAnswer("issue ;", "issuewild ca.example"), false},
		"apex unparsable":       {judgeApex, caaAnswer("issue bad_name", "issuewild ;"), false},
		"closed good":           {judgeClosed, caaAnswer("issue ;"), true},
		"closed with wild ;":    {judgeClosed, caaAnswer("issue ;", "issuewild ;"), true},
		"closed none":           {judgeClosed, caaAnswer(), false},
		"closed account":        {judgeClosed, caaAnswer("issue " + good), false},
		"closed wild permits":   {judgeClosed, caaAnswer("issue ;", "issuewild ca.example"), false},
		"closed unparsable":     {judgeClosed, caaAnswer("issue x y z;;="), false},
		"account good":          {judgeAcct, caaAnswer("issue "+good, "issuewild ;"), true},
		"account none":          {judgeAcct, caaAnswer(), false},
		"account wrong CA":      {judgeAcct, caaAnswer("issue other.example; accounturi=" + acct + "; validationmethods=dns-01"), false},
		"account wrong account": {judgeAcct, caaAnswer("issue letsencrypt.org; accounturi=https://x/2; validationmethods=dns-01"), false},
		"account no methods":    {judgeAcct, caaAnswer("issue letsencrypt.org; accounturi=" + acct), false},
		"account other methods": {judgeAcct, caaAnswer("issue letsencrypt.org; accounturi=" + acct + "; validationmethods=http-01"), false},
		"account extra param":   {judgeAcct, caaAnswer("issue " + good + "; x=y"), false},
		"account wild permits":  {judgeAcct, caaAnswer("issue "+good, "issuewild letsencrypt.org"), false},
		"account unparsable":    {judgeAcct, caaAnswer("issue =;;"), false},
		"account two issue":     {judgeAcct, caaAnswer("issue "+good, "issue ;"), false},
	} {
		if got := tt.judge(tt.in) == ""; got != tt.ok {
			t.Errorf("%s: judged ok = %v", name, got)
		}
	}
	if issue, wild, p := caaValues(caaAnswer("iodef x", "issue ;", "other y")); len(issue) != 1 || len(wild) != 0 || p != "" {
		t.Errorf("caaValues: %v %v %q", issue, wild, p)
	}
}

func TestOnlyText(t *testing.T) {
	txt := func(values ...string) dnsq.Answer {
		var a dnsq.Answer
		for _, v := range values {
			a.Records = append(a.Records, dnsq.Record{Type: dnsq.TypeTXT, Text: v})
		}
		return a
	}
	for name, tt := range map[string]struct {
		in   dnsq.Answer
		want string
		ok   bool
	}{
		"exact": {txt("a"), "a", true}, "none wanted": {txt(), "", true}, "two": {txt("a", "b"), "a", false},
		"other": {txt("b"), "a", false}, "unwanted": {txt("a"), "", false},
		"other type ignored": {dnsq.Answer{Records: []dnsq.Record{{Type: dnsq.TypeA}}}, "", true},
	} {
		if onlyText(tt.in, tt.want) != tt.ok {
			t.Errorf("%s", name)
		}
	}
}

func TestWaitTXT(t *testing.T) {
	r, env := serve(t, refop.Config{})
	env.Timing.Visible, env.Timing.Poll = 150*time.Millisecond, 10*time.Millisecond
	d := newDNSTools(env)
	name := proofLabel + testOwnDomain
	if err := d.waitTXT(ctx(t), name, ""); err != nil {
		t.Errorf("absent record: %v", err)
	}
	if err := d.waitTXT(ctx(t), name, "value"); err != errNotVisible {
		t.Errorf("missing record: %v", err)
	}
	if err := d.waitTXT(ctx(t), "x.nowhere.example", "v"); err != errNotVisible {
		t.Errorf("no zone: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx(t))
	cancel()
	if err := d.waitTXT(cancelled, name, "value"); err == nil || err == errNotVisible {
		t.Errorf("cancelled: %v", err)
	}
	_ = r
	if _, err := systemNS(ctx(t), "invalid."); err == nil {
		t.Log("the system resolver knows invalid.")
	}
}

func TestSchemaProblem(t *testing.T) {
	example, _ := os.ReadFile("../../examples/installation.json")
	if p := schemaProblem("installation", example); p != "" {
		t.Errorf("the example: %s", p)
	}
	bad, _ := json.Marshal(map[string]any{"status": "weird"})
	if p := schemaProblem("installation", bad); !strings.Contains(p, "violates") {
		t.Errorf("invalid: %q", p)
	}
	if p := schemaProblem("installation", []byte("{")); !strings.Contains(p, "not JSON") {
		t.Errorf("not JSON: %q", p)
	}
}

func TestTestKeyThumbprintsAreTheKeysOfTheFile(t *testing.T) {
	data, err := os.ReadFile("../../conformance/keys/test-keys.private.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Keys []struct {
			Kty, Crv, Kid, D string
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, k := range file.Keys {
		if (k.Kty != "OKP" && k.Crv != "P-256") || k.D == "" {
			continue
		}
		found++
	}
	if found != len(testKeyThumbprints) {
		t.Errorf("%d Ed25519 and P-256 test keys, %d thumbprints", found, len(testKeyThumbprints))
	}
	for _, thumbprint := range testKeyThumbprints {
		if !isTestKey(thumbprint) || len(thumbprint) != 43 {
			t.Errorf("thumbprint %q", thumbprint)
		}
	}
	if isTestKey("not a test key") {
		t.Error("isTestKey")
	}
}

func TestAccountPrefixesAreTheOnesOfTheCAList(t *testing.T) {
	cas, err := os.ReadFile("../../cas.md")
	if err != nil {
		t.Fatal(err)
	}
	for caa, prefix := range accountPrefixes {
		if !strings.Contains(string(cas), "`"+caa+"`") || !strings.Contains(string(cas), "`"+prefix+"`") {
			t.Errorf("relay/cas.md does not list %s with the prefix %s", caa, prefix)
		}
	}
	account, caa, ok := accountURI([]string{"unknown.example", "letsencrypt.org"})
	if !ok || caa != "letsencrypt.org" || !strings.HasPrefix(account, accountPrefixes[caa]) || len(account) != len(accountPrefixes[caa])+18 {
		t.Errorf("accountURI: %q %q %v", account, caa, ok)
	}
	if _, _, ok := accountURI([]string{"unknown.example"}); ok {
		t.Error("an unknown CA")
	}
	for range 20 {
		if strings.HasPrefix(strings.TrimPrefix(randomCode(), ""), "-") {
			t.Fatal("code")
		}
	}
	if c := randomCode(); len(c) != 16 {
		t.Errorf("code %q", c)
	}
}
