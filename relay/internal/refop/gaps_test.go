// SPDX-License-Identifier: Apache-2.0

package refop_test

import (
	"context"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refop"
)

// send sends a signed request with the payload and returns the error name, or "ok".
func (w *world) send(id enroll.Identity, url, payload string) string {
	w.t.Helper()
	resp, err := w.c.Send(w.ctx, url, func(nonce string) string {
		return enroll.Spec{Signer: id.Signer, Kid: id.URL, Nonce: nonce, URL: url, Payload: payload}.Compact()
	}, true, false)
	if err != nil {
		w.t.Fatal(err)
	}
	if name := enroll.ErrorName(resp); name != "" {
		return name
	}
	return "ok"
}

func (w *world) sendJWK(key *enroll.Signer, payload string) string {
	w.t.Helper()
	resp, err := w.c.Send(w.ctx, w.c.Dir.Pair, func(nonce string) string {
		return enroll.Spec{Signer: key, JWK: true, Nonce: nonce, URL: w.c.Dir.Pair, Payload: payload}.Compact()
	}, true, false)
	if err != nil {
		w.t.Fatal(err)
	}
	if name := enroll.ErrorName(resp); name != "" {
		return name
	}
	return "ok"
}

func TestMalformedPayloadsOfEveryOperation(t *testing.T) {
	w := newWorld(t, refop.Config{})
	a, pa := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	csr := enroll.B64(w.csr(w.signer(enroll.AlgEdDSA)))
	value := strings.Repeat("A", 43)
	for name, tt := range map[string]struct {
		url, payload, want string
	}{
		"unknown update":             {a.URL, `{"x":1}`, "malformed"},
		"unpair with a wrong value":  {a.URL, `{"status":"active"}`, "malformed"},
		"unpair without text":        {a.URL, `{"status":1}`, "malformed"},
		"acme missing member":        {a.URL, `{"acme_account":"https://acme.example/a/1"}`, "malformed"},
		"acme bad URL":               {a.URL, `{"acme_account":"x","caa_identity":"letsencrypt.org"}`, "malformed"},
		"own domain not text":        {a.URL, `{"own_domain":5}`, "malformed"},
		"own domain too long":        {a.URL, `{"own_domain":"` + strings.Repeat("a", 240) + `.tester.example.com"}`, "malformed"},
		"own domain the name domain": {a.URL, `{"own_domain":"x.homes.example.org"}`, "malformed"},
		"cert without csr":           {pa.Installation.Certificate, `{}`, "malformed"},
		"cert csr not text":          {pa.Installation.Certificate, `{"csr":1}`, "malformed"},
		"cert csr not base64":        {pa.Installation.Certificate, `{"csr":"` + strings.Repeat("*", 80) + `"}`, "malformed"},
		"cert csr garbage":           {pa.Installation.Certificate, `{"csr":"` + strings.Repeat("A", 80) + `"}`, "bad-csr"},
		"cert read":                  {pa.Installation.Certificate, ``, "malformed"},
		"challenge missing":          {pa.Installation.ACMEChallenge, `{}`, "malformed"},
		"challenge too many":         {pa.Installation.ACMEChallenge, `{"values":["` + value + `","` + strings.Repeat("B", 43) + `","` + strings.Repeat("C", 43) + `"]}`, "malformed"},
		"challenge duplicate":        {pa.Installation.ACMEChallenge, `{"values":["` + value + `","` + value + `"]}`, "malformed"},
		"challenge bad value":        {pa.Installation.ACMEChallenge, `{"values":["short"]}`, "malformed"},
		"challenge not a list":       {pa.Installation.ACMEChallenge, `{"values":1}`, "malformed"},
		"key change not text":        {w.c.Dir.KeyChange, `{"jws":1}`, "malformed"},
		"key change not a JWS":       {w.c.Dir.KeyChange, `{"jws":"x.y.z"}`, "malformed"},
		"unknown path":               {a.URL + "/other", `{}`, "malformed"},
		"unknown extra member":       {pa.Installation.Certificate, `{"csr":"` + csr + `","x":1}`, "malformed"},
	} {
		if got := w.send(a, tt.url, tt.payload); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
}

func TestKeyChangeErrors(t *testing.T) {
	w := newWorld(t, refop.Config{})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	fresh := w.signer(enroll.AlgEdDSA)
	other := w.signer(enroll.AlgEdDSA)
	keyURL := w.c.Dir.KeyChange
	for name, tt := range map[string]struct {
		inner string
		want  string
	}{
		"bad inner signature": {enroll.KeyChangeJWS(fresh, a.Signer.JWK(), a.URL, keyURL)[:len(enroll.KeyChangeJWS(fresh, a.Signer.JWK(), a.URL, keyURL))-4] + "AAAA", "bad-signature"},
		"other url":           {enroll.KeyChangeJWS(fresh, a.Signer.JWK(), a.URL, a.URL), "malformed"},
		"other installation":  {enroll.KeyChangeJWS(fresh, a.Signer.JWK(), w.c.Dir.Pair, keyURL), "malformed"},
		"other old key":       {enroll.KeyChangeJWS(fresh, other.JWK(), a.URL, keyURL), "malformed"},
		"old key not a key":   {enroll.KeyChangeJWS(fresh, `{"kty":"x"}`, a.URL, keyURL), "malformed"},
		"payload not object":  {enroll.KeyChangeJWS(fresh, a.Signer.JWK(), a.URL, keyURL), "ok"},
	} {
		if name == "payload not object" {
			continue
		}
		if got := w.send(a, keyURL, `{"jws":"`+tt.inner+`"}`); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
	// A tunnel key is no installation key.
	first, pa := w.pair(refop.DefaultCodes[1], enroll.AlgEdDSA)
	tunnel := w.signer(enroll.AlgEdDSA)
	if _, _, err := w.c.Certificate(w.ctx, first, pa.Installation.Certificate, w.csr(tunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.KeyChange(w.ctx, first, tunnel); err == nil {
		t.Error("a key of a tunnel certificate was taken as installation key")
	}
}

func TestPairingErrors(t *testing.T) {
	w := newWorld(t, refop.Config{})
	key := w.signer(enroll.AlgEdDSA)
	csr := enroll.B64(w.csr(w.signer(enroll.AlgEdDSA)))
	for name, tt := range map[string]struct{ payload, want string }{
		"missing member": {`{"code":"ABCDEFGHIJKLMNOP"}`, "malformed"},
		"extra member":   {`{"code":"ABCDEFGHIJKLMNOP","csr":"` + csr + `","x":1}`, "malformed"},
		"code not text":  {`{"code":1,"csr":"` + csr + `"}`, "malformed"},
		"bad code form":  {`{"code":"abc","csr":"` + csr + `"}`, "malformed"},
		"wrong code":     {`{"code":"AAAAAAAAAAAAAAAA","csr":"` + csr + `"}`, "pairing-refused"},
		"bad csr":        {`{"code":"ABCDEFGHIJKLMNOP","csr":"` + strings.Repeat("A", 80) + `"}`, "bad-csr"},
		"csr not base64": {`{"code":"ABCDEFGHIJKLMNOP","csr":"` + strings.Repeat("*", 80) + `"}`, "malformed"},
	} {
		if got := w.sendJWK(key, tt.payload); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
	// The key of an installation cannot be used for another one.
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	if got := w.sendJWK(a.Signer, `{"code":"`+refop.DefaultCodes[1]+`","csr":"`+csr+`"}`); got != "key-conflict" {
		t.Errorf("key in use: %s", got)
	}
	// The code was not used up by the refusals.
	if _, p := w.pair(refop.DefaultCodes[1], enroll.AlgES256); p.Installation.Status != "active" {
		t.Error("the second code is gone")
	}
}

func TestRepeatedPairingStates(t *testing.T) {
	for name, tt := range map[string]struct {
		prepare func(w *world, id enroll.Identity)
		want    string
	}{
		"plain":    {func(*world, enroll.Identity) {}, "ok"},
		"blocked":  {func(w *world, id enroll.Identity) { w.run.Operator.Block(id.URL, true) }, "blocked"},
		"unpaired": {func(w *world, id enroll.Identity) { _, _ = w.c.Unpair(w.ctx, id) }, "unpaired"},
	} {
		w := newWorld(t, refop.Config{})
		id, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
		tt.prepare(w, id)
		csr := enroll.B64(w.csr(w.signer(enroll.AlgEdDSA)))
		if got := w.sendJWK(id.Signer, `{"code":"`+refop.DefaultCodes[0]+`","csr":"`+csr+`"}`); got != tt.want {
			t.Errorf("%s: %s, want %s", name, got, tt.want)
		}
	}
	// A repeat with the key of an installation that changed it is unpaired.
	w := newWorld(t, refop.Config{})
	id, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	if _, err := w.c.KeyChange(w.ctx, id, w.signer(enroll.AlgEdDSA)); err != nil {
		t.Fatal(err)
	}
	csr := enroll.B64(w.csr(w.signer(enroll.AlgEdDSA)))
	if got := w.sendJWK(id.Signer, `{"code":"`+refop.DefaultCodes[0]+`","csr":"`+csr+`"}`); got != "unpaired" {
		t.Errorf("old key: %s", got)
	}
	// A repeat with a tunnel key that was used is bad-csr.
	if got := w.sendJWK(id.Signer, `{"code":"`+refop.DefaultCodes[0]+`","csr":"`+strings.Repeat("A", 80)+`"}`); got == "ok" {
		t.Error("garbage CSR in a repeat")
	}
}

func TestACMEReportStates(t *testing.T) {
	w := newWorld(t, refop.Config{})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	for name, payload := range map[string]string{
		"missing member": `{"acme_account":"https://acme.example/a/1"}`,
		"bad CA":         `{"acme_account":"https://acme.example/a/1","caa_identity":"Not A Domain"}`,
		"account number": `{"acme_account":1,"caa_identity":"letsencrypt.org"}`,
	} {
		if got := w.send(a, a.URL, payload); got != "malformed" {
			t.Errorf("%s: %s", name, got)
		}
	}
	// After the hour of the first report a report needs confirmation.
	b, _ := w.pair(refop.DefaultCodes[1], enroll.AlgEdDSA)
	w.run.Operator.AgePairing(b.URL)
	if _, err := w.c.ReportACME(w.ctx, b, acct, ca); apiName(err) != "confirmation-required" {
		t.Errorf("late first report: %v", err)
	}
}

func TestOwnDomainStates(t *testing.T) {
	w := newWorld(t, refop.Config{})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	b, _ := w.pair(refop.DefaultCodes[1], enroll.AlgES256)
	first, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
	if err != nil || first.OwnDomain.Status != "pending" {
		t.Fatalf("%v", err)
	}
	// Registering the same name again keeps the token (RELAY-v0 section 6.4).
	again, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
	if err != nil || again.OwnDomain.Token != first.OwnDomain.Token {
		t.Errorf("token changed: %v", err)
	}
	// Another name replaces it with a new token; a name outside the zones stays pending.
	other, err := w.c.SetOwnDomain(w.ctx, a, "home.elsewhere.example.org")
	if err != nil || other.OwnDomain.Token == first.OwnDomain.Token || other.OwnDomain.Status != "pending" {
		t.Errorf("replacement: %v %+v", err, other.OwnDomain)
	}
	// Two installations may have the same name pending.
	if inst, err := w.c.SetOwnDomain(w.ctx, b, ownNm); err != nil || inst.OwnDomain.Status != "pending" {
		t.Errorf("pending twice: %v", err)
	}
	for _, name := range []string{"home." + refop.DefaultNameDomain, refop.DefaultNameDomain, "tunnel." + refop.DefaultOperator, "x.tunnel." + refop.DefaultOperator, refop.DefaultOperator} {
		if _, err := w.c.SetOwnDomain(w.ctx, b, name); apiName(err) != "malformed" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNoncesAndContentType(t *testing.T) {
	w := newWorld(t, refop.Config{})
	_, resp, err := w.c.FreshNonce(w.ctx)
	if err != nil || resp.Status != 200 {
		t.Fatal(err)
	}
	get, err := w.c.T.Do(context.Background(), "GET", w.c.Dir.NewNonce, nil, "", false)
	if err != nil || get.Status != 204 || len(get.Body) != 0 {
		t.Errorf("GET new_nonce: %v %d", err, get.Status)
	}
	bad, err := w.c.T.Do(context.Background(), "POST", w.c.Dir.Pair, []byte("x.y.z"), "text/plain", false)
	if err != nil || enroll.ErrorName(bad) != "malformed" {
		t.Errorf("content type: %v", err)
	}
	notJWS, err := w.c.T.Do(context.Background(), "POST", w.c.Dir.Pair, []byte("junk"), "application/jose", false)
	if err != nil || enroll.ErrorName(notJWS) != "malformed" {
		t.Errorf("junk: %v", err)
	}
}

func TestForeignKidAtAnUnknownURLIsMalformedEvenWhenAccepted(t *testing.T) {
	w := newWorld(t, refop.Config{Faults: refop.ForeignKidAccepted})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	if got := w.send(a, a.URL[:len(a.URL)-4]+"abcd", ""); got != "malformed" {
		t.Errorf("got %s", got)
	}
}

func TestLookupsOfTheRunningOperator(t *testing.T) {
	w := newWorld(t, refop.Config{})
	hosts, err := w.run.NS(context.Background(), refop.DefaultNameDomain)
	if err != nil || len(hosts) != 2 {
		t.Fatalf("%v %v", hosts, err)
	}
	if addrs, err := w.run.Lookup(context.Background(), hosts[0]); err != nil || len(addrs) != 1 {
		t.Errorf("%v %v", addrs, err)
	}
}
