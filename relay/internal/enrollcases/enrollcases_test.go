// SPDX-License-Identifier: Apache-2.0

package enrollcases_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"github.com/home-mandate/spec/jws"
	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/enrollcases"
	"github.com/home-mandate/spec/relay/internal/refop"
)

func TestLoadReadsTheEmbeddedCases(t *testing.T) {
	cases, err := enrollcases.Load(relay.FS())
	if err != nil || len(cases) < 15 || len(cases) > 25 {
		t.Fatalf("%d cases, %v", len(cases), err)
	}
	offline := 0
	for _, c := range cases {
		if c.ID == "" || c.Why == "" || len(c.Steps) == 0 {
			t.Errorf("case %+v", c)
		}
		if c.Offline {
			offline++
		}
	}
	if offline == 0 {
		t.Error("no offline case")
	}
}

func TestLoadRefusesWhatIsNotTheFile(t *testing.T) {
	if _, err := enrollcases.Load(fstest.MapFS{}); err == nil {
		t.Error("missing file")
	}
	for name, content := range map[string]string{
		"not JSON": `x`, "unknown member": `{"description":"","cases":[],"extra":1}`,
		"unknown case member": `{"description":"","cases":[{"id":"a","extra":1}]}`,
	} {
		if _, err := enrollcases.Load(fstest.MapFS{enrollcases.Path: {Data: []byte(content)}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func gen(t *testing.T, alg string) *enroll.Signer {
	t.Helper()
	s, err := enroll.Generate(alg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func actors(t *testing.T) enrollcases.Actors {
	url := "https://op.example.net/enroll/installation/"
	return enrollcases.Actors{
		Dir:            enroll.Directory{NewNonce: "https://op.example.net/enroll/new-nonce", Pair: "https://op.example.net/enroll/pair", KeyChange: "https://op.example.net/enroll/key-change"},
		Self:           enroll.Identity{URL: url + "aaaaaaaaaaaaaaaaaaaaaaaaaa", Signer: gen(t, enroll.AlgEdDSA)},
		Other:          enroll.Identity{URL: url + "bbbbbbbbbbbbbbbbbbbbbbbbbb", Signer: gen(t, enroll.AlgES256)},
		Unpaired:       enroll.Identity{URL: url + "cccccccccccccccccccccccccc", Signer: gen(t, enroll.AlgEdDSA)},
		CertificateURL: url + "aaaaaaaaaaaaaaaaaaaaaaaaaa/certificate", Unknown: url + "zzzzzzzzzzzzzzzzzzzzzzzzzz",
		ForeignEd: gen(t, enroll.AlgEdDSA), ForeignES: gen(t, enroll.AlgES256),
		UsedNonce: enroll.RandomToken(16), CSR: []byte("csr"),
	}
}

func TestRequestBuildsTheSymbolicParts(t *testing.T) {
	a := actors(t)
	nonce := enroll.RandomToken(16)
	base := enrollcases.Step{Kid: "self", To: "self", Header: "same", Nonce: "fresh", Signature: "valid", Alg: "key", Payload: "none"}
	with := func(edit func(*enrollcases.Step)) enrollcases.Step { st := base; edit(&st); return st }
	for name, tt := range map[string]struct {
		step enrollcases.Step
		url  string
		err  error
	}{
		"plain":     {base, a.Self.URL, nil},
		"other":     {with(func(s *enrollcases.Step) { s.To = "other" }), a.Other.URL, nil},
		"unpaired":  {with(func(s *enrollcases.Step) { s.Kid, s.To = "unpaired", "unpaired" }), a.Unpaired.URL, nil},
		"unknown":   {with(func(s *enrollcases.Step) { s.Kid, s.To = "unknown", "unknown" }), a.Unknown, nil},
		"jwk":       {with(func(s *enrollcases.Step) { s.Kid, s.To = "none", "pair" }), a.Dir.Pair, nil},
		"key":       {with(func(s *enrollcases.Step) { s.To = "key-change" }), a.Dir.KeyChange, nil},
		"cert":      {with(func(s *enrollcases.Step) { s.To, s.Payload = "certificate", "csr" }), a.CertificateURL, nil},
		"different": {with(func(s *enrollcases.Step) { s.Header = "different" }), a.Self.URL, nil},
		"alg":       {with(func(s *enrollcases.Step) { s.Alg = "other" }), a.Self.URL, nil},
		"foreign":   {with(func(s *enrollcases.Step) { s.Signature = "foreign" }), a.Self.URL, nil},
		"update":    {with(func(s *enrollcases.Step) { s.Payload = "extra-member" }), a.Self.URL, nil},
		"noop":      {with(func(s *enrollcases.Step) { s.Payload = "noop" }), a.Self.URL, nil},
		"unpair":    {with(func(s *enrollcases.Step) { s.Payload = "unpair" }), a.Self.URL, nil},
		"array":     {with(func(s *enrollcases.Step) { s.Payload = "not-object" }), a.Self.URL, nil},
		"dup":       {with(func(s *enrollcases.Step) { s.Payload = "duplicate-member" }), a.Self.URL, nil},
	} {
		url, compact, err := a.Request(tt.step, nonce)
		if !errors.Is(err, tt.err) || url != tt.url || compact == "" {
			t.Errorf("%s: %q %v", name, url, err)
		}
	}
	// ES256 key with an alg override, and a foreign key of the other algorithm.
	es := a
	es.Self.Signer = gen(t, enroll.AlgES256)
	if _, compact, err := es.Request(with(func(s *enrollcases.Step) { s.Alg, s.Signature = "other", "foreign" }), nonce); err != nil {
		t.Error(err)
	} else if h, _, perr := jws.ParseRequest(compact); perr == nil && h.Alg != "EdDSA" {
		t.Errorf("alg %s", h.Alg)
	}
	for name, edit := range map[string]func(*enrollcases.Actors){
		"no signer":      func(a *enrollcases.Actors) { a.Other = enroll.Identity{} },
		"no URL":         func(a *enrollcases.Actors) { a.CertificateURL = "" },
		"no foreign key": func(a *enrollcases.Actors) { a.ForeignEd = nil },
	} {
		c := a
		edit(&c)
		st := with(func(s *enrollcases.Step) { s.To, s.Signature = "other", "foreign" })
		switch name {
		case "no URL":
			st = with(func(s *enrollcases.Step) { s.To = "certificate" })
		case "no signer":
			st = with(func(s *enrollcases.Step) { s.Kid, s.To = "other", "other" })
		}
		if _, _, err := c.Request(st, nonce); !errors.Is(err, enrollcases.ErrNotPlayable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := (enrollcases.Actors{}).Request(with(func(s *enrollcases.Step) { s.Kid = "none" }), nonce); !errors.Is(err, enrollcases.ErrNotPlayable) {
		t.Errorf("no actors: %v", err)
	}
}

func TestPlayAgainstTheReference(t *testing.T) {
	run := refop.Serve(refop.Config{})
	t.Cleanup(func() { _ = run.Close() })
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, run.Addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: run.Roots},
	}}
	c := &enroll.Client{T: &enroll.HTTPTransport{Client: hc, RetryUnit: time.Millisecond, MaxWaits: 1}, Host: refop.DefaultOperator}
	ctx := context.Background()
	if _, err := c.Load(ctx, "https://"+refop.DefaultOperator+"/enroll/directory"); err != nil {
		t.Fatal(err)
	}
	pair := func(code string) enroll.Identity {
		key := gen(t, enroll.AlgEdDSA)
		csr, _ := enroll.NewCSR(gen(t, enroll.AlgEdDSA).Private())
		p, _, err := c.Pair(ctx, key, code, csr)
		if err != nil {
			t.Fatal(err)
		}
		return enroll.Identity{URL: p.Location, Signer: key}
	}
	self, other := pair(refop.DefaultCodes[0]), pair(refop.DefaultCodes[1])
	a := actors(t)
	a.Dir, a.Self, a.Other = c.Dir, self, other
	a.CertificateURL, a.Unknown = self.URL+"/certificate", self.URL[:len(self.URL)-4]+"abcd"
	nonce, _ := c.TakeNonce(ctx)
	resp, err := c.Send(ctx, self.URL, func(string) string {
		return enroll.Spec{Signer: self.Signer, Kid: self.URL, Nonce: nonce, URL: self.URL}.Compact()
	}, false, false)
	if err != nil || resp.Status != 200 {
		t.Fatal(err)
	}
	a.UsedNonce = nonce
	cases, _ := enrollcases.Load(relay.FS())
	played := 0
	for _, cs := range cases {
		if cs.World != enrollcases.WorldBothActive {
			continue
		}
		results, err := enrollcases.Play(ctx, c, a, cs)
		if err != nil {
			t.Fatalf("%s: %v", cs.ID, err)
		}
		for _, r := range results {
			played++
			if !r.Pass() || !r.HasNonce || r.Case != cs.ID {
				t.Errorf("%s step %d: got %s, want %s", cs.ID, r.Step, r.Got, r.Want)
			}
		}
	}
	if played < 10 {
		t.Errorf("%d steps played", played)
	}
	// A case that the actors cannot play ends with that error; a failing transport ends it too.
	bad := cases[0]
	bad.Steps = []enrollcases.Step{{Kid: "other", To: "other", Header: "same", Nonce: "fresh", Signature: "valid", Alg: "key", Payload: "none", Expect: "ok"}}
	a2 := a
	a2.Other = enroll.Identity{}
	if _, err := enrollcases.Play(ctx, c, a2, bad); !errors.Is(err, enrollcases.ErrNotPlayable) {
		t.Errorf("not playable: %v", err)
	}
	dead := &enroll.Client{T: &enroll.HTTPTransport{Client: &http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("down") }}}}, Host: refop.DefaultOperator, Dir: c.Dir}
	if _, err := enrollcases.Play(ctx, dead, a, cases[0]); err == nil {
		t.Error("a dead transport")
	}
}
