// SPDX-License-Identifier: Apache-2.0

package enroll_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refop"
)

// scripted is a Transport that answers from a list and records the requests.
type scripted struct {
	answers  []enroll.Response
	err      error
	backoffs int
	backoff  error
	calls    []string
}

func (s *scripted) Do(_ context.Context, method, rawURL string, _ []byte, _ string, _ bool) (enroll.Response, error) {
	s.calls = append(s.calls, method+" "+rawURL)
	if s.err != nil {
		return enroll.Response{}, s.err
	}
	a := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	return a, nil
}

func (s *scripted) Backoff(context.Context, enroll.Response) error {
	s.backoffs++
	return s.backoff
}

func problem(status int, name string) enroll.Response {
	h := http.Header{"Content-Type": {"application/problem+json"}, "Replay-Nonce": {enroll.RandomToken(16)}}
	return enroll.Response{Status: status, Header: h, Body: []byte(`{"type":"https://home-mandate.org/relay/errors/` + name + `"}`)}
}

func okJSON(status int, body string) enroll.Response {
	return enroll.Response{Status: status, Header: http.Header{"Replay-Nonce": {enroll.RandomToken(16)}, "Content-Type": {"application/json"}}, Body: []byte(body)}
}

func fakeClient(s *scripted) *enroll.Client {
	return &enroll.Client{T: s, Host: "op.example.net", Dir: enroll.Directory{
		NewNonce: "https://op.example.net/enroll/new-nonce", Pair: pairURL, KeyChange: keyURL}}
}

func TestErrorName(t *testing.T) {
	for _, tt := range []struct {
		resp enroll.Response
		want string
	}{
		{okJSON(200, "{}"), ""}, {okJSON(204, ""), ""},
		{problem(400, "malformed"), "malformed"}, {problem(403, "blocked"), "blocked"},
		{problem(400, "made-up"), "server-internal"},
		{enroll.Response{Status: 400, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("x")}, "server-internal"},
		{enroll.Response{Status: 500, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: []byte("nope")}, "server-internal"},
		{enroll.Response{Status: 400, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: []byte(`{"type":"https://elsewhere/malformed"}`)}, "server-internal"},
	} {
		if got := enroll.ErrorName(tt.resp); got != tt.want {
			t.Errorf("%d %s: %q, want %q", tt.resp.Status, tt.resp.Body, got, tt.want)
		}
	}
	if (&enroll.Error{Name: "blocked"}).Error() != "enrollment error blocked" {
		t.Error("Error text")
	}
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://op.example.net/a": true, "http://op.example.net/a": false, "https://other.example/a": false,
		"https://user@op.example.net/a": false, "https://op.example.net/a#x": false, "https://op.example.net:444/a": false,
		"%": false, "/relative": false,
	} {
		if got := enroll.CheckURL(raw, "op.example.net") == nil; got != ok {
			t.Errorf("%q: %v", raw, got)
		}
	}
}

func TestLoadAndNonces(t *testing.T) {
	dir := `{"new_nonce":"https://op.example.net/enroll/new-nonce","pair":"` + pairURL + `","key_change":"` + keyURL + `"}`
	s := &scripted{answers: []enroll.Response{okJSON(200, dir)}}
	c := &enroll.Client{T: s, Host: "op.example.net"}
	var validated []string
	c.Validate = func(def string, _ []byte) { validated = append(validated, def) }
	if _, err := c.Load(context.Background(), "https://op.example.net/enroll/directory"); err != nil || c.Dir.Pair != pairURL || len(validated) != 1 {
		t.Fatalf("%v %v", err, validated)
	}
	// The nonce of the directory answer is used for the next request, once.
	if n, err := c.TakeNonce(context.Background()); err != nil || !enroll.ValidNonce(n) || len(s.calls) != 1 {
		t.Errorf("TakeNonce: %v %v", err, s.calls)
	}
	head := okJSON(200, "")
	s.answers = []enroll.Response{head}
	if n, _, err := c.FreshNonce(context.Background()); err != nil || n != head.Header.Get("Replay-Nonce") {
		t.Errorf("FreshNonce: %v", err)
	}
	s.answers = []enroll.Response{okJSON(200, "")}
	if n, err := c.TakeNonce(context.Background()); err != nil || n == "" {
		t.Errorf("TakeNonce without one: %v", err)
	}
}

func TestLoadRefusesWhatIsNotADirectory(t *testing.T) {
	good := `{"new_nonce":"https://op.example.net/n","pair":"` + pairURL + `","key_change":"` + keyURL + `"}`
	for name, resp := range map[string]enroll.Response{
		"status":       problem(500, "server-internal"),
		"not JSON":     okJSON(200, "x"),
		"foreign host": okJSON(200, strings.Replace(good, "op.example.net/n", "evil.example/n", 1)),
	} {
		c := &enroll.Client{T: &scripted{answers: []enroll.Response{resp}}, Host: "op.example.net"}
		if _, err := c.Load(context.Background(), "https://op.example.net/enroll/directory"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := &enroll.Client{T: &scripted{err: errors.New("down")}, Host: "op.example.net"}
	if _, err := c.Load(context.Background(), "https://op.example.net/d"); err == nil {
		t.Error("transport error")
	}
	if _, err := c.Load(context.Background(), "https://evil.example/d"); !errors.Is(err, enroll.ErrHost) {
		t.Errorf("foreign enrollment URL: %v", err)
	}
	if enroll.ValidNonce("short") || enroll.ValidNonce(strings.Repeat("A", 200)) || enroll.ValidNonce("!!!!") {
		t.Error("ValidNonce")
	}
}

func TestFreshNonceFailures(t *testing.T) {
	for name, s := range map[string]*scripted{
		"status":   {answers: []enroll.Response{problem(500, "server-internal")}},
		"no nonce": {answers: []enroll.Response{{Status: 200, Header: http.Header{}}}},
		"error":    {err: errors.New("down")},
	} {
		if _, _, err := fakeClient(s).FreshNonce(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := fakeClient(&scripted{})
	c.Dir.NewNonce = "https://evil.example/n"
	if _, _, err := c.FreshNonce(context.Background()); !errors.Is(err, enroll.ErrHost) {
		t.Error("foreign new_nonce")
	}
	if _, err := fakeClient(&scripted{err: errors.New("down")}).TakeNonce(context.Background()); err == nil {
		t.Error("TakeNonce error")
	}
}

func build(nonce string) string { return nonce }

func TestSendRepeatsAfterARateLimitAndOnceAfterBadNonce(t *testing.T) {
	ctx := context.Background()
	s := &scripted{answers: []enroll.Response{okJSON(200, ""), problem(429, "rate-limited"), problem(400, "bad-nonce"), okJSON(200, "{}")}}
	c := fakeClient(s)
	resp, err := c.Send(ctx, pairURL, build, true, false)
	if err != nil || resp.Status != 200 || s.backoffs != 1 {
		t.Fatalf("%v %d %d", err, resp.Status, s.backoffs)
	}
	// A 503 with Retry-After is a rate limit too.
	busy := problem(503, "server-internal")
	busy.Header.Set("Retry-After", "1")
	s = &scripted{answers: []enroll.Response{okJSON(200, ""), busy, okJSON(200, "{}")}}
	if resp, err := fakeClient(s).Send(ctx, pairURL, build, true, false); err != nil || resp.Status != 200 {
		t.Errorf("503: %v", err)
	}
	// bad-nonce is returned as it is when the caller wants it.
	s = &scripted{answers: []enroll.Response{okJSON(200, ""), problem(400, "bad-nonce")}}
	if resp, _ := fakeClient(s).Send(ctx, pairURL, build, false, false); enroll.ErrorName(resp) != "bad-nonce" {
		t.Error("bad-nonce without retry")
	}
	// Only one repeat after bad-nonce.
	s = &scripted{answers: []enroll.Response{okJSON(200, ""), problem(400, "bad-nonce")}}
	if resp, err := fakeClient(s).Send(ctx, pairURL, build, true, false); err != nil && enroll.ErrorName(resp) != "bad-nonce" {
		t.Errorf("second bad-nonce: %v", err)
	}
}

func TestSendGivesUpWhenWaitingIsNotAllowed(t *testing.T) {
	ctx := context.Background()
	s := &scripted{answers: []enroll.Response{okJSON(200, ""), problem(429, "rate-limited")}, backoff: errors.New("budget")}
	if _, err := fakeClient(s).Send(ctx, pairURL, build, true, false); err == nil {
		t.Error("no error")
	}
	s = &scripted{answers: []enroll.Response{okJSON(200, ""), problem(429, "rate-limited")}}
	_, err := fakeClient(s).Send(ctx, pairURL, build, true, false)
	var e *enroll.Error
	if !errors.As(err, &e) || e.Name != "rate-limited" || s.backoffs != 3 {
		t.Errorf("%v after %d waits", err, s.backoffs)
	}
	if _, err := fakeClient(&scripted{err: errors.New("down")}).Send(ctx, pairURL, build, true, false); err == nil {
		t.Error("transport error")
	}
	if _, err := fakeClient(&scripted{}).Send(ctx, "https://evil.example/x", build, true, false); !errors.Is(err, enroll.ErrHost) {
		t.Error("foreign URL")
	}
	c := fakeClient(&scripted{answers: []enroll.Response{okJSON(200, ""), {Status: 500, Header: http.Header{}}}})
	c.NoNonceOnError = 0
	if _, err := c.Send(ctx, pairURL, func(string) string { return "x" }, true, false); err != nil || c.NoNonceOnError != 1 {
		t.Errorf("nonce count %d", c.NoNonceOnError)
	}
}

func TestOperationsAgainstTheReference(t *testing.T) {
	run := refop.Serve(refop.Config{})
	t.Cleanup(func() { _ = run.Close() })
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, run.Addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: run.Roots},
	}}
	tr := &enroll.HTTPTransport{Client: hc, RetryUnit: time.Millisecond, MaxWaits: 1}
	c := &enroll.Client{T: tr, Host: refop.DefaultOperator}
	ctx := context.Background()
	if _, err := c.Load(ctx, "https://"+refop.DefaultOperator+"/enroll/directory"); err != nil {
		t.Fatal(err)
	}
	key, tunnel := gen(t, enroll.AlgEdDSA), gen(t, enroll.AlgES256)
	csr, _ := enroll.NewCSR(tunnel.Private())
	p, _, err := c.Pair(ctx, key, refop.DefaultCodes[0], csr)
	if err != nil || p.Installation.Status != "active" || len(p.Certificate.Chain) != 2 || p.Certificate.NotAfter.IsZero() {
		t.Fatalf("pair: %v %+v", err, p)
	}
	id := enroll.Identity{URL: p.Location, Signer: key}
	if inst, err := c.Read(ctx, id); err != nil || inst.HomeID != p.Installation.HomeID {
		t.Fatalf("read: %v", err)
	}
	acct := "https://acme-v02.api.letsencrypt.org/acme/acct/9"
	if inst, err := c.ReportACME(ctx, id, acct, "letsencrypt.org"); err != nil || inst.ACMEAccount != acct {
		t.Fatalf("report: %v", err)
	}
	if values, err := c.Challenge(ctx, id, p.Installation.ACMEChallenge, []string{enroll.RandomToken(32)}); err != nil || len(values) != 1 {
		t.Fatalf("challenge: %v", err)
	}
	if _, err := c.Challenge(ctx, id, p.Installation.ACMEChallenge, nil); err != nil {
		t.Fatalf("empty challenge: %v", err)
	}
	if inst, err := c.SetOwnDomain(ctx, id, "home.tester.example.com"); err != nil || inst.OwnDomain == nil {
		t.Fatalf("own domain: %v", err)
	}
	if inst, err := c.SetOwnDomain(ctx, id, ""); err != nil || inst.OwnDomain != nil {
		t.Fatalf("remove own domain: %v", err)
	}
	next, _ := enroll.NewCSR(gen(t, enroll.AlgEdDSA).Private())
	if issued, _, err := c.Certificate(ctx, id, p.Installation.Certificate, next); err != nil || len(issued.Chain) == 0 {
		t.Fatalf("certificate: %v", err)
	}
	fresh := gen(t, enroll.AlgES256)
	if _, err := c.KeyChange(ctx, id, fresh); err != nil {
		t.Fatalf("key change: %v", err)
	}
	id.Signer = fresh
	if inst, err := c.Unpair(ctx, id); err != nil || inst.Status != "unpaired" {
		t.Fatalf("unpair: %v", err)
	}
	var e *enroll.Error
	if _, err := c.Read(ctx, id); !errors.As(err, &e) || e.Name != "unpaired" {
		t.Errorf("read after unpair: %v", err)
	}
	if _, _, err := c.Certificate(ctx, id, p.Installation.Certificate, next); !errors.As(err, &e) {
		t.Errorf("certificate after unpair: %v", err)
	}
}

func TestOperationsRefuseUnreadableAnswers(t *testing.T) {
	ctx := context.Background()
	key := gen(t, enroll.AlgEdDSA)
	id := enroll.Identity{URL: instURL, Signer: key}
	bad := func(resp enroll.Response) *enroll.Client {
		return fakeClient(&scripted{answers: []enroll.Response{resp}})
	}
	if _, _, err := bad(okJSON(201, "x")).Pair(ctx, key, "AAAAAAAAAAAAAAAA", []byte("csr")); err == nil {
		t.Error("pair not JSON")
	}
	for name, body := range map[string]string{
		"not JSON cert": `{"installation":{},"tunnel_certificate":"x"}`,
		"bad base64":    `{"installation":{},"tunnel_certificate":{"chain":["***"],"not_after":"2026-01-01T00:00:00Z"}}`,
		"bad time":      `{"installation":{},"tunnel_certificate":{"chain":["AAAA"],"not_after":"soon"}}`,
	} {
		if _, _, err := bad(okJSON(201, body)).Pair(ctx, key, "AAAAAAAAAAAAAAAA", []byte("csr")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := bad(okJSON(200, "{}")).Pair(ctx, key, "AAAAAAAAAAAAAAAA", []byte("csr")); err == nil {
		t.Error("pair with status 200")
	}
	if _, err := bad(okJSON(200, "x")).Read(ctx, id); err == nil {
		t.Error("read not JSON")
	}
	if _, err := bad(problem(400, "malformed")).Read(ctx, id); err == nil {
		t.Error("read error")
	}
	if _, _, err := bad(okJSON(200, "x")).Certificate(ctx, id, instURL+"/certificate", []byte("c")); err == nil {
		t.Error("certificate not JSON")
	}
	if _, _, err := bad(problem(400, "bad-csr")).Certificate(ctx, id, instURL+"/certificate", []byte("c")); err == nil {
		t.Error("certificate error")
	}
	if _, err := bad(okJSON(200, "x")).Challenge(ctx, id, instURL+"/acme-challenge", nil); err == nil {
		t.Error("challenge not JSON")
	}
	if _, err := bad(problem(400, "malformed")).Challenge(ctx, id, instURL+"/acme-challenge", nil); err == nil {
		t.Error("challenge error")
	}
	if _, err := fakeClient(&scripted{err: errors.New("down")}).Challenge(ctx, id, instURL+"/acme-challenge", nil); err == nil {
		t.Error("challenge transport error")
	}
	if _, _, err := fakeClient(&scripted{err: errors.New("down")}).Certificate(ctx, id, instURL+"/certificate", nil); err == nil {
		t.Error("certificate transport error")
	}
	if _, _, err := fakeClient(&scripted{err: errors.New("down")}).Pair(ctx, key, "A", nil); err == nil {
		t.Error("pair transport error")
	}
	// An error status with a success body is still an error.
	if _, err := bad(enroll.Response{Status: 500, Header: http.Header{}, Body: []byte("{}")}).Read(ctx, id); err == nil {
		t.Error("500")
	}
}

func TestHTTPTransport(t *testing.T) {
	srv := httpServer(t)
	tr := &enroll.HTTPTransport{Client: http.DefaultClient, RetryUnit: time.Millisecond, MaxWaits: 1}
	ctx := context.Background()
	resp, err := tr.Do(ctx, "POST", srv+"/echo", []byte("hello"), "application/jose", false)
	if err != nil || resp.Status != 200 || string(resp.Body) != "hello" || resp.Over {
		t.Errorf("%v %+v", err, resp)
	}
	if resp, err = tr.Do(ctx, "GET", srv+"/redirect", nil, "", true); err != nil || resp.Status != 302 {
		t.Errorf("redirect: %v %d", err, resp.Status)
	}
	if resp, err = tr.Do(ctx, "GET", srv+"/big", nil, "", false); err != nil || !resp.Over || len(resp.Body) != enroll.MaxBody {
		t.Errorf("big: %v %d", err, len(resp.Body))
	}
	if _, err = tr.Do(ctx, "GET", "http://"+closedPort(t)+"/", nil, "", false); err == nil {
		t.Error("connection refused")
	}
	if _, err = tr.Do(ctx, "BAD METHOD", srv, nil, "", false); err == nil {
		t.Error("bad method")
	}
	if _, err = tr.Do(ctx, "GET", srv+"/cut", nil, "", false); err == nil {
		t.Error("truncated body")
	}
	limited := enroll.Response{Header: http.Header{"Retry-After": {"1"}}}
	if err := tr.Backoff(ctx, limited); err != nil {
		t.Errorf("first wait: %v", err)
	}
	if err := tr.Backoff(ctx, limited); !errors.Is(err, enroll.ErrBackoff) {
		t.Errorf("second wait: %v", err)
	}
	for _, header := range []string{"", "-3", "soon"} {
		tr2 := &enroll.HTTPTransport{Client: http.DefaultClient, RetryUnit: time.Millisecond, MaxWaits: 1}
		if err := tr2.Backoff(ctx, enroll.Response{Header: http.Header{"Retry-After": {header}}}); err != nil {
			t.Errorf("%q: %v", header, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	tr3 := &enroll.HTTPTransport{Client: http.DefaultClient, MaxWaits: 1}
	if err := tr3.Backoff(cancelled, limited); err == nil {
		t.Error("cancelled wait")
	}
}

func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
