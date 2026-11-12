// SPDX-License-Identifier: Apache-2.0

package refop_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/refop"
)

// world is a reference operator with a client for its enrollment endpoint.
type world struct {
	t   *testing.T
	run *refop.Running
	c   *enroll.Client
	ctx context.Context
}

func newWorld(t *testing.T, cfg refop.Config) *world {
	t.Helper()
	run := refop.Serve(cfg)
	t.Cleanup(func() { _ = run.Close() })
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, run.Addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: run.Roots},
	}}
	c := &enroll.Client{T: &enroll.HTTPTransport{Client: hc, RetryUnit: time.Millisecond, MaxWaits: 3}, Host: run.Operator.Domain()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	w := &world{t: t, run: run, c: c, ctx: ctx}
	if _, err := c.Load(ctx, "https://"+run.Operator.Domain()+"/enroll/directory"); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) signer(alg string) *enroll.Signer {
	w.t.Helper()
	s, err := enroll.Generate(alg)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) csr(s *enroll.Signer) []byte {
	w.t.Helper()
	der, err := enroll.NewCSR(s.Private())
	if err != nil {
		w.t.Fatal(err)
	}
	return der
}

// pair pairs an installation with the code and returns its identity.
func (w *world) pair(code string, alg string) (enroll.Identity, enroll.Paired) {
	w.t.Helper()
	key := w.signer(alg)
	p, _, err := w.c.Pair(w.ctx, key, code, w.csr(w.signer(alg)))
	if err != nil {
		w.t.Fatalf("pair: %v", err)
	}
	return enroll.Identity{URL: p.Location, Signer: key}, p
}
