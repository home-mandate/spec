// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/enrollcases"
)

// sequence plays the steps in the order the pairing codes ask for: everything that needs a
// code comes first (a code is valid for 10 minutes, RELAY-v0 section 5.2).
func (s *script) sequence(ctx context.Context) error {
	if ok, err := s.directory(ctx); !ok || err != nil {
		return err
	}
	if err := s.pairAll(ctx); err != nil || s.insts[0] == nil {
		return err
	}
	steps := []func(context.Context) error{
		s.pairExtras, s.dnsAfterPairing, s.certificates, s.relayTunnel,
		func(ctx context.Context) error { return s.cases(ctx, enrollcases.WorldBothActive) },
		s.spelling, s.acme, s.ownDomain, s.keyChange, s.unpairOther, s.relayDenylist,
	}
	for _, step := range steps {
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

// certificates sends certificate requests that must be refused, and one renewal.
func (s *script) certificates(ctx context.Context) error {
	if !s.wantEnroll() && !s.wantRelay() {
		return nil
	}
	a := s.insts[0]
	url := a.paired.Installation.Certificate
	if s.wantEnroll() {
		if err := s.badCSRs(ctx, a, url); err != nil {
			return err
		}
	}
	if !s.canIssue() {
		return nil
	}
	tunnel, csr := newTunnel(enroll.AlgEdDSA)
	requested := time.Now()
	issued, _, err := s.c.Certificate(ctx, a.id, url, csr)
	if _, fatal := apiName(err); fatal != nil {
		return fatal
	}
	if err == nil {
		s.collect(a, issued, tunnel, requested, time.Now())
	}
	return nil
}

// badCSRs sends certificate requests that the operator has to refuse with bad-csr.
func (s *script) badCSRs(ctx context.Context, a *liveInst, url string) error {
	p384 := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	garbage := make([]byte, 100)
	_, _ = rand.Read(garbage)
	var problems []string
	for _, bad := range []struct {
		name string
		csr  []byte
	}{
		{"the installation key", must(enroll.NewCSR(a.id.Signer.Private()))},
		{"the key of the first tunnel certificate", must(enroll.NewCSR(a.first.Private()))},
		{"a P-384 key", must(enroll.NewCSR(p384))},
		{"garbage", garbage},
	} {
		_, _, err := s.c.Certificate(ctx, a.id, url, bad.csr)
		if err == nil {
			s.extra++
		}
		problem, fatal := expectError(err, "bad-csr")
		if fatal != nil {
			return fatal
		}
		if problem != "" {
			problems = append(problems, "a request with "+bad.name+": "+problem)
		}
	}
	s.rec(CheckEnrollBadCSR, strings.Join(problems, "; "))
	return nil
}

// actors builds what the symbolic cases stand for.
func (s *script) actors(ctx context.Context) (enrollcases.Actors, error) {
	a := s.insts[0]
	nonce, err := s.c.TakeNonce(ctx)
	if err != nil {
		return enrollcases.Actors{}, incompleteFor(err)
	}
	// Use the nonce up with a regular read, so that it is a nonce that was used.
	resp, err := s.c.Send(ctx, a.id.URL, func(string) string {
		return enroll.Spec{Signer: a.id.Signer, Kid: a.id.URL, Nonce: nonce, URL: a.id.URL}.Compact()
	}, false, false)
	if _, fatal := apiName(err); fatal != nil {
		return enrollcases.Actors{}, fatal
	}
	if err != nil || resp.Status != 200 {
		return enrollcases.Actors{}, &incompleteError{"a regular read of the installation failed"}
	}
	url := a.id.URL
	act := enrollcases.Actors{
		Dir: s.c.Dir, Self: a.id, CertificateURL: a.paired.Installation.Certificate,
		Unknown:   url[:strings.LastIndex(url, "/")+1] + enroll.RandomToken(16),
		ForeignEd: must(enroll.Generate(enroll.AlgEdDSA)), ForeignES: must(enroll.Generate(enroll.AlgES256)),
		UsedNonce: nonce,
	}
	if b := s.insts[1]; b != nil {
		act.Other = b.id
	}
	return act, nil
}

// cases plays the cases of enrollment-v0.json of a world that a live test can make.
func (s *script) cases(ctx context.Context, world string) error {
	if !s.wantEnroll() {
		return nil
	}
	all, err := enrollcases.Load(relay.FS())
	if err != nil {
		return err
	}
	act, err := s.actors(ctx)
	if err != nil {
		return err
	}
	if world == enrollcases.WorldOtherUnpaired {
		act.Unpaired = s.insts[1].id
	}
	for _, cs := range all {
		if cs.World != world || cs.Offline {
			continue
		}
		results, err := enrollcases.Play(ctx, s.c, act, cs)
		if errors.Is(err, enrollcases.ErrNotPlayable) {
			s.r.skip(ClassEnrollment)
			continue
		}
		if _, fatal := apiName(err); fatal != nil {
			return fatal
		}
		if err != nil {
			return &incompleteError{"a request of the cases got no answer"}
		}
		s.recordCase(cs, results)
	}
	return nil
}

func (s *script) recordCase(cs enrollcases.Case, results []enrollcases.Result) {
	for _, r := range results {
		if !r.Pass() {
			s.r.failIn(ClassEnrollment, casesFile, cs.ID, fmt.Sprintf("step %d: %s", r.Step+1, r.Got), r.Want)
			return
		}
	}
	s.r.pass(ClassEnrollment)
}

// variants are requests with a defect of spelling (RELAY-v0 section 5.1, step 1); each is
// malformed.
var variants = []struct {
	name   string
	defect enroll.Defect
}{
	{"an extra header member", enroll.ExtraHeaderMember}, {"a member twice in the header", enroll.DuplicateMember},
	{"a signature with padding", enroll.PaddedSignature}, {"a payload with padding", enroll.PaddedPayload},
	{"a nonce of 8 bytes", enroll.ShortNonce}, {"a header member with a capital", enroll.MemberCase},
	{"the algorithm none", enroll.UnknownAlg}, {"a kid and a jwk", enroll.KidAndJWK},
	{"no url in the header", enroll.MissingURL}, {"an ES256 signature with the higher S", enroll.HighS},
	{"a jwk with a private part", enroll.PrivateJWK},
}

func (s *script) spelling(ctx context.Context) error {
	if !s.wantEnroll() {
		return nil
	}
	var problems []string
	for _, v := range variants {
		id, target := s.insts[0].id, s.insts[0].id.URL
		if v.defect == enroll.HighS {
			if s.insts[1] == nil {
				continue
			}
			id, target = s.insts[1].id, s.insts[1].id.URL
		}
		spec := enroll.Spec{Signer: id.Signer, Kid: id.URL, URL: target, Defect: v.defect, Payload: `{"own_domain":null}`}
		if v.defect == enroll.PrivateJWK {
			spec.Kid, spec.JWK, spec.URL, target = "", true, s.c.Dir.Pair, s.c.Dir.Pair
			spec.Payload = `{"code":"` + randomCode() + `","csr":"` + enroll.B64(make([]byte, 100)) + `"}`
		}
		resp, err := s.c.Send(ctx, target, func(nonce string) string {
			spec.Nonce = nonce
			return spec.Compact()
		}, false, false)
		if _, fatal := apiName(err); fatal != nil {
			return fatal
		}
		if err != nil {
			return &incompleteError{"a request with a defect of spelling got no answer"}
		}
		if got := enroll.ErrorName(resp); got != "malformed" {
			problems = append(problems, v.name+": "+orText(got, "accepted"))
		}
	}
	s.rec(CheckEnrollSpelling, strings.Join(problems, "; "))
	return nil
}

// keyChange tries a key change to the key of the other installation, which must not work, and
// then changes the key of the first installation for good.
func (s *script) keyChange(ctx context.Context) error {
	if !s.wantEnroll() {
		return nil
	}
	a, b := s.insts[0], s.insts[1]
	if b != nil {
		_, err := s.c.KeyChange(ctx, a.id, b.id.Signer)
		problem, fatal := expectError(err, "key-conflict")
		if fatal != nil {
			return fatal
		}
		if err == nil {
			// The operator moved the key; go on with it, so that nothing else breaks.
			a.id.Signer = b.id.Signer
		}
		s.rec(CheckEnrollKeyConflict, problem)
	}
	fresh := s.signers["k3"]
	old := a.id
	_, err := s.c.KeyChange(ctx, a.id, fresh)
	if _, fatal := apiName(err); fatal != nil {
		return fatal
	}
	if err != nil {
		s.rec(CheckEnrollKeyChange, "the key change was refused")
		return nil
	}
	a.id.Signer = fresh
	st := s.r.state.State().WithKey(a.state, "k3")
	if err := s.r.state.Save(st); err != nil {
		return err
	}
	_, errOld := s.c.Read(ctx, old)
	name, fatal := apiName(errOld)
	if fatal != nil {
		return fatal
	}
	problem := ""
	switch {
	case name != "bad-signature" && name != "malformed":
		problem = "the old key still works or gets another error: " + orText(name, "success")
	default:
		if _, errNew := s.c.Read(ctx, a.id); errNew != nil {
			problem = "the new key does not work"
		}
	}
	s.rec(CheckEnrollKeyChange, problem)
	return nil
}

// unpairOther unpairs the second installation and checks what follows.
func (s *script) unpairOther(ctx context.Context) error {
	b := s.insts[1]
	if b == nil {
		return nil
	}
	if err := s.relayBeforeUnpair(ctx); err != nil {
		return err
	}
	inst, err := s.c.Unpair(ctx, b.id)
	if _, fatal := apiName(err); fatal != nil {
		return fatal
	}
	problem := ""
	if err != nil {
		problem = "unpairing failed"
	} else if inst.Status != "unpaired" {
		problem = "the answer to unpairing has the status " + esc(inst.Status)
	}
	if problem == "" {
		if err := s.r.state.Save(s.r.state.State().WithUnpaired(b.state)); err != nil {
			return err
		}
	}
	s.rec(CheckEnrollUnpair, problem)
	if problem == "" {
		s.relayUnpaired()
	}
	if inst.Status != "unpaired" {
		return nil
	}
	if err := s.cases(ctx, enrollcases.WorldOtherUnpaired); err != nil {
		return err
	}
	return s.dnsRemoved(ctx, b)
}
