// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/enroll"
)

const (
	// maxCertificates is how many tunnel certificates a run asks for (RELAY-v0 section 8.3
	// and the plan: the operator is spared).
	maxCertificates = 4
	// casesFile names the file of the cases in a report.
	casesFile = "enrollment-v0.json"
)

// liveInst is a test installation of the run.
type liveInst struct {
	id     enroll.Identity
	keyID  string
	state  int
	paired enroll.Paired
	// tunnel is the key of the latest tunnel certificate request.
	tunnel *enroll.Signer
	first  *enroll.Signer
	// creds are the tunnel certificates in the order they were issued, for the class relay.
	creds []tunnelCred
	// lastNotBefore is the notBefore of the latest tunnel certificate.
	lastNotBefore time.Time
}

// script is the sequence that plays the classes enrollment and dns together: they share the
// pairings, and a check of one class needs the state another leaves behind (RELAY-v0
// section 8.3 asks for at most two installations). A check is recorded once, under its class;
// a class that is not selected records nothing.
type script struct {
	r       *run
	c       *enroll.Client
	dns     *dnsTools
	hook    dnsHook
	doc     *metadataDoc
	signers map[string]*enroll.Signer
	insts   [MaxCodes]*liveInst
	// rl is the class relay; nil if it is not selected or cannot be played.
	rl *relayRun
	// ownVerified is set when the own-domain name became verified.
	ownVerified bool
	issued      []issuedCert
	seen        map[string]bool
	schema      []string
	// servers are the name servers of the name domain.
	servers []dnsq.Server
	account string
	caaID   string
	// extra counts certificates issued for requests that had to be refused.
	extra int
}

// scriptState is kept in the run, so that the two classes share one script.
type scriptState struct {
	once sync.Once
	err  error
	s    *script
}

func runEnrollment(ctx context.Context, r *run) error { return r.playScript(ctx) }

func runDNS(ctx context.Context, r *run) error { return r.playScript(ctx) }

func (r *run) playScript(ctx context.Context) error {
	r.scr.once.Do(func() { r.scr.err = r.scr.play(ctx, r) })
	return r.scr.err
}

func (st *scriptState) play(ctx context.Context, r *run) error {
	s := &script{r: r, seen: map[string]bool{}}
	st.s = s
	err := s.setup(ctx)
	if err == nil {
		err = s.sequence(ctx)
	}
	s.finish(err == nil)
	return err
}

func (s *script) setup(ctx context.Context) error {
	doc, err := s.r.loadMeta(ctx)
	if err != nil {
		return err
	}
	s.doc = doc
	u, _ := url.Parse(doc.Enrollment)
	s.c = &enroll.Client{T: s.r.web, Host: u.Host, Validate: s.validate}
	s.dns = newDNSTools(s.r.env)
	switch {
	case s.r.s.DNSHook != "":
		s.hook = newExecHook(s.r.s.DNSHook, s.r.env.Timing.Hook)
	case s.r.s.DNSManual:
		s.hook = manualHook{out: s.r.env.prompt()}
	}
	if s.r.state != nil {
		if s.signers, err = signersOf(s.r.state.State().Keys); err != nil {
			return err
		}
	}
	return nil
}

func (s *script) validate(def string, body []byte) {
	if p := schemaProblem(def, body); p != "" {
		s.schema = append(s.schema, p)
	}
}

// rec records the verdict of a check: no problem is a pass.
func (s *script) rec(id, problem string) {
	if s.seen[id] {
		return
	}
	s.seen[id] = true
	class := strings.SplitN(id, ".", 2)[0]
	if problem == "" {
		s.r.pass(class)
		return
	}
	s.r.fail(class, id, problem, titleOf(id))
}

func titleOf(id string) string {
	for _, c := range checks {
		if c.ID == id {
			return c.Title
		}
	}
	return id
}

// finish counts the checks that were not reached as skipped and records the verdicts that
// need the whole run.
func (s *script) finish(complete bool) {
	if s.c != nil && complete {
		if len(s.issued) > 0 {
			s.judgeCertificates()
		}
		if s.seen[CheckEnrollDirectory] {
			s.rec(CheckEnrollNonceOnError, onlyIf(s.c.NoNonceOnError > 0, "an error response had no Replay-Nonce"))
			s.rec(CheckEnrollSchema, strings.Join(s.schema, "; "))
		}
	}
	if s.rl != nil {
		s.rl.close()
		s.rl.record()
	}
	for _, class := range []string{ClassEnrollment, ClassDNS, ClassRelay} {
		for _, c := range checksOf(class) {
			if !s.seen[c.ID] && c.ID != CheckEnrollCases {
				s.r.skip(class)
			}
		}
	}
}

func onlyIf(cond bool, text string) string {
	if cond {
		return text
	}
	return ""
}

func (s *script) judgeCertificates() {
	problems := map[string]string{}
	for i, c := range s.issued {
		for id, text := range certProblems(c, s.doc.TrustDomain) {
			if problems[id] == "" {
				problems[id] = fmt.Sprintf("certificate %d: %s", i+1, text)
			}
		}
	}
	for _, id := range []string{CheckEnrollCertRules, CheckEnrollCertSAN, CheckEnrollCertLifetime, CheckEnrollCertMonotonic} {
		s.rec(id, problems[id])
	}
}

// apiName returns the name of an error of the operator, "" for no error, and a failure of the
// network as the second result.
func apiName(err error) (string, error) {
	var apiErr *enroll.Error
	var nf *netFailure
	switch {
	case err == nil:
		return "", nil
	case errors.As(err, &apiErr) && apiErr.Name == "rate-limited":
		return "", incompleteFor(errRateLimited)
	case errors.As(err, &apiErr):
		return apiErr.Name, nil
	case errors.As(err, &nf), errors.Is(err, errRateLimited), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "", incompleteFor(err)
	}
	return "unexpected", nil
}

// expectError returns "" if err is the error name, else what happened.
func expectError(err error, name string) (string, error) {
	got, fatal := apiName(err)
	if fatal != nil {
		return "", fatal
	}
	if got == name {
		return "", nil
	}
	if got == "" {
		got = "success"
	}
	return "got " + got + ", want " + name, nil
}

func randomDigits(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i := range raw {
		raw[i] = '0' + raw[i]%10
	}
	raw[0] = '9'
	return string(raw)
}

const codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func randomCode() string {
	raw := make([]byte, codeLength)
	_, _ = rand.Read(raw)
	for i := range raw {
		raw[i] = codeAlphabet[int(raw[i])%len(codeAlphabet)]
	}
	return string(raw)
}

// accountPrefixes are the prefixes of the ACME account URIs of the CAs of relay/cas.md; a test
// compares them with that file.
var accountPrefixes = map[string]string{
	"letsencrypt.org": "https://acme-v02.api.letsencrypt.org/acme/acct/",
}

// accountURI returns the URI of an ACME account that belongs to nobody (RELAY-v0 section 8.3):
// the prefix of the CA and a number far beyond every number the CA has assigned.
func accountURI(cas []string) (account, caaID string, ok bool) {
	for _, ca := range cas {
		if prefix, found := accountPrefixes[ca]; found {
			return prefix + randomDigits(18), ca, true
		}
	}
	return "", "", false
}
