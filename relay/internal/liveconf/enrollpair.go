// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/enroll"
)

var homeIDPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

func (s *script) canIssue() bool { return len(s.issued)+s.extra < maxCertificates }

func (s *script) wantDNS() bool { return s.r.selected(ClassDNS) }

func (s *script) wantEnroll() bool { return s.r.selected(ClassEnrollment) }

// directory fetches the directory and checks the nonces.
func (s *script) directory(ctx context.Context) (bool, error) {
	_, err := s.c.Load(ctx, s.doc.Enrollment)
	name, fatal := apiName(err)
	if fatal != nil {
		return false, fatal
	}
	if err != nil {
		s.rec(CheckEnrollDirectory, "the directory is unusable ("+orText(name, "invalid")+")")
		return false, nil
	}
	s.rec(CheckEnrollDirectory, "")
	problem, err := s.nonces(ctx)
	if err != nil {
		return false, err
	}
	s.rec(CheckEnrollNonce, problem)
	return true, nil
}

func orText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// nonces checks HEAD and GET on new_nonce.
func (s *script) nonces(ctx context.Context) (string, error) {
	head, resp, err := s.c.FreshNonce(ctx)
	if _, fatal := apiName(err); fatal != nil {
		return "", fatal
	}
	if err != nil {
		return "HEAD on new_nonce: status " + strconv.Itoa(resp.Status) + " or no valid nonce", nil
	}
	if len(resp.Body) != 0 {
		return "HEAD on new_nonce has a body", nil
	}
	get, err := s.c.T.Do(ctx, "GET", s.c.Dir.NewNonce, nil, "", false)
	if err != nil {
		return "", incompleteFor(err)
	}
	next := get.Header.Get("Replay-Nonce")
	switch {
	case get.Status != 204 || len(get.Body) != 0:
		return "GET on new_nonce: status " + strconv.Itoa(get.Status) + " or a body, want 204 without a body", nil
	case !enroll.ValidNonce(next):
		return "GET on new_nonce carries no valid nonce", nil
	case next == head:
		return "two responses carry the same nonce", nil
	}
	return "", nil
}

// newTunnel makes a tunnel key and its certificate request.
func newTunnel(alg string) (*enroll.Signer, []byte) {
	key := must(enroll.Generate(alg))
	return key, must(enroll.NewCSR(key.Private()))
}

func tunnelAlg(i int) string { return stateKeyAlgs[i] }

// pairAll pairs one installation for each code, before anything else uses a code's time.
func (s *script) pairAll(ctx context.Context) error {
	var problems []string
	for i := range s.r.s.Codes {
		conflict, tried, err := s.keyInUse(ctx, i)
		if err != nil {
			return err
		}
		problem, err := s.pairOne(ctx, i)
		if err != nil {
			return err
		}
		if tried {
			s.recordPairKeyConflict(i, conflict)
		}
		if problem != "" {
			problems = append(problems, problem)
		}
	}
	if len(s.r.s.Codes) > 0 {
		s.rec(CheckEnrollPairing, strings.Join(problems, "; "))
	}
	return nil
}

// keyInUse sends the code of the second installation with the installation key of the first,
// which must give key-conflict (RELAY-v0 section 5.2); the code is tried again with a new key
// by pairOne. It reports what is wrong with the answer, and whether it tried at all.
func (s *script) keyInUse(ctx context.Context, i int) (string, bool, error) {
	first := s.insts[0]
	if i != 1 || first == nil || !s.wantEnroll() {
		return "", false, nil
	}
	_, csr := newTunnel(tunnelAlg(i))
	p, _, err := s.c.Pair(ctx, first.id.Signer, s.r.s.Codes[i], csr)
	problem, fatal := expectError(err, "key-conflict")
	if fatal != nil {
		return "", true, fatal
	}
	if err == nil {
		if err := s.stray(ctx, p, first.keyID); err != nil {
			return "", true, err
		}
	}
	return problem, true, nil
}

// recordPairKeyConflict records the check after the code was tried again with a new key: the
// code must not be used up by the key-conflict.
func (s *script) recordPairKeyConflict(i int, problem string) {
	if problem == "" && s.insts[i] == nil {
		problem = "the code was used up by key-conflict: it is refused with a new key"
	}
	s.rec(CheckEnrollPairKeyConflict, problem)
}

func (s *script) pairOne(ctx context.Context, i int) (string, error) {
	keyID := "k" + strconv.Itoa(i+1)
	signer := s.signers[keyID]
	if isTestKey(signer.Thumbprint()) {
		return "", errors.New("internal error: a key of the state file is a test key")
	}
	tunnel, csr := newTunnel(tunnelAlg(i))
	requested := time.Now()
	p, _, err := s.c.Pair(ctx, signer, s.r.s.Codes[i], csr)
	received := time.Now()
	name, fatal := apiName(err)
	switch {
	case fatal != nil:
		return "", fatal
	case name == "pairing-refused" && i == 1 && s.insts[0] != nil && s.wantEnroll():
		// After a key-conflict at this code: recordPairKeyConflict finds the code used up.
		return "", nil
	case name == "pairing-refused":
		return "", &incompleteError{"the operator refused a pairing code: it is wrong, used or expired"}
	case err != nil:
		return "pairing failed (" + orText(name, "unreadable response") + ")", nil
	}
	location, problem := s.location(p.Location)
	s.rec(CheckEnrollLocation, problem)
	if location == "" {
		return "", &incompleteError{"the operator sent an installation URL the tool does not use; unpair the test installation in the portal"}
	}
	st := s.r.state.State().WithInstallation(StateInstallation{URL: location, Key: keyID})
	if err := s.r.state.Save(st); err != nil {
		return "", err
	}
	inst := &liveInst{id: enroll.Identity{URL: location, Signer: signer}, keyID: keyID, state: len(st.Installations) - 1, paired: p}
	inst.first = tunnel
	s.insts[i] = inst
	s.collect(inst, p.Certificate, tunnel, requested, received)
	return s.pairingProblem(p), nil
}

// location returns the installation URL of a Location header, resolved against the enrollment
// URL if it is relative, and what is wrong with it. The URL is empty if it cannot be used.
func (s *script) location(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "Location is not a URL"
	}
	if !u.IsAbs() {
		base, _ := url.Parse(s.doc.Enrollment)
		resolved := base.ResolveReference(u).String()
		if enroll.CheckURL(resolved, s.c.Host) != nil {
			return "", "Location is not an absolute URL"
		}
		return resolved, "Location is not an absolute URL"
	}
	if enroll.CheckURL(raw, s.c.Host) != nil {
		return "", "Location is not an HTTPS URL on the enrollment host"
	}
	return raw, ""
}

func (s *script) pairingProblem(p enroll.Paired) string {
	inst := p.Installation
	switch {
	case inst.Status != "active":
		return "the status of the new installation is " + esc(inst.Status)
	case !homeIDPattern.MatchString(inst.HomeID):
		return "the home ID is not 26 characters of a-z and 2-7"
	case inst.PublicName != inst.HomeID+"."+s.doc.NameDomain:
		return "the public name is not the home ID followed by the name domain"
	case enroll.CheckURL(inst.Certificate, s.c.Host) != nil, enroll.CheckURL(inst.ACMEChallenge, s.c.Host) != nil:
		return "the certificate or acme_challenge URL is not on the enrollment host"
	case len(p.Certificate.Chain) == 0:
		return "the pairing response has no certificate"
	}
	return ""
}

// collect remembers a tunnel certificate for the judgement at the end.
func (s *script) collect(inst *liveInst, issued enroll.Issued, key *enroll.Signer, requested, received time.Time) {
	c := issuedCert{chain: issued.Chain, notAfter: issued.NotAfter, key: key.Public(), homeID: inst.paired.Installation.HomeID,
		requested: requested, received: received, earlier: inst.lastNotBefore}
	s.issued = append(s.issued, c)
	inst.tunnel = key
	var leaf *x509.Certificate
	if len(issued.Chain) > 0 {
		leaf, _ = x509.ParseCertificate(issued.Chain[0])
	}
	if leaf == nil {
		// The verdict is recorded now: a run that ends early never reaches judgeCertificates.
		if text := certProblems(c, s.doc.TrustDomain)[CheckEnrollCertRules]; text != "" {
			s.rec(CheckEnrollCertRules, fmt.Sprintf("certificate %d: %s", len(s.issued), text))
		}
		return
	}
	inst.lastNotBefore = leaf.NotBefore
	inst.creds = append(inst.creds, tunnelCred{
		cert:      tls.Certificate{Certificate: issued.Chain, PrivateKey: key.Private()},
		notBefore: leaf.NotBefore, p256: key.Alg() == enroll.AlgES256,
	})
}

// pairExtras repeats the pairing of the second installation, and tries a used code with another
// key and a wrong code.
func (s *script) pairExtras(ctx context.Context) error {
	if b := s.insts[1]; b != nil && s.canIssue() {
		if err := s.repeat(ctx, b); err != nil {
			return err
		}
	}
	if s.insts[0] == nil {
		return nil
	}
	_, csr := newTunnel(enroll.AlgES256)
	p, _, err := s.c.Pair(ctx, s.signers["k4"], s.r.s.Codes[0], csr)
	problem, fatal := expectError(err, "pairing-refused")
	if fatal != nil {
		return fatal
	}
	if err == nil {
		if err := s.stray(ctx, p, "k4"); err != nil {
			return err
		}
	}
	if problem == "" {
		_, _, err = s.c.Pair(ctx, s.signers["k4"], randomCode(), csr)
		if problem, fatal = expectError(err, "pairing-refused"); fatal != nil {
			return fatal
		}
	}
	s.rec(CheckEnrollRefused, problem)
	return nil
}

// repeat repeats the pairing request of an installation with its key and code and a new
// tunnel key (RELAY-v0 section 5.2).
func (s *script) repeat(ctx context.Context, b *liveInst) error {
	tunnel, csr := newTunnel(enroll.AlgEdDSA)
	requested := time.Now()
	p, _, err := s.c.Pair(ctx, b.id.Signer, s.r.s.Codes[1], csr)
	received := time.Now()
	problem, fatal := expectError(err, "")
	if fatal != nil {
		return fatal
	}
	switch {
	case err != nil:
		problem = "the repeated pairing was refused or unreadable (" + problem + ")"
	case !s.sameLocation(p.Location, b.id.URL):
		problem = "the repeated pairing gave another installation URL"
	default:
		s.collect(b, p.Certificate, tunnel, requested, received)
		problem = ""
	}
	s.rec(CheckEnrollRepeat, problem)
	return nil
}

// stray handles the installation that an operator made from a used code and another key
// (which it must not do): the tool records it and unpairs it at once with the key it was made
// for, so that a failed check does not leave a third installation behind.
func (s *script) stray(ctx context.Context, p enroll.Paired, keyID string) error {
	location, _ := s.location(p.Location)
	if location == "" {
		return &incompleteError{"the operator made an installation from a used code and sent no usable URL; unpair it in the portal"}
	}
	st := s.r.state.State().WithInstallation(StateInstallation{URL: location, Key: keyID})
	if err := s.r.state.Save(st); err != nil {
		return err
	}
	done, err := s.c.Unpair(ctx, enroll.Identity{URL: location, Signer: s.signers[keyID]})
	if _, fatal := apiName(err); fatal != nil {
		return fatal
	}
	if isUnpaired(done, err) {
		return s.r.state.Save(s.r.state.State().WithUnpaired(len(st.Installations) - 1))
	}
	return nil
}

func (s *script) sameLocation(raw, want string) bool {
	got, _ := s.location(raw)
	return got == want
}
