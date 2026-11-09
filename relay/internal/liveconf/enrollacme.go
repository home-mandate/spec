// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"strings"

	"github.com/home-mandate/spec/relay/internal/enroll"
)

const unlistedCA = "unlisted-ca.example"

// acme reports ACME accounts that belong to nobody (RELAY-v0 section 8.3), so that the CAA
// record of the test permits nobody and no server certificate can be obtained, and publishes
// challenge values.
func (s *script) acme(ctx context.Context) error {
	if !s.wantEnroll() && !s.wantDNS() {
		return nil
	}
	a, b := s.insts[0], s.insts[1]
	account, caaID, ok := accountURI(s.doc.ACMECAs)
	if !ok {
		s.r.note("acme_cas lists no CA of relay/cas.md: the ACME checks were not made")
		return nil
	}
	s.account, s.caaID = account, caaID
	_, err := s.c.Challenge(ctx, a.id, a.paired.Installation.ACMEChallenge, nil)
	problem, fatal := expectError(err, "malformed")
	if fatal != nil {
		return fatal
	}
	s.rec(CheckEnrollChallengeEarly, problem)
	if err := s.reportAndConfirm(ctx, a, account, caaID); err != nil {
		return err
	}
	if err := s.challenge(ctx, a); err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	accountB, _, _ := accountURI(s.doc.ACMECAs)
	if _, err := s.c.ReportACME(ctx, b.id, accountB, caaID); isFatal(err) {
		return err
	}
	if _, err := s.c.Challenge(ctx, b.id, b.paired.Installation.ACMEChallenge, []string{enroll.RandomToken(32)}); isFatal(err) {
		return err
	}
	_, err = s.c.ReportACME(ctx, b.id, accountB, unlistedCA)
	problem, fatal = expectError(err, "malformed")
	if fatal != nil {
		return fatal
	}
	s.rec(CheckEnrollACMECA, problem)
	return nil
}

// isFatal reports whether err ends the run: the operator cannot be reached.
func isFatal(err error) bool {
	_, fatal := apiName(err)
	return fatal != nil
}

// reportAndConfirm reports the first account, then a second one that needs the confirmation of
// the household, and checks the records in between.
func (s *script) reportAndConfirm(ctx context.Context, a *liveInst, account, caaID string) error {
	inst, err := s.c.ReportACME(ctx, a.id, account, caaID)
	problem, fatal := expectError(err, "")
	if fatal != nil {
		return fatal
	}
	switch {
	case err != nil:
		problem = "the first report was refused (" + problem + ")"
	case inst.ACMEAccount != account || inst.CAAIdentity != caaID:
		problem = "the installation does not show the reported account"
	default:
		problem = ""
	}
	s.rec(CheckEnrollACMEReport, problem)
	second, _, _ := accountURI(s.doc.ACMECAs)
	_, err = s.c.ReportACME(ctx, a.id, second, caaID)
	problem, fatal = expectError(err, "confirmation-required")
	if fatal != nil {
		return fatal
	}
	after, rerr := s.c.Read(ctx, a.id)
	if isFatal(rerr) {
		return rerr
	}
	if problem == "" && (rerr != nil || after.ACMEAccount != account) {
		problem = "the second report changed the account in force"
	}
	s.rec(CheckEnrollACMEConfirm, problem)
	if err := s.dnsAccount(ctx, a); err != nil {
		return err
	}
	// Withdraw the pending pair by reporting the pair in force.
	_, err = s.c.ReportACME(ctx, a.id, account, caaID)
	if isFatal(err) {
		return err
	}
	return nil
}

// challenge publishes a challenge value, checks the answer and the name servers, and removes it.
func (s *script) challenge(ctx context.Context, a *liveInst) error {
	value := enroll.RandomToken(32)
	url := a.paired.Installation.ACMEChallenge
	got, err := s.c.Challenge(ctx, a.id, url, []string{value})
	if _, fatal := apiName(err); fatal != nil {
		return fatal
	}
	switch {
	case err != nil:
		s.rec(CheckEnrollChallenge, "the challenge was refused")
	case len(got) != 1 || got[0] != value:
		s.rec(CheckEnrollChallenge, "the answer does not hold the values that were sent")
	default:
		s.rec(CheckEnrollChallenge, "")
	}
	if err == nil {
		if err := s.dnsChallenge(ctx, a, value); err != nil {
			return err
		}
	}
	_, err = s.c.Challenge(ctx, a.id, url, nil)
	if isFatal(err) {
		return err
	}
	return nil
}

// ownDomain registers an own-domain name, sets its TXT record with the DNS hook and checks the
// states pending and verified, and the refusal of names that are not allowed.
func (s *script) ownDomain(ctx context.Context) error {
	if !s.wantEnroll() && !s.wantRelay() {
		return nil
	}
	a, b := s.insts[0], s.insts[1]
	var problems []string
	for _, name := range []string{"home." + s.doc.OperatorDomain, "home." + s.doc.NameDomain} {
		_, err := s.c.SetOwnDomain(ctx, a.id, name)
		problem, fatal := expectError(err, "malformed")
		if fatal != nil {
			return fatal
		}
		if err == nil {
			_, _ = s.c.SetOwnDomain(ctx, a.id, "")
		}
		if problem != "" {
			problems = append(problems, esc(name)+": "+problem)
		}
	}
	s.rec(CheckEnrollOwnForbidden, strings.Join(problems, "; "))
	own := s.r.s.OwnDomain
	if own == "" || s.hook == nil {
		return nil
	}
	record := proofLabel + own
	if err := s.r.state.Save(s.r.state.State().WithOwnName(own)); err != nil {
		return err
	}
	if err := s.setTXT(ctx, record, placeholder); err != nil {
		return err
	}
	inst, err := s.register(ctx, a, own)
	if err != nil {
		return err
	}
	problem := ""
	switch {
	case inst.OwnDomain == nil || inst.OwnDomain.Name != own:
		problem = "the installation does not show the own-domain name"
	case inst.OwnDomain.Status != "pending":
		problem = "the status is " + esc(inst.OwnDomain.Status) + " before the TXT record exists"
	case !tokenPattern.MatchString(inst.OwnDomain.Token):
		problem = "the token is shorter than 128 bits or not base64url"
	}
	s.rec(CheckEnrollOwnPending, problem)
	if problem != "" || inst.OwnDomain == nil {
		return nil
	}
	if inst, err = s.renewedToken(ctx, a, own, inst); err != nil || inst.OwnDomain == nil {
		return err
	}
	if err := s.relayOwnPending(ctx, own); err != nil {
		return err
	}
	if err := s.setTXT(ctx, record, inst.OwnDomain.Token); err != nil {
		return err
	}
	if err := s.verify(ctx, a, own); err != nil {
		return err
	}
	if s.ownVerified {
		if err := s.relayOwnVerified(ctx, own); err != nil {
			return err
		}
	}
	if b == nil {
		return nil
	}
	_, err = s.c.SetOwnDomain(ctx, b.id, own)
	problem, fatal := expectError(err, "name-unavailable")
	if fatal != nil {
		return fatal
	}
	s.rec(CheckEnrollOwnTaken, problem)
	return nil
}

// register registers the name; a token that a hook cannot be given (it begins with "-") makes
// the tool register again, which gives a new token.
func (s *script) register(ctx context.Context, a *liveInst, own string) (enroll.Installation, error) {
	var inst enroll.Installation
	for range 3 {
		var err error
		inst, err = s.c.SetOwnDomain(ctx, a.id, own)
		if _, fatal := apiName(err); fatal != nil {
			return inst, fatal
		}
		if err != nil || inst.OwnDomain == nil || validToken(inst.OwnDomain.Token) || !tokenPattern.MatchString(inst.OwnDomain.Token) {
			return inst, nil
		}
		if _, err := s.c.SetOwnDomain(ctx, a.id, ""); isFatal(err) {
			return inst, err
		}
	}
	return inst, &incompleteError{"the tokens of the operator cannot be given to a DNS hook"}
}

// renewedToken removes the registration and registers the name again: the token must be a new
// one (RELAY-v0 section 6.4). It returns the installation as the operator shows it last.
func (s *script) renewedToken(ctx context.Context, a *liveInst, own string, first enroll.Installation) (enroll.Installation, error) {
	_, err := s.c.SetOwnDomain(ctx, a.id, "")
	if _, fatal := apiName(err); fatal != nil {
		return first, fatal
	}
	if err != nil {
		s.rec(CheckEnrollOwnToken, "removing the registration failed")
		return first, nil
	}
	inst, err := s.register(ctx, a, own)
	if err != nil {
		return inst, err
	}
	problem := ""
	switch {
	case inst.OwnDomain == nil:
		problem = "the name was not registered again"
	case inst.OwnDomain.Token == first.OwnDomain.Token:
		problem = "a removed registration's token was used again"
	}
	s.rec(CheckEnrollOwnToken, problem)
	return inst, nil
}

// verify registers the name again, which makes the operator look up the TXT record
// (RELAY-v0 section 6.4), until it is verified or the attempts are used.
func (s *script) verify(ctx context.Context, a *liveInst, own string) error {
	problem := "the name is not verified after the TXT record was set"
	for attempt := range 3 {
		inst, err := s.c.SetOwnDomain(ctx, a.id, own)
		if _, fatal := apiName(err); fatal != nil {
			return fatal
		}
		if err == nil && inst.OwnDomain != nil && inst.OwnDomain.Status == "verified" {
			problem = ""
			s.ownVerified = true
			break
		}
		if attempt < 2 {
			if err := sleep(ctx, s.r.env.Timing.Poll); err != nil {
				return incompleteFor(err)
			}
		}
	}
	s.rec(CheckEnrollOwnVerified, problem)
	return nil
}

// setTXT sets the TXT record with the hook and waits until it shows on the name servers of its
// zone. The tool never asks for more than this one record.
func (s *script) setTXT(ctx context.Context, record, value string) error {
	if err := s.hook.Set(ctx, record, value); err != nil {
		return &incompleteError{clean(err.Error())}
	}
	if err := s.dns.waitTXT(ctx, record, value); err != nil {
		return &incompleteError{"the record of the own domain " + err.Error()}
	}
	return nil
}
