// SPDX-License-Identifier: Apache-2.0

package refop_test

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/enrollcases"
	"github.com/home-mandate/spec/relay/internal/refdns"
	"github.com/home-mandate/spec/relay/internal/refop"
)

const (
	acct  = "https://acme-v02.api.letsencrypt.org/acme/acct/999999999999999999"
	acct2 = "https://acme-v02.api.letsencrypt.org/acme/acct/999999999999999998"
	ca    = "letsencrypt.org"
	ownNm = "home.tester.example.com"
)

func loadCases(t *testing.T) []enrollcases.Case {
	t.Helper()
	cases, err := enrollcases.Load(relay.FS())
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// actors builds the actors of the cases from two installations of the world.
func (w *world) actors(self, other enroll.Identity, inst enroll.Installation) enrollcases.Actors {
	w.t.Helper()
	nonce, err := w.c.TakeNonce(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	// Use the nonce up with a regular read.
	resp, err := w.c.Send(w.ctx, self.URL, func(string) string {
		return enroll.Spec{Signer: self.Signer, Kid: self.URL, Nonce: nonce, URL: self.URL}.Compact()
	}, false, false)
	if err != nil || resp.Status != 200 {
		w.t.Fatalf("read: %v %d", err, resp.Status)
	}
	return enrollcases.Actors{
		Dir: w.c.Dir, Self: self, Other: other, CertificateURL: inst.Certificate,
		Unknown:   self.URL[:len(self.URL)-4] + "abcd",
		ForeignEd: w.signer(enroll.AlgEdDSA), ForeignES: w.signer(enroll.AlgES256),
		UsedNonce: nonce, CSR: w.csr(w.signer(enroll.AlgEdDSA)),
	}
}

func (w *world) play(a enrollcases.Actors, world string, offline bool) (failed []string, noNonce bool) {
	w.t.Helper()
	for _, cs := range loadCases(w.t) {
		if cs.World != world || cs.Offline != offline {
			continue
		}
		results, err := enrollcases.Play(w.ctx, w.c, a, cs)
		if err != nil {
			w.t.Fatalf("%s: %v", cs.ID, err)
		}
		for _, r := range results {
			if !r.Pass() {
				failed = append(failed, cs.ID)
			}
			noNonce = noNonce || !r.HasNonce
		}
	}
	return failed, noNonce
}

// casesOutcome plays the live cases against an operator with the fault.
func casesOutcome(t *testing.T, f refop.Fault) (failed []string, noNonce bool) {
	w := newWorld(t, refop.Config{Faults: f})
	a, instA := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	b, _ := w.pair(refop.DefaultCodes[1], enroll.AlgES256)
	act := w.actors(a, b, instA.Installation)
	failed, noNonce = w.play(act, enrollcases.WorldBothActive, false)
	if _, err := w.c.Unpair(w.ctx, b); err != nil {
		t.Fatal(err)
	}
	act.Unpaired = b
	more, noNonce2 := w.play(act, enrollcases.WorldOtherUnpaired, false)
	return append(failed, more...), noNonce || noNonce2
}

func TestCleanReferenceAnswersTheCasesAsTheyAreWritten(t *testing.T) {
	if failed, noNonce := casesOutcome(t, 0); len(failed) > 0 || noNonce {
		t.Errorf("failed %v, response without nonce: %v", failed, noNonce)
	}
}

func TestOfflineCasesAgainstTheReference(t *testing.T) {
	for _, tt := range []struct {
		world          string
		blocked, stale bool
	}{
		{enrollcases.WorldBlocked, true, false}, {enrollcases.WorldOffline, false, true}, {enrollcases.WorldOfflineBlock, true, true},
	} {
		w := newWorld(t, refop.Config{})
		a, inst := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
		act := w.actors(a, enroll.Identity{}, inst.Installation)
		w.run.Operator.Block(a.URL, tt.blocked)
		w.run.Operator.SetOffline(a.URL, tt.stale)
		if failed, _ := w.play(act, tt.world, true); len(failed) > 0 {
			t.Errorf("%s: failed %v", tt.world, failed)
		}
	}
}

// A blocked installation can unpair; an offline-too-long one cannot.
func TestBlockedCanUnpairAndOfflineCannot(t *testing.T) {
	w := newWorld(t, refop.Config{})
	a, _ := w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	b, _ := w.pair(refop.DefaultCodes[1], enroll.AlgEdDSA)
	w.run.Operator.Block(a.URL, true)
	w.run.Operator.SetOffline(b.URL, true)
	if _, err := w.c.Unpair(w.ctx, a); err != nil {
		t.Errorf("blocked unpair: %v", err)
	}
	var e *enroll.Error
	if _, err := w.c.Unpair(w.ctx, b); !errors.As(err, &e) || e.Name != "offline-too-long" {
		t.Errorf("offline unpair: %v", err)
	}
	if len(w.run.Operator.Denylist()) != 1 {
		t.Errorf("denylist %v", w.run.Operator.Denylist())
	}
}

func TestEachOrderFaultFailsItsCase(t *testing.T) {
	for name, tt := range map[string]struct {
		fault refop.Fault
		want  string
	}{
		"E1 nonce reuse": {refop.NonceReuse, "o11"}, "E3 nonce before signature": {refop.NonceBeforeSignature, "o09"},
		"E4 signature before unpaired": {refop.SignatureBeforeUnpaired, "o19"}, "E5 foreign kid": {refop.ForeignKidAccepted, "o05"},
		"E6 extra member": {refop.ExtraPayloadMember, "o14"}, "E18 bad signature after unpair": {refop.BadSignatureAfterUnpair, "o18"},
	} {
		failed, _ := casesOutcome(t, tt.fault)
		if !slices.Contains(failed, tt.want) {
			t.Errorf("%s: failed %v, want %s among them", name, failed, tt.want)
		}
	}
	if _, noNonce := casesOutcome(t, refop.NoNonceOnError); !noNonce {
		t.Error("E2: errors carry a nonce")
	}
}

func apiName(err error) string {
	var e *enroll.Error
	if errors.As(err, &e) {
		return e.Name
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// setup pairs two installations: A with Ed25519, B with ES256.
func setup(t *testing.T, f refop.Fault) (w *world, a, b enroll.Identity, pa enroll.Paired) {
	w = newWorld(t, refop.Config{Faults: f, DNSLag: 2 * time.Second})
	a, pa = w.pair(refop.DefaultCodes[0], enroll.AlgEdDSA)
	b, _ = w.pair(refop.DefaultCodes[1], enroll.AlgES256)
	return w, a, b, pa
}

func rrText(rr dnsmessage.Resource) string {
	switch body := rr.Body.(type) {
	case *dnsmessage.UnknownResource:
		n := int(body.Data[1])
		return fmt.Sprintf("%s %q", body.Data[2:2+n], body.Data[2+n:])
	case *dnsmessage.AResource:
		return netip.AddrFrom4(body.A).String()
	case *dnsmessage.TXTResource:
		return strings.Join(body.TXT, "")
	}
	return "?"
}

func texts(w *world, k int, name string, typ dnsmessage.Type) string {
	var out []string
	for _, rr := range w.run.Operator.DNS().Lookup(k, name, typ) {
		out = append(out, rrText(rr))
	}
	slices.Sort(out)
	return strings.Join(out, "|")
}

func ttl(w *world, name string, typ dnsmessage.Type) uint32 {
	return w.run.Operator.DNS().Lookup(0, name, typ)[0].Header.TTL
}

func leaf(t *testing.T, issued enroll.Issued) *x509.Certificate {
	c, err := x509.ParseCertificate(issued.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sanCritical(c *x509.Certificate) string {
	for _, e := range c.Extensions {
		if e.Id.String() == "2.5.29.17" && e.Critical {
			return "critical"
		}
	}
	return "not critical"
}

// reportAccount puts acct in force for the installation.
func (w *world) reportAccount(id enroll.Identity) {
	w.t.Helper()
	if _, err := w.c.ReportACME(w.ctx, id, acct, ca); err != nil {
		w.t.Fatal(err)
	}
}

func std(inst enroll.Installation) string { return inst.PublicName }

// probes observe one thing a gateway or a resolver can see; each defect changes exactly one.
var probes = []struct {
	name         string
	fault        refop.Fault
	clean, wrong string
	probe        func(t *testing.T, w *world, a, b enroll.Identity, pa enroll.Paired) string
}{
	{"E7 code with another key", refop.CodeWithOtherKey, "pairing-refused", "ok", func(t *testing.T, w *world, _, _ enroll.Identity, _ enroll.Paired) string {
		_, _, err := w.c.Pair(w.ctx, w.signer(enroll.AlgEdDSA), refop.DefaultCodes[0], w.csr(w.signer(enroll.AlgEdDSA)))
		return apiName(err)
	}},
	{"E8 CSR with the installation key", refop.CSRWithInstallationKey, "bad-csr", "ok", func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
		_, _, err := w.c.Certificate(w.ctx, a, pa.Installation.Certificate, w.csr(a.Signer))
		return apiName(err)
	}},
	{"E9 SAN not critical", refop.SANNotCritical, "critical", "not critical", func(t *testing.T, _ *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return sanCritical(leaf(t, pa.Certificate))
	}},
	{"E10 long certificate", refop.LongCertificate, "24h0m0s", "25h0m0s", func(t *testing.T, _ *world, _, _ enroll.Identity, pa enroll.Paired) string {
		c := leaf(t, pa.Certificate)
		return c.NotAfter.Sub(c.NotBefore).String()
	}},
	{"E11 notBefore stalls", refop.NotBeforeStalls, "rises", "stalls", func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
		next, _, err := w.c.Certificate(w.ctx, a, pa.Installation.Certificate, w.csr(w.signer(enroll.AlgEdDSA)))
		if err != nil {
			t.Fatal(err)
		}
		if leaf(t, next).NotBefore.After(leaf(t, pa.Certificate).NotBefore) {
			return "rises"
		}
		return "stalls"
	}},
	{"E12 second report", refop.SecondReportInForce, "confirmation-required", "ok", func(t *testing.T, w *world, a, _ enroll.Identity, _ enroll.Paired) string {
		w.reportAccount(a)
		_, err := w.c.ReportACME(w.ctx, a, acct2, ca)
		return apiName(err)
	}},
	{"E13 CA outside the list", refop.CAOutsideList, "malformed", "ok", func(t *testing.T, w *world, a, _ enroll.Identity, _ enroll.Paired) string {
		_, err := w.c.ReportACME(w.ctx, a, acct, "evil.example")
		return apiName(err)
	}},
	{"E14 challenge before account", refop.ChallengeBeforeAccount, "malformed", "ok", func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
		_, err := w.c.Challenge(w.ctx, a, pa.Installation.ACMEChallenge, nil)
		return apiName(err)
	}},
	{"E15 own name under the operator", refop.OwnNameUnderOperator, "malformed", "ok", func(t *testing.T, w *world, a, _ enroll.Identity, _ enroll.Paired) string {
		_, err := w.c.SetOwnDomain(w.ctx, a, "home."+refop.DefaultOperator)
		return apiName(err)
	}},
	{"E16 verified without TXT", refop.VerifiedWithoutTXT, "pending", "verified", func(t *testing.T, w *world, a, _ enroll.Identity, _ enroll.Paired) string {
		inst, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
		if err != nil {
			t.Fatal(err)
		}
		return inst.OwnDomain.Status
	}},
	{"E17 name held by another", refop.NoNameUnavailable, "name-unavailable", "ok", func(t *testing.T, w *world, a, b enroll.Identity, _ enroll.Paired) string {
		inst, err := w.c.SetOwnDomain(w.ctx, a, ownNm)
		if err != nil {
			t.Fatal(err)
		}
		w.run.Operator.DNS().Replace("_home-mandate-relay."+ownNm, refdns.TypeTXT, refdns.TXT("_home-mandate-relay."+ownNm, 60, inst.OwnDomain.Token))
		if inst, err = w.c.SetOwnDomain(w.ctx, a, ownNm); err != nil || inst.OwnDomain.Status != "verified" {
			t.Fatalf("verify: %v %+v", err, inst.OwnDomain)
		}
		_, err = w.c.SetOwnDomain(w.ctx, b, ownNm)
		return apiName(err)
	}},
	{"E19 relative Location", refop.RelativeLocation, "absolute", "relative", func(t *testing.T, _ *world, _, _ enroll.Identity, pa enroll.Paired) string {
		if strings.HasPrefix(pa.Location, "https://") {
			return "absolute"
		}
		return "relative"
	}},
	{"E20 key change to a foreign key", refop.KeyChangeToForeignKey, "key-conflict", "ok", func(t *testing.T, w *world, a, b enroll.Identity, _ enroll.Paired) string {
		_, err := w.c.KeyChange(w.ctx, a, b.Signer)
		return apiName(err)
	}},
	{"D1 apex without issuewild", refop.ApexNoIssuewild, `issue ";"|issuewild ";"`, `issue ";"`, func(t *testing.T, w *world, _, _ enroll.Identity, _ enroll.Paired) string {
		return texts(w, 1, refop.DefaultNameDomain, refdns.TypeCAA)
	}},
	{"D2 apex permits a CA", refop.ApexIssueCA, `issue ";"|issuewild ";"`, `issue "ca.example"|issuewild ";"`, func(t *testing.T, w *world, _, _ enroll.Identity, _ enroll.Paired) string {
		return texts(w, 1, refop.DefaultNameDomain, refdns.TypeCAA)
	}},
	{"D3 no validationmethods", refop.NoValidationMethods, `issue "letsencrypt.org; accounturi=` + acct + `; validationmethods=dns-01"|issuewild ";"`,
		`issue "letsencrypt.org; accounturi=` + acct + `"|issuewild ";"`, func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
			w.reportAccount(a)
			return texts(w, 1, std(pa.Installation), refdns.TypeCAA)
		}},
	{"D4 long TTL", refop.LongTTL, "300", "7200", func(t *testing.T, w *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return fmt.Sprint(ttl(w, std(pa.Installation), refdns.TypeA))
	}},
	{"D5 CAA stays after unpair", refop.CAAStaysAfterUnpair, "", `issue ";"`, func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
		if _, err := w.c.Unpair(w.ctx, a); err != nil {
			t.Fatal(err)
		}
		return texts(w, 1, std(pa.Installation), refdns.TypeCAA)
	}},
	{"D6 challenge before the second server", refop.ChallengeBeforeSecondServer, "1", "0", func(t *testing.T, w *world, a, _ enroll.Identity, pa enroll.Paired) string {
		w.reportAccount(a)
		if _, err := w.c.Challenge(w.ctx, a, pa.Installation.ACMEChallenge, []string{strings.Repeat("A", 43)}); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(len(w.run.Operator.DNS().Lookup(1, "_acme-challenge."+std(pa.Installation), refdns.TypeTXT)))
	}},
	{"D7 wrong address", refop.WrongAddress, "127.0.0.1", "127.0.0.9", func(t *testing.T, w *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return texts(w, 1, std(pa.Installation), refdns.TypeA)
	}},
	{"D8 extra TXT", refop.ExtraTXT, "", "extra", func(t *testing.T, w *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return texts(w, 1, std(pa.Installation), refdns.TypeTXT)
	}},
	{"D9 no closed CAA", refop.NoClosedCAA, `issue ";"`, "", func(t *testing.T, w *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return texts(w, 1, std(pa.Installation), refdns.TypeCAA)
	}},
	{"D10 CNAME at the apex", refop.ApexCNAME, "0", "1", func(t *testing.T, w *world, _, _ enroll.Identity, pa enroll.Paired) string {
		return fmt.Sprint(len(w.run.Operator.DNS().Lookup(0, refop.DefaultNameDomain, refdns.TypeCNAME)))
	}},
}

func TestEachDefectChangesWhatItIsMeantToChange(t *testing.T) {
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			for _, run := range []struct {
				fault refop.Fault
				want  string
			}{{0, p.clean}, {p.fault, p.wrong}} {
				w, a, b, pa := setup(t, run.fault)
				if got := p.probe(t, w, a, b, pa); got != run.want {
					t.Errorf("fault %v: got %q, want %q", run.fault, got, run.want)
				}
			}
		})
	}
}
