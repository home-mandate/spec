// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/refop"
)

func TestCleanReferencePassesEnrollmentAndDNS(t *testing.T) {
	r, env := serve(t, refop.Config{})
	s := enrollSettings(t, r, ClassEnrollment, ClassDNS)
	res := RunWith(ctx(t), s, env)
	if len(res.Report.Failures) > 0 {
		t.Fatalf("failures: %+v", res.Report.Failures)
	}
	for _, class := range []string{ClassEnrollment, ClassDNS} {
		c := res.Report.Classes[class]
		if !c.Conforms || c.Skipped != 0 {
			t.Errorf("%s: %+v", class, c)
		}
	}
	if res.Report.Installations != (Installations{Created: 2, Unpaired: 2}) {
		t.Errorf("installations %+v", res.Report.Installations)
	}
	if _, err := os.Stat(s.StatePath); err == nil {
		t.Error("the state file is still there")
	}
}

// failures lists the failed checks of a report as "file:id".
func failures(res Result) []string {
	out := []string{}
	for _, f := range res.Report.Failures {
		out = append(out, f.File+":"+f.ID)
	}
	slices.Sort(out)
	return out
}

// TestEachBrokenVariantFailsExactlyItsCheck: every defect of the reference operator fails the
// check meant to catch it, and no other check; a variant runs only the class it belongs to.
func TestEachBrokenVariantFailsExactlyItsCheck(t *testing.T) {
	const cases = "enrollment-v0.json:"
	for name, tt := range map[string]struct {
		fault refop.Fault
		class string
		want  []string
	}{
		"E1 nonce reuse":                  {refop.NonceReuse, ClassEnrollment, []string{cases + "o11", cases + "o13"}},
		"E2 no nonce on error":            {refop.NoNonceOnError, ClassEnrollment, []string{"live:" + CheckEnrollNonceOnError}},
		"E3 nonce before signature":       {refop.NonceBeforeSignature, ClassEnrollment, []string{cases + "o09"}},
		"E4 signature before unpaired":    {refop.SignatureBeforeUnpaired, ClassEnrollment, []string{cases + "o19"}},
		"E5 foreign kid":                  {refop.ForeignKidAccepted, ClassEnrollment, []string{cases + "o05", cases + "o06", cases + "o23"}},
		"E6 extra member":                 {refop.ExtraPayloadMember, ClassEnrollment, []string{cases + "o14"}},
		"E7 code with another key":        {refop.CodeWithOtherKey, ClassEnrollment, []string{"live:" + CheckEnrollRefused}},
		"E8 CSR with installation key":    {refop.CSRWithInstallationKey, ClassEnrollment, []string{"live:" + CheckEnrollBadCSR}},
		"E9 SAN not critical":             {refop.SANNotCritical, ClassEnrollment, []string{"live:" + CheckEnrollCertSAN}},
		"E10 long certificate":            {refop.LongCertificate, ClassEnrollment, []string{"live:" + CheckEnrollCertLifetime}},
		"E11 notBefore stalls":            {refop.NotBeforeStalls, ClassEnrollment, []string{"live:" + CheckEnrollCertMonotonic}},
		"E12 second report":               {refop.SecondReportInForce, ClassEnrollment, []string{"live:" + CheckEnrollACMEConfirm}},
		"E13 CA outside the list":         {refop.CAOutsideList, ClassEnrollment, []string{"live:" + CheckEnrollACMECA}},
		"E14 challenge before account":    {refop.ChallengeBeforeAccount, ClassEnrollment, []string{"live:" + CheckEnrollChallengeEarly}},
		"E15 own name under operator":     {refop.OwnNameUnderOperator, ClassEnrollment, []string{"live:" + CheckEnrollOwnForbidden}},
		"E16 verified without TXT":        {refop.VerifiedWithoutTXT, ClassEnrollment, []string{"live:" + CheckEnrollOwnPending}},
		"E17 no name-unavailable":         {refop.NoNameUnavailable, ClassEnrollment, []string{"live:" + CheckEnrollOwnTaken}},
		"E18 bad signature after unpair":  {refop.BadSignatureAfterUnpair, ClassEnrollment, []string{cases + "o18", cases + "o19", cases + "o20", cases + "o21"}},
		"E19 relative Location":           {refop.RelativeLocation, ClassEnrollment, []string{"live:" + CheckEnrollLocation}},
		"E20 key change to foreign key":   {refop.KeyChangeToForeignKey, ClassEnrollment, []string{"live:" + CheckEnrollKeyConflict}},
		"E21 key-conflict burns the code": {refop.KeyConflictBurnsCode, ClassEnrollment, []string{"live:" + CheckEnrollPairKeyConflict}},
		"E22 token reused":                {refop.TokenReused, ClassEnrollment, []string{"live:" + CheckEnrollOwnToken}},
		"D1 apex without issuewild":       {refop.ApexNoIssuewild, ClassDNS, []string{"live:" + CheckDNSApex}},
		"D2 apex permits a CA":            {refop.ApexIssueCA, ClassDNS, []string{"live:" + CheckDNSApex}},
		"D3 no validationmethods":         {refop.NoValidationMethods, ClassDNS, []string{"live:" + CheckDNSAccount}},
		"D4 long TTL":                     {refop.LongTTL, ClassDNS, []string{"live:" + CheckDNSTTL}},
		"D5 CAA stays":                    {refop.CAAStaysAfterUnpair, ClassDNS, []string{"live:" + CheckDNSRemoved}},
		"D6 challenge before server 2":    {refop.ChallengeBeforeSecondServer, ClassDNS, []string{"live:" + CheckDNSChallenge}},
		"D7 wrong address":                {refop.WrongAddress, ClassDNS, []string{"live:" + CheckDNSAddresses}},
		"D8 extra TXT":                    {refop.ExtraTXT, ClassDNS, []string{"live:" + CheckDNSNoOther}},
		"D9 no closed CAA":                {refop.NoClosedCAA, ClassDNS, []string{"live:" + CheckDNSClosed}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, env := serve(t, refop.Config{Faults: tt.fault, DNSLag: 2 * time.Second})
			set := enrollSettings(t, r, tt.class)
			if !slices.Contains([]refop.Fault{refop.VerifiedWithoutTXT, refop.NoNameUnavailable, refop.TokenReused}, tt.fault) {
				// Only these defects need the own domain and its DNS hook.
				set.OwnDomain, set.DNSHook = "", ""
			}
			res := RunWith(ctx(t), set, env)
			if got := failures(res); !slices.Equal(got, tt.want) {
				t.Errorf("failed %v, want %v", got, tt.want)
			}
			if res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("installations %+v", res.Report.Installations)
			}
			if res.Exit != ExitFails {
				t.Errorf("exit %d (%s)", res.Exit, res.Message)
			}
		})
	}
}
