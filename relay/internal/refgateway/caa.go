// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"slices"
	"strings"
)

// CAAFault is a deliberate defect of CAAEvaluate.
type CAAFault uint64

// Defects of the comparison of CAA records in the monitoring.
const (
	CAATagCase              CAAFault = 1 << iota // tags are compared with regard to case
	CAAIodefCounts                               // other properties, such as iodef, are differences
	CAAWildIgnored                               // issuewild is not checked
	CAAApexIgnored                               // the apex is not checked
	CAAEmptyNoDiff                               // an empty answer is no difference
	CAAGraceNoEnd                                // the excuse for the earlier record has no end
	CAAGraceForeign                              // the excuse covers an earlier pair the gateway did not report
	CAAGraceApex                                 // the excuse covers the apex
	CAAGraceLate                                 // the excuse lasts until the end of the sixtieth minute
	CAAMajority                                  // a difference counts when most resolvers show it
	CAAExactText                                 // records are compared as text
	CAAParamOrder                                // parameters are compared in order
	CAADomainCase                                // the issuer domain name is compared with regard to case
	CAAFlags                                     // a record with flags is another record
	CAADupParam                                  // a parameter that occurs twice counts once
	CAAExtraParam                                // a further parameter is ignored
	CAAParamTagFold                              // parameter tags are compared without regard to case
	CAAValueFold                                 // parameter values are compared without regard to case
	CAADedupe                                    // records with the same meaning count once
	CAAWildMany                                  // any number of issuewild ";" is prescribed
	CAAWildMissing                               // a missing issuewild at the apex is no difference
	CAAMalformedIgnored                          // a value that does not match the grammar is ignored
	CAAChainIgnored                              // a CNAME or DNAME in the chain is no difference
	CAAFailureDiff                               // a failed resolver is a difference
	CAANXFailure                                 // NXDOMAIN is a failure
	CAAOneEnough                                 // one resolver is a successful round (24 hours only)
	CAAProviderCount                             // resolvers of one provider count as several (24 hours only)
	CAAFirstHour                                 // the standard name is checked from the pairing
	CAAFirstHourLate                             // the check starts after the sixtieth minute
	CAAWildRequired                              // issuewild ";" is required at the standard name
	CAAWildForbidden                             // issuewild is a difference at the standard name
	CAAAlarmAlways                               // every evaluation is a difference
	CAAIgnoreValidated                           // DNSSEC-validated answers do not make a round successful (24 hours only)
	CAANeedThree                                 // three resolvers are needed for a successful round (24 hours only)
	CAAHideUnsuccessful                          // a difference counts only in a successful round
	CAAGraceAnything                             // the excuse covers any record, not only the earlier one
	CAAMalformedAsEmpty                          // a value that does not match the grammar is read as ";"
	CAAMalformedPasses                           // a value that does not match the grammar is taken for the prescribed record
	CAATrailingSemicolon                         // a semicolon after the last parameter is accepted
	CAAIssueMissingOK                            // a missing issue property is no difference
	CAAFirstIssueOnly                            // only the first issue property is looked at
	CAAAccountIgnored                            // accounturi is not compared
	CAAIdentityIgnored                           // the issuer domain name is not compared
	CAAMethodsIgnored                            // validationmethods is not compared
	CAAMethodsList                               // validationmethods may list further methods besides dns-01
	CAAEmptyMatchesAll                           // an empty record is also the record of the account
	CAADomainOptional                            // a record without issuer domain name is not compared by it
	CAANoPairAccountOK                           // while no account is in force an account record is no difference
	CAAEmptyParamsIgnored                        // parameters of a record without issuer domain name are ignored
	CAAFirstTwoHours                             // the standard name is checked after two hours, not one
	CAAAncestorChainIgnored                      // a CNAME or DNAME at an ancestor is no difference
	CAAEmptyNotSemicolon                         // an empty value is not read as ";"
)

const graceMinutes, firstHourMinutes = 60, 60

// CAAInput is the input of a case of caa-v0.json.
type CAAInput struct {
	Target              string     `json:"target"`
	Pair                *Pair      `json:"pair"`
	MinutesSincePairing int        `json:"minutes_since_pairing"`
	Grace               *Grace     `json:"grace"`
	AnswersValidated    bool       `json:"answers_validated"`
	Resolvers           []Resolver `json:"resolvers"`
}

// Grace is the state of the excuse for the record that was prescribed before the new pair.
type Grace struct {
	PreviousPair        *Pair `json:"previous_pair"`
	ReportedByGateway   bool  `json:"reported_by_gateway"`
	MinutesSinceLearned int   `json:"minutes_since_learned"`
}

// CAAEvaluate compares the CAA records that resolvers returned with what RELAY-v0 section 6.3
// prescribes, as section 6.7 describes. It returns "difference" or "prescribed". A difference
// counts as soon as one resolver that answered shows it; whether the round was a successful
// query (CAASuccessfulRound) matters only for the 24 hours of section 6.7, never for the result.
func CAAEvaluate(in CAAInput, f CAAFault) string {
	if f.Has(CAAAlarmAlways) {
		return "difference"
	}
	if in.Target == "apex" && f.Has(CAAApexIgnored) || notChecked(in, f) {
		return "prescribed"
	}
	answered, failed := sortAnswers(in, f)
	if failed && f.Has(CAAFailureDiff) {
		return "difference"
	}
	if f.Has(CAAHideUnsuccessful) && !CAASuccessfulRound(in, f) {
		return "prescribed"
	}
	differing := 0
	for _, r := range answered {
		if differs(in, r, f) {
			differing++
		}
	}
	if differing > 0 && (!f.Has(CAAMajority) || differing*2 > len(answered)) {
		return "difference"
	}
	return "prescribed"
}

// sortAnswers splits the resolvers into those that answered and whether any failed.
func sortAnswers(in CAAInput, f CAAFault) (answered []Resolver, failed bool) {
	for _, r := range in.Resolvers {
		if r.answered() && !(r.Status == statusNX && f.Has(CAANXFailure)) {
			answered = append(answered, r)
		} else {
			failed = true
		}
	}
	return answered, failed
}

// notChecked: the standard name is checked one hour after the pairing.
func notChecked(in CAAInput, f CAAFault) bool {
	if in.Target != "name" || f.Has(CAAFirstHour) {
		return false
	}
	limit := firstHourMinutes
	if f.Has(CAAFirstHourLate) {
		limit++
	}
	if f.Has(CAAFirstTwoHours) {
		limit *= 2
	}
	return in.MinutesSincePairing < limit
}

// CAASuccessfulRound reports whether the round counts as a successful query for the 24 hours of
// section 6.7: at least two independent resolvers answered, or the answers are DNSSEC-validated.
func CAASuccessfulRound(in CAAInput, f CAAFault) bool {
	answered, _ := sortAnswers(in, f)
	n := providers(answered)
	if f.Has(CAAProviderCount) {
		n = len(answered)
	}
	need := 2
	switch {
	case f.Has(CAAOneEnough):
		need = 1
	case f.Has(CAANeedThree):
		need = 3
	}
	return len(answered) > 0 && (in.AnswersValidated && !f.Has(CAAIgnoreValidated) || n >= need)
}

func differs(in CAAInput, r Resolver, f CAAFault) bool {
	if followsChain(r, f) {
		return true
	}
	if matches(r.Records, in.Target, in.Pair, f) || len(r.Records) == 0 && f.Has(CAAEmptyNoDiff) {
		return false
	}
	return !excused(in, r, f)
}

// followsChain: the answer followed a CNAME or DNAME at the name or at an ancestor.
func followsChain(r Resolver, f CAAFault) bool {
	return !f.Has(CAAChainIgnored) && slices.ContainsFunc(r.Chain, func(l Link) bool {
		return l.At != "ancestor" || !f.Has(CAAAncestorChainIgnored)
	})
}

// excused: for one hour after the gateway learned a new pair, the record that was prescribed
// before is no difference at the standard name, if the gateway reported that pair itself or
// none was in force.
func excused(in CAAInput, r Resolver, f CAAFault) bool {
	g := in.Grace
	if g == nil || in.Target == "apex" && !f.Has(CAAGraceApex) {
		return false
	}
	limit := graceMinutes
	if f.Has(CAAGraceLate) {
		limit++
	}
	if g.MinutesSinceLearned >= limit && !f.Has(CAAGraceNoEnd) {
		return false
	}
	if g.PreviousPair != nil && !g.ReportedByGateway && !f.Has(CAAGraceForeign) {
		return false
	}
	return f.Has(CAAGraceAnything) || matches(r.Records, "name", g.PreviousPair, f)
}

func options(f CAAFault) matchOptions {
	return matchOptions{
		exactText: f.Has(CAAExactText), paramOrder: f.Has(CAAParamOrder), domainCase: f.Has(CAADomainCase), flags: f.Has(CAAFlags),
		dupParam: f.Has(CAADupParam), extraParam: f.Has(CAAExtraParam), paramTagFold: f.Has(CAAParamTagFold), valueFold: f.Has(CAAValueFold),
		accountIgnored: f.Has(CAAAccountIgnored), identityIgnored: f.Has(CAAIdentityIgnored), methodsIgnored: f.Has(CAAMethodsIgnored),
		methodsList: f.Has(CAAMethodsList), emptyMatchesAll: f.Has(CAAEmptyMatchesAll), domainOptional: f.Has(CAADomainOptional),
		emptyParamsIgnored: f.Has(CAAEmptyParamsIgnored), emptyNotSemicolon: f.Has(CAAEmptyNotSemicolon),
	}
}

// matches reports whether the records are what section 6.3 prescribes at the target for the
// pair (nil while no account is in force).
func matches(records []Record, target string, pair *Pair, f CAAFault) bool {
	issueRaw, wildRaw, other := split(records, f.Has(CAATagCase))
	if f.Has(CAAIodefCounts) && len(other) > 0 {
		return false
	}
	o := options(f)
	issue, ok := parse(issueRaw, f)
	wild, okWild := parse(wildRaw, f)
	if !ok || !okWild {
		return false
	}
	if f.Has(CAADedupe) {
		issue, wild = dedupe(issue), dedupe(wild)
	}
	prescribed := func(p parsed) bool { return p.pass || isEmpty(p.prop, p.raw, o) }
	if target != "apex" && pair != nil {
		prescribed = func(p parsed) bool { return p.pass || isAccount(p.prop, p.raw, *pair, o) }
	} else if target != "apex" && f.Has(CAANoPairAccountOK) {
		prescribed = func(p parsed) bool { return p.pass || p.prop.Domain != "" || isEmpty(p.prop, p.raw, o) }
	}
	if len(issue) == 0 && f.Has(CAAIssueMissingOK) {
		return wildOK(wild, target == "apex", f, o)
	}
	if f.Has(CAAFirstIssueOnly) && len(issue) > 0 {
		issue = issue[:1]
	}
	return one(issue, prescribed) && wildOK(wild, target == "apex", f, o)
}

type parsed struct {
	prop Property
	raw  Record
	// pass marks a value that a defect takes for the prescribed record whatever it says.
	pass bool
}

// parse reads the values; a value that does not match the grammar fails the comparison
// unless a defect ignores it or reads it otherwise.
func parse(records []Record, f CAAFault) ([]parsed, bool) {
	var out []parsed
	for _, r := range records {
		p, ok := ParseProperty(r.Value)
		if !ok && f.Has(CAATrailingSemicolon) {
			p, ok = ParseProperty(strings.TrimRight(strings.TrimRight(r.Value, " \t"), ";"))
		}
		switch {
		case ok:
			out = append(out, parsed{prop: p, raw: r})
		case f.Has(CAAMalformedPasses):
			out = append(out, parsed{raw: r, pass: true})
		case f.Has(CAAMalformedAsEmpty):
			out = append(out, parsed{raw: Record{Flags: r.Flags, Tag: r.Tag, Value: ";"}})
		case !f.Has(CAAMalformedIgnored):
			return nil, false
		}
	}
	return out, true
}

func dedupe(list []parsed) []parsed {
	var out []parsed
	for _, p := range list {
		if len(out) == 0 || !sameMeaning(out[len(out)-1].prop, p.prop) {
			out = append(out, p)
		}
	}
	return out
}

func sameMeaning(a, b Property) bool {
	if a.Domain != b.Domain || len(a.Params) != len(b.Params) {
		return false
	}
	for i := range a.Params {
		if a.Params[i] != b.Params[i] {
			return false
		}
	}
	return true
}

func one(list []parsed, pred func(parsed) bool) bool { return len(list) == 1 && pred(list[0]) }

// wildOK: at the apex exactly one issuewild ";"; at a name none or one.
func wildOK(wild []parsed, required bool, f CAAFault, o matchOptions) bool {
	if f.Has(CAAWildIgnored) {
		return true
	}
	if f.Has(CAAWildForbidden) && len(wild) > 0 && !required {
		return false
	}
	if f.Has(CAAWildRequired) && len(wild) == 0 && !required {
		return false
	}
	if len(wild) == 0 {
		return !required || f.Has(CAAWildMissing)
	}
	if len(wild) > 1 && !f.Has(CAAWildMany) {
		return false
	}
	for _, w := range wild {
		if !w.pass && !isEmpty(w.prop, w.raw, o) {
			return false
		}
	}
	return true
}
