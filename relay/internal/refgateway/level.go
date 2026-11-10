// SPDX-License-Identifier: Apache-2.0

package refgateway

import "strings"

// LevelFault is a deliberate defect of Level.
type LevelFault uint64

// Defects of the determination of the protection level.
const (
	LevelChainIgnored          LevelFault = 1 << iota // a CNAME or DNAME at the name is ignored
	LevelAncestorIgnored                              // a CNAME or DNAME at an ancestor is ignored
	LevelMethodsIgnored                               // validationmethods is not checked
	LevelAccountIgnored                               // accounturi is not checked
	LevelIdentityIgnored                              // the CA is not checked
	LevelOneResolver                                  // one resolver is enough where the zone is unsigned
	LevelFailureOwn                                   // a failed lookup does not lower the level
	LevelParentCAA                                    // the CAA records of the parent count
	LevelNoNotify                                     // a fall of the level is not reported
	LevelBogusUnsigned                                // a bogus zone is treated as unsigned
	LevelProviderCount                                // resolvers of one provider count as several
	LevelDifferIgnored                                // answers of unsigned zones need not be the same
	LevelWildIgnored                                  // issuewild is not checked
	LevelWildMalformedFails                           // a malformed issuewild fails the condition
	LevelManyIssue                                    // any number of issue properties, one of them right
	LevelExtraParam                                   // a further parameter is fine
	LevelDupParam                                     // a parameter that occurs twice counts once
	LevelIdentityCase                                 // the CA is compared with regard to case
	LevelValueFold                                    // parameter values are compared without regard to case
	LevelMalformedIssueIgnored                        // a malformed issue property is ignored
	LevelFlags                                        // a record with flags fails
	LevelOneFailureEnough                             // a failed lookup is left out where the zone is validated
	LevelTagCase                                      // tags are compared with regard to case
	LevelNeverOwn                                     // never the level Own domain
	LevelEmptyOwn                                     // an empty answer is fine
	LevelClosedOwn                                    // issue ";" is fine
	LevelParamTagFold                                 // parameter tags are compared without regard to case
	LevelLenient                                      // a trailing semicolon is fine
	LevelFirstOnly                                    // only the first resolver is judged
	LevelBogusValidated                               // a bogus zone counts as validated
)

// LevelInput is the input of a case of protection-level-v0.json.
type LevelInput struct {
	Account       Pair       `json:"account"`
	PreviousLevel string     `json:"previous_level"`
	DNSSEC        string     `json:"dnssec"`
	Resolvers     []Resolver `json:"resolvers"`
}

// LevelResult is the level and whether the gateway tells its administrator.
type LevelResult struct {
	Level       string `json:"level"`
	NotifyAdmin bool   `json:"notify_admin"`
}

const (
	levelOwn      = "own-domain"
	levelStandard = "standard"
)

// Level determines the protection level of an own-domain name (RELAY-v0 section 6.5).
func Level(in LevelInput, f LevelFault) LevelResult {
	level := levelStandard
	if !f.Has(LevelNeverOwn) && ownDomain(in, f) {
		level = levelOwn
	}
	return LevelResult{Level: level, NotifyAdmin: in.PreviousLevel == levelOwn && level == levelStandard && !f.Has(LevelNoNotify)}
}

func ownDomain(in LevelInput, f LevelFault) bool {
	if in.DNSSEC == "bogus" && !f.Has(LevelBogusUnsigned) && !f.Has(LevelBogusValidated) {
		return false
	}
	answering := in.Resolvers
	for _, r := range in.Resolvers {
		if !r.answered() {
			if !f.Has(LevelFailureOwn) && !(f.Has(LevelOneFailureEnough) && in.DNSSEC == "validated") {
				return false
			}
			answering = withoutFailed(in.Resolvers)
		}
	}
	if len(answering) == 0 {
		return f.Has(LevelFailureOwn)
	}
	if f.Has(LevelFirstOnly) {
		return conditions(answering[0], in.Account, f)
	}
	if !signedOrAgreed(in, answering, f) {
		return false
	}
	for _, r := range answering {
		if !conditions(r, in.Account, f) {
			return false
		}
	}
	return true
}

func withoutFailed(rs []Resolver) []Resolver {
	var out []Resolver
	for _, r := range rs {
		if r.answered() {
			out = append(out, r)
		}
	}
	return out
}

// signedOrAgreed: the answers are validated, or the zone is unsigned and at least two
// independent resolvers give the same answer.
func signedOrAgreed(in LevelInput, rs []Resolver, f LevelFault) bool {
	if in.DNSSEC == "validated" || in.DNSSEC == "bogus" && f.Has(LevelBogusValidated) {
		return true
	}
	n := providers(rs)
	if f.Has(LevelProviderCount) {
		n = len(rs)
	}
	if n < 2 && !f.Has(LevelOneResolver) {
		return false
	}
	return f.Has(LevelDifferIgnored) || allSame(rs)
}

// allSame: the issue and issuewild properties are the same in every answer.
func allSame(rs []Resolver) bool {
	first := signature2(rs[0])
	for _, r := range rs[1:] {
		if signature2(r) != first {
			return false
		}
	}
	return true
}

func signature2(r Resolver) string {
	issue, wild, _ := split(r.Records, false)
	return canonical(issue) + "|" + canonical(wild)
}

// canonical writes the meaning of records in a form that is the same for the same meaning.
func canonical(records []Record) string {
	var list []string
	for _, r := range records {
		prop, ok := ParseProperty(r.Value)
		if !ok {
			list = append(list, "?"+r.Value)
			continue
		}
		s := "r:" + prop.Domain
		for _, p := range sortedParams(prop.Params) {
			s += ";" + p.Tag + "=" + p.Value
		}
		list = append(list, s)
	}
	return strings.Join(sortStrings(list), "\n")
}

func conditions(r Resolver, account Pair, f LevelFault) bool {
	for _, l := range r.Chain {
		if !(l.At == "name" && f.Has(LevelChainIgnored) || l.At == "ancestor" && f.Has(LevelAncestorIgnored)) {
			return false
		}
	}
	records := r.Records
	if len(records) == 0 && f.Has(LevelParentCAA) {
		records = r.ParentRecords
	}
	issue, wild, _ := split(records, f.Has(LevelTagCase))
	return issueOK(issue, account, f) && wildOK2(wild, f)
}

func issueOK(issue []Record, account Pair, f LevelFault) bool {
	if len(issue) == 0 && f.Has(LevelEmptyOwn) {
		return true
	}
	count := len(issue)
	if f.Has(LevelMalformedIssueIgnored) {
		count = 0
		for _, r := range issue {
			if _, ok := ParseProperty(r.Value); ok {
				count++
			}
		}
	}
	if count != 1 && !f.Has(LevelManyIssue) {
		return false
	}
	good := false
	for _, r := range issue {
		prop, ok := ParseProperty(r.Value)
		if !ok && f.Has(LevelLenient) {
			prop, ok = ParseProperty(strings.TrimRight(r.Value, "; \t"))
		}
		switch {
		case ok && prop.Empty() && f.Has(LevelClosedOwn):
			good = true
		case !ok && f.Has(LevelMalformedIssueIgnored):
			continue
		case !ok, f.Has(LevelFlags) && r.Flags != 0:
			if !f.Has(LevelManyIssue) {
				return false
			}
		case accountRecord(prop, account, f):
			good = true
		case !f.Has(LevelManyIssue):
			return false
		}
	}
	return good
}

func accountRecord(prop Property, account Pair, f LevelFault) bool {
	identity := strings.EqualFold(prop.Domain, account.CAAIdentity)
	if f.Has(LevelIdentityCase) {
		identity = prop.Written == account.CAAIdentity
	}
	if !identity && !f.Has(LevelIdentityIgnored) {
		return false
	}
	params := prop.Params
	if f.Has(LevelDupParam) {
		params = lastOfEach(params)
	}
	account1, method := 0, 0
	for _, p := range params {
		switch {
		case (p.Tag == tagAccount || f.Has(LevelParamTagFold) && strings.EqualFold(p.Tag, tagAccount)) && (p.Value == account.ACMEAccount || f.Has(LevelAccountIgnored) || f.Has(LevelValueFold) && strings.EqualFold(p.Value, account.ACMEAccount)):
			account1++
		case (p.Tag == tagMethods || f.Has(LevelParamTagFold) && strings.EqualFold(p.Tag, tagMethods)) && (p.Value == methodDNS01 || f.Has(LevelMethodsIgnored) || f.Has(LevelValueFold) && strings.EqualFold(p.Value, methodDNS01)):
			method++
		case !f.Has(LevelExtraParam):
			return false
		}
	}
	return (account1 == 1 || f.Has(LevelAccountIgnored) && account1 == 0) && (method == 1 || f.Has(LevelMethodsIgnored) && method == 0)
}

// wildOK2: no issuewild property permits anything; one that does not match the grammar permits
// nothing.
func wildOK2(wild []Record, f LevelFault) bool {
	if f.Has(LevelWildIgnored) {
		return true
	}
	for _, r := range wild {
		prop, ok := ParseProperty(r.Value)
		switch {
		case !ok && f.Has(LevelWildMalformedFails), ok && !prop.PermitsNothing():
			return false
		}
	}
	return true
}
