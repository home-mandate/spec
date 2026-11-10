// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"slices"
	"strings"
)

// Record is a CAA record of a case.
type Record struct {
	Flags int    `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// Link is a CNAME or DNAME that an answer followed.
type Link struct {
	Type string `json:"type"`
	At   string `json:"at"`
}

// Resolver is the answer of one resolver in a case.
type Resolver struct {
	Provider      string   `json:"provider"`
	Status        string   `json:"status"`
	Chain         []Link   `json:"chain"`
	Records       []Record `json:"records"`
	ParentRecords []Record `json:"parent_records"`
}

// Pair is the CAA identity and the ACME account of a gateway.
type Pair struct {
	CAAIdentity string `json:"caa_identity"`
	ACMEAccount string `json:"acme_account"`
}

const (
	tagIssue     = "issue"
	tagIssueWild = "issuewild"
	methodDNS01  = "dns-01"
	tagAccount   = "accounturi"
	tagMethods   = "validationmethods"
	statusOK     = "ok"
	statusNX     = "nxdomain"
)

// answered reports whether the resolver gave an answer: NXDOMAIN is an empty answer. Every
// other status is a failure.
func (r Resolver) answered() bool { return r.Status == statusOK || r.Status == statusNX }

func providers(rs []Resolver) int {
	seen := map[string]bool{}
	for _, r := range rs {
		seen[r.Provider] = true
	}
	return len(seen)
}

// split returns the issue and issuewild records, the others apart.
func split(records []Record, caseSensitive bool) (issue, wild, other []Record) {
	for _, r := range records {
		tag := r.Tag
		if !caseSensitive {
			tag = strings.ToLower(tag)
		}
		switch tag {
		case tagIssue:
			issue = append(issue, r)
		case tagIssueWild:
			wild = append(wild, r)
		default:
			other = append(other, r)
		}
	}
	return issue, wild, other
}

// matchOptions are the variations the defects of the comparison make.
type matchOptions struct {
	exactText, paramOrder, domainCase, flags, dupParam, extraParam, paramTagFold, valueFold       bool
	accountIgnored, identityIgnored, methodsIgnored, methodsList, emptyMatchesAll, domainOptional bool
	emptyParamsIgnored, emptyNotSemicolon                                                         bool
}

// isAccount reports whether the property means the record of the pair: its CA, the account
// and validationmethods=dns-01, and nothing else.
func isAccount(prop Property, raw Record, pair Pair, o matchOptions) bool {
	if o.flags && raw.Flags != 0 {
		return false
	}
	if o.exactText {
		return raw.Value == pair.CAAIdentity+"; accounturi="+pair.ACMEAccount+"; validationmethods=dns-01"
	}
	if o.emptyMatchesAll && prop.Empty() {
		return true
	}
	if !sameDomain(prop, pair.CAAIdentity, o) {
		return false
	}
	params := prop.Params
	if o.dupParam {
		params = lastOfEach(params)
	}
	if o.extraParam {
		params = slices.DeleteFunc(slices.Clone(params), func(p Param) bool { return !isOneOf(p.Tag, o) })
	}
	switch {
	case o.accountIgnored:
		return hasParam(params, tagMethods, methodDNS01, o)
	case o.methodsIgnored:
		return hasParam(params, tagAccount, pair.ACMEAccount, o)
	case len(params) != 2:
		return false
	}
	if o.paramOrder && (params[0].Tag != tagAccount || params[1].Tag != tagMethods) {
		return false
	}
	methodOK := hasParam(params, tagMethods, methodDNS01, o) || o.methodsList && listsMethod(params)
	return hasParam(params, tagAccount, pair.ACMEAccount, o) && methodOK
}

// listsMethod reports whether validationmethods is a list that holds dns-01.
func listsMethod(params []Param) bool {
	for _, p := range params {
		if p.Tag == tagMethods && slices.Contains(strings.Split(p.Value, ","), methodDNS01) {
			return true
		}
	}
	return false
}

func isOneOf(tag string, o matchOptions) bool {
	return tag == tagAccount || tag == tagMethods || o.paramTagFold && (strings.EqualFold(tag, tagAccount) || strings.EqualFold(tag, tagMethods))
}

func sameDomain(prop Property, identity string, o matchOptions) bool {
	if o.identityIgnored || o.domainOptional && prop.Domain == "" {
		return true
	}
	if o.domainCase {
		return prop.Written == identity
	}
	return strings.EqualFold(prop.Domain, identity)
}

func hasParam(params []Param, tag, value string, o matchOptions) bool {
	for _, p := range params {
		tagOK := p.Tag == tag || o.paramTagFold && strings.EqualFold(p.Tag, tag)
		valueOK := p.Value == value || o.valueFold && strings.EqualFold(p.Value, value)
		if tagOK && valueOK {
			return true
		}
	}
	return false
}

// lastOfEach keeps the last parameter of each tag, as a reader that overwrites does.
func lastOfEach(params []Param) []Param {
	var out []Param
	for i, p := range params {
		if !slices.ContainsFunc(params[i+1:], func(q Param) bool { return q.Tag == p.Tag }) {
			out = append(out, p)
		}
	}
	return out
}

// isEmpty reports whether the property means ";".
func isEmpty(prop Property, raw Record, o matchOptions) bool {
	if o.flags && raw.Flags != 0 {
		return false
	}
	if o.exactText {
		return raw.Value == ";"
	}
	if o.emptyNotSemicolon && raw.Value == "" {
		return false
	}
	if o.emptyParamsIgnored {
		return prop.PermitsNothing()
	}
	return prop.Empty()
}

func sortedParams(params []Param) []Param {
	out := slices.Clone(params)
	slices.SortFunc(out, func(a, b Param) int { return strings.Compare(a.Tag+"="+a.Value, b.Tag+"="+b.Value) })
	return out
}

func sortStrings(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}
