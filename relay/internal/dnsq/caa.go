// SPDX-License-Identifier: Apache-2.0

package dnsq

import (
	"errors"
	"strings"
)

// CAA is a CAA record (RFC 8659 section 4).
type CAA struct {
	Flags byte
	Tag   string
	Value string
}

// ErrCAA is returned for CAA data that is not a CAA record.
var ErrCAA = errors.New("dnsq: invalid CAA record")

// maxTagLength is the longest tag that fits the one length octet; RFC 8659 asks for 1 to 15
// letters and digits, which is what is accepted here.
const maxTagLength = 15

// ParseCAA parses the data of a CAA record: flags, the length of the tag, the tag and the
// value, which is the rest.
func ParseCAA(data []byte) (CAA, error) {
	if len(data) < 2 {
		return CAA{}, ErrCAA
	}
	n := int(data[1])
	if n == 0 || n > maxTagLength || len(data) < 2+n {
		return CAA{}, ErrCAA
	}
	tag := string(data[2 : 2+n])
	for _, c := range tag {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return CAA{}, ErrCAA
		}
	}
	return CAA{Flags: data[0], Tag: strings.ToLower(tag), Value: string(data[2+n:])}, nil
}

// Param is a parameter of an issue or issuewild value.
type Param struct{ Tag, Value string }

// Issue is the value of an issue or issuewild property: an issuer domain name, which is empty
// for a value that permits no issuance, and parameters (RFC 8659 section 4.2).
type Issue struct {
	Domain string
	Params []Param
}

// Param returns the value of a parameter and whether it is there.
func (i Issue) Param(tag string) (string, bool) {
	for _, p := range i.Params {
		if p.Tag == tag {
			return p.Value, true
		}
	}
	return "", false
}

// ParseIssue parses the value of an issue or issuewild property:
//
//	issuer-domain-name *WSP [";" *WSP [parameter *(*WSP ";" *WSP parameter)] *WSP]
//
// with parameter = tag "=" value. A value that is only ";" gives an empty Issue. Blanks around
// the parts are allowed; anything else that the grammar does not allow is an error.
func ParseIssue(value string) (Issue, error) {
	domain, rest, found := strings.Cut(value, ";")
	issue := Issue{Domain: strings.ToLower(strings.Trim(domain, " \t"))}
	if issue.Domain != "" && !validDomain(issue.Domain) {
		return Issue{}, ErrCAA
	}
	if !found {
		if issue.Domain == "" {
			return Issue{}, ErrCAA
		}
		return issue, nil
	}
	for _, part := range strings.Split(rest, ";") {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		tag, val, ok := strings.Cut(part, "=")
		if !ok || !validTag(tag) || !validParamValue(val) {
			return Issue{}, ErrCAA
		}
		issue.Params = append(issue.Params, Param{Tag: tag, Value: val})
	}
	return issue, nil
}

func validDomain(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// validParamValue: printable ASCII without blanks and semicolons.
func validParamValue(s string) bool {
	for _, c := range s {
		if c <= ' ' || c >= 0x7f || c == ';' {
			return false
		}
	}
	return true
}
