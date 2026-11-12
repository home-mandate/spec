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

// ParseIssue parses the value of an issue or issuewild property by the grammar of RFC 8659
// section 4.2:
//
//	issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
//	parameters  = (parameter *WSP ";" *WSP parameters) / parameter
//	parameter   = tag *WSP "=" *WSP value
//
// An empty value, and one that is only blanks and ";", gives an empty Issue: no issuer, so no
// issuance. The domain is returned in lower case; parameter tags and values as written. A
// value that does not match the grammar is an error: RFC 8659 treats it like an empty issuer
// domain name, which the caller decides on (RELAY-v0 sections 6.5 and 6.7).
func ParseIssue(value string) (Issue, error) {
	p := scanner{s: value}
	p.skipWSP()
	issue := Issue{Domain: strings.ToLower(p.domain())}
	p.skipWSP()
	if p.done() {
		return issue, nil
	}
	if !p.take(';') {
		return Issue{}, ErrCAA
	}
	p.skipWSP()
	for !p.done() {
		param, ok := p.parameter()
		if !ok {
			return Issue{}, ErrCAA
		}
		issue.Params = append(issue.Params, param)
		p.skipWSP()
		if p.done() {
			break
		}
		// A ";" after a parameter needs a parameter after it.
		if !p.take(';') {
			return Issue{}, ErrCAA
		}
		p.skipWSP()
		if p.done() {
			return Issue{}, ErrCAA
		}
	}
	return issue, nil
}

// scanner reads a string byte by byte.
type scanner struct {
	s string
	i int
}

func (p *scanner) done() bool { return p.i >= len(p.s) }

func (p *scanner) take(c byte) bool {
	if p.done() || p.s[p.i] != c {
		return false
	}
	p.i++
	return true
}

func (p *scanner) skipWSP() {
	for !p.done() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// label reads (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT)) and returns it, or "" if there is none.
// Hyphens that no letter or digit follows are not part of it.
func (p *scanner) label() string {
	start := p.i
	if p.done() || !alnum(p.s[p.i]) {
		return ""
	}
	end := p.i + 1
	for j := end; j < len(p.s); j++ {
		if alnum(p.s[j]) {
			end = j + 1
		} else if p.s[j] != '-' {
			break
		}
	}
	p.i = end
	return p.s[start:end]
}

// domain reads label *("." label), or nothing. A "." that no label follows stays unread, so
// that the caller finds it and refuses the value.
func (p *scanner) domain() string {
	start := p.i
	if p.label() == "" {
		return ""
	}
	for p.i+1 < len(p.s) && p.s[p.i] == '.' {
		save := p.i
		p.i++
		if p.label() == "" {
			p.i = save
			break
		}
	}
	return p.s[start:p.i]
}

// parameter reads tag *WSP "=" *WSP value.
func (p *scanner) parameter() (Param, bool) {
	tag := p.label()
	if tag == "" {
		return Param{}, false
	}
	p.skipWSP()
	if !p.take('=') {
		return Param{}, false
	}
	p.skipWSP()
	start := p.i
	for !p.done() && p.s[p.i] > ' ' && p.s[p.i] < 0x7f && p.s[p.i] != ';' {
		p.i++
	}
	return Param{Tag: tag, Value: p.s[start:p.i]}, true
}
