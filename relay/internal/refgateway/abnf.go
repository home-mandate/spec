// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"regexp"
	"strings"
)

// Property is the value of an issue or issuewild property read by the grammar of RFC 8659
// section 4.2. It is written from the ABNF alone, as a regular expression, and is not the code
// of the tool (relay/internal/dnsq); a test compares the two.
type Property struct {
	// Domain is the issuer domain name in lower case, empty if there is none.
	Domain string
	// Written is the domain as it was written.
	Written string
	Params  []Param
}

// Param is a parameter: tag and value as written.
type Param struct{ Tag, Value string }

const (
	abnfWSP   = `[ \t]*`
	abnfLabel = `[A-Za-z0-9](?:-*[A-Za-z0-9])*`
	abnfParam = abnfLabel + abnfWSP + `=` + abnfWSP + `[\x21-\x3a\x3c-\x7e]*`
)

// issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
// parameters  = (parameter *WSP ";" *WSP parameters) / parameter
var issueValue = regexp.MustCompile(`\A` + abnfWSP +
	`(?:` + abnfLabel + `(?:\.` + abnfLabel + `)*` + abnfWSP + `)?` +
	`(?:;` + abnfWSP + `(?:` + abnfParam + `(?:` + abnfWSP + `;` + abnfWSP + abnfParam + `)*` + abnfWSP + `)?)?\z`)

// ParseProperty reads an issue or issuewild value; false if it does not match the grammar.
func ParseProperty(value string) (Property, bool) {
	if !issueValue.MatchString(value) {
		return Property{}, false
	}
	// A value holds no semicolon, so the semicolons separate the parts.
	parts := strings.Split(value, ";")
	written := strings.Trim(parts[0], " \t")
	prop := Property{Domain: strings.ToLower(written), Written: written}
	for _, part := range parts[1:] {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		tag, val, _ := strings.Cut(part, "=")
		prop.Params = append(prop.Params, Param{Tag: strings.TrimRight(tag, " \t"), Value: strings.TrimLeft(val, " \t")})
	}
	return prop, true
}

// Empty reports whether the property is the record that permits no issuance and says
// nothing else.
func (p Property) Empty() bool { return p.Domain == "" && len(p.Params) == 0 }

// PermitsNothing reports whether the property names no issuer.
func (p Property) PermitsNothing() bool { return p.Domain == "" }
