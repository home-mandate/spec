// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"strings"
	"unicode"
)

// PairingFault is a deliberate defect of ParsePairing.
type PairingFault uint64

// Defects of the pairing string. The first group accepts what must be refused, the second
// refuses what must be accepted.
const (
	PairUpperDomain     PairingFault = 1 << iota // upper case in the domain
	PairSingleLabel                              // a domain of one label
	PairNumericTLD                               // a last label that begins with a digit
	PairPort                                     // a port after the domain
	PairUserinfo                                 // userinfo before the domain
	PairTrailingDot                              // a dot at the end of the domain
	PairUnderscore                               // underscores in labels
	PairLongLabel                                // labels of any length
	PairEdgeHyphen                               // hyphens at the edges of labels
	PairEmptyLabel                               // empty labels
	PairLongDomain                               // domains of any length
	PairTrailingNewline                          // a line feed at the end
	PairTrimSpace                                // white space around the string
	PairDigits                                   // the digits 0, 1, 8 and 9 in the code
	PairCodeLength                               // codes of 12 to 20 characters
	PairAnyHyphens                               // hyphens anywhere in the code
	PairSpaces                                   // blanks between the groups of the code
	PairUnicode                                  // letters beyond ASCII in the code
	PairScheme                                   // a scheme before the domain
	PairPath                                     // a path before the code
	PairIDN                                      // letters beyond ASCII in the domain
	PairKeepCase                                 // the code is sent as typed
	PairNeedHyphens                              // all three hyphens are required
	PairNoXN                                     // refuses A-labels
	PairDigitLabel                               // refuses labels that begin with a digit
	PairLabel62                                  // labels of at most 62 characters
	PairDomain252                                // domains of at most 252 characters
	PairDoubleHyphen                             // refuses two hyphens in a row in a label
	PairTLDHyphen                                // refuses a hyphen in the last label
	PairLowerOnlyCode                            // refuses a code in lower or mixed case
	PairMinLabel2                                // refuses labels of one character
	PairNoDigitsInCode                           // refuses the digits 2 to 7 in the code
	PairRefuseAll                                // refuses every string
	PairBrackets                                 // a domain in square brackets
	PairSlashInCode                              // slashes in the code are dropped
	PairEmptyDomain                              // an empty domain
	PairEmptyOK                                  // an empty string
	PairBlankDomain                              // blanks inside the domain
	PairSwapped                                  // domain and code in the other order
	PairEmptyCode                                // an empty code
	PairCodeUnderscore                           // underscores in the code are dropped
	PairUnicodeHyphen                            // U+2010 is a hyphen
	PairNUL                                      // NUL bytes are dropped
	PairTrailingSlash                            // a slash after the code
	PairNoSlash                                  // the code is the last 16 letters
)

const (
	maxDomain   = 253
	maxLabel    = 63
	codeLetters = 16
)

// ParsePairing reads a pairing string (RELAY-v0 section 5.2, $defs/pairing_string): it returns
// the operator domain and the code in upper case without hyphens, or false. The string is
// taken as it is.
func ParsePairing(s string, f PairingFault) (domain, code string, ok bool) {
	if f.Has(PairRefuseAll) {
		return "", "", false
	}
	s = tolerate(s, f)
	if s == "" && f.Has(PairEmptyOK) {
		return "", "", true
	}
	if f.Has(PairTrailingNewline) {
		s = strings.TrimSuffix(s, "\n")
	}
	if f.Has(PairScheme) {
		s = strings.TrimPrefix(s, "https://")
	}
	host, code, found := splitPairing(s, f)
	if !found {
		return "", "", false
	}
	return finish(hostOf(host, f), code, f)
}

func finish(domain, code string, f PairingFault) (string, string, bool) {
	if f.Has(PairSwapped) {
		if d, c, ok := tryPairing(code, domain, f); ok {
			return d, c, true
		}
	}
	return tryPairing(domain, code, f)
}

func tryPairing(domain, code string, f PairingFault) (string, string, bool) {
	if code == "" && f.Has(PairEmptyCode) && validDomain(domain, f) {
		return domain, "", true
	}
	code, ok := normalizeCode(code, f)
	if !ok || !validDomain(domain, f) {
		return "", "", false
	}
	return domain, code, true
}

// tolerate applies the defects that clean the string before it is read.
func tolerate(s string, f PairingFault) string {
	if f.Has(PairTrimSpace) {
		s = strings.TrimSpace(s)
	}
	if f.Has(PairNUL) {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if f.Has(PairUnicodeHyphen) {
		s = strings.ReplaceAll(s, "\u2010", "-")
	}
	if f.Has(PairTrailingSlash) {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

// splitPairing splits at the slash: the domain before it, the code after it.
func splitPairing(s string, f PairingFault) (host, code string, ok bool) {
	slash := strings.IndexByte(s, '/')
	switch {
	case f.Has(PairNoSlash) && slash < 0 && len(s) > codeLetters:
		return s[:len(s)-codeLetters], s[len(s)-codeLetters:], true
	case slash < 0:
		return "", "", false
	case f.Has(PairPath):
		return s[:slash], s[strings.LastIndexByte(s, '/')+1:], true
	}
	code = s[slash+1:]
	if f.Has(PairSlashInCode) {
		code = strings.ReplaceAll(code, "/", "")
	}
	return s[:slash], code, true
}

// hostOf removes what the defects let through around the domain.
func hostOf(host string, f PairingFault) string {
	if f.Has(PairBrackets) && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return "example.example"
	}
	if f.Has(PairUserinfo) {
		if i := strings.LastIndexByte(host, '@'); i >= 0 {
			host = host[i+1:]
		}
	}
	if f.Has(PairPort) {
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
	}
	return host
}

func validDomain(domain string, f PairingFault) bool {
	limit := maxDomain
	if f.Has(PairDomain252) {
		limit--
	}
	if f.Has(PairTrailingDot) {
		domain = strings.TrimSuffix(domain, ".")
	}
	if domain == "" && f.Has(PairEmptyDomain) {
		return true
	}
	if f.Has(PairBlankDomain) {
		domain = strings.ReplaceAll(domain, " ", "x")
	}
	if domain == "" || (len(domain) > limit && !f.Has(PairLongDomain)) {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 && !f.Has(PairSingleLabel) {
		return false
	}
	for i, l := range labels {
		if !validLabel(l, i == len(labels)-1, f) {
			return false
		}
	}
	return true
}

func validLabel(l string, last bool, f PairingFault) bool {
	if l == "" {
		return f.Has(PairEmptyLabel)
	}
	limit := maxLabel
	if f.Has(PairLabel62) {
		limit--
	}
	switch {
	case len(l) > limit && !f.Has(PairLongLabel):
		return false
	case len(l) == 1 && f.Has(PairMinLabel2):
		return false
	case !f.Has(PairEdgeHyphen) && (l[0] == '-' || l[len(l)-1] == '-'):
		return false
	case f.Has(PairNoXN) && strings.HasPrefix(l, "xn--"):
		return false
	case f.Has(PairDoubleHyphen) && strings.Contains(l, "--"):
		return false
	case f.Has(PairTLDHyphen) && last && strings.Contains(l, "-"):
		return false
	}
	if !labelStart(l[0], last, f) {
		return false
	}
	for i := 0; i < len(l); i++ {
		if !labelByte(l[i], f) {
			return false
		}
	}
	return true
}

// labelStart: the last label begins with a letter; the others with a letter or a digit.
func labelStart(c byte, last bool, f PairingFault) bool {
	letter := c >= 'a' && c <= 'z' || f.Has(PairUpperDomain) && c >= 'A' && c <= 'Z'
	digit := c >= '0' && c <= '9'
	switch {
	case letter:
		return true
	case digit:
		return !last && !f.Has(PairDigitLabel) || last && f.Has(PairNumericTLD)
	}
	return c == '-' && f.Has(PairEdgeHyphen) || c == '_' && f.Has(PairUnderscore) || c >= 0x80 && f.Has(PairIDN)
}

func labelByte(c byte, f PairingFault) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		return true
	case c >= 'A' && c <= 'Z':
		return f.Has(PairUpperDomain)
	case c == '_':
		return f.Has(PairUnderscore)
	case c >= 0x80:
		return f.Has(PairIDN)
	}
	return false
}

// normalizeCode reads the code: 16 letters A to Z and digits 2 to 7 in either case, with a
// hyphen allowed after each group of four except the last.
func normalizeCode(s string, f PairingFault) (string, bool) {
	var letters []rune
	hyphens, previousSeparator := 0, false
	for _, c := range s {
		switch {
		case c == '_' && f.Has(PairCodeUnderscore):
			continue
		case c == '-' || c == ' ' && f.Has(PairSpaces):
			n := len(letters)
			if !(f.Has(PairAnyHyphens) && c == '-') && (previousSeparator || n != 4 && n != 8 && n != 12) {
				return "", false
			}
			hyphens++
			previousSeparator = true
		case codeLetter(c, f):
			letters = append(letters, c)
			previousSeparator = false
		default:
			return "", false
		}
	}
	if !codeLength(len(letters), f) || f.Has(PairNeedHyphens) && hyphens != 3 {
		return "", false
	}
	out := string(letters)
	if f.Has(PairLowerOnlyCode) && out != strings.ToUpper(out) {
		return "", false
	}
	if f.Has(PairKeepCase) {
		return out, true
	}
	return strings.ToUpper(out), true
}

func codeLength(n int, f PairingFault) bool {
	if f.Has(PairCodeLength) {
		return n >= 12 && n <= 20
	}
	return n == codeLetters
}

func codeLetter(c rune, f PairingFault) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return true
	case c >= '2' && c <= '7':
		return !f.Has(PairNoDigitsInCode)
	case c == '0' || c == '1' || c == '8' || c == '9':
		return f.Has(PairDigits)
	}
	return f.Has(PairUnicode) && c > unicode.MaxASCII && unicode.IsLetter(c)
}
