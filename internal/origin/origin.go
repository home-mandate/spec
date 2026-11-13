// SPDX-License-Identifier: Apache-2.0

// Package origin is the reference for the decisions of SPEC-v0 Section 11.7 items 1 and 6:
// whether a configured value is a public origin, and whether the htu of a DPoP proof matches
// the URL an implementation built from its public origin. The cases are in
// conformance/origin-v0.json.
package origin

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxHostLength  = 253
	maxLabelLength = 63
	defaultPort    = 443
	maxPort        = 65535
)

// Errors of Valid. Each names the first rule of Section 11.7 item 1 that the value breaks.
var (
	ErrScheme = errors.New("origin: the scheme is not https://")
	ErrExtra  = errors.New("origin: userinfo, path, query or fragment")
	ErrPort   = errors.New("origin: the port is empty, not a number, has a leading zero, is out of range or is 443")
	ErrHost   = errors.New("origin: the host is not a DNS name of at least two labels in lower case with A-labels")
)

var lookup = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.ValidateLabels(true), idna.StrictDomainName(true), idna.Transitional(false))

// Valid reports whether value is a public origin in the one form of Section 11.7 item 1.
func Valid(value string) error {
	rest, ok := strings.CutPrefix(value, "https://")
	if !ok {
		return ErrScheme
	}
	if strings.ContainsAny(rest, "/?#@\\") {
		return ErrExtra
	}
	host, port, hasPort := strings.Cut(rest, ":")
	if hasPort && !validPort(port) {
		return ErrPort
	}
	if !validHost(host) {
		return ErrHost
	}
	return nil
}

// validPort: decimal digits without a leading zero, 1 to 65535, and not the default port.
func validPort(port string) bool {
	if port == "" || port[0] == '0' || strings.ContainsFunc(port, func(r rune) bool { return r < '0' || r > '9' }) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n <= maxPort && n != defaultPort
}

// validHost: at least two labels of letters, digits and hyphens in lower case, neither
// beginning nor ending with a hyphen, the last not all digits (so that no IPv4 address
// passes), and IDNA lookup maps the name to itself (A-labels that decode, no upper case).
func validHost(host string) bool {
	if host == "" || len(host) > maxHostLength {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	mapped, err := lookup.ToASCII(host)
	return err == nil && mapped == host
}

func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelLength || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// HTUMatches reports whether the htu of a DPoP proof matches target, the URL that the
// implementation built from its public origin: both normalized as RFC 3986 Sections 6.2.2 and
// 6.2.3 describe (case, percent-encoding, dot segments, default port, empty path), without
// query and fragment (RFC 9449 Section 4.3). A value that does not parse as an absolute URL
// with a host matches nothing.
func HTUMatches(htu, target string) bool {
	a, ok := normalize(htu)
	if !ok {
		return false
	}
	b, ok := normalize(target)
	return ok && a == b
}

func normalize(raw string) (string, bool) {
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == defaultPortOf(scheme) {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path, ok := normalizePercent(u.EscapedPath())
	if !ok {
		return "", false
	}
	path = removeDotSegments(path)
	if path == "" {
		path = "/"
	}
	user := ""
	if u.User != nil {
		user = u.User.String() + "@"
	}
	return scheme + "://" + user + host + path, true
}

func defaultPortOf(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// normalizePercent decodes percent-encoded unreserved characters and writes the hexadecimal
// digits of every other triplet in upper case (RFC 3986 Section 6.2.2.1 and 6.2.2.2).
func normalizePercent(p string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			b.WriteByte(p[i])
			continue
		}
		if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
			return "", false
		}
		v, _ := strconv.ParseUint(p[i+1:i+3], 16, 8)
		if c := byte(v); isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(p[i+1:i+3]))
		}
		i += 2
	}
	return b.String(), true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0
}

// removeDotSegments is the algorithm of RFC 3986 Section 5.2.4.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			out = dropLast(out)
		case in == "/..":
			in = "/"
			out = dropLast(out)
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				end = len(in)
			} else {
				end += start
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}

func dropLast(s []string) []string {
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}
