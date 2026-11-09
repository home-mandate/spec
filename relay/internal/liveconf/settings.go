// SPDX-License-Identifier: Apache-2.0

// Package liveconf runs the live test of an operator (RELAY-v0 section 8.3): the run flow,
// the checks of the four conformance classes as a table with fixed IDs, the report, the
// state file that lets an interrupted run be cleaned up, and the time values. The tool
// relay-conformance is a thin command line around it.
//
// All four classes are implemented. The classes enrollment, dns and relay share one sequence
// (the installations and their tunnel certificates are the same), so a check of one class that
// needs the state another leaves behind is played at the point of the sequence where that state
// exists.
package liveconf

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Conformance classes of operators (RELAY-v0 section 8.1).
const (
	ClassMetadata   = "metadata"
	ClassEnrollment = "enrollment"
	ClassDNS        = "dns"
	ClassRelay      = "relay"
)

// AllClasses lists the classes in the order of a run.
var AllClasses = []string{ClassMetadata, ClassEnrollment, ClassDNS, ClassRelay}

const (
	// MaxCodes is how many pairing codes a run uses: a run creates at most two installations.
	MaxCodes = 2
	// MaxTimeout is the upper bound of -timeout; the clean-up comes on top (Timing.Cleanup).
	MaxTimeout = 60 * time.Minute
	// codeLength is the length of a pairing code without hyphens (RELAY-v0 section 5.2).
	codeLength = 16
)

// domainPattern is the pattern of $defs/domain in the schemas.
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ErrUsage is returned for settings that no run can start with.
var ErrUsage = errors.New("liveconf: invalid settings")

// Settings is what the command line asks for.
type Settings struct {
	// Operator is the operator domain.
	Operator string
	// Classes are the classes to run; empty means all. A run of fewer than all four is never
	// conformant.
	Classes []string
	// Codes are pairing codes of the test account, as given.
	Codes []string
	// OwnDomain is a name in a zone of the tester for the own-domain checks.
	OwnDomain string
	// DNSHook is the command that sets and removes the challenge TXT record of OwnDomain.
	DNSHook string
	// DNSManual asks the tester to set the record by hand.
	DNSManual bool
	// StatePath is where the state file goes; empty means a new file in the working directory.
	StatePath string
	// CleanupPath, if set, makes the call a clean-up of the state file at this path; no
	// other setting but Timeout, DNSHook and DNSManual may be set.
	CleanupPath string
	// Timeout limits the run; zero means MaxTimeout.
	Timeout time.Duration
	// Version is the version of the tool for the report.
	Version string
}

func usagef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, args...))
}

// ValidDomain reports whether s is a lower-case DNS name with at least two labels.
func ValidDomain(s string) bool {
	return len(s) <= 253 && domainPattern.MatchString(s)
}

// NormalizeCode returns the pairing code in upper case without hyphens, the form that is
// sent (RELAY-v0 section 5.2), or an error if it is not 16 characters from A-Z and 2-7.
// The error never contains the code.
func NormalizeCode(code string) (string, error) {
	n := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	if len(n) != codeLength || strings.Trim(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		return "", usagef("a pairing code is 16 characters from A-Z and 2-7")
	}
	return n, nil
}

// Validate checks the settings. It returns the settings with the defaults filled in:
// all classes, MaxTimeout, normalized codes.
func (s Settings) Validate() (Settings, error) {
	if s.Timeout < 0 || s.Timeout > MaxTimeout {
		return s, usagef("timeout must be between 1s and %s", MaxTimeout)
	}
	if s.Timeout == 0 {
		s.Timeout = MaxTimeout
	}
	if s.DNSHook != "" && s.DNSManual {
		return s, usagef("use either a DNS hook or manual DNS, not both")
	}
	if s.DNSHook != "" && !isCommandLine(s.DNSHook) {
		return s, usagef("the DNS hook is not a command")
	}
	if s.CleanupPath != "" {
		if s.Operator != "" || len(s.Classes) > 0 || len(s.Codes) > 0 || s.OwnDomain != "" || s.StatePath != "" {
			return s, usagef("a clean-up takes only the state file")
		}
		return s, nil
	}
	return s.validateRun()
}

func (s Settings) validateRun() (Settings, error) {
	if !ValidDomain(s.Operator) {
		return s, usagef("the operator must be a lower-case domain name")
	}
	if s.OwnDomain != "" && !ValidDomain(s.OwnDomain) {
		return s, usagef("the own domain must be a lower-case domain name")
	}
	if s.OwnDomain == "" && (s.DNSHook != "" || s.DNSManual) {
		return s, usagef("a DNS hook or manual DNS needs an own domain")
	}
	if s.OwnDomain != "" && s.DNSHook == "" && !s.DNSManual {
		return s, usagef("an own domain needs a DNS hook or manual DNS")
	}
	classes, err := normalizeClasses(s.Classes)
	if err != nil {
		return s, err
	}
	s.Classes = classes
	if len(s.Codes) > MaxCodes {
		return s, usagef("at most %d pairing codes", MaxCodes)
	}
	codes := make([]string, 0, len(s.Codes))
	for _, c := range s.Codes {
		n, err := NormalizeCode(c)
		if err != nil {
			return s, err
		}
		if slices.Contains(codes, n) {
			return s, usagef("the pairing codes must differ")
		}
		codes = append(codes, n)
	}
	s.Codes = codes
	return s, nil
}

func normalizeClasses(classes []string) ([]string, error) {
	if len(classes) == 0 {
		return slices.Clone(AllClasses), nil
	}
	for _, c := range classes {
		if !slices.Contains(AllClasses, c) {
			return nil, usagef("unknown class %s", esc(c))
		}
	}
	// Keep the order of a run and ignore repeats.
	out := make([]string, 0, len(classes))
	for _, c := range AllClasses {
		if slices.Contains(classes, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// isCommandLine reports whether a DNS hook has a command to run: at least one word (white space
// alone gives none), which is no flag and has no NUL byte.
func isCommandLine(hook string) bool {
	words := strings.Fields(hook)
	return len(words) > 0 && !strings.HasPrefix(words[0], "-") && !strings.ContainsRune(hook, 0)
}
