// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"slices"
	"strings"
	"time"
)

// CTFault is a deliberate defect of CTAlarms.
type CTFault uint64

// Defects of the evaluation of certificates in Certificate Transparency logs.
const (
	CTExactOnly         CTFault = 1 << iota // wildcards do not count
	CTWildDeep                              // a wildcard covers any number of labels
	CTWildApex                              // a wildcard also covers the name it is the parent of
	CTCaseSensitive                         // names are compared with regard to case
	CTNoLookback                            // every certificate counts, whenever it was valid
	CTExpiredIgnored                        // an expired certificate raises nothing
	CTExpiredAlarm                          // an expired certificate is an alarm, not a past exposure
	CTOldKeyOwn                             // a certificate of an earlier key is the gateway's own
	CTOldKeyForeign                         // a certificate of an earlier key is never the gateway's own
	CTOldKeyInclusive                       // logged at the moment of the replacement still counts as before
	CTAckAll                                // an acknowledgement ends the alarms for all certificates
	CTNotYetIgnored                         // a certificate that is not valid yet raises no alarm
	CTLookbackExclusive                     // a certificate that expired at the beginning of monitoring is not valid since it
	CTNowExclusive                          // a certificate that expires at the check is not valid any more
	CTSubdomain                             // names below a public name count
	CTSuffix                                // names that merely end in a public name count
	CTOnlyStandard                          // only the first public name is watched
	CTStartExclusive                        // a certificate that is valid from the check on is not valid since the beginning of monitoring
	CTAlarmAlways                           // every certificate raises an alarm
	CTNeverAlarm                            // no certificate raises an alarm
	CTAckByName                             // an acknowledgement also ends the alarm for certificates with the same names
	CTAckByKey                              // an acknowledgement also ends the alarm for certificates with the same public key
	CTAckFirstOnly                          // an acknowledgement ends the alarm for the first certificate of a digest only
)

// ServerKeys are the gateway's server keys.
type ServerKeys struct {
	Current string       `json:"current"`
	Earlier []EarlierKey `json:"earlier"`
}

// EarlierKey is a server key that was replaced.
type EarlierKey struct {
	PublicKey string `json:"public_key"`
	Replaced  string `json:"replaced"`
}

// Certificate is a certificate found in a log.
type Certificate struct {
	ID string `json:"id"`
	// Digest is the SHA-256 digest of the TBSCertificate without poison and SCT list, in base64url.
	Digest    string   `json:"digest"`
	Names     []string `json:"names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	PublicKey string   `json:"public_key"`
	Logged    string   `json:"logged"`
}

// CTInput is the input of a case of conformance/ct-v0.json in the root of the repository.
type CTInput struct {
	PublicNames  []string      `json:"public_names"`
	Since        string        `json:"since"`
	Now          string        `json:"now"`
	ServerKeys   ServerKeys    `json:"server_keys"`
	Acknowledged []string      `json:"acknowledged"`
	Certificates []Certificate `json:"certificates"`
}

// CTResult is the result for one certificate.
type CTResult struct {
	ID     string `json:"id"`
	Result string `json:"result"`
}

// times are the parsed times of a certificate and of the check.
type times struct{ since, now, notBefore, notAfter, logged time.Time }

// CTAlarms decides for each certificate whether the gateway raises an alarm (SPEC-v0 section
// 11.7 item 7, RELAY-v0 section 6.7): "alarm", "past-exposure" or "none". A time that does not parse is a defect of the case.
func CTAlarms(in CTInput, f CTFault) ([]CTResult, error) {
	out := make([]CTResult, 0, len(in.Certificates))
	for i, c := range in.Certificates {
		t, err := parseTimes(in, c)
		if err != nil {
			return nil, err
		}
		keys, err := earlierTimes(in.ServerKeys)
		if err != nil {
			return nil, err
		}
		out = append(out, CTResult{c.ID, decide(in, i, t, keys, f)})
	}
	return out, nil
}

func parseTimes(in CTInput, c Certificate) (times, error) {
	var t times
	var err error
	for _, x := range []struct {
		to   *time.Time
		text string
	}{{&t.since, in.Since}, {&t.now, in.Now}, {&t.notBefore, c.NotBefore}, {&t.notAfter, c.NotAfter}, {&t.logged, c.Logged}} {
		if *x.to, err = time.Parse(time.RFC3339, x.text); err != nil {
			return t, err
		}
	}
	return t, nil
}

// earlierTimes maps the public key of each earlier server key to the time it was replaced.
func earlierTimes(keys ServerKeys) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for _, k := range keys.Earlier {
		replaced, err := time.Parse(time.RFC3339, k.Replaced)
		if err != nil {
			return nil, err
		}
		out[k.PublicKey] = replaced
	}
	return out, nil
}

func decide(in CTInput, index int, t times, earlier map[string]time.Time, f CTFault) string {
	c := in.Certificates[index]
	if f.Has(CTAlarmAlways) {
		return "alarm"
	}
	if f.Has(CTNeverAlarm) {
		return "none"
	}
	if isOwn(in.ServerKeys.Current, earlier, c, t, f) || acknowledged(in, index, f) || !coversAny(in.PublicNames, c.Names, f) {
		return "none"
	}
	if f.Has(CTNoLookback) {
		return classify(t, f)
	}
	if t.notBefore.After(t.now) && f.Has(CTNotYetIgnored) || f.Has(CTStartExclusive) && t.notBefore.Equal(t.now) {
		return "none"
	}
	if t.notAfter.Before(t.since) || f.Has(CTLookbackExclusive) && t.notAfter.Equal(t.since) {
		return "none"
	}
	return classify(t, f)
}

// acknowledged: the digest of the certificate is among the acknowledged ones, and nothing else
// is, unless a defect widens the match.
func acknowledged(in CTInput, index int, f CTFault) bool {
	c := in.Certificates[index]
	if f.Has(CTAckAll) && len(in.Acknowledged) > 0 {
		return true
	}
	if slices.Contains(in.Acknowledged, c.Digest) {
		return !f.Has(CTAckFirstOnly) || !slices.ContainsFunc(in.Certificates[:index], func(o Certificate) bool { return o.Digest == c.Digest })
	}
	for _, o := range in.Certificates {
		if !slices.Contains(in.Acknowledged, o.Digest) {
			continue
		}
		if f.Has(CTAckByName) && slices.Equal(o.Names, c.Names) || f.Has(CTAckByKey) && o.PublicKey == c.PublicKey {
			return true
		}
	}
	return false
}

// classify: a certificate that expired before the check is a past exposure.
func classify(t times, f CTFault) string {
	expired := t.notAfter.Before(t.now) || f.Has(CTNowExclusive) && t.notAfter.Equal(t.now)
	switch {
	case !expired:
		return "alarm"
	case f.Has(CTExpiredIgnored):
		return "none"
	case f.Has(CTExpiredAlarm):
		return "alarm"
	}
	return "past-exposure"
}

// isOwn: the certificate has the public key of the current server key, or of an earlier one and
// was logged strictly before that key was replaced.
func isOwn(current string, earlier map[string]time.Time, c Certificate, t times, f CTFault) bool {
	if c.PublicKey == current {
		return true
	}
	replaced, ok := earlier[c.PublicKey]
	switch {
	case !ok, f.Has(CTOldKeyForeign):
		return false
	case f.Has(CTOldKeyOwn):
		return true
	}
	return t.logged.Before(replaced) || f.Has(CTOldKeyInclusive) && t.logged.Equal(replaced)
}

func coversAny(public, certNames []string, f CTFault) bool {
	if f.Has(CTOnlyStandard) && len(public) > 1 {
		public = public[:1]
	}
	for _, p := range public {
		for _, n := range certNames {
			if covers(n, p, f) {
				return true
			}
		}
	}
	return false
}

// covers reports whether the certificate name matches the public name: the same name, or a
// wildcard of one label in the leftmost position.
func covers(certName, public string, f CTFault) bool {
	if !f.Has(CTCaseSensitive) {
		certName, public = strings.ToLower(certName), strings.ToLower(public)
	}
	switch {
	case certName == public:
		return true
	case f.Has(CTSubdomain) && strings.HasSuffix(certName, "."+public):
		return true
	case f.Has(CTSuffix) && strings.HasSuffix(certName, public):
		return true
	case f.Has(CTExactOnly) || !strings.HasPrefix(certName, "*."):
		return false
	}
	domain := certName[2:]
	if f.Has(CTWildApex) && domain == public {
		return true
	}
	rest, ok := strings.CutSuffix(public, "."+domain)
	return ok && rest != "" && (!strings.Contains(rest, ".") || f.Has(CTWildDeep))
}
