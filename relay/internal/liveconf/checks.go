// SPDX-License-Identifier: Apache-2.0

package liveconf

import "slices"

// Check describes one check of a live run. The IDs are fixed: reports and the list printed by
// -list refer to them.
type Check struct {
	ID      string
	Class   string
	Section string
	Title   string
}

// Check IDs of the class metadata.
const (
	CheckMetadataFetch     = "metadata.fetch"
	CheckMetadataSize      = "metadata.size"
	CheckMetadataIJSON     = "metadata.i-json"
	CheckMetadataSchema    = "metadata.schema"
	CheckMetadataOperator  = "metadata.operator-domain"
	CheckMetadataRules     = "metadata.rules"
	CheckMetadataLevels    = "metadata.protection-levels"
	CheckMetadataDomains   = "metadata.registered-domains"
	CheckMetadataAddresses = "metadata.relay-addresses"
)

// Check IDs of the class enrollment.
const (
	CheckEnrollDirectory       = "enrollment.directory"
	CheckEnrollNonce           = "enrollment.nonce"
	CheckEnrollNonceOnError    = "enrollment.nonce-on-error"
	CheckEnrollSpelling        = "enrollment.spelling"
	CheckEnrollSchema          = "enrollment.schema"
	CheckEnrollPairing         = "enrollment.pairing"
	CheckEnrollLocation        = "enrollment.location"
	CheckEnrollRepeat          = "enrollment.pairing-repeat"
	CheckEnrollRefused         = "enrollment.pairing-refused"
	CheckEnrollBadCSR          = "enrollment.bad-csr"
	CheckEnrollCertRules       = "enrollment.cert-rules"
	CheckEnrollCertSAN         = "enrollment.cert-san"
	CheckEnrollCertLifetime    = "enrollment.cert-lifetime"
	CheckEnrollCertMonotonic   = "enrollment.cert-monotonic"
	CheckEnrollKeyChange       = "enrollment.key-change"
	CheckEnrollKeyConflict     = "enrollment.key-conflict"
	CheckEnrollACMEReport      = "enrollment.acme-report"
	CheckEnrollACMEConfirm     = "enrollment.acme-confirmation"
	CheckEnrollACMECA          = "enrollment.acme-ca"
	CheckEnrollChallengeEarly  = "enrollment.challenge-needs-account"
	CheckEnrollChallenge       = "enrollment.challenge"
	CheckEnrollOwnForbidden    = "enrollment.own-forbidden"
	CheckEnrollOwnPending      = "enrollment.own-pending"
	CheckEnrollOwnVerified     = "enrollment.own-verified"
	CheckEnrollOwnTaken        = "enrollment.own-unavailable"
	CheckEnrollOwnToken        = "enrollment.own-token-new"
	CheckEnrollPairKeyConflict = "enrollment.pairing-key-conflict"
	CheckEnrollUnpair          = "enrollment.unpair"
	// CheckEnrollCases is the check of the cases of enrollment-v0.json; a failure names the
	// file and the case.
	CheckEnrollCases = "enrollment.cases"
)

// Check IDs of the class dns.
const (
	CheckDNSServers   = "dns.servers"
	CheckDNSApex      = "dns.apex-caa"
	CheckDNSClosed    = "dns.name-caa-closed"
	CheckDNSAccount   = "dns.name-caa-account"
	CheckDNSAddresses = "dns.addresses"
	CheckDNSTTL       = "dns.ttl"
	CheckDNSNoOther   = "dns.no-other-records"
	CheckDNSChallenge = "dns.challenge-visible"
	CheckDNSRemoved   = "dns.removed"
)

// Check IDs of the class relay.
const (
	CheckRelayKey      = "relay.relay-key"
	CheckRelayTLS      = "relay.tls"
	CheckRelayHello    = "relay.hello"
	CheckRelayFrames   = "relay.frames"
	CheckRelayPins     = "relay.pins"
	CheckRelaySession  = "relay.session"
	CheckRelayBinding  = "relay.binding"
	CheckRelaySilent   = "relay.silent-close"
	CheckRelayRouting  = "relay.routing"
	CheckRelayProxy    = "relay.proxy"
	CheckRelayStream   = "relay.stream"
	CheckRelayDenylist = "relay.denylist"
)

// checks is the table of all checks of this version.
var checks = []Check{
	{CheckMetadataFetch, ClassMetadata, "3", "the document is served over HTTPS with a valid certificate, without a redirect"},
	{CheckMetadataSize, ClassMetadata, "3", "the document is at most 16 KiB"},
	{CheckMetadataIJSON, ClassMetadata, "3", "the document is I-JSON"},
	{CheckMetadataSchema, ClassMetadata, "3", "the document is valid against the schema"},
	{CheckMetadataOperator, ClassMetadata, "3", "operator_domain is the host the document was fetched from"},
	{CheckMetadataRules, ClassMetadata, "3, 6.8", "the rules beyond the schema: hosts, pins, address forms"},
	{CheckMetadataLevels, ClassMetadata, "7.3", "both protection levels are offered"},
	{CheckMetadataDomains, ClassMetadata, "7.1", "the name domain is in no registered domain of the operator's sites"},
	{CheckMetadataAddresses, ClassMetadata, "3", "relay_addresses are globally reachable unicast addresses"},

	{CheckEnrollDirectory, ClassEnrollment, "5.1", "the directory is served and names URLs on the enrollment host"},
	{CheckEnrollNonce, ClassEnrollment, "5.1", "HEAD and GET on new_nonce answer 200 and 204 with distinct nonces of at least 128 bits"},
	{CheckEnrollNonceOnError, ClassEnrollment, "5.1", "error responses carry a fresh Replay-Nonce"},
	{CheckEnrollCases, ClassEnrollment, "5.1", "requests of enrollment-v0.json get the errors of the order of the steps"},
	{CheckEnrollSpelling, ClassEnrollment, "5.1", "requests with a defect of spelling are malformed"},
	{CheckEnrollSchema, ClassEnrollment, "5", "responses are valid against the schema"},
	{CheckEnrollPairing, ClassEnrollment, "5.2", "pairing answers 201 with an installation whose name is the home ID and the name domain, and a certificate"},
	{CheckEnrollLocation, ClassEnrollment, "5.2", "Location is the absolute installation URL on the enrollment host"},
	{CheckEnrollRepeat, ClassEnrollment, "5.2", "a repeated pairing with the same key and code is answered like the first"},
	{CheckEnrollPairKeyConflict, ClassEnrollment, "5.2", "an installation key in use is key-conflict at pairing and leaves the code usable with a new key"},
	{CheckEnrollRefused, ClassEnrollment, "5.2", "a used code with another key, and a wrong code, are pairing-refused"},
	{CheckEnrollBadCSR, ClassEnrollment, "5.4", "certificate requests with the installation key, a key of an earlier certificate, a wrong key type and garbage are bad-csr"},
	{CheckEnrollCertRules, ClassEnrollment, "5.4", "tunnel certificates have the tunnel key, cA=false, the key usages, a serial of 64 bits and the not_after of the response"},
	{CheckEnrollCertSAN, ClassEnrollment, "5.4", "tunnel certificates have an empty subject and the SPIFFE ID as only name, critical"},
	{CheckEnrollCertLifetime, ClassEnrollment, "5.4", "tunnel certificates last at most 24 hours and start no earlier than 5 minutes before issuance"},
	{CheckEnrollCertMonotonic, ClassEnrollment, "5.4", "notBefore rises from one tunnel certificate of an installation to the next"},
	{CheckEnrollKeyChange, ClassEnrollment, "5.5", "a key change takes effect: the new key works, the old key is bad-signature"},
	{CheckEnrollKeyConflict, ClassEnrollment, "5.5", "a key change to the key of another installation is key-conflict"},
	{CheckEnrollACMEReport, ClassEnrollment, "5.6", "the first report of an ACME account is answered 200 and shows in the installation"},
	{CheckEnrollACMEConfirm, ClassEnrollment, "5.6", "a second, different report is confirmation-required and changes nothing"},
	{CheckEnrollACMECA, ClassEnrollment, "6.3", "a report with a CA that is not in acme_cas is malformed"},
	{CheckEnrollChallengeEarly, ClassEnrollment, "5.6", "challenge values are refused while no account is in force"},
	{CheckEnrollChallenge, ClassEnrollment, "5.6", "challenge values are answered 200 with the same values"},
	{CheckEnrollOwnForbidden, ClassEnrollment, "6.4", "the operator domain, the name domain and names below them are malformed own-domain names"},
	{CheckEnrollOwnPending, ClassEnrollment, "6.4", "an own-domain name without its TXT record is pending, with a token of at least 128 bits"},
	{CheckEnrollOwnVerified, ClassEnrollment, "6.4", "registering the name again after the TXT record is set makes it verified"},
	{CheckEnrollOwnTaken, ClassEnrollment, "6.4", "an own-domain name that another installation holds is name-unavailable"},
	{CheckEnrollOwnToken, ClassEnrollment, "6.4", "registering an own-domain name again after removing it gives a new token"},
	{CheckEnrollUnpair, ClassEnrollment, "5.7", "unpairing answers 200 with the status unpaired"},

	{CheckDNSServers, ClassDNS, "6.3", "the name servers of the name domain are found and answer"},
	{CheckDNSApex, ClassDNS, "6.3", "the apex of the name domain has exactly the CAA records issue \";\" and issuewild \";\""},
	{CheckDNSClosed, ClassDNS, "5.2", "a new standard name has issue \";\" as its only CAA issue record until an account is reported"},
	{CheckDNSAccount, ClassDNS, "5.6", "after the report the CAA record is the account's, with accounturi and validationmethods=dns-01"},
	{CheckDNSAddresses, ClassDNS, "6.3", "A and AAAA of a standard name are the relay_addresses"},
	{CheckDNSTTL, ClassDNS, "6.3", "A, AAAA and CAA records have a TTL of at most 3600 seconds"},
	{CheckDNSNoOther, ClassDNS, "6.3", "a standard name has no TXT, CNAME, DNAME or NS record"},
	{CheckDNSChallenge, ClassDNS, "5.6", "challenge values show on all name servers when the answer is 200"},
	{CheckDNSRemoved, ClassDNS, "5.7", "after unpairing no record of the standard name and its challenge name is left"},

	{CheckRelayKey, ClassRelay, "4.1, 6.8", "the key the relay presents is one of relay_pins"},
	{CheckRelayTLS, ClassRelay, "4.2", "tunnel connections follow the probes of tls-v0.json: TLS 1.3, X25519MLKEM768, hm-tunnel/1, a tunnel certificate, no resumption"},
	{CheckRelayHello, ClassRelay, "4.4", "the relay sends nothing before hello and answers it with a valid hello-ack"},
	{CheckRelayFrames, ClassRelay, "4.3, 4.4", "a frame of frames-v0.json that a gateway can send and the relay must refuse ends the connection"},
	{CheckRelayPins, ClassRelay, "4.7", "a pins frame of the gateway is refused, and pins of the relay are well formed"},
	{CheckRelaySession, ClassRelay, "4.4", "a second control connection of an installation is session-exists, and one with a newer certificate replaces the first, which gets superseded"},
	{CheckRelayBinding, ClassRelay, "4.5", "data connections bind or are closed as binding-v0.json says, and tokens are consumed as it says"},
	{CheckRelaySilent, ClassRelay, "4.5", "a data connection that is closed gets no byte before it is closed"},
	{CheckRelayRouting, ClassRelay, "4.5, 6.1", "an agent connection is routed by the standard name without regard to case and by a verified own-domain name; other names are closed without a TLS handshake"},
	{CheckRelayProxy, ClassRelay, "4.6", "the PROXY header has the form of section 4.6, and the relay does not take it from the agent"},
	{CheckRelayStream, ClassRelay, "4.5", "the bytes of an agent pass unchanged, and the end of each direction is passed on"},
	{CheckRelayDenylist, ClassRelay, "4.1", "the certificate of an unpaired installation is refused, and its connections are closed within 60 seconds of unpairing"},
}

// Checks returns the table of checks in the order of a run.
func Checks() []Check {
	return slices.Clone(checks)
}

// checksOf returns the checks of one class.
func checksOf(class string) []Check {
	return slices.DeleteFunc(Checks(), func(c Check) bool { return c.Class != class })
}
