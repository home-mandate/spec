// SPDX-License-Identifier: Apache-2.0

package refop

// Defects of the enrollment endpoint (RELAY-v0 section 5), one for each check of the class
// enrollment. They continue the mask of the defects of the metadata.
const (
	// NonceReuse (E1) accepts a nonce more than once.
	NonceReuse Fault = 1 << (iota + 8)
	// NoNonceOnError (E2) leaves Replay-Nonce out of error responses.
	NoNonceOnError
	// NonceBeforeSignature (E3) checks the nonce before the signature.
	NonceBeforeSignature
	// SignatureBeforeUnpaired (E4) checks the signature before it says unpaired.
	SignatureBeforeUnpaired
	// ForeignKidAccepted (E5) lets the kid of one installation act at the URL of another.
	ForeignKidAccepted
	// ExtraPayloadMember (E6) accepts a payload member the schema does not list.
	ExtraPayloadMember
	// CodeWithOtherKey (E7) lets a used pairing code be redeemed with another key.
	CodeWithOtherKey
	// CSRWithInstallationKey (E8) accepts a certificate request with the installation key.
	CSRWithInstallationKey
	// SANNotCritical (E9) issues a certificate whose subject alternative name is not critical.
	SANNotCritical
	// LongCertificate (E10) issues a certificate that lasts 25 hours.
	LongCertificate
	// NotBeforeStalls (E11) issues a certificate whose notBefore does not rise.
	NotBeforeStalls
	// SecondReportInForce (E12) puts a second ACME report in force without confirmation.
	SecondReportInForce
	// CAOutsideList (E13) accepts a CA that is not in acme_cas.
	CAOutsideList
	// ChallengeBeforeAccount (E14) publishes challenge values before an account is in force.
	ChallengeBeforeAccount
	// OwnNameUnderOperator (E15) accepts an own-domain name under the operator domain.
	OwnNameUnderOperator
	// VerifiedWithoutTXT (E16) verifies an own-domain name without its TXT record.
	VerifiedWithoutTXT
	// NoNameUnavailable (E17) registers a name that another installation holds.
	NoNameUnavailable
	// BadSignatureAfterUnpair (E18) answers bad-signature instead of unpaired.
	BadSignatureAfterUnpair
	// RelativeLocation (E19) sends a relative Location.
	RelativeLocation
	// KeyChangeToForeignKey (E20) lets a key change take the key of another installation.
	KeyChangeToForeignKey
)

// Defects of the DNS records of an installation (RELAY-v0 sections 5.6 and 6.3), one for each
// check of the class dns.
const (
	// ApexNoIssuewild (D1) leaves issuewild ";" out of the CAA records at the apex.
	ApexNoIssuewild Fault = 1 << (iota + 28)
	// ApexIssueCA (D2) permits a CA at the apex.
	ApexIssueCA
	// NoValidationMethods (D3) leaves validationmethods out of the CAA record of a name.
	NoValidationMethods
	// LongTTL (D4) publishes records with a TTL of two hours.
	LongTTL
	// CAAStaysAfterUnpair (D5) leaves the CAA record of a name when it unpairs.
	CAAStaysAfterUnpair
	// ChallengeBeforeSecondServer (D6) answers a challenge before the second name server has it.
	ChallengeBeforeSecondServer
	// WrongAddress (D7) publishes an A record that is not in relay_addresses.
	WrongAddress
	// ExtraTXT (D8) publishes a TXT record at the standard name.
	ExtraTXT
	// NoClosedCAA (D9) publishes no CAA record before the ACME report.
	NoClosedCAA
)

// DashToken makes the token of an own-domain name begin with "-", which a DNS hook cannot be
// given as a value; the tool registers again for another token (RELAY-v0 section 6.4).
const DashToken Fault = 1 << 37

// More defects of the enrollment endpoint (RELAY-v0 sections 5.2 and 6.4).
const (
	// KeyConflictBurnsCode (E21) uses a pairing code up when it answers key-conflict.
	KeyConflictBurnsCode Fault = 1 << (iota + 38)
	// TokenReused (E22) gives an own-domain registration the token of the one that ended.
	TokenReused
	// UnpairIgnored (E23) answers 200 to an unpairing but leaves the installation active.
	UnpairIgnored
)
