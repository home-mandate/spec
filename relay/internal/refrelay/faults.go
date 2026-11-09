// SPDX-License-Identifier: Apache-2.0

package refrelay

// Fault switches on one deliberate defect of the relay. Faults are constants and combine as a
// mask; the names R1 to R17 are those of the plan of the test tool.
type Fault uint32

// Has reports whether f contains the defect.
func (f Fault) Has(defect Fault) bool { return f&defect != 0 }

const (
	// TLS12 (R1) accepts TLS 1.2.
	TLS12 Fault = 1 << iota
	// GroupX25519 (R2) accepts and prefers the key exchange group X25519.
	GroupX25519
	// Resumption (R3) lets a client resume its session.
	Resumption
	// NoDenylist (R4) neither checks the denylist at a handshake nor closes open connections
	// of a certificate that was added to it.
	NoDenylist
	// TokenReuse (R5) lets a token bind more than once.
	TokenReuse
	// ForeignToken (R6) binds a token of another installation.
	ForeignToken
	// ByteBeforeClose (R7) writes a frame to a data connection before it closes it.
	ByteBeforeClose
	// MappedIPv4 (R8) writes the addresses of an IPv4 agent as IPv4-mapped IPv6 addresses.
	MappedIPv4
	// RealDestination (R9) writes the relay's own address as the destination of the PROXY header.
	RealDestination
	// AgentProxyHeader (R10) takes the source address from a PROXY header an agent sends.
	AgentProxyHeader
	// PendingRouted (R11) routes an own-domain name that is still pending.
	PendingRouted
	// CaseSensitiveSNI (R12) compares the server name with regard to case.
	CaseSensitiveSNI
	// PinsFromGateway (R13) accepts a pins frame from the gateway.
	PinsFromGateway
	// Heartbeat3 (R14) announces a heartbeat interval of 3 seconds.
	Heartbeat3
	// NoSessionExists (R15) lets a second control connection of an installation live next to
	// the first instead of answering session-exists.
	NoSessionExists
	// KeyNotPinned (R16) presents a key that is not in relay_pins.
	KeyNotPinned
	// NoCloseNotify (R17) does not pass the end of a direction on as close_notify.
	NoCloseNotify
)
