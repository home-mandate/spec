// SPDX-License-Identifier: Apache-2.0

// Package refgateway is the reference for the decisions a gateway makes in RELAY-v0, as pure
// functions of the inputs of the cases in relay/conformance: the pairing string (section 5.2),
// new pins (sections 4.7 and 6.8), the PROXY header (section 4.6), the address to connect to
// (section 3), the CAA records of the monitoring (section 6.7), the protection level (section
// 6.5) and the certificates in Certificate Transparency (section 6.7).
//
// It is for tests only: it shows that the cases agree with the text and with each other, not
// that any gateway behaves as it does. Each function takes a fault, a mask of deliberate
// defects; the tests show that every defect makes exactly the cases fail that are meant to
// catch it. Nothing outside tests may import this package (the guard in
// relay/cmd/relay-conformance checks that).
package refgateway

// Fault families have their own types so that a mask of one cannot be passed to another.

// Has reports whether the mask contains the fault.
func (f PairingFault) Has(d PairingFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f PinFault) Has(d PinFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f ProxyFault) Has(d ProxyFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f DestFault) Has(d DestFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f CAAFault) Has(d CAAFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f LevelFault) Has(d LevelFault) bool { return f&d != 0 }

// Has reports whether the mask contains the fault.
func (f CTFault) Has(d CTFault) bool { return f&d != 0 }
