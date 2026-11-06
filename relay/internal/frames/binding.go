// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"errors"
	"time"
)

// Token states.
const (
	Open      = "open"
	Used      = "used"
	Withdrawn = "withdrawn"
	Expired   = "expired"
)

// Token is a token the relay sent in a stream-open.
type Token struct {
	Token        []byte
	Installation string
	State        string
}

// RelayState is what the relay knows when a data connection sends its first bytes.
type RelayState struct {
	Tokens []Token
	// ControlNotBefore is the notBefore of the certificate of the installation's control
	// connection.
	ControlNotBefore time.Time
	// LimitReached says that a limit of the installation refuses a new binding.
	LimitReached bool
}

// Connection is the data connection: the installation and notBefore of its certificate.
type Connection struct {
	Installation string
	NotBefore    time.Time
}

// Binding is the result of the first bytes of a data connection.
type Binding struct {
	// Bound is true if the relay binds the connection; otherwise it closes it without
	// any answer.
	Bound bool
	// Consumed are the tokens that the presentation consumed. Determined is false where
	// section 4.5 lets the relay close before it reads the token, so that whether the token
	// is consumed is up to it.
	Consumed   [][]byte
	Determined bool
	// CaseError is set for first bytes that are no frame a case can hold (ErrCase), so that
	// a typo in a case is not taken for a refusal.
	CaseError error
}

// Bind applies section 4.5 to the first bytes of a data connection.
func Bind(state RelayState, conn Connection, first []byte) Binding {
	if conn.NotBefore.Before(state.ControlNotBefore) {
		return Binding{}
	}
	// A data-bind longer than 32 bytes: the relay may read the 36 bytes of a data-bind,
	// and with them a token, before it refuses the frame.
	if len(first) >= headerSize+TokenSize && first[0] == 0 && first[1] == typeDataBind && int(first[2])<<8|int(first[3]) > TokenSize {
		return Binding{}
	}
	token, err := DataBind(first)
	if errors.Is(err, ErrCase) {
		return Binding{Determined: true, CaseError: err}
	}
	if err != nil {
		return Binding{Determined: true}
	}
	for _, t := range state.Tokens {
		if !bytes.Equal(t.Token, token) {
			continue
		}
		if t.State != Open {
			return Binding{Determined: true}
		}
		// The first presentation consumes the token, also when the relay refuses it.
		consumed := Binding{Consumed: [][]byte{token}, Determined: true}
		consumed.Bound = t.Installation == conn.Installation && !state.LimitReached
		return consumed
	}
	return Binding{Determined: true}
}
