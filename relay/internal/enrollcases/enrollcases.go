// SPDX-License-Identifier: Apache-2.0

// Package enrollcases reads the cases of relay/conformance/enrollment-v0.json and plays them
// against an enrollment endpoint: the tests of the reference operator and the live test play
// the same cases with the same code. A case is symbolic; Actors give it keys and URLs.
package enrollcases

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/home-mandate/spec/relay/internal/enroll"
)

// Path is the case file within the files of package relay.
const Path = "conformance/enrollment-v0.json"

// Worlds that a live test can set up; the others need an operator that is blocked or has been
// offline for days.
const (
	WorldBothActive    = "both-active"
	WorldOtherUnpaired = "other-unpaired"
	WorldBlocked       = "blocked"
	WorldOffline       = "offline"
	WorldOfflineBlock  = "offline-blocked"
)

// Step is one request of a case.
type Step struct {
	Kid       string `json:"kid"`
	To        string `json:"to"`
	Header    string `json:"header"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	Alg       string `json:"alg"`
	Payload   string `json:"payload"`
	Expect    string `json:"expect"`
}

// Case is a case of the file.
type Case struct {
	ID      string `json:"id"`
	World   string `json:"world"`
	Offline bool   `json:"offline"`
	Why     string `json:"why"`
	Steps   []Step `json:"steps"`
}

// Load reads the cases from the files of package relay.
func Load(files fs.FS) ([]Case, error) {
	data, err := fs.ReadFile(files, Path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Description string `json:"description"`
		Cases       []Case `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc.Cases, nil
}

// Actors are what the symbolic parts of a case stand for.
type Actors struct {
	Dir enroll.Directory
	// Self is the installation under test, Other the second one, Unpaired an installation
	// that was unpaired. Other and Unpaired may be unset if a world has no such installation.
	Self, Other, Unpaired enroll.Identity
	// CertificateURL is the URL for tunnel certificates of Self.
	CertificateURL string
	// Unknown is an installation URL that exists nowhere.
	Unknown string
	// ForeignEd and ForeignES are keys of no installation, one for each algorithm.
	ForeignEd, ForeignES *enroll.Signer
	// UsedNonce is a nonce that an earlier request used up.
	UsedNonce string
	// CSR is a valid certificate request.
	CSR []byte
}

// ErrNotPlayable is returned for a case that the actors cannot play.
var ErrNotPlayable = errors.New("enrollcases: the actors lack what the case needs")

func (a Actors) identity(name string) enroll.Identity {
	switch name {
	case "other":
		return a.Other
	case "unpaired":
		return a.Unpaired
	case "unknown":
		return enroll.Identity{URL: a.Unknown, Signer: a.Self.Signer}
	}
	return a.Self
}

func (a Actors) target(name string) string {
	switch name {
	case "pair":
		return a.Dir.Pair
	case "key-change":
		return a.Dir.KeyChange
	case "certificate":
		return a.CertificateURL
	case "unknown":
		return a.Unknown
	}
	return a.identity(name).URL
}

func (a Actors) foreign(alg string) *enroll.Signer {
	if alg == enroll.AlgES256 {
		return a.ForeignES
	}
	return a.ForeignEd
}

func (st Step) payload(a Actors) string {
	switch st.Payload {
	case "csr":
		return `{"csr":"` + enroll.B64(a.CSR) + `"}`
	case "extra-member":
		return `{"own_domain":null,"extra":1}`
	case "noop":
		return `{"own_domain":null}`
	case "unpair":
		return `{"status":"unpaired"}`
	}
	return ""
}

func (st Step) defect() enroll.Defect {
	switch st.Payload {
	case "not-object":
		return enroll.ArrayPayload
	case "duplicate-member":
		return enroll.DuplicatePayloadMember
	}
	return enroll.NoDefect
}

// Request builds the request of a step with the nonce, and returns the URL it goes to.
func (a Actors) Request(st Step, nonce string) (rawURL, compact string, err error) {
	id := a.identity(st.Kid)
	rawURL = a.target(st.To)
	if id.Signer == nil || rawURL == "" || (st.Kid == "none" && a.Self.Signer == nil) {
		return "", "", ErrNotPlayable
	}
	spec := enroll.Spec{Signer: id.Signer, Nonce: nonce, URL: rawURL, Payload: st.payload(a), Defect: st.defect()}
	if st.Kid == "none" {
		spec.JWK = true
	} else {
		spec.Kid = id.URL
	}
	if st.Header == "different" {
		spec.URL = a.Dir.NewNonce
	}
	if st.Alg == "other" {
		spec.Alg = enroll.AlgES256
		if id.Signer.Alg() == enroll.AlgES256 {
			spec.Alg = enroll.AlgEdDSA
		}
	}
	if st.Signature == "foreign" {
		if spec.SignWith = a.foreign(id.Signer.Alg()); spec.SignWith == nil {
			return "", "", ErrNotPlayable
		}
	}
	return rawURL, spec.Compact(), nil
}

// Result is the outcome of one step.
type Result struct {
	Case string
	Step int
	Got  string
	Want string
	// HasNonce says that the response carried a valid Replay-Nonce.
	HasNonce bool
	Status   int
}

// Pass reports whether the operator answered as the case says.
func (r Result) Pass() bool { return r.Got == r.Want }

// Play sends the steps of a case with the client and returns one result for each step that
// was sent. A transport failure ends the case with its error.
func Play(ctx context.Context, c *enroll.Client, a Actors, cs Case) ([]Result, error) {
	var results []Result
	previous := ""
	for i, st := range cs.Steps {
		if _, _, err := a.Request(st, ""); err != nil {
			return results, err
		}
		var used string
		resp, err := c.Send(ctx, a.target(st.To), func(fresh string) string {
			used = nonceFor(st, fresh, previous, a)
			_, compact, _ := a.Request(st, used)
			return compact
		}, false, false)
		if err != nil {
			return results, err
		}
		previous = used
		got := enroll.ErrorName(resp)
		if got == "" {
			got = "ok"
		}
		results = append(results, Result{Case: cs.ID, Step: i, Got: got, Want: st.Expect,
			HasNonce: enroll.ValidNonce(resp.Header.Get("Replay-Nonce")), Status: resp.Status})
	}
	return results, nil
}

func nonceFor(st Step, fresh, previous string, a Actors) string {
	switch st.Nonce {
	case "used":
		return a.UsedNonce
	case "unknown":
		return enroll.RandomToken(16)
	case "previous":
		return previous
	}
	return fresh
}
