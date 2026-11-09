// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/home-mandate/spec/jws"
)

const (
	maxRequestBytes = 32 << 10
	problemBase     = "https://home-mandate.org/relay/errors/"
)

var errorStatus = map[string]int{
	"malformed": 400, "bad-nonce": 400, "bad-signature": 401, "pairing-refused": 403,
	"confirmation-required": 403, "offline-too-long": 403, "blocked": 403, "bad-csr": 400,
	"name-unavailable": 409, "key-conflict": 409, "unpaired": 410, "rate-limited": 429, "server-internal": 500,
}

func (o *Operator) routeEnrollment(mux *http.ServeMux) {
	mux.HandleFunc("GET /enroll/directory", o.directory)
	mux.HandleFunc("HEAD /enroll/new-nonce", o.newNonce)
	mux.HandleFunc("GET /enroll/new-nonce", o.newNonce)
	mux.HandleFunc("POST /enroll/", o.post)
}

// nonce makes a fresh nonce and remembers it. The caller holds the lock.
func (o *Operator) nonce() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	n := base64.RawURLEncoding.EncodeToString(raw)
	o.nonces[n] = true
	return n
}

// useNonce reports whether n is a nonce that was issued and not used; it uses it up unless
// NonceReuse is set. The caller holds the lock.
func (o *Operator) useNonce(n string) bool {
	ok := o.nonces[n]
	if ok && !o.cfg.Faults.Has(NonceReuse) {
		delete(o.nonces, n)
	}
	return ok
}

func (o *Operator) directory(w http.ResponseWriter, _ *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reply(w, http.StatusOK, map[string]string{
		"new_nonce": o.base() + "/enroll/new-nonce", "pair": o.base() + "/enroll/pair", "key_change": o.base() + "/enroll/key-change",
	}, nil)
}

func (o *Operator) newNonce(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	w.Header().Set("Replay-Nonce", o.nonce())
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// reply writes a JSON success. The caller holds the lock.
func (o *Operator) reply(w http.ResponseWriter, status int, v any, header map[string]string) {
	w.Header().Set("Replay-Nonce", o.nonce())
	w.Header().Set("Content-Type", "application/json")
	for k, val := range header {
		w.Header().Set(k, val)
	}
	w.WriteHeader(status)
	_, _ = w.Write(must(json.Marshal(v)))
}

// fail writes the error name of section 5.1. The caller holds the lock.
func (o *Operator) fail(w http.ResponseWriter, name string) {
	if !o.cfg.Faults.Has(NoNonceOnError) {
		w.Header().Set("Replay-Nonce", o.nonce())
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(errorStatus[name])
	_, _ = w.Write(must(json.Marshal(map[string]any{"type": problemBase + name, "status": errorStatus[name]})))
}

// request is a request that passed the steps 1 to 4 of section 5.1.
type request struct {
	url     string
	header  jws.RequestHeader
	payload []byte
	inst    *installation
}

func (o *Operator) post(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil || r.Header.Get("Content-Type") != "application/jose" {
		o.fail(w, "malformed")
		return
	}
	req, name := o.authenticate(r.URL.Path, string(body))
	if name != "" {
		o.fail(w, name)
		return
	}
	if name := o.checkState(req); name != "" {
		o.fail(w, name)
		return
	}
	o.dispatch(w, req)
}

// authenticate runs the steps 1 to 4 of RELAY-v0 section 5.1 and returns the name of the
// error of the first step that fails.
func (o *Operator) authenticate(path, compact string) (*request, string) {
	url := o.base() + path
	header, payload, err := jws.ParseRequest(compact)
	if err != nil {
		return nil, "malformed"
	}
	if (header.JWK != nil) != (url == o.base()+"/enroll/pair") {
		return nil, "malformed"
	}
	req := &request{url: url, header: header, payload: payload}
	if header.Kid != "" {
		if name := o.checkKid(req, compact); name != "" {
			return nil, name
		}
	}
	if o.cfg.Faults.Has(NonceBeforeSignature) && !o.useNonce(header.Nonce) {
		return nil, "bad-nonce"
	}
	var key crypto.PublicKey
	if req.inst != nil {
		key = req.inst.key
	}
	if _, _, err := jws.VerifyRequest(compact, key); err != nil {
		if errors.Is(err, jws.ErrSignature) {
			return nil, "bad-signature"
		}
		return nil, "malformed"
	}
	if !o.cfg.Faults.Has(NonceBeforeSignature) && !o.useNonce(header.Nonce) {
		return nil, "bad-nonce"
	}
	if header.URL != url {
		return nil, "malformed"
	}
	return req, ""
}

// checkKid is step 3: the installation the kid names and the URL it may act on.
func (o *Operator) checkKid(req *request, compact string) string {
	inst := o.lookup(req.header.Kid)
	switch {
	case inst == nil:
		return "bad-signature"
	case inst.status == "unpaired":
		if o.cfg.Faults.Has(BadSignatureAfterUnpair) {
			return "bad-signature"
		}
		if o.cfg.Faults.Has(SignatureBeforeUnpaired) {
			if _, _, err := jws.VerifyRequest(compact, inst.key); err != nil && errors.Is(err, jws.ErrSignature) {
				return "bad-signature"
			}
		}
		return "unpaired"
	}
	req.inst = inst
	own := o.installationURL(inst)
	allowed := req.url == own || len(req.url) > len(own) && req.url[:len(own)+1] == own+"/" || req.url == o.base()+"/enroll/key-change"
	if !allowed && !o.cfg.Faults.Has(ForeignKidAccepted) {
		return "malformed"
	}
	return ""
}

// checkState is step 5: blocked and offline installations.
func (o *Operator) checkState(req *request) string {
	inst := req.inst
	if inst == nil {
		return ""
	}
	read := req.url == o.installationURL(inst) && len(req.payload) == 0
	unpair := string(req.payload) == `{"status":"unpaired"}`
	switch {
	case inst.offline && !read:
		return "offline-too-long"
	case inst.blocked && !read && !unpair:
		return "blocked"
	}
	return ""
}

// target returns the installation that a URL below an installation URL belongs to, and the
// rest of the path.
func (o *Operator) target(url string) (*installation, string) {
	rest, ok := strings.CutPrefix(url, o.base()+instPath)
	if !ok {
		return nil, ""
	}
	id, sub, _ := strings.Cut(rest, "/")
	return o.insts[id], sub
}

func (o *Operator) dispatch(w http.ResponseWriter, req *request) {
	inst, sub := o.target(req.url)
	switch {
	case req.url == o.base()+"/enroll/pair":
		o.pair(w, req)
	case req.url == o.base()+"/enroll/key-change":
		o.keyChange(w, req)
	case inst != nil && sub == "":
		o.installationRequest(w, req, inst)
	case inst != nil && sub == "certificate":
		o.certificate(w, req, inst)
	case inst != nil && sub == "acme-challenge":
		o.challenge(w, req, inst)
	default:
		o.fail(w, "malformed")
	}
}
