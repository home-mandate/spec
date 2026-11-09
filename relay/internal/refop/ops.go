// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/home-mandate/spec/jws"
	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

var (
	codePattern   = regexp.MustCompile(`^[A-Z2-7]{16}$`)
	domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	urlPattern    = regexp.MustCompile(`^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~/-]*)?$`)
	valuePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

var b64 = base64.RawURLEncoding.Strict()

func sameKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && k.Equal(b)
}

// object reads a payload that has to be a JSON object with exactly the members in allowed
// (more with ExtraPayloadMember) and at least those in required.
func (o *Operator) object(payload []byte, allowed, required []string) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(payload, &m) != nil || m == nil {
		return nil, false
	}
	for k := range m {
		if !slices.Contains(allowed, k) && !o.cfg.Faults.Has(ExtraPayloadMember) {
			return nil, false
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, false
		}
	}
	return m, true
}

func text(raw json.RawMessage) (string, bool) {
	var s string
	return s, bytes.HasPrefix(raw, []byte(`"`)) && json.Unmarshal(raw, &s) == nil
}

func (o *Operator) csrKey(csr string, inst *installation, installationKey crypto.PublicKey) (crypto.PublicKey, string) {
	der, err := b64.DecodeString(csr)
	if err != nil || len(csr) < 64 {
		return nil, "malformed"
	}
	var earlier []crypto.PublicKey
	if inst != nil {
		earlier = inst.tunnelKeys
		installationKey = inst.key
	}
	if o.cfg.Faults.Has(CSRWithInstallationKey) {
		installationKey = nil
	}
	key, err := tunnelcert.CheckCSR(der, installationKey, earlier)
	if err != nil {
		return nil, "bad-csr"
	}
	return key, ""
}

func certJSON(chain [][]byte, notAfter time.Time) map[string]any {
	enc := make([]string, len(chain))
	for i, c := range chain {
		enc[i] = base64.RawURLEncoding.EncodeToString(c)
	}
	return map[string]any{"chain": enc, "not_after": notAfter.UTC().Format("2006-01-02T15:04:05Z")}
}

func (o *Operator) instJSON(inst *installation) map[string]any {
	url := o.installationURL(inst)
	m := map[string]any{
		"status": inst.status, "home_id": inst.homeID, "public_name": o.stdName(inst), "max_offline_days": 30,
		"certificate": url + "/certificate", "acme_challenge": url + "/acme-challenge",
	}
	if inst.acme != nil {
		m["acme_account"], m["caa_identity"] = inst.acme.account, inst.acme.caa
	}
	if inst.own != nil {
		m["own_domain"] = map[string]string{"name": inst.own.name, "token": inst.own.token, "status": inst.own.status}
	}
	return m
}

func (o *Operator) pair(w http.ResponseWriter, req *request) {
	m, ok := o.object(req.payload, []string{"code", "csr"}, []string{"code", "csr"})
	code, ok1 := text(m["code"])
	csr, ok2 := text(m["csr"])
	if !ok || !ok1 || !ok2 || !codePattern.MatchString(code) {
		o.fail(w, "malformed")
		return
	}
	key := req.header.JWK
	use := o.codes[code]
	switch {
	case !slices.Contains(o.cfg.Codes, code):
		o.fail(w, "pairing-refused")
	case use != nil && sameKey(use.key, key):
		o.repeatPair(w, use, csr, key)
	case use != nil && !o.cfg.Faults.Has(CodeWithOtherKey):
		o.fail(w, "pairing-refused")
	default:
		o.createInstallation(w, code, csr, key)
	}
}

func (o *Operator) createInstallation(w http.ResponseWriter, code, csr string, key crypto.PublicKey) {
	for _, other := range o.insts {
		if sameKey(other.key, key) {
			if o.cfg.Faults.Has(KeyConflictBurnsCode) {
				// A key of nobody: the code is used up, and no repetition can match it.
				o.codes[code] = &codeUse{inst: other.id}
			}
			o.fail(w, "key-conflict")
			return
		}
	}
	tunnelKey, name := o.csrKey(csr, nil, key)
	if name != "" {
		o.fail(w, name)
		return
	}
	inst := &installation{id: randomLabel(instIDBytes), homeID: o.newHomeID(), key: key, status: "active", pairedAt: time.Now()}
	o.insts[inst.id] = inst
	o.codes[code] = &codeUse{inst: inst.id, key: key}
	o.publishName(inst)
	o.paired(w, inst, tunnelKey)
}

func (o *Operator) repeatPair(w http.ResponseWriter, use *codeUse, csr string, key crypto.PublicKey) {
	inst := o.insts[use.inst]
	switch {
	case inst.status == "unpaired" || !sameKey(inst.key, key):
		o.fail(w, "unpaired")
		return
	case inst.blocked:
		o.fail(w, "blocked")
		return
	}
	tunnelKey, name := o.csrKey(csr, inst, key)
	if name != "" {
		o.fail(w, name)
		return
	}
	o.paired(w, inst, tunnelKey)
}

func (o *Operator) paired(w http.ResponseWriter, inst *installation, tunnelKey crypto.PublicKey) {
	chain, notAfter := o.issue(inst, tunnelKey)
	location := o.installationURL(inst)
	if o.cfg.Faults.Has(RelativeLocation) {
		location = instPath + inst.id
	}
	o.reply(w, http.StatusCreated, map[string]any{"installation": o.instJSON(inst), "tunnel_certificate": certJSON(chain, notAfter)},
		map[string]string{"Location": location})
}

func (o *Operator) certificate(w http.ResponseWriter, req *request, inst *installation) {
	m, ok := o.object(req.payload, []string{"csr"}, []string{"csr"})
	csr, ok1 := text(m["csr"])
	if !ok || !ok1 {
		o.fail(w, "malformed")
		return
	}
	key, name := o.csrKey(csr, inst, nil)
	if name != "" {
		o.fail(w, name)
		return
	}
	chain, notAfter := o.issue(inst, key)
	o.reply(w, http.StatusOK, certJSON(chain, notAfter), nil)
}

func (o *Operator) installationRequest(w http.ResponseWriter, req *request, inst *installation) {
	if len(req.payload) == 0 {
		o.reply(w, http.StatusOK, o.instJSON(inst), nil)
		return
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(req.payload, &members)
	switch {
	case members["acme_account"] != nil || members["caa_identity"] != nil:
		o.reportACME(w, req, inst)
	case members["own_domain"] != nil:
		o.registerOwnDomain(w, req, inst)
	case members["status"] != nil:
		o.unpair(w, req, inst)
	default:
		o.fail(w, "malformed")
	}
}

func (o *Operator) unpair(w http.ResponseWriter, req *request, inst *installation) {
	m, ok := o.object(req.payload, []string{"status"}, []string{"status"})
	if status, isText := text(m["status"]); !ok || !isText || status != "unpaired" {
		o.fail(w, "malformed")
		return
	}
	if o.cfg.Faults.Has(UnpairIgnored) {
		o.reply(w, http.StatusOK, o.instJSON(inst), nil)
		return
	}
	inst.status = "unpaired"
	inst.own = nil
	for _, s := range inst.serials {
		o.denylist = append(o.denylist, hex.EncodeToString(s.Bytes()))
	}
	o.unpublish(inst)
	o.reply(w, http.StatusOK, o.instJSON(inst), nil)
}

func (o *Operator) keyChange(w http.ResponseWriter, req *request) {
	m, ok := o.object(req.payload, []string{"jws"}, []string{"jws"})
	inner, isText := text(m["jws"])
	if !ok || !isText {
		o.fail(w, "malformed")
		return
	}
	head, payload, err := jws.ParseKeyChange(inner)
	if err != nil {
		o.fail(w, "malformed")
		return
	}
	if _, _, err := jws.VerifyKeyChange(inner); err != nil {
		o.fail(w, "bad-signature")
		return
	}
	inst := req.inst
	var body struct {
		Installation string          `json:"installation"`
		OldKey       json.RawMessage `json:"old_key"`
	}
	if json.Unmarshal(payload, &body) != nil || head.URL != req.url || body.Installation != req.header.Kid {
		o.fail(w, "malformed")
		return
	}
	if oldKey, err := jws.ParseJWK(body.OldKey); err != nil || !sameKey(oldKey, inst.key) {
		o.fail(w, "malformed")
		return
	}
	if o.keyTaken(inst, head.JWK) {
		o.fail(w, "key-conflict")
		return
	}
	inst.key = head.JWK
	o.reply(w, http.StatusOK, o.instJSON(inst), nil)
}

// keyTaken reports whether key is the key of another installation or of a tunnel certificate
// of this one.
func (o *Operator) keyTaken(inst *installation, key crypto.PublicKey) bool {
	if !o.cfg.Faults.Has(KeyChangeToForeignKey) {
		for _, other := range o.insts {
			if other != inst && sameKey(other.key, key) {
				return true
			}
		}
	}
	return slices.ContainsFunc(inst.tunnelKeys, func(k crypto.PublicKey) bool { return sameKey(k, key) })
}
