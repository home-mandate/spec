// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

// ACMECAs are the acme_cas of the reference operator.
var ACMECAs = []string{"letsencrypt.org"}

const maxOwnName = 233

func (o *Operator) reportACME(w http.ResponseWriter, req *request, inst *installation) {
	m, ok := o.object(req.payload, []string{"acme_account", "caa_identity"}, []string{"acme_account", "caa_identity"})
	account, ok1 := text(m["acme_account"])
	caa, ok2 := text(m["caa_identity"])
	if !ok || !ok1 || !ok2 || !urlPattern.MatchString(account) || !domainPattern.MatchString(caa) {
		o.fail(w, "malformed")
		return
	}
	pair := acmePair{account, caa}
	switch {
	case inst.acme != nil && *inst.acme == pair:
		inst.pending = nil
	case !slices.Contains(ACMECAs, caa) && !o.cfg.Faults.Has(CAOutsideList):
		o.fail(w, "malformed")
		return
	case inst.acme == nil && time.Since(inst.pairedAt) <= pairValidity,
		inst.acme != nil && o.cfg.Faults.Has(SecondReportInForce):
		inst.acme = &pair
		o.publishCAA(inst)
	default:
		inst.pending = &pair
		o.fail(w, "confirmation-required")
		return
	}
	o.reply(w, http.StatusOK, o.instJSON(inst), nil)
}

func (o *Operator) challenge(w http.ResponseWriter, req *request, inst *installation) {
	m, ok := o.object(req.payload, []string{"values"}, []string{"values"})
	var values []string
	if !ok || json.Unmarshal(m["values"], &values) != nil || len(values) > 2 || hasDuplicate(values) ||
		slices.ContainsFunc(values, func(v string) bool { return !valuePattern.MatchString(v) }) {
		o.fail(w, "malformed")
		return
	}
	if inst.acme == nil && !o.cfg.Faults.Has(ChallengeBeforeAccount) {
		o.fail(w, "malformed")
		return
	}
	o.publishChallenge(inst, values)
	o.reply(w, http.StatusOK, map[string]any{"values": append([]string{}, values...)}, nil)
}

func hasDuplicate(values []string) bool {
	for i, v := range values {
		if slices.Contains(values[:i], v) {
			return true
		}
	}
	return false
}

// forbidden reports whether an own-domain name may not be registered: the name domain, the
// operator domain, the trust domain, the host of the relay and names below them.
func (o *Operator) forbidden(name string) bool {
	for _, d := range []string{DefaultNameDomain, o.cfg.Operator, "tunnel." + o.cfg.Operator} {
		if name == d || strings.HasSuffix(name, "."+d) {
			return !(o.cfg.Faults.Has(OwnNameUnderOperator) && d == o.cfg.Operator)
		}
	}
	return false
}

func (o *Operator) registerOwnDomain(w http.ResponseWriter, req *request, inst *installation) {
	m, ok := o.object(req.payload, []string{"own_domain"}, []string{"own_domain"})
	if ok && string(m["own_domain"]) == "null" {
		o.endRegistration(inst)
		o.reply(w, http.StatusOK, o.instJSON(inst), nil)
		return
	}
	name, isText := text(m["own_domain"])
	if !ok || !isText || len(name) > maxOwnName || !domainPattern.MatchString(name) || o.forbidden(name) {
		o.fail(w, "malformed")
		return
	}
	if o.held(name, inst) && !o.cfg.Faults.Has(NoNameUnavailable) {
		o.fail(w, "name-unavailable")
		return
	}
	if inst.own == nil || inst.own.name != name {
		o.endRegistration(inst)
		raw := make([]byte, tokenBytes)
		_, _ = rand.Read(raw)
		token := base64.RawURLEncoding.EncodeToString(raw)
		if o.cfg.Faults.Has(DashToken) {
			token = "-" + token[1:]
		}
		if o.cfg.Faults.Has(TokenReused) && inst.endedToken != "" {
			token = inst.endedToken
		}
		inst.own = &ownDomain{name: name, token: token, status: "pending"}
	}
	// A new registration and a repeated one both look the TXT record up (RELAY-v0 section 6.4).
	if found, ok := o.proof(name); (ok && found == inst.own.token || o.cfg.Faults.Has(VerifiedWithoutTXT)) && !o.held(name, inst) {
		inst.own.status = "verified"
	}
	o.reply(w, http.StatusOK, o.instJSON(inst), nil)
}

// endRegistration ends the own-domain registration of the installation; its token is discarded
// (RELAY-v0 section 6.4), and only the defect TokenReused remembers it.
func (o *Operator) endRegistration(inst *installation) {
	if inst.own != nil {
		inst.endedToken = inst.own.token
	}
	inst.own = nil
}
