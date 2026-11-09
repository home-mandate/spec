// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/home-mandate/spec/internal/ijson"
	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/metadata"
)

const (
	metadataPath   = "/.well-known/home-mandate-relay"
	metadataSchema = "https://home-mandate.org/relay-metadata/v0/metadata.schema.json"
	// maxLocations is how many places of a schema violation a failure names.
	maxLocations = 5
	levelsMember = "protection_levels"
)

// metadataDoc holds the members the checks of the class metadata read.
type metadataDoc struct {
	metadata.Document
	ProtectionLevels []string `json:"protection_levels"`
	ACMECAs          []string `json:"acme_cas"`
	TrustDomain      string   `json:"trust_domain"`
}

// compiledSchema is the schema of the metadata from the embedded files.
var compiledSchema = sync.OnceValue(func() *jsonschema.Schema {
	data := must(relayFile(relay.MetadataSchemaPath))
	doc := must(jsonschema.UnmarshalJSON(bytes.NewReader(data)))
	c := jsonschema.NewCompiler()
	must0(c.AddResource(metadataSchema, doc))
	return must(c.Compile(metadataSchema))
})

// metaRun is the state of one run of the class metadata.
type metaRun struct {
	r   *run
	res fetched
	doc *metadataDoc
}

// runMetadata plays the checks of the class metadata (RELAY-v0 sections 3, 7.1, 7.3). A check
// whose input an earlier check found broken is skipped, so that one defect fails one check.
func runMetadata(ctx context.Context, r *run) error {
	res, err := r.web.get(ctx, "https://"+r.s.Operator+metadataPath, metadata.MaxBytes)
	m := &metaRun{r: r, res: res}
	var nf *netFailure
	if errors.As(err, &nf) && nf.kind == kindCertificate {
		r.fail(ClassMetadata, CheckMetadataFetch, "the certificate is not valid for the operator domain", "a valid certificate")
		m.skipRest(1)
		return nil
	}
	if err != nil {
		return incompleteFor(err)
	}
	ok := m.step(CheckMetadataFetch, true, m.fetch)
	ok = m.step(CheckMetadataSize, ok, m.size)
	ok = m.step(CheckMetadataIJSON, ok, m.ijson)
	m.step(CheckMetadataSchema, ok, m.schema)
	decoded := m.doc != nil
	m.step(CheckMetadataOperator, decoded, m.operatorDomain)
	m.step(CheckMetadataRules, decoded, m.rules)
	m.step(CheckMetadataLevels, decoded, m.levels)
	m.step(CheckMetadataDomains, decoded, m.domains)
	m.step(CheckMetadataAddresses, decoded, m.addresses)
	if m.doc != nil {
		r.enrollURL = m.doc.Enrollment
	}
	return nil
}

// skipRest counts the checks after the first n as skipped.
func (m *metaRun) skipRest(n int) {
	for range checksOf(ClassMetadata)[n:] {
		m.r.skip(ClassMetadata)
	}
}

// step runs fn if its input is sound and records the verdict; it returns whether fn passed.
func (m *metaRun) step(id string, input bool, fn func() (string, string)) bool {
	if !input {
		m.r.skip(ClassMetadata)
		return false
	}
	got, want := fn()
	if got != "" {
		m.r.fail(ClassMetadata, id, got, want)
		return false
	}
	m.r.pass(ClassMetadata)
	return true
}

// A check function returns "" for a pass and, for a failure, what it saw and what it wanted.

func (m *metaRun) fetch() (string, string) {
	const want = "status 200 without a redirect"
	switch s := m.res.Status; {
	case s == 200:
		return "", ""
	case s >= 300 && s < 400:
		return fmt.Sprintf("a redirect (status %d)", s), want
	default:
		return fmt.Sprintf("status %d", s), want
	}
}

func (m *metaRun) size() (string, string) {
	if m.res.Over {
		return fmt.Sprintf("more than %d bytes", metadata.MaxBytes), fmt.Sprintf("at most %d bytes", metadata.MaxBytes)
	}
	return "", ""
}

func (m *metaRun) ijson() (string, string) {
	if err := ijson.Check(m.res.Body); err != nil {
		return err.Error(), "I-JSON (RFC 7493)"
	}
	return "", ""
}

// schema validates the document and decodes it for the checks that follow. A violation that
// concerns only the protection levels is left to their own check.
func (m *metaRun) schema() (string, string) {
	instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(m.res.Body))
	err := compiledSchema().Validate(instance)
	var doc metadataDoc
	if derr := json.Unmarshal(m.res.Body, &doc); derr == nil {
		m.doc = &doc
	}
	var violation *jsonschema.ValidationError
	_ = errors.As(err, &violation)
	failed := err != nil && (violation == nil || violatesOutsideLevels(violation))
	if failed || m.doc == nil {
		return "violations at " + strings.Join(locations(violation), ", "), "a document valid against the schema"
	}
	return "", ""
}

// leaves returns the innermost errors of a validation error.
func leaves(e *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if e == nil {
		return nil
	}
	if len(e.Causes) == 0 {
		return []*jsonschema.ValidationError{e}
	}
	var out []*jsonschema.ValidationError
	for _, c := range e.Causes {
		out = append(out, leaves(c)...)
	}
	return out
}

func violatesOutsideLevels(e *jsonschema.ValidationError) bool {
	for _, leaf := range leaves(e) {
		if len(leaf.InstanceLocation) == 0 || leaf.InstanceLocation[0] != levelsMember {
			return true
		}
	}
	return false
}

// locations names, quoted, the places of the violations in the document.
func locations(e *jsonschema.ValidationError) []string {
	var out []string
	for _, leaf := range leaves(e) {
		place := esc("/" + strings.Join(leaf.InstanceLocation, "/"))
		if !slices.Contains(out, place) {
			out = append(out, place)
		}
	}
	return out[:min(len(out), maxLocations)]
}

func (m *metaRun) operatorDomain() (string, string) {
	if m.doc.OperatorDomain != m.r.s.Operator {
		return "operator_domain " + esc(m.doc.OperatorDomain), "the host " + esc(m.r.s.Operator)
	}
	return "", ""
}

// rules applies the rules beyond the schema. The operator domain is the document's own, which
// metadata.operator-domain has judged already.
func (m *metaRun) rules() (string, string) {
	if err := metadata.Check(m.doc.OperatorDomain, m.res.Body); err != nil {
		return err.Error(), "a document that meets the rules of sections 3 and 6.8"
	}
	return "", ""
}

func (m *metaRun) levels() (string, string) {
	got := slices.Sorted(slices.Values(m.doc.ProtectionLevels))
	if !slices.Equal(got, []string{"own-domain", "standard"}) {
		return "protection_levels " + esc(strings.Join(got, ",")), "standard and own-domain"
	}
	return "", ""
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// domains checks that the name domain is in none of the registered domains of the sites of
// the operator (RELAY-v0 section 7.1).
func (m *metaRun) domains() (string, string) {
	m.r.note("Public Suffix List: golang.org/x/net " + dependencyVersion(debug.ReadBuildInfo()))
	d := m.doc
	name, err := nameRegisteredDomain(d.NameDomain)
	if err != nil {
		return "name_domain " + esc(d.NameDomain) + " has no registered domain", "a registered domain"
	}
	for _, site := range []struct{ member, host string }{
		{"operator_domain", d.OperatorDomain}, {"enrollment", hostOf(d.Enrollment)}, {"portal", hostOf(d.Portal)},
		{"privacy_policy", hostOf(d.PrivacyPolicy)}, {"relay", d.Relay.Host},
	} {
		reg, err := registeredDomain(site.host, d.NameDomain)
		if err != nil || reg == name {
			return fmt.Sprintf("%s %s is in the registered domain of the name domain %s", site.member, esc(site.host), esc(d.NameDomain)),
				"separate registered domains"
		}
	}
	return "", ""
}

// addresses checks that relay_addresses (and the planned ones) are globally reachable
// unicast addresses (RELAY-v0 section 3) and notes a missing address family (section 7.1).
func (m *metaRun) addresses() (string, string) {
	d := m.doc
	all := slices.Clone(d.RelayAddresses)
	if d.RelayAddressesPlanned != nil {
		all = append(all, d.RelayAddressesPlanned.Addresses...)
	}
	families := map[bool]bool{}
	for _, s := range all {
		a, err := netip.ParseAddr(s)
		if err != nil || !m.r.web.policy(a) {
			return "the address " + esc(s), "a globally reachable unicast address"
		}
		families[a.Is4()] = true
	}
	if !families[true] {
		m.r.note("relay_addresses has no IPv4 address (RELAY-v0 section 7.1 asks for both families)")
	}
	if !families[false] {
		m.r.note("relay_addresses has no IPv6 address (RELAY-v0 section 7.1 asks for both families)")
	}
	return "", ""
}

// loadMeta fetches and decodes the metadata for the classes that need it, if no earlier class
// did. A document that is not usable makes the class incomplete: the class metadata judges it.
func (r *run) loadMeta(ctx context.Context) (*metadataDoc, error) {
	if r.meta != nil {
		return r.meta, nil
	}
	res, err := r.web.get(ctx, "https://"+r.s.Operator+metadataPath, metadata.MaxBytes)
	if err != nil {
		return nil, incompleteFor(err)
	}
	var doc metadataDoc
	if res.Status != 200 || res.Over || metadata.Check(r.s.Operator, res.Body) != nil || json.Unmarshal(res.Body, &doc) != nil ||
		doc.OperatorDomain != r.s.Operator || !strings.HasPrefix(doc.Enrollment, "https://") {
		return nil, &incompleteError{"the metadata of the operator is not usable: see the class metadata"}
	}
	r.meta, r.enrollURL = &doc, doc.Enrollment
	return r.meta, nil
}
