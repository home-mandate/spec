// SPDX-License-Identifier: Apache-2.0

// Package refop is a reference operator of the Relay Specification (RELAY-v0), for tests of
// the live test tool relay-conformance only: the clean reference passes the tool, and each
// deliberately broken variant, switched on by a Fault, fails exactly the check meant to catch
// it. Neither the tool nor the files of package relay import it (a test checks that).
//
// It holds the metadata of the operator (RELAY-v0 section 3), the enrollment endpoint and its
// CA (sections 5 and 6.4), the DNS records of the installations, and, with a reference relay,
// the registry that relay asks (package refrelay).
package refop

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/refdns"
	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// DefaultCodes are the pairing codes of the test account of a reference operator.
var DefaultCodes = []string{"ABCDEFGHIJKLMNOP", "QRSTUVWXYZ234567"}

// Fault switches on one deliberate defect. Faults are constants and combine as a mask.
type Fault uint64

// Defects of the metadata, one for each check of the class metadata.
const (
	// MetadataRedirect answers the request for the metadata with a redirect.
	MetadataRedirect Fault = 1 << iota
	// MetadataOperatorDomain publishes an operator_domain other than the host.
	MetadataOperatorDomain
	// MetadataTooLarge pads the document beyond 16 KiB.
	MetadataTooLarge
	// MetadataDuplicate repeats a member.
	MetadataDuplicate
	// MetadataUnknown adds a member the schema does not list.
	MetadataUnknown
	// MetadataNoLevel leaves out the protection level own-domain.
	MetadataNoLevel
	// MetadataSameDomain puts the name domain in the registered domain of the operator.
	MetadataSameDomain
	// MetadataPrivateAddress adds an address in a private range to relay_addresses.
	MetadataPrivateAddress
)

// Has reports whether f contains the defect.
func (f Fault) Has(defect Fault) bool { return f&defect != 0 }

// Defaults of the reference operator.
const (
	DefaultOperator   = "op.example.net"
	DefaultNameDomain = "homes.example.org"
	// DefaultTesterZone is the zone of the tester in the reference DNS.
	DefaultTesterZone = "tester.example.com"
	// MetadataPath is where the metadata is served (RELAY-v0 section 3).
	MetadataPath = "/.well-known/home-mandate-relay"
	// paddingBytes lifts a document past the limit of 16 KiB.
	paddingBytes = 17 << 10
)

// Config configures a reference operator.
type Config struct {
	// Operator is the operator domain; empty means DefaultOperator.
	Operator string
	// Faults are the defects the operator shows.
	Faults Fault
	// Document, if set, is served as the metadata as it is (hostile content in tests).
	Document []byte
	// Handler, if set, serves every request instead of the operator (limits and errors that
	// an operator can show but the reference does not).
	Handler http.Handler
	// Codes are the pairing codes the test account holds, upper case without hyphens; empty
	// means DefaultCodes.
	Codes []string
	// TesterZone is a zone of the tester, served by the reference DNS, for own-domain names;
	// empty means DefaultTesterZone.
	TesterZone string
	// Wrap, if set, wraps the handler of the operator (tests make requests fail with it).
	Wrap func(http.Handler) http.Handler
	// Relay is a reference relay that serves the operator's tunnel: its pin is published in
	// relay_pins, Serve starts it with the operator as its registry, and Remap sends the
	// connections for relay.host and for relay_addresses to it.
	Relay *refrelay.Relay
	// DNSLag is how long the second name server lags behind with ChallengeBeforeSecondServer;
	// zero means 500 ms.
	DNSLag time.Duration
}

// Operator is a reference operator.
type Operator struct {
	cfg Config
	dns *refdns.DNS
	ca  *issuer

	mu       sync.Mutex
	nonces   map[string]bool
	insts    map[string]*installation
	codes    map[string]*codeUse
	homeIDs  map[string]bool
	denylist []string
}

// New returns a reference operator. Close stops its DNS.
func New(cfg Config) *Operator {
	if cfg.Operator == "" {
		cfg.Operator = DefaultOperator
	}
	if len(cfg.Codes) == 0 {
		cfg.Codes = DefaultCodes
	}
	if cfg.TesterZone == "" {
		cfg.TesterZone = DefaultTesterZone
	}
	if cfg.DNSLag == 0 {
		cfg.DNSLag = 500 * time.Millisecond
	}
	d := must(refdns.New(DefaultNameDomain, cfg.TesterZone))
	o := &Operator{cfg: cfg, dns: d, ca: newIssuer(cfg.Operator), nonces: map[string]bool{},
		insts: map[string]*installation{}, codes: map[string]*codeUse{}, homeIDs: map[string]bool{}}
	o.publishApex()
	return o
}

// Close stops the DNS of the operator.
func (o *Operator) Close() { o.dns.Close() }

// DNS returns the DNS the operator publishes in.
func (o *Operator) DNS() *refdns.DNS { return o.dns }

// Domain returns the operator domain.
func (o *Operator) Domain() string { return o.cfg.Operator }

// Handler serves the metadata.
func (o *Operator) Handler() http.Handler {
	if o.cfg.Handler != nil {
		return o.cfg.Handler
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+MetadataPath, o.serveMetadata)
	o.routeEnrollment(mux)
	if o.cfg.Wrap != nil {
		return o.cfg.Wrap(mux)
	}
	return mux
}

func (o *Operator) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if o.cfg.Faults.Has(MetadataRedirect) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(o.Metadata())
}

// Metadata returns the document an operator with this configuration publishes: the example
// of relay/examples/metadata.json with the domains of the reference operator, and the
// defects of the configuration.
func (o *Operator) Metadata() []byte {
	if o.cfg.Document != nil {
		return o.cfg.Document
	}
	doc := o.document()
	data := must(json.Marshal(doc))
	if o.cfg.Faults.Has(MetadataDuplicate) {
		data = append(bytes.TrimSuffix(data, []byte("}")), []byte(`,"max_offline_days":30}`)...)
	}
	if o.cfg.Faults.Has(MetadataTooLarge) {
		data = append(data, bytes.Repeat([]byte(" "), paddingBytes)...)
	}
	return data
}

// parent returns the domain without its first label.
func parent(domain string) string {
	_, rest, _ := strings.Cut(domain, ".")
	return rest
}

func (o *Operator) document() map[string]any {
	example := must(relayExample())
	var doc map[string]any
	must0(json.Unmarshal(example, &doc))
	op := o.cfg.Operator
	doc["operator_domain"] = op
	doc["name_domain"] = DefaultNameDomain
	doc["trust_domain"] = op
	doc["enrollment"] = "https://" + op + "/enroll/directory"
	doc["relay"] = map[string]any{"host": "tunnel." + op, "port": 8443}
	doc["relay_addresses"] = []string{"127.0.0.1", "::1"}
	doc["portal"] = "https://" + op + "/"
	doc["privacy_policy"] = "https://" + op + "/privacy"
	f := o.cfg.Faults
	if f.Has(MetadataOperatorDomain) {
		doc["operator_domain"] = parent(op)
	}
	if f.Has(MetadataUnknown) {
		doc["extra"] = 1
	}
	if f.Has(MetadataNoLevel) {
		doc["protection_levels"] = []string{"standard"}
	}
	if f.Has(MetadataSameDomain) {
		doc["name_domain"] = "homes." + parent(op)
	}
	if o.cfg.Relay != nil {
		doc["relay_pins"] = o.cfg.Relay.Pins()
	}
	if f.Has(MetadataPrivateAddress) {
		doc["relay_addresses"] = []string{"127.0.0.1", "10.0.0.1"}
	}
	return doc
}

func relayExample() ([]byte, error) {
	return fsReadFile(relay.MetadataExamplePath)
}

// must returns v and panics on an error that cannot happen with the inputs of this package.
func must[T any](v T, err error) T {
	must0(err)
	return v
}

func must0(err error) {
	if err != nil {
		panic("refop: " + err.Error())
	}
}
