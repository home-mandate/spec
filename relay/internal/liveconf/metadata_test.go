// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refop"
)

var metadataOnly = Settings{Operator: refop.DefaultOperator, Classes: []string{ClassMetadata}}

// TestReferenceMetadataPasses: the clean reference passes every check of the class.
func TestReferenceMetadataPasses(t *testing.T) {
	_, env := serve(t, refop.Config{})
	res := RunWith(ctx(t), metadataOnly, env)
	c := res.Report.Classes[ClassMetadata]
	want := len(checksOf(ClassMetadata))
	if len(res.Report.Failures) != 0 || !c.Conforms || c.Passed != want || c.Cases != want || c.NotRun {
		t.Fatalf("class %+v, failures %+v", c, res.Report.Failures)
	}
	if res.Report.Conforms || res.Exit != ExitIncomplete {
		t.Errorf("a run of one class is conformant: exit %d", res.Exit)
	}
	var pslNote bool
	for _, n := range res.Report.Notes {
		pslNote = pslNote || strings.HasPrefix(n, "Public Suffix List: golang.org/x/net v")
	}
	if !pslNote {
		t.Errorf("no note on the state of the Public Suffix List: %v", res.Report.Notes)
	}
}

// TestBrokenMetadataFailsExactlyItsCheck: each deliberate defect fails the one check meant to
// catch it, and no other.
func TestBrokenMetadataFailsExactlyItsCheck(t *testing.T) {
	for _, v := range []struct {
		name  string
		fault refop.Fault
		check string
	}{
		{"M1 redirect", refop.MetadataRedirect, CheckMetadataFetch},
		{"M2 operator_domain is not the host", refop.MetadataOperatorDomain, CheckMetadataOperator},
		{"M3 too large", refop.MetadataTooLarge, CheckMetadataSize},
		{"M4 duplicate member", refop.MetadataDuplicate, CheckMetadataIJSON},
		{"M5 unknown member", refop.MetadataUnknown, CheckMetadataSchema},
		{"M6 protection level missing", refop.MetadataNoLevel, CheckMetadataLevels},
		{"M7 same registered domain", refop.MetadataSameDomain, CheckMetadataDomains},
		{"M8 private relay address", refop.MetadataPrivateAddress, CheckMetadataAddresses},
		{"M9 only TLS 1.2", refop.OnlyTLS12, CheckMetadataFetch},
	} {
		t.Run(v.name, func(t *testing.T) {
			_, env := serve(t, refop.Config{Faults: v.fault})
			res := RunWith(ctx(t), metadataOnly, env)
			if got := failureIDs(res); !slices.Equal(got, []string{v.check}) {
				t.Fatalf("failed checks %v, want only %s", got, v.check)
			}
			c := res.Report.Classes[ClassMetadata]
			if c.Conforms || c.Failed != 1 || c.Passed+c.Failed+c.Skipped != c.Cases || res.Exit != ExitFails || res.Report.Conforms {
				t.Errorf("class %+v, exit %d", c, res.Exit)
			}
		})
	}
}

func TestEveryMetadataFaultIsCovered(t *testing.T) {
	// The eight faults of the document and refop.OnlyTLS12 are the variants above; a new fault
	// of the document needs a variant. refop.MetadataPrivateAddress is the last one.
	if refop.MetadataPrivateAddress != 1<<7 {
		t.Error("a metadata fault was added without a variant")
	}
}

func TestSkippedChecksCountAgainstTheClass(t *testing.T) {
	_, env := serve(t, refop.Config{Faults: refop.MetadataRedirect})
	c := RunWith(ctx(t), metadataOnly, env).Report.Classes[ClassMetadata]
	if c.Skipped != len(checksOf(ClassMetadata))-1 || c.Conforms {
		t.Errorf("class %+v", c)
	}
}

func TestUntrustedCertificateFailsTheFetch(t *testing.T) {
	_, env := serve(t, refop.Config{})
	env.Roots = nil
	res := RunWith(ctx(t), metadataOnly, env)
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataFetch}) || res.Exit != ExitFails {
		t.Errorf("failures %v, exit %d", got, res.Exit)
	}
	if c := res.Report.Classes[ClassMetadata]; c.Skipped != len(checksOf(ClassMetadata))-1 {
		t.Errorf("class %+v", c)
	}
}

func TestUnreachableOperatorIsIncompleteNotAFailure(t *testing.T) {
	_, env := serve(t, refop.Config{})
	gone := closedPort(t)
	env.Net.Remap = func(string) string { return gone }
	res := RunWith(ctx(t), metadataOnly, env)
	c := res.Report.Classes[ClassMetadata]
	if !c.NotRun || c.Conforms || len(res.Report.Failures) != 0 || res.Exit != ExitIncomplete ||
		!strings.Contains(c.Reason, "cannot be reached") {
		t.Errorf("class %+v, exit %d", c, res.Exit)
	}
}

func TestRateLimitIsIncomplete(t *testing.T) {
	_, env := serve(t, refop.Config{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Retry-After", "100000")
		rw.WriteHeader(http.StatusTooManyRequests)
	})})
	res := RunWith(ctx(t), metadataOnly, env)
	c := res.Report.Classes[ClassMetadata]
	if !c.NotRun || !strings.Contains(c.Reason, "limits the rate") || res.Exit != ExitIncomplete {
		t.Errorf("class %+v, exit %d", c, res.Exit)
	}
}

func TestAnErrorStatusFailsTheFetch(t *testing.T) {
	_, env := serve(t, refop.Config{Handler: http.NotFoundHandler()})
	res := RunWith(ctx(t), metadataOnly, env)
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataFetch}) || res.Report.Failures[0].Got != "status 404" {
		t.Errorf("failures %+v", res.Report.Failures)
	}
}

// documentWith serves the reference metadata changed by edit.
func documentWith(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(refop.New(refop.Config{}).Metadata(), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func failuresOf(t *testing.T, doc []byte) Result {
	t.Helper()
	_, env := serve(t, refop.Config{Document: doc})
	return RunWith(ctx(t), metadataOnly, env)
}

func TestSchemaFailureNamesTheLocations(t *testing.T) {
	res := failuresOf(t, documentWith(t, func(d map[string]any) {
		d["max_offline_days"] = "thirty"
		d["relay_addresses"] = "127.0.0.1"
	}))
	if got := failureIDs(res); !slices.Contains(got, CheckMetadataSchema) {
		t.Fatalf("failures %v", got)
	}
	for _, f := range res.Report.Failures {
		if f.ID == CheckMetadataSchema && !strings.Contains(f.Got, `"/max_offline_days"`) {
			t.Errorf("got %q", f.Got)
		}
	}
	// Members of the wrong type cannot be decoded, so the checks that need them are skipped.
	if c := res.Report.Classes[ClassMetadata]; c.Skipped == 0 {
		t.Errorf("class %+v", c)
	}
}

func TestSchemaFailureOfAnotherTypeOfMemberIsStillAFailure(t *testing.T) {
	res := failuresOf(t, []byte(`{"type":"https://home-mandate.org/relay-metadata/v0"}`))
	if got := failureIDs(res); !slices.Contains(got, CheckMetadataSchema) {
		t.Errorf("failures %v", got)
	}
	res = failuresOf(t, []byte(`[]`))
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataSchema}) {
		t.Errorf("failures %v", got)
	}
}

func TestUnknownProtectionLevelFailsItsOwnCheck(t *testing.T) {
	res := failuresOf(t, documentWith(t, func(d map[string]any) {
		d["protection_levels"] = []string{"standard", "own-domain", "gold"}
	}))
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataLevels}) {
		t.Errorf("failures %v", got)
	}
}

func TestRulesBeyondTheSchema(t *testing.T) {
	res := failuresOf(t, documentWith(t, func(d map[string]any) {
		d["relay_backup_pins"] = d["relay_pins"]
	}))
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataRules}) {
		t.Errorf("failures %v", got)
	}
}

func TestPlannedAddressesAreChecked(t *testing.T) {
	res := failuresOf(t, documentWith(t, func(d map[string]any) {
		d["relay_addresses_planned"] = map[string]any{"addresses": []string{"192.168.1.1"}, "from": "2030-01-01T00:00:00Z"}
	}))
	if got := failureIDs(res); !slices.Equal(got, []string{CheckMetadataAddresses}) {
		t.Errorf("failures %v", got)
	}
}

func TestMissingAddressFamilyIsOnlyANote(t *testing.T) {
	res := failuresOf(t, documentWith(t, func(d map[string]any) { d["relay_addresses"] = []string{"127.0.0.1"} }))
	if len(res.Report.Failures) != 0 || !slices.ContainsFunc(res.Report.Notes, func(n string) bool { return strings.Contains(n, "no IPv6") }) {
		t.Errorf("failures %v, notes %v", res.Report.Failures, res.Report.Notes)
	}
	res = failuresOf(t, documentWith(t, func(d map[string]any) { d["relay_addresses"] = []string{"::1"} }))
	if len(res.Report.Failures) != 0 || !slices.ContainsFunc(res.Report.Notes, func(n string) bool { return strings.Contains(n, "no IPv4") }) {
		t.Errorf("failures %v, notes %v", res.Report.Failures, res.Report.Notes)
	}
}

func TestDomainsCheckOnBrokenSites(t *testing.T) {
	for name, doc := range map[string]*metadataDoc{
		"no name domain":         {},
		"portal without a host":  docWith(func(d *metadataDoc) { d.Portal = "%" }),
		"portal in name domain":  docWith(func(d *metadataDoc) { d.Portal = "https://homes.example.org/" }),
		"relay in name registry": docWith(func(d *metadataDoc) { d.Relay.Host = "tunnel.example.org" }),
	} {
		m := &metaRun{r: newRun(metadataOnly, Env{Timing: testTiming()}), doc: doc}
		if got, _ := m.domains(); got == "" {
			t.Errorf("%s: domains passed", name)
		}
	}
	m := &metaRun{r: newRun(metadataOnly, Env{Timing: testTiming()}), doc: docWith(func(*metadataDoc) {})}
	if got, want := m.domains(); got != "" {
		t.Errorf("a sound document failed: %s, %s", got, want)
	}
}

func docWith(edit func(*metadataDoc)) *metadataDoc {
	var d metadataDoc
	_ = json.Unmarshal(refop.New(refop.Config{}).Metadata(), &d)
	edit(&d)
	return &d
}

func TestUnparseableAddressFails(t *testing.T) {
	m := &metaRun{r: newRun(metadataOnly, Env{Timing: testTiming()}), doc: docWith(func(d *metadataDoc) { d.RelayAddresses = []string{"nonsense"} })}
	m.r.web.policy = loopbackPolicy
	if got, _ := m.addresses(); got == "" {
		t.Error("addresses passed")
	}
}

func TestHostileMetadataNeverReachesTheOutputRaw(t *testing.T) {
	evil := "evil\n::error::pwned" + string(rune(0x202e)) + "\x1b[31m" + string(rune(0x1F600))
	doc := documentWith(t, func(d map[string]any) {
		d["operator_domain"] = evil
		d["name_domain"] = evil
		d["portal"] = "https://" + evil + "/"
		d["protection_levels"] = []string{evil}
		d["extra "+evil] = evil
	})
	res := failuresOf(t, doc)
	if len(res.Report.Failures) == 0 {
		t.Fatal("hostile document passed")
	}
	var out bytes.Buffer
	Summarize(&out, res.Report)
	if err := res.Report.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, b := range out.Bytes() {
		if b != '\n' && (b < 0x20 || b >= 0x7f) {
			t.Fatalf("output holds byte %#x:\n%s", b, out.String())
		}
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::") {
			t.Errorf("a line starts a workflow command: %s", line)
		}
	}
	if strings.Contains(out.String(), "pwned\n") {
		t.Error("the hostile text broke a line")
	}
}

func TestSchemaIsCompiledFromTheEmbeddedFiles(t *testing.T) {
	if compiledSchema() == nil {
		t.Fatal("no schema")
	}
	defer func() {
		if recover() == nil {
			t.Error("must0 does not panic")
		}
	}()
	must0(http.ErrNotSupported)
}

func TestLeavesOfNothing(t *testing.T) {
	if leaves(nil) != nil || len(locations(nil)) != 0 {
		t.Error("leaves of nil")
	}
}
