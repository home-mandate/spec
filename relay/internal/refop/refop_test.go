// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/metadata"
)

func TestCleanMetadataIsValid(t *testing.T) {
	o := New(Config{})
	if err := metadata.Check(o.Domain(), o.Metadata()); err != nil {
		t.Fatal(err)
	}
}

func TestEachMetadataFaultChangesTheDocument(t *testing.T) {
	clean := string(New(Config{}).Metadata())
	for name, f := range map[string]Fault{
		"operator domain": MetadataOperatorDomain, "too large": MetadataTooLarge, "duplicate": MetadataDuplicate,
		"unknown": MetadataUnknown, "no level": MetadataNoLevel, "same domain": MetadataSameDomain,
		"private address": MetadataPrivateAddress,
	} {
		o := New(Config{Faults: f})
		if got := string(o.Metadata()); got == clean {
			t.Errorf("%s: document unchanged", name)
		}
		if !f.Has(f) || Fault(0).Has(f) {
			t.Errorf("%s: Has is wrong", name)
		}
	}
	if n := len(New(Config{Faults: MetadataTooLarge}).Metadata()); n <= metadata.MaxBytes {
		t.Errorf("too large document has %d bytes", n)
	}
	if !bytes.Contains(New(Config{Faults: MetadataDuplicate}).Metadata(), []byte(`"max_offline_days":30}`)) {
		t.Error("no duplicate member")
	}
	if !json.Valid(New(Config{Faults: MetadataUnknown}).Metadata()) {
		t.Error("invalid JSON")
	}
}

func TestDocumentOverridesEverything(t *testing.T) {
	o := New(Config{Operator: "x.example", Document: []byte("{}"), Faults: MetadataTooLarge})
	if got := string(o.Metadata()); got != "{}" || o.Domain() != "x.example" {
		t.Errorf("Metadata = %q, Domain = %q", got, o.Domain())
	}
}

func TestHandler(t *testing.T) {
	for _, tt := range []struct {
		fault  Fault
		path   string
		status int
	}{
		{0, MetadataPath, http.StatusOK},
		{MetadataRedirect, MetadataPath, http.StatusFound},
		{0, "/other", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		New(Config{Faults: tt.fault}).Handler().ServeHTTP(rec, httptest.NewRequest("GET", tt.path, nil))
		if rec.Code != tt.status {
			t.Errorf("%v %s: %d, want %d", tt.fault, tt.path, rec.Code, tt.status)
		}
	}
}

func TestHandlerOverride(t *testing.T) {
	rec := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	New(Config{Handler: h}).Handler().ServeHTTP(rec, httptest.NewRequest("GET", MetadataPath, nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("status %d", rec.Code)
	}
}

func TestServeSpeaksTLSForTheOperatorDomain(t *testing.T) {
	r := Serve(Config{})
	defer r.Close()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: r.Roots, ServerName: DefaultOperator},
	}}
	resp, err := client.Get("https://" + r.Addr + MetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if r.Remap("other.example:443") != "other.example:443" || r.Remap("garbage") != "garbage" {
		t.Error("Remap changed a foreign host")
	}
	if got := r.Remap(DefaultOperator + ":443"); got != r.Addr {
		t.Errorf("Remap = %q", got)
	}
}

func TestMustPanicsOnAnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.HasPrefix(r.(string), "refop:") {
			t.Errorf("recover = %v", r)
		}
	}()
	must0(http.ErrServerClosed)
}
