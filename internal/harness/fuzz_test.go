// SPDX-License-Identifier: Apache-2.0

package harness_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mandate-spec/mandate-spec/internal/harness"
)

// FuzzServe: whatever arrives on the test interface, the harness answers every line
// with one line and never panics.
func FuzzServe(f *testing.F) {
	for _, seed := range []string{
		`{"op":"capabilities"}`,
		`{"op":"validate","mandate":"{}"}`,
		`{"op":"evaluate","mandate":"{}","request":{"resource":{"entity_id":"a","category":"light"},"action":"read","time":"2026-10-12T19:00:00+02:00","parameters":{"x":1e99}}}`,
		`{"op":"select","mandates":[{"mandate":"x"}],"subject":{"client_id":"a","principal":"b"},"request":{"time":"x"}}`,
		`{"op":"verify_audit","jsonl":"{}\n{}","keys":{"keys":[]}}`,
		`{"op":"verify_signed","jws":"a.b.c","keys":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}}`,
		`{"op":"succession","stored":"{}","offered":"{}"}`,
		`{"op":"entry_digest","entry":"{\"seq\":1}"}`,
		`nope`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsAny(line, "\n\r") || line == "" {
			return
		}
		var out bytes.Buffer
		if err := harness.Serve(strings.NewReader(line+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(out.String(), "\n"); got != 1 {
			t.Fatalf("%d response lines for one request", got)
		}
	})
}
