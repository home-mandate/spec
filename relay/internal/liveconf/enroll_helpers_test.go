// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refop"
)

// TestHookHelper is the DNS hook of the tests: the test binary, called with
// "-- hookhelper <control URL> set|delete <name> [<value>]". It sets and removes the TXT
// record in the reference DNS through its control endpoint, as a hook does at a DNS provider.
func TestHookHelper(t *testing.T) {
	args := os.Args
	for i, a := range args {
		if a != "--" {
			continue
		}
		args = args[i+1:]
		if len(args) < 4 || args[0] != "hookhelper" {
			return
		}
		q := url.Values{"name": {args[3]}}
		method := http.MethodDelete
		if args[2] == "set" {
			method = http.MethodPost
			q.Set("value", args[4])
		}
		req, _ := http.NewRequest(method, args[1]+"/txt?"+q.Encode(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			os.Exit(3)
		}
		os.Exit(0)
	}
}

const testOwnDomain = "home." + refop.DefaultTesterZone

// hookFor returns the command line of the hook for a reference operator.
func hookFor(t *testing.T, r *refop.Running) string {
	t.Helper()
	base, stop := r.Operator.DNS().Control()
	t.Cleanup(stop)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe + " -test.run=^TestHookHelper$ -- hookhelper " + base
}

func newStatePath(t *testing.T) string { return filepath.Join(t.TempDir(), "state.json") }

// enrollSettings are the settings of a run of the classes enrollment and dns.
func enrollSettings(t *testing.T, r *refop.Running, classes ...string) Settings {
	return Settings{
		Operator: refop.DefaultOperator, Classes: classes, Codes: refop.DefaultCodes,
		OwnDomain: testOwnDomain, DNSHook: hookFor(t, r), StatePath: newStatePath(t), Version: "test",
	}
}
