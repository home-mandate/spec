// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/home-mandate/spec/relay/internal/refop"
)

const secretToken = "s3cret-token"

// leftover writes a state file with the given installation URLs, as a killed run leaves it.
func leftover(t *testing.T, urls ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	st := newState(refop.DefaultOperator, []StateKey{{ID: "k1", Alg: "Ed25519", Private: "AAAA"}})
	for _, u := range urls {
		st = st.WithInstallation(StateInstallation{URL: u, Key: "k1"})
	}
	f, err := CreateState(path, st)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close() // a killed process releases its lock
	return path
}

func cleanupSettings(path string) Settings { return Settings{CleanupPath: path} }

type unpairLog struct {
	urls []string
	fail map[string]bool
}

func (l *unpairLog) unpair(_ context.Context, _ *Web, _ string, inst StateInstallation, keys []StateKey) error {
	l.urls = append(l.urls, inst.URL)
	if len(keys) != 1 {
		return errors.New("the keys of the run are missing")
	}
	if l.fail[inst.URL] {
		return errors.New("refused " + inst.URL)
	}
	return nil
}

func TestCleanupAfterAKillUnpairsAndDeletesTheState(t *testing.T) {
	_, env := serve(t, refop.Config{})
	log := &unpairLog{}
	env.Unpair = log.unpair
	path := leftover(t, "https://op.example.net/enroll/installations/"+secretToken+"-1", "https://op.example.net/enroll/installations/"+secretToken+"-2")
	res := CleanupWith(ctx(t), cleanupSettings(path), env)
	if res.Exit != ExitConforms || len(log.urls) != 2 {
		t.Fatalf("exit %d (%s), unpaired %v", res.Exit, res.Message, log.urls)
	}
	for _, p := range []string{path, path + ".lock"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if strings.Contains(res.Message, secretToken) {
		t.Error("an installation URL is in the message")
	}
}

func TestCleanupRetriesOnlyWhatIsLeft(t *testing.T) {
	_, env := serve(t, refop.Config{})
	first := "https://op.example.net/enroll/installations/" + secretToken + "-1"
	second := "https://op.example.net/enroll/installations/" + secretToken + "-2"
	log := &unpairLog{fail: map[string]bool{second: true}}
	env.Unpair = log.unpair
	path := leftover(t, first, second)
	res := CleanupWith(ctx(t), cleanupSettings(path), env)
	if res.Exit != ExitCleanup || !strings.Contains(res.Message, "-cleanup") || !strings.Contains(res.Message, path) || strings.Contains(res.Message, secretToken) {
		t.Fatalf("exit %d, message %q", res.Exit, res.Message)
	}
	f, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); !got.Installations[0].Unpaired || got.Installations[1].Unpaired {
		t.Errorf("state after a partial clean-up: %+v", got)
	}
	_ = f.Close()
	log.fail, log.urls = nil, nil
	if res := CleanupWith(ctx(t), cleanupSettings(path), env); res.Exit != ExitConforms || len(log.urls) != 1 || log.urls[0] != second {
		t.Errorf("second try: exit %d (%s), unpaired %v", res.Exit, res.Message, log.urls)
	}
}

func TestCleanupNeverContactsAForeignHost(t *testing.T) {
	_, env := serve(t, refop.Config{})
	log := &unpairLog{}
	env.Unpair = log.unpair
	for _, u := range []string{
		"https://evil.example/enroll/installations/" + secretToken,
		"https://op.example.net:8443/enroll/installations/" + secretToken,
		"http://op.example.net/enroll/installations/" + secretToken,
		"https://user@op.example.net/" + secretToken,
	} {
		path := leftover(t, u)
		res := CleanupWith(ctx(t), cleanupSettings(path), env)
		if res.Exit != ExitCleanup || strings.Contains(res.Message, secretToken) {
			t.Errorf("%s: exit %d, message %q", u, res.Exit, res.Message)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: the state file was deleted: %v", u, err)
		}
	}
	if len(log.urls) != 0 {
		t.Errorf("unpair was called for %v", log.urls)
	}
}

func TestCleanupWithoutInstallationsJustDeletesTheState(t *testing.T) {
	_, env := serve(t, refop.Config{})
	path := leftover(t)
	if res := CleanupWith(ctx(t), cleanupSettings(path), env); res.Exit != ExitConforms {
		t.Errorf("exit %d: %s", res.Exit, res.Message)
	}
}

func TestCleanupFailures(t *testing.T) {
	good := "https://op.example.net/enroll/installations/" + secretToken
	t.Run("unusable state file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		_ = os.WriteFile(path, []byte("{}"), 0o600)
		if res := CleanupWith(ctx(t), cleanupSettings(path), envWithoutNetwork()); res.Exit != ExitCleanup {
			t.Errorf("exit %d", res.Exit)
		}
	})
	t.Run("state file in use", func(t *testing.T) {
		path := leftover(t, good)
		f, err := OpenState(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if res := CleanupWith(ctx(t), cleanupSettings(path), envWithoutNetwork()); res.Exit != ExitCleanup {
			t.Errorf("exit %d", res.Exit)
		}
	})
	t.Run("operator unreachable", func(t *testing.T) {
		_, env := serve(t, refop.Config{})
		gone := closedPort(t)
		env.Net.Remap = func(string) string { return gone }
		path := leftover(t, good)
		if res := CleanupWith(ctx(t), cleanupSettings(path), env); res.Exit != ExitCleanup || !strings.Contains(res.Message, "cannot be reached") {
			t.Errorf("exit %d, %s", res.Exit, res.Message)
		}
	})
	for name, cfg := range map[string]refop.Config{
		"metadata missing":                  {Handler: http.NotFoundHandler()},
		"metadata too large":                {Faults: refop.MetadataTooLarge},
		"metadata invalid":                  {Document: []byte(`{"operator_domain":"op.example.net","enrollment":"https://op.example.net/e","portal":"https://op.example.net/","privacy_policy":"https://op.example.net/p","name_domain":"op.example.net","relay":{"host":"t.op.example.net"}}`)},
		"metadata not an object":            {Document: []byte(`{"operator_domain":"op.example.net","enrollment":1}`)},
		"metadata levels of the wrong type": {Document: documentWith(t, func(d map[string]any) { d["protection_levels"] = 1 })},
		"metadata for another operator":     {Document: []byte(`{}`)},
	} {
		t.Run(name, func(t *testing.T) {
			_, env := serve(t, cfg)
			log := &unpairLog{}
			env.Unpair = log.unpair
			path := leftover(t, good)
			if res := CleanupWith(ctx(t), cleanupSettings(path), env); res.Exit != ExitCleanup || len(log.urls) != 0 {
				t.Errorf("exit %d, unpaired %v", res.Exit, log.urls)
			}
		})
	}
	t.Run("state cannot be saved", func(t *testing.T) {
		_, env := serve(t, refop.Config{})
		env.Unpair = (&unpairLog{}).unpair
		path := leftover(t, good)
		f, err := OpenState(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path+".tmp", 0o700); err != nil {
			t.Fatal(err)
		}
		err = cleanupInstallations(ctx(t), f, "https://op.example.net/enroll/directory", newWeb(env), env.Unpair, nil)
		if err == nil || !strings.Contains(err.Error(), "1 of 1") {
			t.Errorf("error %v", err)
		}
	})
}
