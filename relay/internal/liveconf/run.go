// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"time"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/netguard"
)

// Exit codes of relay-conformance (RELAY-v0 section 8.3). A failed clean-up (4) takes
// precedence over every other result.
const (
	ExitConforms    = 0
	ExitFails       = 1
	ExitUsage       = 2
	ExitIncomplete  = 3
	ExitCleanup     = 4
	notImplemented  = "not implemented in this version of the tool"
	notSelected     = "not selected"
	stateNameBytes  = 4
	dateLayout      = "2006-01-02"
	internalFailure = "internal error, the run was aborted"
)

// Env is what tests change and the command does not: the filter of the addresses, the
// roots that verify servers, the time values and the unpairing. The command uses
// productionEnv through Execute only; a test of the command checks that it builds nothing else.
type Env struct {
	Net    netguard.Options
	Roots  *x509.CertPool
	Timing Timing
	// NS looks up the name servers of a zone apex; nil means the system's resolver.
	NS func(ctx context.Context, name string) ([]string, error)
	// Prompt receives what the tool asks of the tester (-dns-manual); nil means standard error.
	Prompt io.Writer
	// Unpair unpairs one test installation.
	Unpair Unpairer
}

// Unpairer unpairs a test installation with the keys of the run; enrollment is the URL of the
// enrollment directory the installation URL has to be on.
type Unpairer func(ctx context.Context, w *Web, enrollment string, inst StateInstallation, keys []StateKey) error

// productionEnv is the setting of the command: the address filter without exceptions, the
// system's roots, the real time values.
func productionEnv() Env {
	return Env{Timing: DefaultTiming, Unpair: unpairInstallation}
}

// Result is the outcome of a run or a clean-up.
type Result struct {
	Report Report
	// Exit is the exit code of the command.
	Exit int
	// Message is a line for the error output; empty if there is nothing to say.
	Message string
}

// Execute runs the live test as the command does.
func Execute(ctx context.Context, s Settings) Result {
	return RunWith(ctx, s, productionEnv())
}

// ExecuteCleanup unpairs what the state file at s.CleanupPath lists, as the command does.
func ExecuteCleanup(ctx context.Context, s Settings) Result {
	return CleanupWith(ctx, s, productionEnv())
}

// classRunner plays the checks of one class.
type classRunner func(ctx context.Context, r *run) error

// incompleteError says that a class could not be run, for a reason that is no failure of the
// operator: it cannot be reached, it limits the rate.
type incompleteError struct{ reason string }

func (e *incompleteError) Error() string { return e.reason }

func incompleteFor(err error) error {
	if errors.Is(err, errRateLimited) {
		return &incompleteError{"the operator limits the rate of requests"}
	}
	return &incompleteError{"the operator cannot be reached (" + classify(err).kind + ")"}
}

// run is the state of one run.
type run struct {
	s       Settings
	env     Env
	web     *Web
	rep     Report
	runners map[string]classRunner

	state         *StateFile
	statePath     string
	enrollURL     string
	meta          *metadataDoc
	scr           scriptState
	usage         bool
	cleanupFailed bool
	message       string
}

func newRun(s Settings, env Env) *run {
	manifest := sha256.Sum256(must(fs.ReadFile(relay.FS(), relay.ManifestPath)))
	r := &run{
		s: s, env: env, web: newWeb(env),
		runners: map[string]classRunner{ClassMetadata: runMetadata, ClassEnrollment: runEnrollment, ClassDNS: runDNS, ClassRelay: runRelay},
		rep: Report{
			Spec: SpecName, Version: s.Version, Manifest: hex.EncodeToString(manifest[:]), Operator: s.Operator,
			Date: time.Now().UTC().Format(dateLayout), Classes: map[string]*ClassResult{},
			Failures: []Failure{}, Notes: []string{}, Incomplete: []string{},
		},
	}
	for _, class := range AllClasses {
		r.rep.Classes[class] = &ClassResult{NotRun: true, Reason: notSelected}
	}
	return r
}

// RunWith runs the live test with the environment env.
func RunWith(ctx context.Context, s Settings, env Env) Result {
	return runWith(ctx, s, env, nil)
}

// runWith is RunWith with a hook that changes the run before it starts; tests use it to plug
// in classes that do not exist yet.
func runWith(ctx context.Context, s Settings, env Env, prepare func(*run)) Result {
	s, err := s.Validate()
	if err == nil && s.CleanupPath != "" {
		err = usagef("a run takes no state file to clean up")
	}
	if err != nil {
		return Result{Exit: ExitUsage, Message: err.Error()}
	}
	r := newRun(s, env)
	if prepare != nil {
		prepare(r)
	}
	r.exec(ctx)
	r.cleanup()
	return r.result()
}

// exec plays the classes. A panic is caught here, so that the clean-up still runs.
func (r *run) exec(ctx context.Context) {
	defer func() {
		if recover() != nil {
			r.rep.Incomplete = append(r.rep.Incomplete, internalFailure)
		}
	}()
	if len(r.s.Codes) > 0 {
		if err := r.openState(); err != nil {
			r.usage, r.message = true, err.Error()
			return
		}
	}
	ctx, cancel := context.WithTimeout(ctx, r.s.Timeout)
	defer cancel()
	for _, class := range r.s.Classes {
		if _, ok := r.runners[class]; ok {
			*r.rep.Classes[class] = ClassResult{}
		}
	}
	for _, class := range r.s.Classes {
		c := r.rep.Classes[class]
		fn, ok := r.runners[class]
		if !ok {
			c.Reason = notImplemented
			continue
		}
		if err := fn(ctx, r); err != nil {
			*c = ClassResult{NotRun: true, Reason: clean(err.Error())}
		}
	}
}

// stateKeyAlgs are the algorithms of the throwaway keys of a run: the installation keys of
// the two pairings (EdDSA, ES256), the key of a key change and a key of no installation.
var stateKeyAlgs = []string{enroll.AlgEdDSA, enroll.AlgES256, enroll.AlgEdDSA, enroll.AlgES256}

// openState creates the state file with the throwaway keys, before anything is sent.
func (r *run) openState() error {
	keys := make([]StateKey, len(stateKeyAlgs))
	for i, alg := range stateKeyAlgs {
		der := must(must(enroll.Generate(alg)).PKCS8())
		keys[i] = StateKey{ID: "k" + strconv.Itoa(i+1), Alg: alg, Private: base64.RawURLEncoding.EncodeToString(der)}
	}
	r.statePath = r.s.StatePath
	if r.statePath == "" {
		suffix := make([]byte, stateNameBytes)
		_, _ = rand.Read(suffix)
		r.statePath = "relay-conformance-" + hex.EncodeToString(suffix) + ".state.json"
	}
	f, err := CreateState(r.statePath, newState(r.s.Operator, keys))
	if err != nil {
		return err
	}
	r.state = f
	return nil
}

// cleanup unpairs every installation of the run, after the limit of the run and also after an
// abort, within its own time limit.
func (r *run) cleanup() {
	if r.state == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.env.Timing.Cleanup)
	defer cancel()
	err := cleanupInstallations(ctx, r.state, r.enrollURL, r.web, r.env.Unpair, newOwnRecord(r.s, r.env))
	st := r.state.State()
	r.rep.Installations = Installations{Created: len(st.Installations), Unpaired: len(st.Installations) - st.Pending()}
	if err != nil {
		_ = r.state.Close()
		r.cleanupFailed = true
		r.message = fmt.Sprintf("clean-up failed (%v): run relay-conformance -cleanup %q", err, r.statePath)
	}
}

func (r *run) result() Result {
	rep := r.rep
	failed := len(rep.Failures) > 0 || rep.FailuresOmitted > 0
	for _, class := range AllClasses {
		c := rep.Classes[class]
		c.Conforms = !c.NotRun && c.Cases > 0 && c.Passed == c.Cases
		failed = failed || c.Failed > 0
		if c.NotRun {
			rep.Incomplete = append(rep.Incomplete, fmt.Sprintf("class %s was not run: %s", class, c.Reason))
		}
	}
	if n := len(r.s.Codes); n < MaxCodes {
		rep.Incomplete = append(rep.Incomplete, fmt.Sprintf("conformance needs %d pairing codes, %d given", MaxCodes, n))
	}
	if r.s.OwnDomain == "" {
		rep.Incomplete = append(rep.Incomplete, "conformance needs an own domain")
	}
	rep.Incomplete = cleanTexts(rep.Incomplete)
	rep.Notes = cleanTexts(rep.Notes)
	rep.Conforms = !failed && len(rep.Incomplete) == 0 && !r.cleanupFailed && !r.usage
	exit := ExitConforms
	switch {
	case r.cleanupFailed:
		exit = ExitCleanup
	case r.usage:
		exit = ExitUsage
	case failed:
		exit = ExitFails
	case !rep.Conforms:
		exit = ExitIncomplete
	}
	return Result{Report: rep, Exit: exit, Message: r.message}
}

func cleanTexts(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = clean(s)
	}
	return out
}

// Recording of results.

func (r *run) pass(class string) {
	if !r.selected(class) {
		return
	}
	c := r.rep.Classes[class]
	c.Cases++
	c.Passed++
}

func (r *run) skip(class string) {
	if !r.selected(class) {
		return
	}
	c := r.rep.Classes[class]
	c.Cases++
	c.Skipped++
}

// fail records a failed check. Texts are cleaned here, whatever the caller did.
func (r *run) fail(class, id, got, want string) {
	r.failIn(class, LiveFile, id, got, want)
}

// failIn records a failed check of a file of cases.
func (r *run) failIn(class, file, id, got, want string) {
	if !r.selected(class) {
		return
	}
	c := r.rep.Classes[class]
	c.Cases++
	c.Failed++
	if len(r.rep.Failures) >= maxFailures {
		r.rep.FailuresOmitted++
		return
	}
	r.rep.Failures = append(r.rep.Failures, Failure{Class: class, File: file, ID: id, Got: clean(got), Want: clean(want)})
}

func (r *run) note(text string) {
	r.rep.Notes = append(r.rep.Notes, text)
}

// must returns v and panics on an error that cannot happen: the inputs are the tool's own.
func must[T any](v T, err error) T {
	must0(err)
	return v
}

func must2[A, B any](a A, b B, err error) (A, B) {
	must0(err)
	return a, b
}

func must0(err error) {
	if err != nil {
		panic("liveconf: " + err.Error())
	}
}

func relayFile(name string) ([]byte, error) { return fs.ReadFile(relay.FS(), name) }

// selected reports whether the class is part of the run; the checks of a class that is not are
// not recorded, even if a step that another class needs plays them.
func (r *run) selected(class string) bool { return slices.Contains(r.s.Classes, class) }
