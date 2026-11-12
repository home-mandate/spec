// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/home-mandate/spec/relay/internal/metadata"
)

// cleanupInstallations unpairs every installation of the state file that is not unpaired yet,
// and deletes the state file when none is left. It records each success at once. Only URLs on
// the enrollment host are used. The error says how many remain, never which.
func cleanupInstallations(ctx context.Context, f *StateFile, enrollment string, w *Web, unpair Unpairer, txt *ownRecord) error {
	st := f.State()
	failed := 0
	for i, inst := range st.Installations {
		if inst.Unpaired {
			continue
		}
		if CheckInstallationURL(inst.URL, enrollment) != nil || unpair(ctx, w, enrollment, inst, st.Keys) != nil {
			failed++
			continue
		}
		st = st.WithUnpaired(i)
		if f.Save(st) != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d installations not unpaired", failed, len(st.Installations))
	}
	if st.OwnName != "" {
		if err := txt.remove(ctx, st.OwnName); err != nil {
			return err
		}
	}
	return f.Remove()
}

// ownRecord removes the TXT record of the own-domain name with the DNS hook of the call. The
// state file names the record, not the command: a clean-up needs -dns-hook (or -dns-manual) again.
type ownRecord struct {
	hook dnsHook
	dns  *dnsTools
}

var errNeedHook = errors.New("the state file lists a DNS record: give -dns-hook or -dns-manual again")

func (o *ownRecord) remove(ctx context.Context, ownName string) error {
	if o == nil {
		return errNeedHook
	}
	name := proofLabel + ownName
	if err := o.hook.Delete(ctx, name); err != nil {
		return err
	}
	return o.dns.waitTXT(ctx, name, "")
}

// newOwnRecord returns the remover for the hook of the settings, nil if there is none.
func newOwnRecord(s Settings, env Env) *ownRecord {
	dns := newDNSTools(env)
	switch {
	case s.DNSHook != "":
		return &ownRecord{hook: newExecHook(s.DNSHook, env.Timing.Hook), dns: dns}
	case s.DNSManual:
		return &ownRecord{hook: manualHook{out: env.prompt()}, dns: dns}
	}
	return nil
}

func (e Env) prompt() io.Writer {
	if e.Prompt != nil {
		return e.Prompt
	}
	return os.Stderr
}

// CleanupWith unpairs what the state file at s.CleanupPath lists. It fetches the metadata of
// the operator in the state file again, because the enrollment host that the installation URLs
// have to be on comes from there and from nowhere else.
func CleanupWith(ctx context.Context, s Settings, env Env) Result {
	s, err := s.Validate()
	if err == nil && s.CleanupPath == "" {
		err = usagef("a clean-up needs the path of a state file")
	}
	if err != nil {
		return Result{Exit: ExitUsage, Message: err.Error()}
	}
	fail := func(err error) Result {
		return Result{Exit: ExitCleanup, Message: fmt.Sprintf("clean-up failed (%v): run relay-conformance -cleanup %q", err, s.CleanupPath)}
	}
	f, err := OpenState(s.CleanupPath)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, min(env.Timing.Cleanup, s.Timeout))
	defer cancel()
	w := newWeb(env)
	enrollment, err := fetchEnrollment(ctx, w, f.State().Operator)
	if err == nil {
		err = cleanupInstallations(ctx, f, enrollment, w, env.Unpair, newOwnRecord(s, env))
	}
	if err != nil {
		_ = f.Close()
		return fail(err)
	}
	return Result{Exit: ExitConforms, Message: "clean-up done: the state file is deleted"}
}

// fetchEnrollment fetches the metadata of the operator and returns its enrollment URL.
func fetchEnrollment(ctx context.Context, w *Web, operator string) (string, error) {
	res, err := w.get(ctx, "https://"+operator+metadataPath, metadata.MaxBytes)
	if err != nil {
		return "", incompleteFor(err)
	}
	if res.Status != 200 || res.Over {
		return "", errors.New("the metadata could not be fetched")
	}
	if err := metadata.Check(operator, res.Body); err != nil {
		return "", errors.New("the metadata is invalid")
	}
	var doc metadataDoc
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		return "", errors.New("the metadata is invalid")
	}
	return doc.Enrollment, nil
}
