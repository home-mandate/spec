// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
)

// SpecName is the value of the member spec of a report.
const SpecName = "relay-v0"

// LiveFile is the file of a failure that a live check found; the cases of the files of
// relay/conformance are played offline by the tests of the repository.
const LiveFile = "live"

// Report is the machine-readable result of a run. The members spec, manifest, classes and
// failures have the names and the meaning of the report of mandate-conformance (the types
// are not shared, so that the format of that report stays as it is).
type Report struct {
	Spec string `json:"spec"`
	// Version is the version of the tool.
	Version string `json:"version"`
	// Manifest is the SHA-256 of relay/conformance/manifest.json: it identifies the cases.
	Manifest string `json:"manifest"`
	Operator string `json:"operator"`
	// Date is the day of the run, UTC (RELAY-v0 section 8.1).
	Date    string                  `json:"date"`
	Classes map[string]*ClassResult `json:"classes"`
	// Failures lists at most 200 failures, each text at most 200 characters.
	Failures        []Failure     `json:"failures"`
	FailuresOmitted int           `json:"failures_omitted,omitempty"`
	Installations   Installations `json:"installations"`
	// Notes are hints that do not decide conformance: DNSSEC, IPv6, the Public Suffix List.
	Notes []string `json:"notes"`
	// Incomplete lists why a run cannot be conformant although nothing failed.
	Incomplete []string `json:"incomplete"`
	Conforms   bool     `json:"conforms"`
}

// ClassResult counts the checks of one conformance class. An operator conforms to the class
// if every check passed; a check that was skipped counts against it.
type ClassResult struct {
	Cases    int  `json:"cases"`
	Passed   int  `json:"passed"`
	Failed   int  `json:"failed"`
	Skipped  int  `json:"skipped"`
	Conforms bool `json:"conforms"`
	// NotRun is set for a class that was not selected, that this version of the tool does not
	// implement, or that could not be run; a class that was not run never conforms.
	NotRun bool   `json:"not_run,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Failure is one check that did not yield the expected result.
type Failure struct {
	Class string `json:"class"`
	File  string `json:"file"`
	ID    string `json:"id"`
	Got   string `json:"got"`
	Want  string `json:"want"`
}

// Installations counts the test installations of the run.
type Installations struct {
	Created  int `json:"created"`
	Unpaired int `json:"unpaired"`
}

// Write writes the report as indented JSON.
func (r Report) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Summarize prints a report for people. Every text that came from the operator was cleaned
// when it entered the report, so each line starts with text of the tool.
func Summarize(w io.Writer, r Report) {
	fmt.Fprintf(w, "relay-conformance %s: %s, version %s, operator %s, %s\n", SpecName, r.Spec, clean(r.Version), clean(r.Operator), r.Date)
	for _, name := range AllClasses {
		c := r.Classes[name]
		switch {
		case c == nil:
		case c.NotRun:
			fmt.Fprintf(w, "class %s: not run (%s)\n", name, clean(c.Reason))
		default:
			fmt.Fprintf(w, "class %s: %d checks, %d passed, %d failed, %d skipped, conforms: %t\n",
				name, c.Cases, c.Passed, c.Failed, c.Skipped, c.Conforms)
		}
	}
	for _, f := range r.Failures {
		fmt.Fprintf(w, "FAIL %s %s: got %s, want %s\n", f.Class, f.ID, f.Got, f.Want)
	}
	if r.FailuresOmitted > 0 {
		fmt.Fprintf(w, "%d more failures not shown\n", r.FailuresOmitted)
	}
	for _, s := range r.Incomplete {
		fmt.Fprintf(w, "incomplete: %s\n", s)
	}
	for _, s := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", s)
	}
	fmt.Fprintf(w, "installations: %d created, %d unpaired\n", r.Installations.Created, r.Installations.Unpaired)
	fmt.Fprintf(w, "conforms: %t\n", r.Conforms)
}

// publicSuffixModule is the module that holds the Public Suffix List the tool uses.
const publicSuffixModule = "golang.org/x/net"

// dependencyVersion returns the version of the module with the Public Suffix List in the
// build information of the tool, or "unknown".
func dependencyVersion(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == publicSuffixModule {
			return dep.Version
		}
	}
	return "unknown"
}
