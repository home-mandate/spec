// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
)

// Exit codes of mandate-conformance.
const (
	ExitConforms = 0
	ExitFails    = 1
	ExitUsage    = 2
)

const usage = `usage:
  mandate-conformance [-report file] [-classes a,b] -exec <command> [arguments]
  mandate-conformance [-report file] -authzen <url> -control <url> [-header "Name: value"]

Process binding (-exec): starts the command and tests the classes evaluator, selection,
signatures, audit and audit-anchored. The exit code is 0 if the implementation conforms to
the classes named with -classes (default: evaluator).
HTTP binding (-authzen, -control): tests the class pdp.
`

type headerFlag struct{ header http.Header }

func (h *headerFlag) String() string { return "" }

func (h *headerFlag) Set(value string) error {
	name, content, ok := strings.Cut(value, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return errors.New(`expected "Name: value"`)
	}
	h.header.Add(strings.TrimSpace(name), strings.TrimSpace(content))
	return nil
}

// Main is mandate-conformance: it runs the cases of fsys against an implementation,
// prints a summary and writes the report.
func Main(ctx context.Context, fsys fs.FS, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mandate-conformance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	exec := flags.Bool("exec", false, "start the remaining arguments as the implementation")
	authzen := flags.String("authzen", "", "base URL of the AuthZEN API")
	control := flags.String("control", "", "URL of the test control resource")
	reportPath := flags.String("report", "", "write the report as JSON to this file")
	classes := flags.String("classes", "", "classes the implementation must conform to")
	timeout := flags.Duration("timeout", 10*time.Minute, "limit for the whole run")
	header := headerFlag{header: http.Header{}}
	flags.Var(&header, "header", "HTTP header for every request")
	if err := flags.Parse(args); err != nil {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	var report Report
	var err error
	required := []string{ClassEvaluator}
	switch {
	case *exec && *authzen == "" && flags.NArg() > 0:
		report, err = runProcess(ctx, fsys, flags.Args())
	case !*exec && *authzen != "" && *control != "" && flags.NArg() == 0:
		required = []string{ClassPDP}
		report, err = RunPDP(ctx, fsys, PDP{AuthZEN: *authzen, Control: *control, Header: header.header})
	default:
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "mandate-conformance:", err)
		return ExitFails
	}
	if *classes != "" {
		required = strings.Split(*classes, ",")
	}
	summarize(stdout, report, required)
	if *reportPath != "" {
		if err := writeReport(*reportPath, report); err != nil {
			fmt.Fprintln(stderr, "mandate-conformance:", err)
			return ExitFails
		}
	}
	if !report.Conforms(required...) {
		return ExitFails
	}
	return ExitConforms
}

func runProcess(ctx context.Context, fsys fs.FS, argv []string) (Report, error) {
	process, err := StartProcess(ctx, argv)
	if err != nil {
		return Report{}, err
	}
	report, err := Run(fsys, process)
	if closeErr := process.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("conformance: the implementation ended with an error: %w", closeErr)
	}
	return report, err
}

func summarize(w io.Writer, report Report, required []string) {
	fmt.Fprintf(w, "implementation: %s %s\nmanifest: %s\n", report.Implementation.Name, report.Implementation.Version, report.Manifest)
	for _, name := range report.ClassNames() {
		c := report.Classes[name]
		verdict := "does not conform"
		if c.Conforms {
			verdict = "conforms"
		}
		fmt.Fprintf(w, "%-15s %4d cases, %4d passed, %3d failed, %3d skipped: %s\n", name, c.Cases, c.Passed, c.Failed, c.Skipped, verdict)
	}
	for _, f := range report.Failures {
		fmt.Fprintf(w, "FAIL %s %s %s\n     got  %s\n     want %s\n", f.Class, f.File, f.ID, f.Got, f.Want)
	}
	fmt.Fprintf(w, "required: %s\n", strings.Join(required, ", "))
}

func writeReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
