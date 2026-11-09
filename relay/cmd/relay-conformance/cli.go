// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/home-mandate/spec/relay/internal/liveconf"
)

const usage = `usage:
  relay-conformance -operator <domain> [-code-file <file>]... [-code <code>]...
                    [-own-domain <name> (-dns-hook <command> | -dns-manual)]
                    [-classes metadata,enrollment,dns,relay] [-report <file>]
                    [-state <file>] [-timeout <duration>]
  relay-conformance -cleanup <state file> [-dns-hook <command> | -dns-manual]
  relay-conformance -list

Pairing codes (at most two) come from -code-file (preferred: one code in the file), -code
or, if neither is given, from the environment variable RELAY_CONFORMANCE_CODES (codes
separated by commas or blanks). An operator conforms only with two codes and an own domain
and with all four classes. -timeout is at most 1h.
Exit codes: 0 conformant, 1 not conformant, 2 wrong call, 3 incomplete, 4 clean-up failed.
`

// maxCodeFileBytes limits what is read from a file with a pairing code.
const maxCodeFileBytes = 1 << 10

// codesEnv is the environment variable with pairing codes.
const codesEnv = "RELAY_CONFORMANCE_CODES"

// executor runs the live test; the command's is liveconf.Execute and liveconf.ExecuteCleanup.
type executor struct {
	run     func(context.Context, liveconf.Settings) liveconf.Result
	cleanup func(context.Context, liveconf.Settings) liveconf.Result
}

// list collects the values of a repeatable flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// run is the command: it returns the exit code.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, ex executor) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "relay-conformance: internal error")
			code = liveconf.ExitIncomplete
		}
	}()
	flags := flag.NewFlagSet("relay-conformance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var codes, codeFiles list
	listChecks := flags.Bool("list", false, "print the checks")
	s := liveconf.Settings{Version: buildVersion(version, debug.ReadBuildInfo)}
	var classes string
	flags.StringVar(&s.Operator, "operator", "", "operator domain")
	flags.Var(&codes, "code", "pairing code (repeatable)")
	flags.Var(&codeFiles, "code-file", "file with a pairing code (repeatable)")
	flags.StringVar(&s.OwnDomain, "own-domain", "", "name in a zone of the tester")
	flags.StringVar(&s.DNSHook, "dns-hook", "", "command that sets and removes the challenge TXT record")
	flags.BoolVar(&s.DNSManual, "dns-manual", false, "set the challenge TXT record by hand")
	flags.StringVar(&s.StatePath, "state", "", "state file")
	flags.StringVar(&s.CleanupPath, "cleanup", "", "state file of a run to clean up")
	flags.StringVar(&classes, "classes", "", "classes to run, separated by commas")
	flags.DurationVar(&s.Timeout, "timeout", 0, "limit of the run, at most 1h")
	reportPath := flags.String("report", "", "write the report as JSON to this file")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return liveconf.ExitUsage
	}
	if *listChecks {
		printChecks(stdout)
		return liveconf.ExitConforms
	}
	if classes != "" {
		s.Classes = strings.Split(classes, ",")
	}
	var err error
	if s.Codes, err = gatherCodes(codes, codeFiles, getenv(codesEnv)); err != nil {
		fmt.Fprintln(stderr, "relay-conformance:", err)
		return liveconf.ExitUsage
	}
	if _, err := s.Validate(); err != nil {
		fmt.Fprintln(stderr, "relay-conformance:", err)
		return liveconf.ExitUsage
	}
	if s.CleanupPath != "" {
		return report(ex.cleanup(ctx, s), "", stdout, stderr)
	}
	return report(ex.run(ctx, s), *reportPath, stdout, stderr)
}

func printChecks(w io.Writer) {
	for _, c := range liveconf.Checks() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.ID, c.Class, c.Section, c.Title)
	}
}

// report prints the result and writes the report file; a failure to write it makes a
// conformant or incomplete result incomplete, and leaves a failed or unclean one as it is.
func report(res liveconf.Result, path string, stdout, stderr io.Writer) int {
	if res.Report.Spec != "" {
		liveconf.Summarize(stdout, res.Report)
	}
	if res.Message != "" {
		out := stderr
		if res.Exit == liveconf.ExitConforms {
			out = stdout
		}
		fmt.Fprintln(out, "relay-conformance:", res.Message)
	}
	if path == "" {
		return res.Exit
	}
	if err := writeReport(path, res.Report); err != nil {
		fmt.Fprintln(stderr, "relay-conformance: the report could not be written:", err)
		return reportFailed(res.Exit)
	}
	return res.Exit
}

func reportFailed(code int) int {
	if code == liveconf.ExitCleanup || code == liveconf.ExitFails {
		return code
	}
	return liveconf.ExitIncomplete
}

func writeReport(path string, r liveconf.Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return errors.Join(r.Write(f), f.Close())
}

// gatherCodes reads the pairing codes: from the files, else from -code, else from the
// environment. The errors never contain a code.
func gatherCodes(codes, files list, env string) ([]string, error) {
	out := slices.Clone(codes)
	for _, name := range files {
		code, err := readCodeFile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, code)
	}
	if len(out) == 0 {
		out = strings.FieldsFunc(env, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	}
	return out, nil
}

func readCodeFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", errors.New("a code file cannot be read")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCodeFileBytes+1))
	if err != nil || len(data) > maxCodeFileBytes {
		return "", errors.New("a code file cannot be read or is too large")
	}
	return strings.TrimSpace(string(data)), nil
}

// buildVersion returns the version of the tool: the one set at build time, else the module
// version of the build, else "devel".
func buildVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
	if ldflags != "" {
		return ldflags
	}
	if info, ok := read(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "devel"
}
