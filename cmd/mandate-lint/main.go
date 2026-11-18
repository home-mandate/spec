// SPDX-License-Identifier: Apache-2.0

// Command mandate-lint reports the risky patterns of mandates that SPEC-v0 section 12.4 names:
//
//	mandate-lint mandate.json other.json
//	mandate-lint < mandate.json
//	mandate-lint -json mandate.json
//
// It exits with 0 when no mandate has a finding, 1 when one has, and 2 when a mandate cannot be
// read or is not valid. The findings are warnings: they change no verdict of the evaluation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/home-mandate/spec/lint"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// maxInput bounds what is read of one mandate: a mandate is at most 256 KiB (SPEC-v0 section
// 3.1 item 5), and one byte more shows that it is longer.
const maxInput = 256<<10 + 1

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mandate-lint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "write the findings as JSON, one object per mandate and line")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	files := flags.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	status := 0
	for _, name := range files {
		data, err := read(name, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return 2
		}
		findings, err := lint.Mandate(data)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return 2
		}
		if len(findings) > 0 {
			status = 1
		}
		if *asJSON {
			if err := json.NewEncoder(stdout).Encode(struct {
				File     string         `json:"file"`
				Findings []lint.Finding `json:"findings"`
			}{name, findings}); err != nil {
				return 2
			}
			continue
		}
		for _, f := range findings {
			fmt.Fprintf(stdout, "%s: %s\n", name, f)
		}
	}
	return status
}

func read(name string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return io.ReadAll(io.LimitReader(r, maxInput))
}
