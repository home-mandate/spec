// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Process is an implementation started as a child process that speaks the process
// binding on its standard input and output.
type Process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
}

// StartProcess starts argv. The process is killed when ctx ends.
func StartProcess(ctx context.Context, argv []string) (*Process, error) {
	if len(argv) == 0 {
		return nil, errors.New("conformance: no command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("conformance: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("conformance: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("conformance: start %s: %w", argv[0], err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	return &Process{cmd: cmd, stdin: stdin, stdout: scanner}, nil
}

// Do writes one request and reads one response.
func (p *Process) Do(req Request) (Response, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("conformance: %w", err)
	}
	if _, err := p.stdin.Write(append(line, '\n')); err != nil {
		return Response{}, fmt.Errorf("conformance: write request: %w", err)
	}
	if !p.stdout.Scan() {
		if err := p.stdout.Err(); err != nil {
			return Response{}, fmt.Errorf("conformance: read response: %w", err)
		}
		return Response{}, errors.New("conformance: the implementation closed its output")
	}
	var resp Response
	if err := json.Unmarshal(p.stdout.Bytes(), &resp); err != nil {
		return Response{}, fmt.Errorf("conformance: response is not JSON: %w", err)
	}
	return resp, nil
}

// Close ends the process by closing its input and waits for it.
func (p *Process) Close() error {
	_ = p.stdin.Close()
	return p.cmd.Wait()
}
