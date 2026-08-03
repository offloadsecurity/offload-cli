// Package scanners wraps external security tools (gitleaks, syft, grype, trivy)
// and normalizes their output into the unified finding model. Each scanner is
// optional: if its binary is missing, the scan reports the tool as SKIPPED
// rather than silently producing zero findings.
package scanners

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Result is the outcome of one scanner.
type Result struct {
	Tool     string
	Skipped  bool   // binary not installed
	SkipHint string // how to install it
	Err      error  // the tool ran but failed
	Count    int
}

// available reports whether a binary is on PATH and returns its resolved path.
func available(bin string) (string, bool) {
	p, err := exec.LookPath(bin)
	return p, err == nil
}

// run executes a command with a timeout and returns stdout. A non-zero exit is
// returned as an error together with stderr, EXCEPT callers may choose to
// tolerate specific exit codes (scanners often exit non-zero when they find
// issues) by inspecting the returned *exec.ExitError.
func run(ctx context.Context, timeout time.Duration, bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.Bytes(), fmt.Errorf("%s timed out after %s", bin, timeout)
	}
	if err != nil {
		return stdout.Bytes(), &toolError{bin: bin, err: err, stderr: stderr.String()}
	}
	return stdout.Bytes(), nil
}

type toolError struct {
	bin    string
	err    error
	stderr string
}

func (e *toolError) Error() string {
	msg := fmt.Sprintf("%s failed: %v", e.bin, e.err)
	if e.stderr != "" {
		msg += "\n" + truncate(e.stderr, 500)
	}
	return msg
}

// exitCode returns the process exit code from a toolError, or -1.
func exitCode(err error) int {
	te, ok := err.(*toolError)
	if !ok {
		return -1
	}
	if ee, ok := te.err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
