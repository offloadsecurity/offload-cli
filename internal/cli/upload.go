package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/offloadsecurity/offload-cli/internal/upload"
)

// exitUploadFailed: the findings did not (all) reach the platform. A
// --fail-on gate hit (3) takes precedence; see runScan.
const exitUploadFailed = 4

// finalExit applies the exit-code precedence: 3 (--fail-on hit) > 4 (upload
// failed) > 0. The gate is the security verdict, so an upload problem never
// masks it; the upload failure is still printed.
func finalExit(gateHit, uploadFailed bool) int {
	switch {
	case gateHit:
		return exitGateHit
	case uploadFailed:
		return exitUploadFailed
	}
	return exitOK
}

// envLookup is os.Getenv, swapped in tests.
var envLookup upload.Env = os.Getenv

// stderr is where upload progress goes (stdout may carry JSON / SARIF).
var stderr io.Writer = os.Stderr

type uploadFlags struct {
	platformURL, repository, branch, defaultBranch, commit *string
}

func addUploadFlags(fs *flag.FlagSet) uploadFlags {
	return uploadFlags{
		platformURL:   fs.String("platform-url", "", "Offload platform URL (or set OFFLOAD_URL)"),
		repository:    fs.String("repository", "", "repository the findings belong to (default: git remote origin)"),
		branch:        fs.String("branch", "", "branch scanned (default: detected)"),
		defaultBranch: fs.String("default-branch", "", "repository default branch (default: detected)"),
		commit:        fs.String("commit", "", "commit SHA scanned (default: git HEAD)"),
	}
}

func (u uploadFlags) target(dir string) upload.Target {
	return upload.DetectTarget(dir, upload.Target{
		Repository:    *u.repository,
		Branch:        *u.branch,
		DefaultBranch: *u.defaultBranch,
		CommitSHA:     *u.commit,
	}, envLookup)
}

// runUpload: `offload upload <results.json>` sends a JSON report written
// earlier by `offload scan --format json`.
func runUpload(args []string) int {
	fs := newFlagSet("upload")
	uf := addUploadFlags(fs)
	if err := fs.Parse(reorder(args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: offload upload <results.json> [--platform-url URL] [--repository URL] [--branch B]")
		return exitUsage
	}
	cfg, err := upload.NewConfig(*uf.platformURL, envLookup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	in, err := upload.FromJSON(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", fs.Arg(0), err)
		return exitError
	}
	// Detect git from the directory that was scanned when it still exists,
	// so finding paths are joined onto the right repository path.
	dir := "."
	if in.ScannedPath != "" {
		if st, err := os.Stat(in.ScannedPath); err == nil && st.IsDir() {
			dir = in.ScannedPath
		}
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if err := upload.Run(stderr, cfg, in, uf.target(dir), Version); err != nil {
		return exitUploadFailed
	}
	return exitOK
}
