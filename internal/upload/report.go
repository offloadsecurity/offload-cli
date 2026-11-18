package upload

import (
	"fmt"
	"io"
	"strings"
)

// Run builds the plan, uploads it and prints what happened to w (stderr:
// stdout may carry JSON / SARIF). It returns a non-nil error when nothing,
// or not everything, reached the platform.
func Run(w io.Writer, cfg *Config, in Input, t Target, version string) error {
	fmt.Fprintf(w, "\nUploading to %s\n", cfg.BaseURL)
	if t.Repository == "" {
		err := &Error{Msg: "cannot tell which repository these findings belong to: pass --repository https://host/owner/repo (no git remote \"origin\" found)"}
		fmt.Fprintf(w, "  ✗ upload failed: %s\n", err.Msg)
		return err
	}
	fmt.Fprintf(w, "  repository %s", t.Repository)
	if t.Branch != "" {
		fmt.Fprintf(w, "  branch %s", t.Branch)
	}
	if t.CommitSHA != "" {
		fmt.Fprintf(w, "  commit %.12s", t.CommitSHA)
	}
	fmt.Fprintln(w)

	p, err := BuildPlan(in, t.PathPrefix, version)
	if err != nil {
		fmt.Fprintf(w, "  ✗ upload failed: %v\n", err)
		return err
	}
	if len(p.Skipped) > 0 {
		fmt.Fprintf(w, "  not sent (scanner skipped, so nothing is resolved for it): %s\n", strings.Join(p.Skipped, ", "))
	}
	if p.SBOMComponents > 0 {
		fmt.Fprintf(w, "  not sent: %d SBOM component entries (inventory, not findings)\n", p.SBOMComponents)
	}
	if p.Empty() {
		err := &Error{Msg: "nothing to upload: no scanner ran"}
		fmt.Fprintf(w, "  ✗ upload failed: %s\n", err.Msg)
		return err
	}

	res, err := Upload(cfg, p, t)
	if res != nil {
		for _, warn := range res.Warnings {
			fmt.Fprintf(w, "  ! %s\n", redact(warn, cfg.APIKey))
		}
		for _, u := range res.Uploads {
			for _, tool := range u.Tools {
				fmt.Fprintf(w, "  ✓ %-22s %d sent, %d stored: %d new, %d updated, %d reopened, %d resolved\n",
					tool.Tool, tool.ResultsReceived, tool.ResultsIngested, tool.New, tool.Updated, tool.Reopened, tool.Resolved)
				if tool.SkippedReason != "" {
					fmt.Fprintf(w, "    nothing resolved on absence: %s\n", tool.SkippedReason)
				}
			}
			if u.BranchScopeNote != "" {
				fmt.Fprintf(w, "  ! %s\n", u.BranchScopeNote)
			}
			scope := strings.TrimPrefix(u.ScopeKey, "repo-")
			fmt.Fprintf(w, "  upload %s → %s\n", u.UploadID, scope)
		}
	}
	if err != nil {
		fmt.Fprintf(w, "  ✗ upload failed: %s\n", redact(err.Error(), cfg.APIKey))
		return err
	}
	// The endpoint returns no link; point at where the platform shows imports.
	fmt.Fprintf(w, "  View: %s → Code Command Center → SARIF Imports\n", cfg.BaseURL)
	return nil
}
