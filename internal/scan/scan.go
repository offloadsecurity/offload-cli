// Package scan orchestrates the scanner adapters: it runs them (concurrently
// where independent), deduplicates results by fingerprint, and returns an
// aggregated report.
package scan

import (
	"context"
	"os"
	"sort"
	"sync"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scanners"
)

// Scanner keys accepted by --scanners.
const (
	Secrets = "secrets"
	SBOM    = "sbom"
	SCA     = "sca"
	IaC     = "iac"
)

// AllScanners is the default enabled set, in a stable order.
var AllScanners = []string{Secrets, SBOM, SCA, IaC}

// Options controls a scan run.
type Options struct {
	Dir                   string
	Enabled               map[string]bool
	IncludeSBOMComponents bool
	// NoVerdicts disables secret verdicts (raw gitleaks behaviour).
	NoVerdicts bool
}

// Report is the aggregated outcome.
type Report struct {
	Dir      string
	Findings []finding.Finding
	Tools    []scanners.Result
	// Counts tallies counted findings by severity. Findings a secret verdict
	// dismissed are excluded here (they never trip --fail-on) and tallied in
	// Dismissed instead.
	Counts    map[finding.Severity]int
	Dismissed int
	// DismissedHidden is set when dismissed findings were removed from
	// Findings for display (--hide-dismissed). Dismissed still counts them.
	DismissedHidden bool
}

// Run executes the enabled scanners and returns an aggregated, deduplicated
// report. SBOM+SCA run as a pair (SCA consumes the SBOM); secrets and IaC run
// concurrently alongside.
func Run(ctx context.Context, opts Options) Report {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []finding.Finding
		tools    []scanners.Result
	)
	collect := func(fs []finding.Finding, r scanners.Result) {
		mu.Lock()
		defer mu.Unlock()
		findings = append(findings, fs...)
		tools = append(tools, r)
	}

	if opts.Enabled[Secrets] {
		wg.Add(1)
		go func() { defer wg.Done(); fs, r := scanners.Secrets(ctx, opts.Dir, !opts.NoVerdicts); collect(fs, r) }()
	}
	if opts.Enabled[IaC] {
		wg.Add(1)
		go func() { defer wg.Done(); fs, r := scanners.IaC(ctx, opts.Dir); collect(fs, r) }()
	}
	// SBOM → SCA pipeline (sequential, but concurrent with the two above).
	if opts.Enabled[SBOM] || opts.Enabled[SCA] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sbomPath := scanners.DefaultSBOMPath()
			defer os.Remove(sbomPath)

			if opts.Enabled[SBOM] || opts.Enabled[SCA] {
				fs, r := scanners.SBOM(ctx, opts.Dir, sbomPath, opts.IncludeSBOMComponents)
				collect(fs, r)
				if r.Skipped || r.Err != nil {
					// Can't run SCA without an SBOM; report SCA as unavailable.
					if opts.Enabled[SCA] {
						collect(nil, scanners.Result{Tool: scanners.SCABinary, Skipped: r.Skipped,
							SkipHint: sbomDependencyHint(r), Err: dependErr(r)})
					}
					return
				}
			}
			if opts.Enabled[SCA] {
				fs, r := scanners.SCA(ctx, sbomPath)
				collect(fs, r)
			}
		}()
	}
	wg.Wait()

	return NewReport(opts.Dir, findings, tools)
}

// NewReport deduplicates findings and tallies them into a report. Findings
// a secret verdict dismissed are tallied in Dismissed, not Counts.
func NewReport(dir string, findings []finding.Finding, tools []scanners.Result) Report {
	rep := Report{Dir: dir, Counts: map[finding.Severity]int{}}
	rep.Findings = dedupe(findings)
	rep.Tools = tools
	sort.Slice(rep.Tools, func(i, j int) bool { return rep.Tools[i].Tool < rep.Tools[j].Tool })
	for _, f := range rep.Findings {
		if f.Dismissed() {
			rep.Dismissed++
			continue
		}
		rep.Counts[f.Severity]++
	}
	return rep
}

// Total is the number of findings found, counted and dismissed, including
// any hidden from display.
func (r Report) Total() int {
	n := r.Dismissed
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// HideDismissed removes dismissed findings from Findings for display. The
// Dismissed tally is kept, so the summary still discloses them.
func (r *Report) HideDismissed() {
	kept := r.Findings[:0:0]
	for _, f := range r.Findings {
		if !f.Dismissed() {
			kept = append(kept, f)
		}
	}
	r.Findings = kept
	r.DismissedHidden = true
}

// dedupe merges findings sharing a fingerprint (same real issue found by more
// than one tool), keeping the most severe, and sorts most-severe first, with
// findings a secret verdict dismissed listed after all counted ones.
func dedupe(in []finding.Finding) []finding.Finding {
	byFP := map[string]finding.Finding{}
	order := []string{}
	for _, f := range in {
		existing, ok := byFP[f.Fingerprint]
		if !ok {
			byFP[f.Fingerprint] = f
			order = append(order, f.Fingerprint)
			continue
		}
		// keep the more severe; prefer one that carries a fix
		replace := f.Severity.Rank() < existing.Severity.Rank() ||
			(existing.FixVersion == "" && f.FixVersion != "")
		// never let a dismissed secret stand in for an actionable one
		if existing.Dismissed() != f.Dismissed() {
			replace = !f.Dismissed()
		}
		if replace {
			f.Fingerprint = existing.Fingerprint
			byFP[existing.Fingerprint] = f
		}
	}
	out := make([]finding.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, byFP[fp])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if di, dj := out[i].Dismissed(), out[j].Dismissed(); di != dj {
			return dj
		}
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() < out[j].Severity.Rank()
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// HighestSeverity returns the most severe severity present, or "" if clean.
func (r Report) HighestSeverity() finding.Severity {
	for _, s := range finding.Order {
		if r.Counts[s] > 0 {
			return s
		}
	}
	return ""
}

func sbomDependencyHint(r scanners.Result) string {
	if r.Skipped {
		return "SCA needs an SBOM from syft — " + r.SkipHint
	}
	return ""
}

func dependErr(r scanners.Result) error {
	if r.Err != nil {
		return r.Err
	}
	return nil
}
