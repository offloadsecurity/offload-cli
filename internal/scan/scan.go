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
}

// Report is the aggregated outcome.
type Report struct {
	Dir      string
	Findings []finding.Finding
	Tools    []scanners.Result
	Counts   map[finding.Severity]int
}

// Run executes the enabled scanners and returns an aggregated, deduplicated
// report. SBOM+SCA run as a pair (SCA consumes the SBOM); secrets and IaC run
// concurrently alongside.
func Run(ctx context.Context, opts Options) Report {
	rep := Report{Dir: opts.Dir, Counts: map[finding.Severity]int{}}

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
		go func() { defer wg.Done(); fs, r := scanners.Secrets(ctx, opts.Dir); collect(fs, r) }()
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

	rep.Findings = dedupe(findings)
	rep.Tools = tools
	sort.Slice(rep.Tools, func(i, j int) bool { return rep.Tools[i].Tool < rep.Tools[j].Tool })
	for _, f := range rep.Findings {
		rep.Counts[f.Severity]++
	}
	return rep
}

// dedupe merges findings sharing a fingerprint (same real issue found by more
// than one tool), keeping the most severe, and sorts most-severe first.
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
		if f.Severity.Rank() < existing.Severity.Rank() ||
			(existing.FixVersion == "" && f.FixVersion != "") {
			f.Fingerprint = existing.Fingerprint
			byFP[existing.Fingerprint] = f
		}
	}
	out := make([]finding.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, byFP[fp])
	}
	sort.SliceStable(out, func(i, j int) bool {
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
