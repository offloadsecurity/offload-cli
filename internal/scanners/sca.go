package scanners

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
)

// SCABinary is the tool this scanner wraps.
const SCABinary = "grype"

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID         string   `json:"id"`
			Severity   string   `json:"severity"`
			DataSource string   `json:"dataSource"`
			URLs       []string `json:"urls"`
			Fix        struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
			CVSS []grypeCVSS `json:"cvss"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			CVSS []grypeCVSS `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

type grypeCVSS struct {
	Version string `json:"version"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

// SCA matches an SBOM against known vulnerabilities with grype. Command mirrors
// the platform:
//
//	grype sbom:<sbomPath> -o json -q
//
// grype exits non-zero when it finds vulnerabilities; that is not an error.
func SCA(ctx context.Context, sbomPath string) ([]finding.Finding, Result) {
	res := Result{Tool: SCABinary}
	if _, ok := available(SCABinary); !ok {
		res.Skipped = true
		res.SkipHint = "install grype: https://github.com/anchore/grype#installation"
		return nil, res
	}

	out, err := run(ctx, 8*time.Minute, SCABinary, "sbom:"+sbomPath, "-o", "json", "-q")
	// grype uses --fail-on to control exit codes; by default a plain run exits 0.
	// Tolerate a non-zero exit only when we still got parseable JSON.
	if err != nil && len(out) == 0 {
		res.Err = err
		return nil, res
	}

	var report grypeReport
	if err := json.Unmarshal(out, &report); err != nil {
		res.Err = err
		return nil, res
	}

	findings := make([]finding.Finding, 0, len(report.Matches))
	for _, m := range report.Matches {
		v := m.Vulnerability
		fix := ""
		if len(v.Fix.Versions) > 0 {
			fix = strings.Join(v.Fix.Versions, ", ")
		}
		refs := v.URLs
		if v.DataSource != "" {
			refs = append([]string{v.DataSource}, refs...)
		}
		cvss := bestCVSS(v.CVSS)
		if cvss == 0 {
			for _, rel := range m.RelatedVulnerabilities {
				if c := bestCVSS(rel.CVSS); c > 0 {
					cvss = c
					break
				}
			}
		}
		manifest := ""
		if len(m.Artifact.Locations) > 0 {
			// grype reports paths rooted at the scan dir with a leading slash;
			// strip it so SARIF/GitHub see a repo-relative path.
			manifest = strings.TrimPrefix(m.Artifact.Locations[0].Path, "/")
		}
		title := v.ID + " in " + m.Artifact.Name
		desc := ""
		if fix != "" {
			desc = "Fixed in " + fix
		} else if v.Fix.State != "" {
			desc = "Fix state: " + v.Fix.State
		}
		findings = append(findings, finding.New(finding.Finding{
			Category:          finding.CategoryPackageVuln,
			Severity:          finding.NormalizeSeverity(v.Severity),
			Title:             title,
			Description:       desc,
			RuleID:            v.ID,
			PrimaryIdentifier: v.ID,
			File:              manifest,
			Package:           m.Artifact.Name,
			Version:           m.Artifact.Version,
			Ecosystem:         m.Artifact.Type,
			PURL:              m.Artifact.PURL,
			FixVersion:        fix,
			CVSS:              cvss,
			References:        refs,
			Tool:              SCABinary,
		}))
	}
	res.Count = len(findings)
	return findings, res
}

// bestCVSS prefers a v3.x base score, falling back to any available score.
func bestCVSS(scores []grypeCVSS) float64 {
	var fallback float64
	for _, s := range scores {
		if strings.HasPrefix(s.Version, "3") && s.Metrics.BaseScore > 0 {
			return s.Metrics.BaseScore
		}
		if s.Metrics.BaseScore > 0 {
			fallback = s.Metrics.BaseScore
		}
	}
	return fallback
}
