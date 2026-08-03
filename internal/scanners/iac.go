package scanners

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
)

// IaCBinary is the tool this scanner wraps. We use trivy's config scanner for
// IaC misconfiguration so the CLI needs no Python runtime (unlike checkov),
// keeping the single-binary story intact.
const IaCBinary = "trivy"

type trivyConfigReport struct {
	Results []struct {
		Target            string `json:"Target"`
		Type              string `json:"Type"`
		Misconfigurations []struct {
			ID            string   `json:"ID"`
			AVDID         string   `json:"AVDID"`
			Title         string   `json:"Title"`
			Description   string   `json:"Description"`
			Message       string   `json:"Message"`
			Severity      string   `json:"Severity"`
			Resolution    string   `json:"Resolution"`
			PrimaryURL    string   `json:"PrimaryURL"`
			References    []string `json:"References"`
			CauseMetadata struct {
				Resource  string `json:"Resource"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

// IaC scans a directory for infrastructure-as-code misconfigurations with
// trivy. Command:
//
//	trivy config <dir> --format json --quiet --exit-code 0
func IaC(ctx context.Context, dir string) ([]finding.Finding, Result) {
	res := Result{Tool: IaCBinary}
	if _, ok := available(IaCBinary); !ok {
		res.Skipped = true
		res.SkipHint = "install trivy: https://trivy.dev/latest/getting-started/installation/"
		return nil, res
	}

	out, err := run(ctx, 8*time.Minute, IaCBinary,
		"config", dir, "--format", "json", "--quiet", "--exit-code", "0")
	if err != nil && len(out) == 0 {
		res.Err = err
		return nil, res
	}

	var report trivyConfigReport
	if err := json.Unmarshal(out, &report); err != nil {
		res.Err = err
		return nil, res
	}

	var findings []finding.Finding
	for _, r := range report.Results {
		for _, mc := range r.Misconfigurations {
			id := mc.AVDID
			if id == "" {
				id = mc.ID
			}
			title := mc.Title
			if title == "" {
				title = mc.Message
			}
			desc := mc.Description
			if mc.Resolution != "" {
				desc = strings.TrimSpace(desc + " Resolution: " + mc.Resolution)
			}
			refs := mc.References
			if mc.PrimaryURL != "" {
				refs = append([]string{mc.PrimaryURL}, refs...)
			}
			findings = append(findings, finding.New(finding.Finding{
				Category:          finding.CategoryIaC,
				Severity:          finding.NormalizeSeverity(mc.Severity),
				Title:             title,
				Description:       desc,
				RuleID:            id,
				PrimaryIdentifier: id,
				File:              r.Target,
				LineStart:         mc.CauseMetadata.StartLine,
				LineEnd:           mc.CauseMetadata.EndLine,
				Resource:          mc.CauseMetadata.Resource,
				References:        refs,
				Tool:              IaCBinary,
			}))
		}
	}
	res.Count = len(findings)
	return findings, res
}
