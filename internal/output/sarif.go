package output

import (
	"encoding/json"
	"io"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
)

// SARIF 2.1.0 minimal object graph — enough for GitHub code-scanning upload.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool              `json:"tool"`
	Results    []sarifResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifText              `json:"shortDescription"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"`
	Message             sarifText              `json:"message"`
	Locations           []sarifLocation        `json:"locations,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// sarifLevel maps the canonical severity onto SARIF's level vocabulary
// (mirrors sarif_normalizer._CANONICAL_TO_SARIF).
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.Critical, finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes the report as a SARIF 2.1.0 log.
func SARIF(w io.Writer, rep scan.Report, version string) error {
	rulesSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range rep.Findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = string(f.Category)
		}
		if !rulesSeen[ruleID] {
			rulesSeen[ruleID] = true
			helpURI := ""
			if len(f.References) > 0 {
				helpURI = f.References[0]
			}
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             string(f.Category),
				ShortDescription: sarifText{Text: f.Title},
				HelpURI:          helpURI,
				Properties: map[string]interface{}{
					"category": string(f.Category),
					"tool":     f.Tool,
				},
			})
		}

		res := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title},
			PartialFingerprints: map[string]string{
				"offloadFingerprint": f.Fingerprint,
			},
			Properties: map[string]interface{}{
				"severity": string(f.Severity),
				"tool":     f.Tool,
			},
		}
		if sv := f.SecretVerdict; sv != nil {
			res.Properties["secretVerdict"] = sv
			if t := verdictTag(*sv); t != "" {
				res.Message.Text += " " + t
			}
			if f.Dismissed() {
				// Dismissed: kept as a note so it stays visible in code
				// scanning without failing an error-level check. The
				// scanner's severity stays in properties.severity.
				res.Level = "note"
				res.Properties["dismissed"] = true
			}
		}
		// GitHub code scanning requires every result to carry at least one
		// location. Use the file when we have one; otherwise fall back to the
		// package coordinates so dependency findings (which may not map to a
		// source line) still validate.
		uri := f.File
		if uri == "" {
			if f.Package != "" {
				uri = f.Package
			} else {
				uri = "unknown"
			}
		}
		var region *sarifRegion
		if f.File != "" && f.LineStart > 0 {
			region = &sarifRegion{StartLine: f.LineStart, EndLine: f.LineEnd}
		}
		res.Locations = []sarifLocation{{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: uri},
				Region:           region,
			},
		}}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "offload-cli",
				InformationURI: "https://github.com/offloadsecurity/offload-cli",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	if rep.DismissedHidden && rep.Dismissed > 0 {
		log.Runs[0].Properties = map[string]interface{}{"dismissedHidden": rep.Dismissed}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
