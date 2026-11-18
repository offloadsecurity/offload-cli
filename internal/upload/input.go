// Package upload sends a scan's findings to an Offload Security platform
// instance through its SARIF import endpoint (POST /api/cicd/sarif/upload),
// authenticated by a CI/CD API key.
package upload

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
)

// Tool statuses, as in the JSON report's "scanners" array.
const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusError   = "error"
)

// ToolRun is one scanner's outcome in a scan.
type ToolRun struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Input is what an upload is built from: a live scan report or a JSON report
// written earlier by `offload scan --format json`.
type Input struct {
	ScannedPath string
	Findings    []finding.Finding
	Tools       []ToolRun
}

// FromReport converts a scan report.
func FromReport(rep scan.Report) Input {
	in := Input{ScannedPath: rep.Dir, Findings: rep.Findings}
	for _, t := range rep.Tools {
		st := StatusOK
		switch {
		case t.Skipped:
			st = StatusSkipped
		case t.Err != nil:
			st = StatusError
		}
		in.Tools = append(in.Tools, ToolRun{Name: t.Tool, Status: st})
	}
	return in
}

// jsonReport is the subset of output.JSON's envelope an upload needs.
type jsonReport struct {
	Tool     string            `json:"tool"`
	Dir      string            `json:"scanned_path"`
	Tools    []ToolRun         `json:"scanners"`
	Findings []finding.Finding `json:"findings"`
	// DismissedHidden: written with --hide-dismissed, so findings are missing.
	DismissedHidden bool `json:"dismissed_hidden"`
}

// FromJSON reads a report written by `offload scan --format json`.
func FromJSON(r io.Reader) (Input, error) {
	var rep jsonReport
	dec := json.NewDecoder(r)
	if err := dec.Decode(&rep); err != nil {
		return Input{}, fmt.Errorf("not an offload JSON report: %v", err)
	}
	if rep.Tool != "offload-cli" {
		return Input{}, fmt.Errorf("not an offload JSON report (tool=%q); write one with `offload scan --format json --output results.json`", rep.Tool)
	}
	if rep.DismissedHidden {
		// A full-run upload resolves every finding it does not carry, so a
		// report missing its dismissed findings would resolve them.
		return Input{}, fmt.Errorf("this report was written with --hide-dismissed, so dismissed findings are missing " +
			"and uploading it would resolve them on the platform; write it again without --hide-dismissed")
	}
	for _, t := range rep.Tools {
		switch t.Status {
		case StatusOK, StatusSkipped, StatusError:
		default:
			return Input{}, fmt.Errorf("scanner %q has unknown status %q", t.Name, t.Status)
		}
	}
	return Input{ScannedPath: rep.Dir, Findings: rep.Findings, Tools: rep.Tools}, nil
}
