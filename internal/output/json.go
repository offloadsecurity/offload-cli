// Package output renders a scan report as a table, JSON, or SARIF.
package output

import (
	"encoding/json"
	"io"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
	"github.com/offloadsecurity/offload-cli/internal/scanners"
)

// jsonReport is the stable JSON envelope. Findings use the unified-finding
// shape so downstream consumers see the same schema the platform emits.
type jsonReport struct {
	Tool     string            `json:"tool"`
	Version  string            `json:"version"`
	Dir      string            `json:"scanned_path"`
	Summary  map[string]int    `json:"summary"`
	Tools    []toolStatus      `json:"scanners"`
	Findings []finding.Finding `json:"findings"`
}

type toolStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok | skipped | error
	Count   int    `json:"findings"`
	Message string `json:"message,omitempty"`
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, rep scan.Report, version string) error {
	out := jsonReport{
		Tool:     "offload-cli",
		Version:  version,
		Dir:      rep.Dir,
		Summary:  map[string]int{},
		Findings: rep.Findings,
	}
	for _, s := range finding.Order {
		out.Summary[string(s)] = rep.Counts[s]
	}
	out.Summary["total"] = len(rep.Findings)
	for _, t := range rep.Tools {
		out.Tools = append(out.Tools, toStatus(t))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func toStatus(t scanners.Result) toolStatus {
	st := toolStatus{Name: t.Tool, Count: t.Count, Status: "ok"}
	switch {
	case t.Skipped:
		st.Status = "skipped"
		st.Message = t.SkipHint
	case t.Err != nil:
		st.Status = "error"
		st.Message = t.Err.Error()
	}
	return st
}
