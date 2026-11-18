// Package output renders a scan report as a table, JSON, or SARIF.
package output

import (
	"encoding/json"
	"io"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
	"github.com/offloadsecurity/offload-cli/internal/scanners"
)

// jsonReport is the stable JSON envelope. Summary severity counts cover
// counted findings only; "dismissed" counts secret findings a verdict
// dismissed, and "total" is both together. Findings use the unified-finding
// shape so downstream consumers see the same schema the platform emits.
type jsonReport struct {
	Tool     string            `json:"tool"`
	Version  string            `json:"version"`
	Dir      string            `json:"scanned_path"`
	Summary  map[string]int    `json:"summary"`
	Tools    []toolStatus      `json:"scanners"`
	Findings []finding.Finding `json:"findings"`
	// DismissedHidden: dismissed findings were left out of "findings"
	// (--hide-dismissed); summary.dismissed still counts them.
	DismissedHidden bool `json:"dismissed_hidden,omitempty"`
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
		Tool:            "offload-cli",
		Version:         version,
		Dir:             rep.Dir,
		Summary:         map[string]int{},
		Findings:        rep.Findings,
		DismissedHidden: rep.DismissedHidden,
	}
	for _, s := range finding.Order {
		out.Summary[string(s)] = rep.Counts[s]
	}
	out.Summary["dismissed"] = rep.Dismissed
	out.Summary["total"] = rep.Total()
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
