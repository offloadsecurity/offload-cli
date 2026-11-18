package upload

import (
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/offloadsecurity/offload-cli/internal/finding"
)

// The platform's default limits (SARIF_UPLOAD_MAX_BYTES, SARIF_INGEST_MAX_RESULTS).
// They are only used to decide when to split the upload per tool up front; the
// server's own (configurable) limits are what refuse a body, and its 413 also
// triggers the split.
const (
	defaultMaxBodyBytes = 10 * 1024 * 1024
	defaultMaxResults   = 50000
)

// driverPrefix names each run "offload-cli/<tool>". The platform files a run
// under scanner "sarif:<normalised driver name>", so the CLI's results stay
// apart from a team's own gitleaks / trivy SARIF uploads (a full run of one
// never resolves the other's findings), while the tool stem still lets the
// platform classify secrets.
const driverPrefix = "offload-cli/"

// Batch is one SARIF log to POST, covering one or more tools.
type Batch struct {
	Tools   []string // scanner tools whose runs the log carries
	Results int
	Body    []byte
}

// Plan is what an upload will send.
type Plan struct {
	// Tools that ran (ok or error), each a run in the log, in a stable order.
	Tools []string
	// Skipped tools are not sent at all: no run means the platform resolves
	// nothing on their behalf (a missing tool is never "zero findings").
	Skipped []string
	// Results per tool.
	Counts map[string]int
	// SBOMComponents is the number of SBOM inventory entries left out: the
	// endpoint ingests findings, not a component inventory.
	SBOMComponents int
	whole          Batch
	perTool        []Batch
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
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
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
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

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

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

// tags drive the platform's classification (classify_sarif_result): secret,
// IaC misconfiguration or package vulnerability.
func tags(c finding.Category) []string {
	switch c {
	case finding.CategorySecret:
		return []string{"security", "secret"}
	case finding.CategoryIaC:
		return []string{"security", "iac", "misconfiguration"}
	case finding.CategoryPackageVuln:
		return []string{"security", "vulnerability", "sca", "dependency"}
	}
	return []string{"security"}
}

// repoPath joins the scanned directory's path inside the repository onto a
// finding's (scan-dir relative) file path, so paths match the repository
// root the platform scopes by.
func repoPath(prefix, file string) string {
	if file == "" || prefix == "" || path.IsAbs(file) || strings.HasPrefix(file, "/") {
		return file
	}
	return path.Join(prefix, file)
}

// toResult renders one finding. Only redacted / non-secret fields are sent:
// for a secret finding that is the rule, the file and line, and the rule's
// description; never the snippet (already redacted, but not needed) or any
// free text from the match.
func toResult(f finding.Finding, prefix string) sarifResult {
	ruleID := f.RuleID
	if ruleID == "" {
		ruleID = string(f.Category)
	}
	props := map[string]interface{}{
		"severity":         string(f.Severity),
		"tags":             tags(f.Category),
		"finding_category": string(f.Category),
	}
	if f.Category == finding.CategoryPackageVuln && f.Package != "" {
		props["packageName"] = f.Package
		if f.Version != "" {
			props["packageVersion"] = f.Version
		}
		if f.PURL != "" {
			props["purl"] = f.PURL
		}
		if f.FixVersion != "" {
			props["fixVersion"] = f.FixVersion
		}
	}
	msg := f.Title
	if f.Category != finding.CategorySecret && f.Description != "" {
		msg += ". " + f.Description
	}
	res := sarifResult{
		RuleID:              ruleID,
		Level:               sarifLevel(f.Severity),
		Message:             sarifText{Text: msg},
		PartialFingerprints: map[string]string{"offloadFingerprint": f.Fingerprint},
		Properties:          props,
	}
	file := repoPath(prefix, f.File)
	var loc sarifLocation
	if file != "" {
		var region *sarifRegion
		if f.LineStart > 0 {
			region = &sarifRegion{StartLine: f.LineStart, EndLine: f.LineEnd}
		}
		loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: sarifArtifact{URI: file}, Region: region}
	}
	if f.Resource != "" {
		loc.LogicalLocations = []sarifLogical{{FullyQualifiedName: f.Resource}}
	}
	if loc.PhysicalLocation != nil || loc.LogicalLocations != nil {
		res.Locations = []sarifLocation{loc}
	}
	return res
}

// ruleTitle is the rule's shortDescription, which the platform uses as the
// title of EVERY result of that rule. A package vulnerability's title names
// the package ("CVE-x in openssl") while its rule (the advisory) is shared by
// every affected package, so its rule title is the advisory id alone; the
// package stays in each result's message and packageName property.
func ruleTitle(f finding.Finding, ruleID string) string {
	if f.Category == finding.CategoryPackageVuln {
		return ruleID
	}
	return f.Title
}

func buildRun(tool string, ok bool, fs []finding.Finding, prefix, version string) sarifRun {
	rules := []sarifRule{}
	seen := map[string]bool{}
	results := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		r := toResult(f, prefix)
		if !seen[r.RuleID] {
			seen[r.RuleID] = true
			help := ""
			if len(f.References) > 0 {
				help = f.References[0]
			}
			rules = append(rules, sarifRule{
				ID:               r.RuleID,
				Name:             string(f.Category),
				ShortDescription: sarifText{Text: ruleTitle(f, r.RuleID)},
				HelpURI:          help,
				Properties:       map[string]interface{}{"tags": tags(f.Category)},
			})
		}
		results = append(results, r)
	}
	return sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           driverPrefix + tool,
			InformationURI: "https://github.com/offloadsecurity/offload-cli",
			Version:        version,
			Rules:          rules,
		}},
		Invocations: []sarifInvocation{{ExecutionSuccessful: ok}},
		Results:     results,
	}
}

func encode(runs []sarifRun) ([]byte, error) {
	return json.Marshal(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	})
}

// BuildPlan turns a scan into SARIF: one run per scanner that ran. A tool
// that errored is sent with executionSuccessful=false (the platform then
// resolves nothing for it); a skipped tool is not sent.
func BuildPlan(in Input, prefix, version string) (*Plan, error) {
	status := map[string]string{}
	for _, t := range in.Tools {
		status[t.Name] = t.Status
	}
	byTool := map[string][]finding.Finding{}
	p := &Plan{Counts: map[string]int{}}
	for _, f := range in.Findings {
		if f.Category == finding.CategorySBOM {
			p.SBOMComponents++
			continue
		}
		byTool[f.Tool] = append(byTool[f.Tool], f)
		if _, ok := status[f.Tool]; !ok {
			// Findings from a tool with no recorded status: send them, but
			// never as a complete run.
			status[f.Tool] = StatusError
		}
	}
	names := make([]string, 0, len(status))
	for n := range status {
		names = append(names, n)
	}
	sort.Strings(names)

	var runs []sarifRun
	total := 0
	for _, n := range names {
		st := status[n]
		// syft builds the SBOM grype consumes; it reports no findings of its
		// own (component inventory is counted in SBOMComponents).
		if st == StatusSkipped || (n == "syft" && len(byTool[n]) == 0) {
			if st == StatusSkipped {
				p.Skipped = append(p.Skipped, n)
			}
			continue
		}
		run := buildRun(n, st == StatusOK, byTool[n], prefix, version)
		body, err := encode([]sarifRun{run})
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
		p.Tools = append(p.Tools, n)
		p.Counts[n] = len(run.Results)
		total += len(run.Results)
		p.perTool = append(p.perTool, Batch{Tools: []string{n}, Results: len(run.Results), Body: body})
	}
	if len(runs) > 0 {
		body, err := encode(runs)
		if err != nil {
			return nil, err
		}
		p.whole = Batch{Tools: append([]string(nil), p.Tools...), Results: total, Body: body}
	}
	return p, nil
}

// Empty reports whether nothing would be sent.
func (p *Plan) Empty() bool { return len(p.Tools) == 0 }

// needsSplit reports whether the combined log is over the platform's default
// limits, so it is sent per tool from the start.
func (p *Plan) needsSplit() bool {
	return len(p.whole.Body) > defaultMaxBodyBytes || p.whole.Results > defaultMaxResults
}
