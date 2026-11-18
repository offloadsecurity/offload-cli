// Package finding defines the unified finding model shared by every scanner
// adapter and output formatter. It mirrors the Offload platform's canonical
// vocabulary (severity ladder, ranks, categories) so a finding produced by the
// CLI is shaped exactly like one produced by the platform.
package finding

import (
	"strings"

	"github.com/offloadsecurity/offload-cli/internal/verdict"
)

// Severity is the canonical, lowercase severity vocabulary. It matches
// backend/core/scanner_kit.normalize_severity in the platform.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Order is the canonical ordering, most severe first (mirrors SEVERITY_ORDER).
var Order = []Severity{Critical, High, Medium, Low, Info}

// rank mirrors findings_enrichment.SEVERITY_RANKS: critical=0 … info=4.
var rank = map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}

// Rank returns the numeric rank (lower is more severe). Unknown severities
// sort last, alongside info.
func (s Severity) Rank() int {
	if r, ok := rank[s]; ok {
		return r
	}
	return len(Order)
}

// AtLeast reports whether s is at least as severe as threshold (used by the
// --fail-on CI gate).
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() <= threshold.Rank()
}

// NormalizeSeverity maps the many severity spellings scanners emit onto the
// canonical ladder. It is intentionally forgiving (mirrors _SEVERITY_MAP).
func NormalizeSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "defcon1", "9", "10":
		return Critical
	case "high", "error", "important", "severe":
		return High
	case "medium", "moderate", "warning", "warn":
		return Medium
	case "low", "minor", "note", "negligible":
		return Low
	case "info", "informational", "none", "unknown", "":
		return Info
	default:
		return Info
	}
}

// Category is the finding class. It selects the fingerprint discriminators and
// mirrors the platform's CATEGORY_* constants.
type Category string

const (
	CategorySecret      Category = "secret"
	CategoryPackageVuln Category = "package_vuln"
	CategoryIaC         Category = "iac_misconfig"
	CategorySBOM        Category = "sbom_component"
)

// Finding is one deduplicated result. Fields are a superset across scanner
// types; a given finding populates only what applies. JSON tags match the
// platform's unified-finding envelope where practical.
type Finding struct {
	Fingerprint  string   `json:"finding_fingerprint"`
	Category     Category `json:"finding_category"`
	Severity     Severity `json:"severity"`
	SeverityRank int      `json:"severity_rank"`
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`

	// Identity
	RuleID            string `json:"rule_id,omitempty"`            // gitleaks RuleID, checkov/trivy check id, CVE
	PrimaryIdentifier string `json:"primary_identifier,omitempty"` // human-facing id (CVE-…, KSV…, aws-…)

	// Location
	File      string `json:"file,omitempty"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	// ColumnStart is the match's start column (secrets only); part of a
	// secret's fingerprint, see Fingerprint.
	ColumnStart int    `json:"column_start,omitempty"`
	Snippet     string `json:"code_snippet,omitempty"`
	Resource    string `json:"resource,omitempty"` // IaC resource address

	// Software component (SCA / SBOM)
	Package    string  `json:"package_name,omitempty"`
	Version    string  `json:"package_version,omitempty"`
	Ecosystem  string  `json:"ecosystem,omitempty"`
	PURL       string  `json:"purl,omitempty"`
	FixVersion string  `json:"fix_version,omitempty"`
	CVSS       float64 `json:"cvss_score,omitempty"`

	References []string `json:"references,omitempty"`

	// Provenance
	Tool string `json:"tool"`

	// SecretVerdict is the heuristic verdict on a secret finding (nil for
	// other categories, or when verdicts are disabled with --no-verdicts).
	SecretVerdict *verdict.Result `json:"secret_verdict,omitempty"`
}

// Dismissed reports whether the secret verdict dismissed this finding
// (a high-confidence not_a_secret / likely_false_positive). Dismissed
// findings stay in the report but do not count toward --fail-on.
func (f Finding) Dismissed() bool {
	return f.SecretVerdict != nil && f.SecretVerdict.Dismissed()
}

// New stamps the severity rank and fingerprint, returning a ready finding.
func New(f Finding) Finding {
	f.Severity = normalizeOrInfo(f.Severity)
	f.SeverityRank = f.Severity.Rank()
	f.Fingerprint = Fingerprint(f)
	return f
}

func normalizeOrInfo(s Severity) Severity {
	if _, ok := rank[s]; ok {
		return s
	}
	return NormalizeSeverity(string(s))
}
