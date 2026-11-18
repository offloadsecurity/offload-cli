package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/verdict"
)

// SecretsBinary is the tool this scanner wraps.
const SecretsBinary = "gitleaks"

// criticalSecretRules escalate to critical — leaked cloud/root credentials.
var criticalSecretRules = map[string]bool{
	"aws-access-token": true, "aws-secret-key": true,
	"gcp-service-account": true, "gcp-api-key": true,
	"azure-storage-account-key": true,
	"private-key":               true, "rsa-private-key": true,
	"github-pat": true, "github-fine-grained-pat": true,
	"gitlab-pat": true, "slack-bot-token": true,
}

// gitleaksV8 is one entry of gitleaks v8 JSON report output.
type gitleaksV8 struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"`
	Commit      string  `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
}

// Secrets scans a directory for hardcoded secrets with gitleaks. When
// verdicts is true each finding is classified (see package verdict) from the
// raw value and its source line, in memory, before the value is redacted; the
// raw value is never stored on the finding.
// Command mirrors the platform:
//
//	gitleaks detect --source <dir> --report-format json --report-path <out> --no-git --exit-code 0
func Secrets(ctx context.Context, dir string, verdicts bool) ([]finding.Finding, Result) {
	res := Result{Tool: SecretsBinary}
	if _, ok := available(SecretsBinary); !ok {
		res.Skipped = true
		res.SkipHint = "install gitleaks: https://github.com/gitleaks/gitleaks#installing"
		return nil, res
	}

	// The report holds raw secrets: write it into a private (0700) temp dir
	// with an unpredictable name, never a shared fixed path.
	tmp, err := os.MkdirTemp("", "offload-gitleaks-")
	if err != nil {
		res.Err = err
		return nil, res
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "report.json")
	_, err = run(ctx, 5*time.Minute, SecretsBinary,
		"detect", "--source", dir,
		"--report-format", "json", "--report-path", out,
		"--no-git", "--exit-code", "0")
	if err != nil {
		res.Err = err
		return nil, res
	}

	raw, err := os.ReadFile(out)
	if err != nil || len(raw) == 0 {
		return nil, res // no report written => no secrets
	}
	findings, err := ParseGitleaksReport(dir, raw, verdicts)
	if err != nil {
		res.Err = err
		return nil, res
	}
	res.Count = len(findings)
	return findings, res
}

// ParseGitleaksReport turns a gitleaks v8 JSON report for dir into findings.
// With verdicts, each finding is classified from its raw value and source
// line before the value is redacted; only the redacted snippet and the
// verdict are kept.
func ParseGitleaksReport(dir string, raw []byte, verdicts bool) ([]finding.Finding, error) {
	var entries []gitleaksV8
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}

	var lines map[string]map[int]string
	if verdicts {
		lines = sourceLines(dir, entries)
	}

	findings := make([]finding.Finding, 0, len(entries))
	for _, e := range entries {
		sev := finding.High
		if criticalSecretRules[strings.ToLower(e.RuleID)] {
			sev = finding.Critical
		}
		title := e.Description
		if title == "" {
			title = "Hardcoded secret detected (" + e.RuleID + ")"
		}
		var sv *verdict.Result
		if verdicts {
			in := verdict.Input{
				Secret:   e.Secret,
				Match:    e.Match,
				Line:     lines[e.File][e.StartLine],
				FilePath: relPath(dir, e.File),
				RuleID:   e.RuleID,
			}
			if e.Entropy > 0 {
				ent := e.Entropy
				in.Entropy = &ent
			}
			r := verdict.Classify(in)
			sv = &r
		}
		findings = append(findings, finding.New(finding.Finding{
			Category:          finding.CategorySecret,
			Severity:          sev,
			Title:             title,
			RuleID:            e.RuleID,
			PrimaryIdentifier: e.RuleID,
			File:              relPath(dir, e.File),
			LineStart:         e.StartLine,
			LineEnd:           e.EndLine,
			Snippet:           redact(e.Secret, e.Match),
			Tool:              SecretsBinary,
			SecretVerdict:     sv,
		}))
	}
	return findings, nil
}

// redact reveals only the first/last 3 chars of a secret (mirrors the
// platform's redaction) so the report never carries the live credential.
func redact(secret, fallback string) string {
	s := secret
	if s == "" {
		s = fallback
	}
	if len(s) <= 8 {
		return "***"
	}
	return s[:3] + strings.Repeat("*", 6) + s[len(s)-3:]
}

func relPath(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return p
}
