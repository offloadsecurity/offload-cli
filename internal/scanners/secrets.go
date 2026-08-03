package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
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
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	Commit      string `json:"Commit"`
}

// Secrets scans a directory for hardcoded secrets with gitleaks.
// Command mirrors the platform:
//
//	gitleaks detect --source <dir> --report-format json --report-path <out> --no-git --exit-code 0
func Secrets(ctx context.Context, dir string) ([]finding.Finding, Result) {
	res := Result{Tool: SecretsBinary}
	if _, ok := available(SecretsBinary); !ok {
		res.Skipped = true
		res.SkipHint = "install gitleaks: https://github.com/gitleaks/gitleaks#installing"
		return nil, res
	}

	out := filepath.Join(os.TempDir(), "offload-gitleaks.json")
	defer os.Remove(out)
	_, err := run(ctx, 5*time.Minute, SecretsBinary,
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
	var entries []gitleaksV8
	if err := json.Unmarshal(raw, &entries); err != nil {
		res.Err = err
		return nil, res
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
		}))
	}
	res.Count = len(findings)
	return findings, res
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
