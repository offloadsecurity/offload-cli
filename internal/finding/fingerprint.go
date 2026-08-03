package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint produces a stable, scanner-independent identity for a finding,
// mirroring backend/services/finding_fingerprint.build_fingerprint: a SHA-256
// over the category plus a small set of identity discriminators, truncated to
// 32 hex chars. It deliberately EXCLUDES the tool name, severity, line numbers,
// and timestamps so the same real issue found by different tools (or re-found
// on a later scan) collapses to one identity.
func Fingerprint(f Finding) string {
	var disc []string
	switch f.Category {
	case CategoryPackageVuln:
		// package-vuln identity = (cve/advisory id, package name)
		disc = []string{f.PrimaryIdentifier, f.Package}
	case CategorySecret:
		// secret/code identity = (rule id, file path, snippet hash)
		disc = []string{f.RuleID, f.File, snippetHash(f.Snippet)}
	case CategoryIaC:
		// iac identity = (check id, file path, resource address)
		disc = []string{f.RuleID, f.File, f.Resource}
	case CategorySBOM:
		// component identity = (package name, version)
		disc = []string{f.Package, f.Version}
	default:
		disc = []string{f.RuleID, f.File, f.PrimaryIdentifier}
	}

	parts := make([]string, 0, len(disc)+1)
	parts = append(parts, string(f.Category))
	for _, d := range disc {
		parts = append(parts, strings.ToLower(strings.TrimSpace(d)))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:32]
}

func snippetHash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
