package finding

import "testing"

func TestSeverityRankAndAtLeast(t *testing.T) {
	if Critical.Rank() >= High.Rank() {
		t.Fatalf("critical should outrank high")
	}
	if !High.AtLeast(Medium) {
		t.Errorf("high should be >= medium")
	}
	if Low.AtLeast(High) {
		t.Errorf("low should not be >= high")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": Critical, "Error": High, "warning": Medium,
		"negligible": Low, "": Info, "bogus": Info, "Moderate": Medium,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

// Fingerprint must be stable, tool-independent, and severity-independent so the
// same real issue collapses to one identity across tools and rescans.
func TestFingerprintStableAcrossToolAndSeverity(t *testing.T) {
	a := New(Finding{Category: CategoryPackageVuln, PrimaryIdentifier: "CVE-2021-1", Package: "lodash", Severity: High, Tool: "grype"})
	b := New(Finding{Category: CategoryPackageVuln, PrimaryIdentifier: "CVE-2021-1", Package: "lodash", Severity: Critical, Tool: "trivy"})
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint should ignore tool/severity: %s != %s", a.Fingerprint, b.Fingerprint)
	}
	c := New(Finding{Category: CategoryPackageVuln, PrimaryIdentifier: "CVE-2021-2", Package: "lodash", Severity: High})
	if a.Fingerprint == c.Fingerprint {
		t.Errorf("different CVE should differ")
	}
	if len(a.Fingerprint) != 32 {
		t.Errorf("fingerprint should be 32 hex chars, got %d", len(a.Fingerprint))
	}
}

func TestFingerprintCategoriesDiffer(t *testing.T) {
	secret := New(Finding{Category: CategorySecret, RuleID: "aws-access-token", File: "a.py", Snippet: "AKIA..."})
	iac := New(Finding{Category: CategoryIaC, RuleID: "AVD-AWS-0086", File: "main.tf", Resource: "aws_sg.x"})
	if secret.Fingerprint == iac.Fingerprint {
		t.Errorf("distinct categories must not collide")
	}
}

// Two distinct short secrets redact to the same snippet; their position must
// keep them apart, and the fingerprint must never be a hash of the raw value.
func TestSecretFingerprintDisambiguatesByPosition(t *testing.T) {
	base := Finding{Category: CategorySecret, RuleID: "generic-api-key", File: "a.env", Snippet: "***"}
	at := func(line, col int) string {
		f := base
		f.LineStart, f.ColumnStart = line, col
		return New(f).Fingerprint
	}
	cases := []struct {
		name string
		a, b string
		same bool
	}{
		{"different lines", at(1, 5), at(2, 5), false},
		{"same line, different columns", at(1, 5), at(1, 30), false},
		{"same position (rescan)", at(3, 7), at(3, 7), true},
	}
	for _, c := range cases {
		if (c.a == c.b) != c.same {
			t.Errorf("%s: same=%v want %v", c.name, c.a == c.b, c.same)
		}
	}
}
