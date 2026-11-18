package cli

import (
	"testing"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
	"github.com/offloadsecurity/offload-cli/internal/verdict"
)

func secretFinding(file string, sev finding.Severity, v *verdict.Result) finding.Finding {
	return finding.New(finding.Finding{Category: finding.CategorySecret, Severity: sev, RuleID: "generic-api-key",
		File: file, Snippet: file, Tool: "gitleaks", SecretVerdict: v})
}

func TestFailOnExcludesDismissed(t *testing.T) {
	dismissed := verdict.Classify(verdict.Input{Secret: "<your-api-key>", Line: `api_key = "<your-api-key>"`, RuleID: "generic-api-key"})
	real := verdict.Classify(verdict.Input{Secret: "Zk9x!q2LmP0vR7sT4wY1", Line: `api_key = "Zk9x!q2LmP0vR7sT4wY1"`, RuleID: "generic-api-key"})
	if !dismissed.Dismissed() || real.Dismissed() {
		t.Fatalf("fixture verdicts wrong: %+v %+v", dismissed, real)
	}

	cases := []struct {
		name     string
		findings []finding.Finding
		gate     finding.Severity
		hit      bool
	}{
		{"only dismissed criticals", []finding.Finding{secretFinding("a", finding.Critical, &dismissed), secretFinding("b", finding.High, &dismissed)}, finding.Low, false},
		{"real high", []finding.Finding{secretFinding("a", finding.Critical, &dismissed), secretFinding("b", finding.High, &real)}, finding.High, true},
		{"real high below critical gate", []finding.Finding{secretFinding("b", finding.High, &real)}, finding.Critical, false},
		{"no verdicts counts all", []finding.Finding{secretFinding("a", finding.Critical, nil)}, finding.Critical, true},
		{"no gate", []finding.Finding{secretFinding("a", finding.Critical, &real)}, "", false},
	}
	for _, c := range cases {
		rep := scan.NewReport(".", c.findings, nil)
		if _, hit := gateHit(rep, c.gate); hit != c.hit {
			t.Errorf("%s: hit=%v want %v", c.name, hit, c.hit)
		}
	}
}

// A dismissed secret sharing a fingerprint with an actionable one must not
// stand in for it.
func TestDedupeKeepsActionableOverDismissed(t *testing.T) {
	dismissed := verdict.Classify(verdict.Input{Secret: "<your-api-key>", Line: `api_key = "<your-api-key>"`, RuleID: "generic-api-key"})
	real := verdict.Classify(verdict.Input{Secret: "Zk9x!q2LmP0vR7sT4wY1", Line: `api_key = "Zk9x!q2LmP0vR7sT4wY1"`, RuleID: "generic-api-key"})
	rep := scan.NewReport(".", []finding.Finding{
		secretFinding("same", finding.High, &dismissed),
		secretFinding("same", finding.High, &real),
	}, nil)
	if len(rep.Findings) != 1 || rep.Findings[0].Dismissed() || rep.Counts[finding.High] != 1 {
		t.Errorf("dedupe dropped the actionable finding: %+v", rep)
	}
}

func TestReorderKnowsNewBoolFlags(t *testing.T) {
	got := reorder([]string{".", "--no-verdicts", "--hide-dismissed", "--format", "json"})
	want := []string{"--no-verdicts", "--hide-dismissed", "--format", "json", "."}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

// runScan keeps the full report for --upload before --hide-dismissed trims
// the displayed one; hiding must not touch that copy, or a full-run upload
// would resolve the hidden findings on the platform.
func TestHideDismissedLeavesUploadCopyIntact(t *testing.T) {
	dismissed := verdict.Classify(verdict.Input{Secret: "<your-api-key>", Line: `api_key = "<your-api-key>"`, RuleID: "generic-api-key"})
	rep := scan.NewReport(".", []finding.Finding{
		secretFinding("a", finding.High, &dismissed),
		secretFinding("b", finding.High, nil),
	}, nil)
	full := rep
	rep.HideDismissed()
	if len(rep.Findings) != 1 || len(full.Findings) != 2 || !full.Findings[1].Dismissed() && !full.Findings[0].Dismissed() {
		t.Errorf("display=%d upload=%d", len(rep.Findings), len(full.Findings))
	}
}
