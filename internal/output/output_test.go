package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offloadsecurity/offload-cli/internal/scan"
	"github.com/offloadsecurity/offload-cli/internal/scanners"
)

// Raw values that must never reach any output format.
const (
	rawKey   = "Zk9x!q2LmP0vR7sT4wY1AbCd"
	rawToken = "Pz7Lq2Wm9Xv4Bn8Kt3Rj6Hs1Df5Gc0Ae" // not a real key; reported under a provider rule
)

// fixtureReport builds a report the way a scan does: a gitleaks report with
// raw values, parsed (and classified) against files on disk.
func fixtureReport(t *testing.T, verdicts bool) scan.Report {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"config.py": `API_KEY = "` + rawKey + `"` + "\n",
		"pay.py":    `stripe_key = "` + rawToken + `"` + "\n",
		"auth.py":   "password = login_data.password\n",
		"app.py":    `api_key = "<your-api-key>"` + "\n",
		"run.sh":    `mongo --password="${MONGO_PASS}"` + "\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(rule, file, secret, match string) map[string]interface{} {
		return map[string]interface{}{"RuleID": rule, "File": filepath.Join(dir, file), "StartLine": 1, "EndLine": 1,
			"Secret": secret, "Match": match, "Description": "Detected a " + rule}
	}
	raw, _ := json.Marshal([]map[string]interface{}{
		entry("generic-api-key", "config.py", rawKey, `API_KEY = "`+rawKey+`"`),
		entry("stripe-access-token", "pay.py", rawToken, rawToken),
		entry("generic-api-key", "auth.py", "login_data.password", "password = login_data.password"),
		entry("generic-api-key", "app.py", "<your-api-key>", `api_key = "<your-api-key>"`),
		entry("generic-api-key", "run.sh", "${MONGO_PASS}", `password="${MONGO_PASS}"`),
	})
	fs, err := scanners.ParseGitleaksReport(dir, raw, verdicts)
	if err != nil {
		t.Fatal(err)
	}
	return scan.NewReport(dir, fs, []scanners.Result{{Tool: "gitleaks", Count: len(fs)}})
}

func render(t *testing.T, rep scan.Report) map[string]string {
	t.Helper()
	var tb, js, sf bytes.Buffer
	Table(&tb, rep, false)
	if err := JSON(&js, rep, "test"); err != nil {
		t.Fatal(err)
	}
	if err := SARIF(&sf, rep, "test"); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"table": tb.String(), "json": js.String(), "sarif": sf.String()}
}

func TestNoRawSecretInAnyOutputFormat(t *testing.T) {
	for _, verdicts := range []bool{true, false} {
		rep := fixtureReport(t, verdicts)
		for format, out := range render(t, rep) {
			// including the values of findings the verdict dismissed
			for _, raw := range []string{rawKey, rawToken, "<your-api-key>", "${MONGO_PASS}", "login_data.password"} {
				if strings.Contains(out, raw) {
					t.Errorf("verdicts=%v %s output contains a raw secret", verdicts, format)
				}
			}
		}
	}
}

func TestDismissedCountsAndOrdering(t *testing.T) {
	rep := fixtureReport(t, true)
	if rep.Dismissed != 3 || rep.Total() != 5 {
		t.Fatalf("dismissed=%d total=%d, want 3/5", rep.Dismissed, rep.Total())
	}
	// counted findings first, dismissed last
	for i, f := range rep.Findings {
		if f.Dismissed() != (i >= 2) {
			t.Errorf("finding %d (%s) out of order: dismissed=%v", i, f.File, f.Dismissed())
		}
	}
	out := render(t, rep)
	if !strings.Contains(out["table"], "3 dismissed as not secrets") ||
		!strings.Contains(out["table"], "(2 counted)") ||
		!strings.Contains(out["table"], "[likely false positive: placeholder]") ||
		!strings.Contains(out["table"], "[not a secret: runtime value]") {
		t.Errorf("table summary/tags:\n%s", out["table"])
	}

	var js struct {
		Summary  map[string]int `json:"summary"`
		Findings []struct {
			SecretVerdict *struct {
				Verdict    string `json:"verdict"`
				Actionable bool   `json:"actionable"`
				Reason     string `json:"reason"`
			} `json:"secret_verdict"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out["json"]), &js); err != nil {
		t.Fatal(err)
	}
	if js.Summary["dismissed"] != 3 || js.Summary["total"] != 5 || js.Summary["critical"]+js.Summary["high"] != 2 {
		t.Errorf("json summary: %v", js.Summary)
	}
	if len(js.Findings) != 5 || js.Findings[4].SecretVerdict == nil || js.Findings[4].SecretVerdict.Actionable {
		t.Errorf("json findings should carry verdicts: %s", out["json"])
	}

	var sf struct {
		Runs []struct {
			Results []struct {
				Level      string                 `json:"level"`
				Message    struct{ Text string }  `json:"message"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out["sarif"]), &sf); err != nil {
		t.Fatal(err)
	}
	levels := ""
	for _, r := range sf.Runs[0].Results {
		levels += r.Level + " "
		if r.Properties["secretVerdict"] == nil {
			t.Errorf("sarif result missing secretVerdict: %+v", r)
		}
	}
	if levels != "error error note note note " {
		t.Errorf("sarif levels = %q", levels)
	}
}

func TestHideDismissedStillDisclosesCount(t *testing.T) {
	rep := fixtureReport(t, true)
	rep.HideDismissed()
	if len(rep.Findings) != 2 || rep.Dismissed != 3 {
		t.Fatalf("findings=%d dismissed=%d", len(rep.Findings), rep.Dismissed)
	}
	out := render(t, rep)
	if !strings.Contains(out["table"], "3 dismissed as not secrets, hidden") {
		t.Errorf("table must disclose hidden findings:\n%s", out["table"])
	}
	if !strings.Contains(out["json"], `"dismissed_hidden": true`) || !strings.Contains(out["json"], `"dismissed": 3`) {
		t.Errorf("json must disclose hidden findings:\n%s", out["json"])
	}
	if !strings.Contains(out["sarif"], `"dismissedHidden": 3`) {
		t.Errorf("sarif must disclose hidden findings")
	}
}

func TestNoVerdictsIsRawBehaviour(t *testing.T) {
	rep := fixtureReport(t, false)
	if rep.Dismissed != 0 || rep.Counts["high"]+rep.Counts["critical"] != 5 {
		t.Errorf("without verdicts every finding counts: %+v", rep.Counts)
	}
	out := render(t, rep)
	if strings.Contains(out["json"], "secret_verdict") || strings.Contains(out["table"], "dismissed") {
		t.Errorf("no verdict output expected")
	}
}

// Two distinct short secrets from the same rule and file both survive
// dedupe; scanning the same file again yields the same fingerprints; and no
// fingerprint is a plain hash of the raw value.
func TestShortSecretsAreNotCollapsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.env"), []byte("DB_PASS=Ab3kq9\nAPI_PASS=Zx7mw2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]map[string]interface{}{
		{"RuleID": "generic-api-key", "File": filepath.Join(dir, "app.env"), "StartLine": 1, "EndLine": 1, "StartColumn": 1,
			"Secret": "Ab3kq9", "Match": "DB_PASS=Ab3kq9"},
		{"RuleID": "generic-api-key", "File": filepath.Join(dir, "app.env"), "StartLine": 2, "EndLine": 2, "StartColumn": 1,
			"Secret": "Zx7mw2", "Match": "API_PASS=Zx7mw2"},
	})
	scanOnce := func() scan.Report {
		fs, err := scanners.ParseGitleaksReport(dir, raw, true)
		if err != nil {
			t.Fatal(err)
		}
		return scan.NewReport(dir, fs, nil)
	}
	first, second := scanOnce(), scanOnce()
	if len(first.Findings) != 2 || first.Total() != 2 {
		t.Fatalf("two distinct short secrets must stay two findings, got %d", len(first.Findings))
	}
	if first.Findings[0].Fingerprint == first.Findings[1].Fingerprint {
		t.Errorf("distinct secrets share a fingerprint")
	}
	for i := range first.Findings {
		if first.Findings[i].Fingerprint != second.Findings[i].Fingerprint {
			t.Errorf("fingerprint not stable across runs: %s vs %s", first.Findings[i].Fingerprint, second.Findings[i].Fingerprint)
		}
		for _, v := range []string{"Ab3kq9", "Zx7mw2"} {
			sum := sha256.Sum256([]byte(v))
			if strings.HasPrefix(hex.EncodeToString(sum[:]), first.Findings[i].Fingerprint[:12]) {
				t.Errorf("fingerprint looks like a hash of the raw value")
			}
		}
	}
}
