package upload

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
)

const testKey = "osk_TEST_dGhpcy1pcy1hLXRlc3Qta2V5LW5vdC1yZWFs"

func envOf(m map[string]string) Env { return func(k string) string { return m[k] } }

func sampleInput() Input {
	return Input{
		ScannedPath: ".",
		Findings: []finding.Finding{
			finding.New(finding.Finding{Category: finding.CategorySecret, Severity: finding.Critical,
				Title: "AWS key", RuleID: "aws-access-token", File: "config.py", LineStart: 3,
				Snippet: "AKI******XYZ", Tool: "gitleaks"}),
			finding.New(finding.Finding{Category: finding.CategoryPackageVuln, Severity: finding.High,
				Title: "CVE-2021-1 in lodash", Description: "Fixed in 4.17.21", RuleID: "CVE-2021-1",
				PrimaryIdentifier: "CVE-2021-1", Package: "lodash", Version: "4.17.4",
				PURL: "pkg:npm/lodash@4.17.4", FixVersion: "4.17.21", File: "package-lock.json", Tool: "grype"}),
			finding.New(finding.Finding{Category: finding.CategoryIaC, Severity: finding.Medium,
				Title: "Open SG", RuleID: "AVD-AWS-0107", File: "main.tf", LineStart: 6,
				Resource: "aws_security_group.web", Tool: "trivy"}),
			finding.New(finding.Finding{Category: finding.CategorySBOM, Severity: finding.Info,
				Title: "lodash 4.17.4", Package: "lodash", Version: "4.17.4", Tool: "syft"}),
		},
		Tools: []ToolRun{{"gitleaks", StatusOK}, {"grype", StatusOK}, {"syft", StatusOK}, {"trivy", StatusOK}},
	}
}

func okBody(tools ...string) string {
	var ts []map[string]interface{}
	for _, t := range tools {
		ts = append(ts, map[string]interface{}{"tool": t, "scanner": "sarif:" + t, "results_received": 1,
			"results_ingested": 1, "new": 1, "resolved_on_absence": true})
	}
	b, _ := json.Marshal(map[string]interface{}{"success": true, "message": "SARIF ingested", "data": map[string]interface{}{
		"upload_id": "sarif-abc", "repository": "https://github.com/o/r", "scope_key": "repo-https://github.com/o/r",
		"full_run": true, "results_in_log": 3, "tools": ts}})
	return string(b)
}

func errBody(msg string) string {
	b, _ := json.Marshal(map[string]interface{}{"success": false, "data": nil,
		"error": map[string]interface{}{"code": "HTTP_ERROR", "message": msg}})
	return string(b)
}

type recorded struct {
	path, query, key, ctype string
	body                    []byte
}

// server answers with the scripted (status, body, headers) responses in turn.
func server(t *testing.T, script ...func(w http.ResponseWriter)) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.URL.Path, r.URL.RawQuery, r.Header.Get("X-API-Key"), r.Header.Get("Content-Type"), b})
		n := i
		i++
		mu.Unlock()
		if n >= len(script) {
			n = len(script) - 1
		}
		script[n](w)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func reply(code int, body string, hdr ...string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

func testConfig(t *testing.T, base string) (*Config, *[]time.Duration) {
	t.Helper()
	cfg, err := NewConfig(base, envOf(map[string]string{EnvAPIKey: testKey}))
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	cfg.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return cfg, &sleeps
}

var target = Target{Repository: "https://github.com/o/r", Branch: "main", DefaultBranch: "main", CommitSHA: "0123456789abcdef0123456789abcdef01234567"}

func TestUploadSuccess(t *testing.T) {
	srv, got := server(t, reply(200, okBody("offload-cli/gitleaks", "offload-cli/grype", "offload-cli/trivy")))
	cfg, _ := testConfig(t, srv.URL+"/api/") // trailing /api is tolerated
	var out bytes.Buffer
	if err := Run(&out, cfg, sampleInput(), target, "v0.2.0"); err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	if len(*got) != 1 {
		t.Fatalf("want 1 request, got %d", len(*got))
	}
	r := (*got)[0]
	if r.path != Endpoint || r.key != testKey || r.ctype != "application/sarif+json" {
		t.Fatalf("bad request: %+v", r)
	}
	for _, want := range []string{"repository=https%3A%2F%2Fgithub.com%2Fo%2Fr", "branch=main", "default_branch=main", "full_run=true", "commit_sha=0123456789abcdef"} {
		if !strings.Contains(r.query, want) {
			t.Errorf("query %q lacks %q", r.query, want)
		}
	}
	var log sarifLog
	if err := json.Unmarshal(r.body, &log); err != nil || log.Version != "2.1.0" {
		t.Fatalf("body is not SARIF 2.1.0: %v", err)
	}
	var drivers []string
	for _, run := range log.Runs {
		drivers = append(drivers, run.Tool.Driver.Name)
		if !run.Invocations[0].ExecutionSuccessful {
			t.Errorf("%s marked unsuccessful", run.Tool.Driver.Name)
		}
	}
	if got := strings.Join(drivers, ","); got != "offload-cli/gitleaks,offload-cli/grype,offload-cli/trivy" {
		t.Errorf("runs = %s (syft inventory must not be a run)", got)
	}
	// The redacted snippet is not sent either.
	if bytes.Contains(r.body, []byte("AKI******XYZ")) {
		t.Error("secret snippet was sent")
	}
	// Package props and tags drive the platform's classification.
	for _, want := range []string{`"packageName":"lodash"`, `"purl":"pkg:npm/lodash@4.17.4"`, `"secret"`, `"misconfiguration"`, `"fullyQualifiedName":"aws_security_group.web"`} {
		if !bytes.Contains(r.body, []byte(want)) {
			t.Errorf("body lacks %s", want)
		}
	}
	for _, want := range []string{"1 SBOM component entries", "upload sarif-abc", "SARIF Imports"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestUploadErrorClasses(t *testing.T) {
	cases := []struct {
		name     string
		script   []func(http.ResponseWriter)
		status   int
		requests int
		want     string
	}{
		{"401 bad key", []func(http.ResponseWriter){reply(401, errBody("Invalid or revoked API key"))}, 401, 1, "rejected the API key"},
		{"403 scope", []func(http.ResponseWriter){reply(403, errBody("API key does not have the required scope: 'scans:trigger'."))}, 403, 1, "scans:trigger"},
		{"413 single tool", []func(http.ResponseWriter){reply(413, errBody("SARIF body is over the limit"))}, 413, 1, "upload too large"},
		{"500 persistent", []func(http.ResponseWriter){reply(500, errBody("boom"))}, 500, maxAttempts, "HTTP 500"},
		{"429 long Retry-After", []func(http.ResponseWriter){reply(429, errBody("SARIF upload limit reached"), "Retry-After", "3600")}, 429, 1, "not waiting that long"},
		{"404 wrong URL", []func(http.ResponseWriter){reply(404, `{"detail":"Not Found"}`)}, 404, 1, "not found"},
		{"redirect not followed", []func(http.ResponseWriter){reply(307, "", "Location", "https://evil.example/x")}, 307, 1, "redirects are not followed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, got := server(t, tc.script...)
			cfg, _ := testConfig(t, srv.URL)
			in := sampleInput()
			in.Findings = in.Findings[:1] // gitleaks only: one batch
			in.Tools = []ToolRun{{"gitleaks", StatusOK}}
			var out bytes.Buffer
			err := Run(&out, cfg, in, target, "v")
			var ue *Error
			if !errors.As(err, &ue) || ue.Status != tc.status {
				t.Fatalf("err = %v, want status %d", err, tc.status)
			}
			if !strings.Contains(ue.Msg, tc.want) || !strings.Contains(out.String(), tc.want) {
				t.Errorf("message %q / output lacks %q", ue.Msg, tc.want)
			}
			if len(*got) != tc.requests {
				t.Errorf("requests = %d, want %d", len(*got), tc.requests)
			}
		})
	}
}

func TestRetry429ThenSuccess(t *testing.T) {
	srv, got := server(t,
		reply(429, errBody("at capacity"), "Retry-After", "2"),
		reply(503, "upstream down"),
		reply(200, okBody("offload-cli/gitleaks")))
	cfg, sleeps := testConfig(t, srv.URL)
	cfg.Backoff = func(a int) time.Duration { return time.Duration(a) * time.Millisecond }
	in := sampleInput()
	in.Findings, in.Tools = in.Findings[:1], []ToolRun{{"gitleaks", StatusOK}}
	var out bytes.Buffer
	if err := Run(&out, cfg, in, target, "v"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(*got) != 3 {
		t.Fatalf("requests = %d", len(*got))
	}
	if want := []time.Duration{2 * time.Second, 2 * time.Millisecond}; fmt.Sprint(*sleeps) != fmt.Sprint(want) {
		t.Errorf("sleeps = %v, want %v (Retry-After honoured, then backoff)", *sleeps, want)
	}
}

func TestCombined413SplitsPerTool(t *testing.T) {
	srv, got := server(t,
		reply(413, errBody("SARIF body is over the limit")),
		reply(200, okBody("offload-cli/gitleaks")),
		reply(200, okBody("offload-cli/grype")),
		reply(200, okBody("offload-cli/trivy")))
	cfg, _ := testConfig(t, srv.URL)
	var out bytes.Buffer
	if err := Run(&out, cfg, sampleInput(), target, "v"); err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	if len(*got) != 4 {
		t.Fatalf("requests = %d, want combined + 3 per tool", len(*got))
	}
	for _, r := range (*got)[1:] {
		var log sarifLog
		json.Unmarshal(r.body, &log)
		if len(log.Runs) != 1 {
			t.Errorf("split upload carries %d runs", len(log.Runs))
		}
	}
	if !strings.Contains(out.String(), "one upload per tool") {
		t.Error("split not disclosed")
	}
}

func TestDefaultBranchUnknownFallsBackToPartial(t *testing.T) {
	srv, got := server(t,
		reply(400, errBody("full_run=true for branch 'feat', but the repository's default branch is not known ... Pass default_branch=<the repository default>")),
		reply(200, okBody("offload-cli/gitleaks")))
	cfg, _ := testConfig(t, srv.URL)
	in := sampleInput()
	in.Findings, in.Tools = in.Findings[:1], []ToolRun{{"gitleaks", StatusOK}}
	tg := target
	tg.Branch, tg.DefaultBranch = "feat", ""
	var out bytes.Buffer
	if err := Run(&out, cfg, in, tg, "v"); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 || !strings.Contains((*got)[1].query, "full_run=false") {
		t.Fatalf("want a partial retry, got %+v", *got)
	}
	if !strings.Contains(out.String(), "NOT resolved") {
		t.Error("partial upload not disclosed")
	}
}

func TestUnknownBranchIsPartial(t *testing.T) {
	srv, got := server(t, reply(200, okBody("offload-cli/gitleaks")))
	cfg, _ := testConfig(t, srv.URL)
	tg := target
	tg.Branch = ""
	var out bytes.Buffer
	if err := Run(&out, cfg, sampleInput(), tg, "v"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*got)[0].query, "full_run=false") || !strings.Contains(out.String(), "branch unknown") {
		t.Errorf("unknown branch must be a disclosed partial upload: %s", (*got)[0].query)
	}
}

func TestKeyNeverPrinted(t *testing.T) {
	// The server echoes the key back in every error message, the worst case.
	echo := func(code int) func(http.ResponseWriter) {
		return reply(code, errBody("bad key "+testKey))
	}
	for _, code := range []int{400, 401, 403, 413, 429, 500} {
		srv, _ := server(t, echo(code))
		cfg, _ := testConfig(t, srv.URL)
		cfg.Backoff = func(int) time.Duration { return 0 }
		var out bytes.Buffer
		err := Run(&out, cfg, sampleInput(), target, "v")
		if err == nil {
			t.Fatalf("%d: want error", code)
		}
		if strings.Contains(out.String(), testKey) || strings.Contains(err.Error(), testKey) {
			t.Errorf("%d: API key leaked:\n%s", code, out.String())
		}
	}
	// Transport error path.
	cfg, _ := testConfig(t, "http://127.0.0.1:1")
	cfg.Backoff = func(int) time.Duration { return 0 }
	var out bytes.Buffer
	if err := Run(&out, cfg, sampleInput(), target, "v"); err == nil || strings.Contains(out.String(), testKey) {
		t.Errorf("transport error leaked key or succeeded: %v", err)
	}
}

func TestNewConfig(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a cert"), 0o600)
	cases := []struct {
		name, url string
		env       map[string]string
		wantErr   string
		wantBase  string
	}{
		{"ok", "https://offload.example.com/", map[string]string{EnvAPIKey: "k"}, "", "https://offload.example.com"},
		{"strip /api", "https://h.example/api", map[string]string{EnvAPIKey: "k"}, "", "https://h.example"},
		{"env url", "", map[string]string{EnvAPIKey: "k", EnvURL: "https://e.example"}, "", "https://e.example"},
		{"no url", "", map[string]string{EnvAPIKey: "k"}, "platform URL", ""},
		{"no key", "https://h.example", nil, EnvAPIKey, ""},
		{"plain http remote", "http://h.example", map[string]string{EnvAPIKey: "k"}, "plain http", ""},
		{"plain http loopback", "http://localhost:8000", map[string]string{EnvAPIKey: "k"}, "", "http://localhost:8000"},
		{"creds in url", "https://u:p@h.example", map[string]string{EnvAPIKey: "k"}, "credentials", ""},
		{"bad ca", "https://h.example", map[string]string{EnvAPIKey: "k", EnvCACert: bad}, "no PEM", ""},
		{"missing ca", "https://h.example", map[string]string{EnvAPIKey: "k", EnvCACert: filepath.Join(dir, "nope")}, "cannot read", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(tc.url, envOf(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || cfg.BaseURL != tc.wantBase {
				t.Fatalf("cfg = %+v err = %v", cfg, err)
			}
		})
	}
}

func TestCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, okBody("offload-cli/gitleaks"))
	}))
	defer srv.Close()
	in := sampleInput()
	in.Findings, in.Tools = in.Findings[:1], []ToolRun{{"gitleaks", StatusOK}}

	// Without the CA: verification fails (TLS is verified by default).
	cfg, _ := testConfig(t, srv.URL)
	cfg.Backoff = func(int) time.Duration { return 0 }
	if err := Run(io.Discard, cfg, in, target, "v"); err == nil {
		t.Fatal("self-signed server accepted without OFFLOAD_CA_CERT")
	}
	// With OFFLOAD_CA_CERT pointing at its certificate: accepted.
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	cfg2, err := NewConfig(srv.URL, envOf(map[string]string{EnvAPIKey: testKey, EnvCACert: pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(io.Discard, cfg2, in, target, "v"); err != nil {
		t.Fatalf("with CA: %v", err)
	}
}

func TestBuildPlanStatuses(t *testing.T) {
	in := sampleInput()
	in.Tools = []ToolRun{{"gitleaks", StatusOK}, {"grype", StatusSkipped}, {"syft", StatusSkipped}, {"trivy", StatusError}}
	in.Findings = in.Findings[:1]
	p, err := BuildPlan(in, "svc", "v")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Tools, ",") != "gitleaks,trivy" || strings.Join(p.Skipped, ",") != "grype,syft" {
		t.Fatalf("tools=%v skipped=%v", p.Tools, p.Skipped)
	}
	var log sarifLog
	json.Unmarshal(p.whole.Body, &log)
	if !log.Runs[0].Invocations[0].ExecutionSuccessful || log.Runs[1].Invocations[0].ExecutionSuccessful {
		t.Error("an errored tool must be sent with executionSuccessful=false")
	}
	if uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "svc/config.py" {
		t.Errorf("path prefix not applied: %s", uri)
	}
	if empty, _ := BuildPlan(Input{Tools: []ToolRun{{"gitleaks", StatusSkipped}}}, "", "v"); !empty.Empty() {
		t.Error("all-skipped plan should be empty")
	}
}

func TestFromJSON(t *testing.T) {
	good := `{"tool":"offload-cli","version":"v","scanned_path":".","summary":{},"scanners":[{"name":"gitleaks","status":"ok","findings":1}],"findings":[{"finding_fingerprint":"f","finding_category":"secret","severity":"high","severity_rank":1,"title":"t","tool":"gitleaks"}]}`
	in, err := FromJSON(strings.NewReader(good))
	if err != nil || len(in.Findings) != 1 || in.Tools[0].Status != StatusOK {
		t.Fatalf("in=%+v err=%v", in, err)
	}
	for _, bad := range []string{`{"tool":"other"}`, `not json`, `{"tool":"offload-cli","scanners":[{"name":"x","status":"weird"}]}`} {
		if _, err := FromJSON(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestNormalizeRepository(t *testing.T) {
	cases := map[string]string{
		"git@github.com:acme/shop.git":                           "https://github.com/acme/shop",
		"https://github.com/acme/shop.git":                       "https://github.com/acme/shop",
		"https://x-access-token:ghs_SECRET@github.com/acme/shop": "https://github.com/acme/shop",
		"ssh://git@gitlab.example.com:2222/grp/sub/p.git":        "https://gitlab.example.com/grp/sub/p",
		"https://git.example.com:8443/a/b":                       "https://git.example.com:8443/a/b",
		"":                                                       "",
	}
	for in, want := range cases {
		if got := NormalizeRepository(in); got != want {
			t.Errorf("NormalizeRepository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectTarget(t *testing.T) {
	fake := func(answers map[string]string) func(string, ...string) (string, error) {
		return func(dir string, args ...string) (string, error) {
			if v, ok := answers[strings.Join(args, " ")]; ok {
				return v, nil
			}
			return "", errors.New("no")
		}
	}
	defer func(g func(string, ...string) (string, error)) { gitRunner = g }(gitRunner)

	evPath := filepath.Join(t.TempDir(), "event.json")
	os.WriteFile(evPath, []byte(`{"repository":{"default_branch":"trunk"}}`), 0o600)

	cases := []struct {
		name  string
		git   map[string]string
		env   map[string]string
		flags Target
		want  Target
	}{
		{"local git",
			map[string]string{"remote get-url origin": "git@github.com:o/r.git", "rev-parse --abbrev-ref HEAD": "feat/x",
				"symbolic-ref --short refs/remotes/origin/HEAD": "origin/main", "rev-parse HEAD": "abcdef1234567",
				"rev-parse --show-prefix": "svc/"},
			nil, Target{},
			Target{Repository: "https://github.com/o/r", Branch: "feat/x", DefaultBranch: "main", CommitSHA: "abcdef1234567", PathPrefix: "svc"}},
		{"github actions PR",
			map[string]string{"rev-parse --abbrev-ref HEAD": "HEAD", "rev-parse HEAD": "1234567abc"},
			map[string]string{"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r", "GITHUB_HEAD_REF": "pr-branch",
				"GITHUB_REF_NAME": "12/merge", "GITHUB_EVENT_PATH": evPath},
			Target{},
			Target{Repository: "https://github.com/o/r", Branch: "pr-branch", DefaultBranch: "trunk", CommitSHA: "1234567abc"}},
		{"detached HEAD, no CI",
			map[string]string{"remote get-url origin": "https://github.com/o/r", "rev-parse --abbrev-ref HEAD": "HEAD"},
			nil, Target{},
			Target{Repository: "https://github.com/o/r"}},
		{"flags win, bad sha dropped",
			map[string]string{"remote get-url origin": "git@github.com:o/r.git", "rev-parse --abbrev-ref HEAD": "dev"},
			nil, Target{Repository: "https://gitlab.com/x/y.git", Branch: "release", CommitSHA: "not-a-sha"},
			Target{Repository: "https://gitlab.com/x/y", Branch: "release"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gitRunner = fake(tc.git)
			if got := DetectTarget("/repo", tc.flags, envOf(tc.env)); got != tc.want {
				t.Errorf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
