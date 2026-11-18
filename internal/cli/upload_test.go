package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliTestKey = "osk_CLI_TEST_not_a_real_key_0123456789"

func TestFinalExitPrecedence(t *testing.T) {
	cases := []struct {
		gateHit, uploadFailed bool
		want                  int
	}{
		{false, false, exitOK},
		{false, true, exitUploadFailed},
		{true, false, exitGateHit},
		{true, true, exitGateHit}, // the gate verdict is never masked
	}
	for _, tc := range cases {
		if got := finalExit(tc.gateHit, tc.uploadFailed); got != tc.want {
			t.Errorf("finalExit(%v,%v) = %d, want %d", tc.gateHit, tc.uploadFailed, got, tc.want)
		}
	}
}

func TestReorderUploadIsBool(t *testing.T) {
	got := strings.Join(reorder([]string{".", "--upload", "--fail-on", "high"}), " ")
	if got != "--upload --fail-on high ." {
		t.Errorf("reorder = %q", got)
	}
}

func withEnv(t *testing.T, m map[string]string) {
	t.Helper()
	old := envLookup
	envLookup = func(k string) string { return m[k] }
	t.Cleanup(func() { envLookup = old })
}

func TestScanUploadPreflight(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"no key", map[string]string{"OFFLOAD_URL": "https://h.example"}, []string{dir, "--upload"}},
		{"no url", map[string]string{"OFFLOAD_API_KEY": cliTestKey}, []string{dir, "--upload"}},
		{"plain http", map[string]string{"OFFLOAD_API_KEY": cliTestKey}, []string{dir, "--upload", "--platform-url", "http://h.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, tc.env)
			if got := runScan(tc.args); got != exitUsage {
				t.Errorf("exit = %d, want %d (refused before scanning)", got, exitUsage)
			}
		})
	}
}

func TestUploadCommand(t *testing.T) {
	var sawKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("X-API-Key")
		if r.URL.Query().Get("fail") != "" || strings.Contains(r.URL.RawQuery, "o%2Fdenied") {
			w.WriteHeader(403)
			io.WriteString(w, `{"success":false,"error":{"message":"API key does not have the required scope: 'scans:trigger'. key `+cliTestKey+`"}}`)
			return
		}
		io.WriteString(w, `{"success":true,"data":{"upload_id":"sarif-1","scope_key":"repo-https://github.com/o/r","tools":[{"tool":"offload-cli/gitleaks","results_received":1,"results_ingested":1,"new":1}]}}`)
	}))
	defer srv.Close()

	report := filepath.Join(t.TempDir(), "results.json")
	os.WriteFile(report, []byte(`{"tool":"offload-cli","version":"v","scanned_path":"/nonexistent-dir","summary":{},
"scanners":[{"name":"gitleaks","status":"ok","findings":1}],
"findings":[{"finding_fingerprint":"f","finding_category":"secret","severity":"high","severity_rank":1,"title":"t","rule_id":"generic-api-key","file":"a.py","tool":"gitleaks"}]}`), 0o600)

	cases := []struct {
		name string
		repo string
		want int
	}{
		{"ok", "https://github.com/o/r", exitOK},
		{"403", "https://github.com/o/denied", exitUploadFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, map[string]string{"OFFLOAD_API_KEY": cliTestKey})
			var buf bytes.Buffer
			old := stderr
			stderr = &buf
			defer func() { stderr = old }()
			got := runUpload([]string{report, "--platform-url", srv.URL, "--repository", tc.repo, "--branch", "main"})
			if got != tc.want {
				t.Fatalf("exit = %d, want %d\n%s", got, tc.want, buf.String())
			}
			if sawKey != cliTestKey {
				t.Error("key not sent in X-API-Key")
			}
			if strings.Contains(buf.String(), cliTestKey) {
				t.Errorf("API key printed:\n%s", buf.String())
			}
			if tc.want == exitUploadFailed && !strings.Contains(buf.String(), "scans:trigger") {
				t.Errorf("403 message missing scope hint:\n%s", buf.String())
			}
		})
	}
}

func TestUploadCommandUsage(t *testing.T) {
	withEnv(t, map[string]string{"OFFLOAD_API_KEY": cliTestKey, "OFFLOAD_URL": "https://h.example"})
	if got := runUpload(nil); got != exitUsage {
		t.Errorf("no file: exit %d", got)
	}
	if got := runUpload([]string{filepath.Join(t.TempDir(), "missing.json")}); got != exitError {
		t.Errorf("missing file: exit %d", got)
	}
}
