package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offloadsecurity/offload-cli/internal/verdict"
)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func report(t *testing.T, entries ...gitleaksV8) []byte {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseGitleaksReportClassifiesFromSourceLine(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "app", "auth.py")
	cfg := filepath.Join(dir, "config.py")
	write(t, auth, "import os\n\ndef login(login_data):\n    password = login_data.password\n    return password\n")
	write(t, cfg, "API_KEY = \"Zk9x!q2LmP0vR7sT4wY1AbCd\"\n")
	raw := report(t,
		// gitleaks' JSON report omits the line: the verdict must read it.
		gitleaksV8{RuleID: "generic-api-key", File: auth, StartLine: 4, EndLine: 4,
			Secret: "login_data.password", Match: "password = login_data.password"},
		gitleaksV8{RuleID: "generic-api-key", File: cfg, StartLine: 1, EndLine: 1, Entropy: 4.4,
			Secret: "Zk9x!q2LmP0vR7sT4wY1AbCd", Match: `API_KEY = "Zk9x!q2LmP0vR7sT4wY1AbCd"`},
	)
	fs, err := ParseGitleaksReport(dir, raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if v := fs[0].SecretVerdict; v == nil || v.Verdict != verdict.NotASecret || !fs[0].Dismissed() {
		t.Errorf("runtime assignment should be dismissed: %+v", v)
	}
	if v := fs[1].SecretVerdict; v == nil || v.Verdict != verdict.LikelySecret || fs[1].Dismissed() {
		t.Errorf("literal key should be a likely secret: %+v", v)
	}
	if fs[0].File != filepath.Join("app", "auth.py") {
		t.Errorf("file should be relative: %s", fs[0].File)
	}
	b, _ := json.Marshal(fs)
	if strings.Contains(string(b), "Zk9x!q2LmP0vR7sT4wY1AbCd") {
		t.Errorf("raw secret leaked into findings: %s", b)
	}

	off, err := ParseGitleaksReport(dir, raw, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range off {
		if f.SecretVerdict != nil || f.Dismissed() {
			t.Errorf("--no-verdicts must leave findings unclassified: %+v", f)
		}
	}
}

func TestSourceLinesIsBoundedAndSafe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "repo")
	outside := filepath.Join(root, "outside.txt")
	write(t, outside, "password = login_data.password\n")
	write(t, filepath.Join(dir, "bin.dat"), "a\x00b\nsecond\n")
	write(t, filepath.Join(dir, "long.js"), strings.Repeat("x", maxLineBytes*2)+"\nshort line\n")
	write(t, filepath.Join(dir, "crlf.env"), "A=1\r\nTOKEN=abc\r\n")
	write(t, filepath.Join(dir, "nonl.py"), "x = 1\nlast = 2")
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	got := sourceLines(dir, []gitleaksV8{
		{File: outside, StartLine: 1},
		{File: filepath.Join(dir, "link.txt"), StartLine: 1},
		{File: filepath.Join(dir, "missing.py"), StartLine: 1},
		{File: filepath.Join(dir, "bin.dat"), StartLine: 1},
		{File: filepath.Join(dir, "bin.dat"), StartLine: 2},
		{File: filepath.Join(dir, "long.js"), StartLine: 1},
		{File: filepath.Join(dir, "long.js"), StartLine: 2},
		{File: filepath.Join(dir, "crlf.env"), StartLine: 2},
		{File: filepath.Join(dir, "nonl.py"), StartLine: 2},
		{File: filepath.Join(dir, "nonl.py"), StartLine: 9},
		{File: dir, StartLine: 1},
	})
	for _, f := range []string{outside, filepath.Join(dir, "link.txt"), filepath.Join(dir, "missing.py"), dir} {
		if _, ok := got[f]; ok {
			t.Errorf("must not read %s", f)
		}
	}
	check := func(file string, n int, want string, present bool) {
		t.Helper()
		v, ok := got[filepath.Join(dir, file)][n]
		if ok != present || v != want {
			t.Errorf("%s:%d = %q,%v want %q,%v", file, n, v, ok, want, present)
		}
	}
	check("bin.dat", 1, "", false) // binary line skipped
	check("bin.dat", 2, "second", true)
	check("long.js", 1, "", false) // over-long line skipped, not buffered
	check("long.js", 2, "short line", true)
	check("crlf.env", 2, "TOKEN=abc", true)
	check("nonl.py", 2, "last = 2", true)
	check("nonl.py", 9, "", false)
}
