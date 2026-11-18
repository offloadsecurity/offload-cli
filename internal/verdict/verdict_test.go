package verdict

import (
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type tc struct {
	name                                   string
	secret, match, line, ctx, path, ruleID string
	entropy                                *float64
}

func run(t tc) Result {
	rule := t.ruleID
	if rule == "" {
		rule = "generic-api-key"
	}
	return Classify(Input{Secret: t.secret, Match: t.match, Line: t.line, Context: t.ctx,
		FilePath: t.path, RuleID: rule, Entropy: t.entropy})
}

func has(r Result, sig string) bool { return contains(r.Signals, sig) }

func suppressed(r Result) bool { return r.NonSecret() && r.Confidence == High }

// outcome maps a verdict onto the three review outcomes: DETECT (actionable
// secret), SUPPRESS (dismissed) and ANALYSE (visible, needs a human).
func outcome(r Result) string {
	if r.NonSecret() {
		if r.Confidence == High {
			return "SUPPRESS"
		}
		return "ANALYSE"
	}
	if r.Confidence != Low {
		return "DETECT"
	}
	return "ANALYSE"
}

func f64(f float64) *float64 { return &f }

// providerKey is a hardcoded literal reported by a provider-format rule.
// Not a real key: the verdict keys on the rule id, not the value's prefix.
const providerKey = "Q4eC39HqLyjWDarjtT1zdp7dcXk"

// withChecksum builds a GitHub-format token from prefix and a 30-char body,
// using the checksum verified against GitHub's published vector.
func withChecksum(prefix, body string) string {
	return prefix + body + toBase62(crc32.ChecksumIEEE([]byte(body)))
}

// Unlike the Offload platform's classifier, a dismissal's reason masks the judged value too (a
// verdict is a heuristic; output never carries a possibly-real value).
func TestHeadlineExamples(t *testing.T) {
	pem := `-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n`
	r := run(tc{secret: pem, match: `"` + pem + `"`, line: `"private_key": "` + pem + `"`, path: "config/creds.json", ruleID: "private-key"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Actionable ||
		!strings.Contains(r.Reason, "1-character body") || !has(r, "pem_placeholder_body") {
		t.Errorf("placeholder PEM: %+v", r)
	}

	r = run(tc{secret: `password="${MONGO_PASS}`, match: `password="${MONGO_PASS}`,
		line: `mongo --password="${MONGO_PASS}" --eval x`, path: "scripts/backup.sh", ruleID: "Hardcoded Password"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Actionable ||
		strings.Contains(r.Reason, "${MONGO_PASS}") || !strings.Contains(r.Reason, "`…S} (13 chars)`") ||
		!strings.Contains(r.Reason, "environment variable") {
		t.Errorf("env ref in flag: %+v", r)
	}

	r = run(tc{secret: "Password: [the password you entered]", match: "Password: [the password you entered]",
		line: `echo "Password: [the password you entered]"`, path: "setup.sh"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Tag() != "placeholder" ||
		strings.Contains(r.Reason, "[the password you entered]") {
		t.Errorf("bracketed text: %+v", r)
	}

	r = run(tc{secret: "$MONGO_APP_PASSWORD", match: "pwd: '$MONGO_APP_PASSWORD'", line: "  pwd: '$MONGO_APP_PASSWORD'",
		path: "k8s/values.yaml", ruleID: "custom-mongo-pwd"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || !has(r, "env_var_reference") {
		t.Errorf("$VAR in yaml: %+v", r)
	}

	r = run(tc{secret: "password = login_data.password", match: "password = login_data.password",
		line: "    password = login_data.password", path: "app/auth.py", ruleID: "Hardcoded Password"})
	if r.Verdict != NotASecret || r.Confidence != High || r.Actionable ||
		strings.Contains(r.Reason, "login_data.password") || !strings.Contains(r.Reason, "`…rd (19 chars)`") ||
		!strings.Contains(r.Reason, "runtime") {
		t.Errorf("runtime assignment: %+v", r)
	}

	r = run(tc{secret: "password:\n        authenticate(user, pw)", match: "password:\n        authenticate(user, pw)",
		line: "    if username and password:", path: "app/auth.py", ruleID: "Hardcoded Password"})
	if r.Verdict != NotASecret || r.Confidence != High || strings.Contains(r.Reason, "username") {
		t.Errorf("control flow: %+v", r)
	}
}

func TestRealSecretsStayActionable(t *testing.T) {
	r := run(tc{secret: providerKey, match: providerKey + `"`,
		line: `api_key = "` + providerKey + `"`, path: "app/pay.py", ruleID: "stripe-access-token", entropy: f64(4.75)})
	if r.Verdict != LikelySecret || r.Confidence != High || !r.Actionable || strings.Contains(r.Reason, "Q4eC") {
		t.Errorf("provider literal: %+v", r)
	}

	r = run(tc{secret: "Zk9x!q2LmP0vR7sT4wY1", match: `DB_PASSWORD = "Zk9x!q2LmP0vR7sT4wY1"`,
		line: `DB_PASSWORD = "Zk9x!q2LmP0vR7sT4wY1"`, path: "settings.py"})
	if r.Verdict != LikelySecret || !r.Actionable || strings.Contains(r.Reason, "Zk9x") {
		t.Errorf("high entropy: %+v", r)
	}

	r = run(tc{secret: "hunter2", match: `password = "hunter2"`, line: `password = "hunter2"`, path: "config.py"})
	if r.Verdict != LikelySecret || r.Confidence != Medium || !r.Actionable {
		t.Errorf("weak password: %+v", r)
	}
}

func TestCommonWeakPasswordsNeverConfidentlyDismissed(t *testing.T) {
	for _, c := range []tc{
		{secret: "admin", line: `password = "admin"`, path: "config.py"},
		{secret: "root", line: "DB_PASSWORD: root", path: "config.yml"},
		{secret: "password", line: `PASSWORD = "password"`, path: "settings.py"},
		{secret: "secret", line: "mysql -p secret", path: "deploy.sh"},
		{secret: "test", line: `db_pass = "test"`, path: "config.py"},
		{secret: "default", line: "ADMIN_PASSWORD=default", path: ".env"},
	} {
		c.match = c.line
		r := run(c)
		if !r.Actionable || suppressed(r) {
			t.Errorf("%s: %+v", c.secret, r)
		}
	}
	r := run(tc{secret: "changeme", match: `password = "changeme"`, line: `password = "changeme"`, path: "config.py"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != Medium || !r.Actionable {
		t.Errorf("changeme under password: %+v", r)
	}
	r = run(tc{secret: "changeme", match: `api_key = "changeme"`, line: `api_key = "changeme"`, path: "config.py"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Actionable {
		t.Errorf("changeme under api_key: %+v", r)
	}
	r = run(tc{secret: "your_password_here", line: `password = "your_password_here"`, path: "config.py"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Actionable {
		t.Errorf("structural placeholder: %+v", r)
	}
}

func TestUnquotedValues(t *testing.T) {
	r := run(tc{secret: "export API_KEY=abcdef1234567890ABCDEF", match: "export API_KEY=abcdef1234567890ABCDEF",
		line: "export API_KEY=abcdef1234567890ABCDEF", path: "env.sh", ruleID: "API Key"})
	if r.Verdict != LikelySecret || !r.Actionable {
		t.Errorf("shell literal: %+v", r)
	}
	r = run(tc{secret: "abc123def456", match: "password: abc123def456", line: "password: abc123def456",
		path: "docker-compose.yml", ruleID: "Hardcoded Password"})
	if r.Verdict != LikelySecret || !r.Actionable {
		t.Errorf("yaml literal: %+v", r)
	}
	r = run(tc{secret: "password = DEFAULT_PASSWORD", match: "password = DEFAULT_PASSWORD",
		line: "password = DEFAULT_PASSWORD", path: "settings.py", ruleID: "Hardcoded Password"})
	if r.Verdict != NotASecret || !has(r, "variable_assignment") {
		t.Errorf("code identifier: %+v", r)
	}
}

func TestPEM(t *testing.T) {
	body := "MIIEowIBAAKCAQEAxZ0m9k2q3v4b5n6m7l8k9j0h1g2f3d4s5a6q7w8e9r0t1y2u3i4o5p6a7s8d9f0g1h2j3k4l"
	ctx := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n" + body + "\n-----END RSA PRIVATE KEY-----"
	h := "-----BEGIN RSA PRIVATE KEY-----"
	r := run(tc{secret: h, match: h, line: h, ctx: ctx, path: "id_rsa", ruleID: "Private Key"})
	if r.Verdict != LikelySecret || r.Confidence != High || !r.Actionable || has(r, "in_comment") {
		t.Errorf("real PEM: %+v", r)
	}
	r = run(tc{secret: h, match: h, line: h, path: "k.pem", ruleID: "Private Key"})
	if r.Verdict != LikelySecret || !r.Actionable {
		t.Errorf("header only: %+v", r)
	}
	r = run(tc{secret: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", path: "c.pem", ruleID: "private-key"})
	if r.Verdict != NotASecret || !has(r, "public_key_material") {
		t.Errorf("certificate: %+v", r)
	}
}

func TestReferenceShapes(t *testing.T) {
	for _, c := range []tc{
		{secret: "password: {{ .Values.db.password }}", match: "password: {{ .Values.db.password }}", line: "  password: {{ .Values.db.password }}", path: "templates/secret.yaml"},
		{secret: "${{ secrets.NPM_TOKEN }}", match: "token: ${{ secrets.NPM_TOKEN }}", line: "  token: ${{ secrets.NPM_TOKEN }}", path: ".github/workflows/ci.yml"},
		{secret: "process.env.API_KEY", match: "apiKey: process.env.API_KEY", line: "  apiKey: process.env.API_KEY,", path: "src/config.js"},
		{secret: "mongodb://app:${DB_PASS}@db:27017", match: "mongodb://app:${DB_PASS}@", line: "url: mongodb://app:${DB_PASS}@db:27017", path: "compose.yml"},
	} {
		c.ruleID = "Hardcoded Password"
		if r := run(c); r.Verdict != LikelyFalsePositive || r.Confidence != High {
			t.Errorf("%s: %+v", c.secret, r)
		}
	}
}

func TestExpressionShapes(t *testing.T) {
	for _, c := range []tc{
		{secret: "password = getpass()", line: "password = getpass()", path: "cli.py"},
		{secret: "password = request.form['password']", line: "password = request.form['password']", path: "views.py"},
		{secret: "password = this.state.password", line: "    password = this.state.password;", path: "Login.jsx"},
	} {
		c.match, c.ruleID = c.secret, "Hardcoded Password"
		if r := run(c); r.Verdict != NotASecret || r.Confidence != High {
			t.Errorf("%s: %+v", c.secret, r)
		}
	}
}

func TestPlaceholderValues(t *testing.T) {
	for _, v := range []string{"<your-api-key>", "changeme", "AKIAIOSFODNN7EXAMPLE", "xxxxxxxxxxxx", "your_password_here", "REPLACE_WITH_REAL_KEY"} {
		rule := "generic-api-key"
		if strings.HasPrefix(v, "AKIA") {
			rule = "aws-access-token"
		}
		line := `api_key = "` + v + `"`
		if r := run(tc{secret: v, match: line, line: line, path: "app.py", ruleID: rule}); r.Verdict != LikelyFalsePositive || r.Confidence != High {
			t.Errorf("%s: %+v", v, r)
		}
	}
}

func TestLookalikesAndPaths(t *testing.T) {
	h := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if r := run(tc{secret: h, line: `integrity_hash = "` + h + `"`, path: "lock.py"}); r.Verdict != NotASecret || !has(r, "hash_lookalike") {
		t.Errorf("content hash: %+v", r)
	}
	if r := run(tc{secret: "sha512-abcDEF0123456789abcDEF0123456789", line: `"integrity": "sha512-..."`, path: "frontend/package-lock.json"}); r.Verdict != LikelyFalsePositive || !has(r, "lockfile") {
		t.Errorf("lockfile: %+v", r)
	}
	r := run(tc{secret: "qwzx9plm", match: `password = "qwzx9plm"`, line: `password = "qwzx9plm"`, path: "docs/getting-started.md"})
	if r.Verdict != LikelySecret || r.Confidence != Medium || !r.Actionable || !has(r, "documentation_low_entropy") {
		t.Errorf("docs literal: %+v", r)
	}
	r = run(tc{secret: "qwzx9plm", match: `password = "qwzx9plm"`, line: `password = "qwzx9plm"`, path: "tests/fixtures/users.py"})
	if r.Verdict != LikelySecret || !r.Actionable {
		t.Errorf("test literal: %+v", r)
	}
	r = run(tc{secret: "password123", line: `password = "password123"`, path: "docs/getting-started.md"})
	if r.Verdict != LikelySecret || r.Confidence != Medium || !r.Actionable {
		t.Errorf("password123 in docs: %+v", r)
	}
	r = run(tc{secret: "database-admin-1", line: `api_key = "database-admin-1"`, path: "docs/getting-started.md"})
	if r.Verdict != LikelyFalsePositive || !has(r, "stopword_in_value") {
		t.Errorf("stopword token in docs: %+v", r)
	}
	r = run(tc{secret: "AKIAQ7W8E9R0T1Y2U3I4", line: `key = "AKIAQ7W8E9R0T1Y2U3I4"`, path: "tests/test_s3.py", ruleID: "aws-access-token"})
	if r.Verdict != LikelySecret || !r.Actionable || !has(r, "test_or_fixture_path") {
		t.Errorf("provider key in tests: %+v", r)
	}
}

func TestExtractCandidateValue(t *testing.T) {
	for _, c := range []struct{ secret, match, want string }{
		{"", `password = "abc"`, "abc"},
		{"", "aws_secret_access_key: 'k' ", "k"},
		{"mongodb://u:p%40ss@h", "", "p%40ss"},
		{"", "Bearer abcdef", "abcdef"},
		{"plain", "", "plain"},
		{"dGhlkeyab9Xq2mZ==", "", "dGhlkeyab9Xq2mZ=="},
	} {
		if got := ExtractCandidateValue(c.secret, c.match); got != c.want {
			t.Errorf("ExtractCandidateValue(%q,%q)=%q want %q", c.secret, c.match, got, c.want)
		}
	}
}

func TestGitHubChecksum(t *testing.T) {
	// GitHub's published example: body zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ has
	// checksum 0mLq17 (base62 of the CRC32 of the body).
	if got := toBase62(crc32.ChecksumIEEE([]byte("zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ"))); got != "0mLq17" {
		t.Fatalf("checksum of the published example = %q, want 0mLq17", got)
	}
	body := "Kq7ZpX2mWv9LbN4tYc8RjH3sDf6GuE"
	good := withChecksum("ghp_", body)
	last := byte('A')
	if good[len(good)-1] == 'A' {
		last = 'B'
	}
	bad := good[:len(good)-1] + string(last)
	for _, c := range []struct {
		v         string
		valid, ok bool
	}{
		{good, true, true},
		{bad, false, true},
		{withChecksum("npm_", body), true, true},
		{providerKey, false, false},
	} {
		if v, ok := GitHubTokenChecksum(c.v); v != c.valid || ok != c.ok {
			t.Errorf("%s: got (%v,%v)", c.v, v, ok)
		}
	}
	fake := "ghp_" + strings.Repeat("aB3", 12)
	r := run(tc{secret: fake, match: fake, line: `token = "` + fake + `"`, ruleID: "github-pat"})
	// a failed checksum lowers confidence but never dismisses (stays counted)
	if r.Verdict != LikelyFalsePositive || r.Confidence != Medium || !r.Actionable || !has(r, "checksum_invalid") {
		t.Errorf("bad checksum: %+v", r)
	}
	r = run(tc{secret: good, match: good, line: `token = "` + good + `"`, ruleID: "github-pat"})
	if r.Verdict != LikelySecret || !has(r, "checksum_valid") || !r.Actionable {
		t.Errorf("good checksum: %+v", r)
	}
}

func TestNonSecretKeyNames(t *testing.T) {
	for _, kv := range [][2]string{
		{"api_version", "2023-10-01-preview"},
		{"public_key", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"},
		{"user_id", "8f14e45fceea167a5a36dedd4bea2543"},
		{"csrf_token", "a8f5f167f44f4964e6c998dee827110c"},
		{"key_file", "/etc/ssl/private/server.key"},
		{"token_endpoint", "https://login.example.com/oauth2/v2.0/token"},
		{"primary_key", "8f14e45fceea167a5a36dedd4bea2543"},
	} {
		line := kv[0] + ` = "` + kv[1] + `"`
		r := run(tc{secret: kv[1], match: line, line: line, path: "c.py"})
		if r.Verdict != NotASecret || r.Confidence != High || !has(r, "non_secret_key_name") {
			t.Errorf("%s: %+v", kv[0], r)
		}
	}
	r := run(tc{secret: "AKIAQ7W8E9R0T1Y2U3I4", line: `key_id = "AKIAQ7W8E9R0T1Y2U3I4"`, path: "c.py", ruleID: "aws-access-token"})
	if r.Verdict != LikelySecret {
		t.Errorf("provider rule ignores key-name allowlist: %+v", r)
	}
}

func TestHashedOrEncrypted(t *testing.T) {
	for _, v := range []string{
		"$2b$12$KIXQ4xkGl3cP0w9lJh6jUeTjzq1qfR1hqfAZQmQ3sQvXcWnE6Yq2S",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash",
		"{SSHA}MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw",
		"ENC(k3J9sdf8SDF+sdf==)",
		"ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]",
		"vault:v1:8SDb53iRxL0Tm7mOsn7hK6l3L2Z8x",
	} {
		line := `password = "` + v + `"`
		r := run(tc{secret: v, match: line, line: line, path: "seed.py", ruleID: "Hardcoded Password"})
		if r.Verdict != LikelyFalsePositive || r.Confidence != High || !has(r, "hashed_or_encrypted_value") {
			t.Errorf("%s: %+v", v, r)
		}
	}
}

func TestFormatPositionalSequentialPunctuation(t *testing.T) {
	for _, v := range []string{"%s", "$1", "${2}", "{0}", "@DB_PASSWORD@", "true", "null",
		"/usr/share/keys/id_rsa", "abcdefghijklmnop", "0123456789012345", "!@#$%^&*()"} {
		line := `api_key = "` + v + `"`
		if r := run(tc{secret: v, match: line, line: line, path: "c.py"}); r.Verdict != LikelyFalsePositive || r.Confidence != High {
			t.Errorf("%s: %+v", v, r)
		}
	}
}

func TestLettersStopwordsContextSwagger(t *testing.T) {
	r := run(tc{secret: "supersecretvalue", line: `api_key = "supersecretvalue"`, path: "c.py"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != High || r.Actionable {
		t.Errorf("letters-only token: %+v", r)
	}
	r = run(tc{secret: "supersecretpassword", line: `password = "supersecretpassword"`, path: "c.py", ruleID: "Hardcoded Password"})
	if r.Verdict != LikelyFalsePositive || r.Confidence != Medium || !r.Actionable {
		t.Errorf("letters-only password: %+v", r)
	}
	r = run(tc{secret: "database-admin-1", line: `secret_key = "database-admin-1"`, path: "c.py"})
	if r.Verdict != LikelyFalsePositive || !has(r, "stopword_in_value") {
		t.Errorf("stopword: %+v", r)
	}
	r = run(tc{secret: "Zk9xQ2LmP0vR7sT4wY1aPiB8", line: `secret_key = "Zk9xQ2LmP0vR7sT4wY1aPiB8"`, path: "c.py"})
	if r.Verdict != LikelySecret {
		t.Errorf("high-entropy key with a short word: %+v", r)
	}
	r = run(tc{secret: "k9J2mX7qLp0vR4tZ", line: `# Example: api_key = "k9J2mX7qLp0vR4tZ"`, path: "c.py"})
	if r.Verdict != LikelyFalsePositive || !has(r, "context_banlist_word") {
		t.Errorf("context banlist: %+v", r)
	}
	r = run(tc{secret: "k9J2mX7qLp0vR4tZ99", line: `"api_key": "k9J2mX7qLp0vR4tZ99"`, path: "docs/swagger.json"})
	if r.Verdict != LikelyFalsePositive || !has(r, "swagger_file") {
		t.Errorf("swagger: %+v", r)
	}
	if len(stopwords) < 1400 || !contains(stopwords, "example") || !contains(stopwords, "password") {
		t.Errorf("stopword list is not the gitleaks list (%d entries)", len(stopwords))
	}
}

func TestReviewRoundCases(t *testing.T) {
	r := run(tc{secret: "dGhlkeyab9Xq2mZ==", line: `token = "dGhlkeyab9Xq2mZ=="`, path: "a.py"})
	if r.Verdict != LikelySecret || !r.Actionable {
		t.Errorf("padded base64 token: %+v", r)
	}
	r = run(tc{secret: "password = os.path.join(", line: `password = os.path.join("secrets", "db.txt")`, path: "a.py", ruleID: "Hardcoded Password"})
	if has(r, "hardcoded_fallback_literal") {
		t.Errorf("os.path.join is not a lookup: %+v", r)
	}
	r = run(tc{secret: "api_version = os.getenv(", line: `api_version = os.getenv("V", "2023-10")`, path: "a.py"})
	if r.Verdict != NotASecret || !has(r, "non_secret_key_name") {
		t.Errorf("api_version fallback: %+v", r)
	}
	r = run(tc{secret: "password = os.getenv(", line: `password = os.getenv("DB_PASSWORD", "Secret123")`, path: "a.py", ruleID: "Hardcoded Password"})
	if r.Verdict != LikelySecret || !has(r, "hardcoded_fallback_literal") {
		t.Errorf("getenv fallback: %+v", r)
	}
	r = run(tc{secret: "password = config.get(", line: `password = config.get("db_password_v2")`, path: "a.py", ruleID: "Hardcoded Password"})
	if r.Verdict != NotASecret || r.Confidence != Medium || !has(r, "unresolved_source_call") {
		t.Errorf("config.get: %+v", r)
	}
	r = run(tc{secret: "password = decode(", line: `password = decode("U2VjcmV0MTIz")`, path: "a.py", ruleID: "Hardcoded Password"})
	if !has(r, "encoded_literal_argument") {
		t.Errorf("decode literal: %+v", r)
	}
	r = run(tc{secret: "password = auth_config.load(", line: "password = auth_config.load()", path: "a.py", ruleID: "Hardcoded Password"})
	if r.Verdict != NotASecret || r.Confidence != Medium {
		t.Errorf("auth_config.load: %+v", r)
	}
	r = run(tc{secret: "bcrypt.checkpw(password, hashed)", line: "bcrypt.checkpw(password, hashed)", path: "a.py", ruleID: "custom"})
	if r.Confidence != High || !has(r, "verifies_or_hashes_variable") {
		t.Errorf("checkpw: %+v", r)
	}
}

// Hash/encrypt calls are dismissed only when every argument is a variable.
func TestHashCallArguments(t *testing.T) {
	cases := []struct {
		line      string
		dismissed bool
	}{
		{"encryptedPassword: encrypt(dto.password),", true},
		{"encryptedPassword: encrypt(dto.password, this.key),", true},
		{"encryptedPassword: encrypt(dto.password, this.key,),", true}, // trailing comma
		{"password: encrypt(dto.password,,),", false},
		{"password: encrypt(12345678),", false},
		{"password: encrypt([1, 2, 3]),", false},
		{"password: hash(0xDEADBEEF)", false},
		{"password: encrypt(),", false},
		{"password: encrypt(`${prefix}Xk9mP2vLq8zR`),", false},
	}
	for _, c := range cases {
		r := run(tc{secret: c.line, line: c.line, path: "auth.service.ts", ruleID: "Hardcoded Password"})
		got := has(r, "verifies_or_hashes_variable")
		if got != c.dismissed {
			t.Errorf("%q: verifies_or_hashes_variable=%v want %v (%+v)", c.line, got, c.dismissed, r)
		}
		if c.dismissed && (r.Verdict != NotASecret || r.Confidence != High) {
			t.Errorf("%q: want high not_a_secret, got %+v", c.line, r)
		}
		if !c.dismissed && r.Verdict == NotASecret && r.Confidence == High {
			t.Errorf("%q: literal argument must stay actionable, got %+v", c.line, r)
		}
	}
	r := run(tc{secret: "password: decrypt(cfg.blob)", line: "password: decrypt(cfg.blob)", path: "a.ts", ruleID: "Hardcoded Password"})
	if r.Confidence == High {
		t.Errorf("decrypt of a config blob must not be high: %+v", r)
	}
}

// The hardcoded-password regression matrix: each true positive is paired
// with its negative control. Inputs are fed as a "password" regex produces
// them (match truncated at the first quote or space).
var (
	pwRe   = regexp.MustCompile(`(?i)password[ \t]*[=:][ \t]*['"]?[^'"\s]{8,}`)
	connRe = regexp.MustCompile(`postgres://[^:]+:[^@]+@`)
)

func matrixRun(t *testing.T, line, path, rule string, rx *regexp.Regexp) Result {
	t.Helper()
	m := rx.FindString(line)
	if m == "" {
		t.Fatalf("pattern must match %q", line)
	}
	return Classify(Input{Secret: m, Match: m, Line: line, FilePath: path, RuleID: rule})
}

func TestPasswordMatrix(t *testing.T) {
	for _, c := range []struct{ id, want, line, path string }{
		{"TP-01", "DETECT", `password = "Admin@123"`, "app.py"},
		{"TN-01", "SUPPRESS", "password = login_data.password", "app.py"},
		{"TP-02", "DETECT", "DB_PASSWORD=Secret123", ".env"},
		{"TN-02", "SUPPRESS", `password = os.getenv("DB_PASSWORD")`, "app.py"},
		{"TP-03", "DETECT", `password = os.getenv("DB_PASSWORD", "Secret123")`, "app.py"},
		{"TN-03", "SUPPRESS", `mongo --password="${MONGO_PASS}"`, "run.sh"},
		{"TP-04", "DETECT", `password = get_secret("DB_PASSWORD") or "Secret123"`, "app.py"},
		{"TN-04", "SUPPRESS", `password = get_secret("DB_PASSWORD")`, "app.py"},
		{"TP-05", "DETECT", `mysql --password="Secret123"`, "run.sh"},
		{"TN-05", "SUPPRESS", `mysql --password="$DB_PASSWORD"`, "run.sh"},
		{"TP-07", "DETECT", "ENV DB_PASSWORD=Secret123", "Dockerfile"},
		{"TN-07", "SUPPRESS", "ENV DB_PASSWORD=${DB_PASSWORD}", "Dockerfile"},
		{"TP-08", "DETECT", `  DB_PASSWORD: "Secret123"`, ".github/workflows/ci.yml"},
		{"TP-09", "DETECT", `  password = "Secret123"`, "main.tf"},
		{"TN-09", "SUPPRESS", "  password = var.db_password", "main.tf"},
		{"TN-10", "SUPPRESS", "password = generate_password()", "app.py"},
		{"TP-11", "DETECT", `DEFAULT_PASSWORD="Secret123"`, "settings.py"},
		{"TN-11", "SUPPRESS", "password = DEFAULT_PASSWORD", "app.py"},
		{"TP-12", "DETECT", "db.password=Secret123", "app.properties"},
		{"TN-12", "ANALYSE", `password = config.get("password")`, "app.py"},
		{"TN-13", "ANALYSE", "password = decode(value)", "app.py"},
		{"TN-16", "SUPPRESS", "# Never hardcode passwords: password = keep_it_secret", "app.py"},
		{"S4-b", "SUPPRESS", "password = getpass()", "cli.py"},
		{"S5-a", "ANALYSE", `password = "password"`, "app.py"},
		{"S5-b", "ANALYSE", `password = "changeme"`, "app.py"},
		{"S5-d", "DETECT", `password = "Admin@123"`, "tests/fixtures.py"},
		{"S5-e", "DETECT", `password = "Admin@123"`, "docs/setup.md"},
	} {
		r := matrixRun(t, c.line, c.path, "Hardcoded Password", pwRe)
		if got := outcome(r); got != c.want {
			t.Errorf("%s %q: got %s [%s/%s] %s", c.id, c.line, got, r.Verdict, r.Confidence, r.Reason)
		}
	}
}

func TestConnectionStrings(t *testing.T) {
	r := matrixRun(t, `DATABASE_URL = "postgres://admin:Secret123@db"`, "settings.py", "PostgreSQL Connection String", connRe)
	if outcome(r) != "DETECT" {
		t.Errorf("TP-06: %+v", r)
	}
	for _, line := range []string{`DATABASE_URL = "postgres://admin:hunter@db"`, `DSN = "postgres://app:database@pg:5432/x"`} {
		r := matrixRun(t, line, "settings.py", "PostgreSQL Connection String", connRe)
		if !r.Actionable || r.Confidence == High && r.NonSecret() {
			t.Errorf("weak URL password must not be dismissed %q: %+v", line, r)
		}
	}
	r = matrixRun(t, `DATABASE_URL = "postgres://${DB_USER}:${DB_PASSWORD}@db"`, "settings.py", "PostgreSQL Connection String", connRe)
	if outcome(r) != "SUPPRESS" {
		t.Errorf("TN-06: %+v", r)
	}
}

// Lines a broader rule hands over whole must still be suppressed.
func TestNegativeControlsWholeLine(t *testing.T) {
	for _, c := range []struct{ id, line, path string }{
		{"TN-14", `echo "Password: [the password you entered]"`, "setup.sh"},
		{"TN-15", "if username and password:", "app.py"},
		{"TN-17", `password = ""`, "app.py"},
		{"S4-c", "def login(username, password):", "auth.py"},
		{"S4-d", "password_min_length=12", "settings.py"},
		{"S4-e", "logger.info(password)", "auth.py"},
		{"S4-f", `password_hash="$2b$12$KIXQ4xkGl3cP0w9lJh6jUeTjzq1qfR1hqfAZQmQ3sQvXcWnE6Yq2S"`, "seed.py"},
		{"S4-a", "bcrypt.checkpw(password, hashed)", "auth.py"},
	} {
		r := Classify(Input{Secret: c.line, Match: c.line, Line: c.line, FilePath: c.path, RuleID: "custom-password"})
		if outcome(r) != "SUPPRESS" {
			t.Errorf("%s: %+v", c.id, r)
		}
	}
}

func TestCoverageGapLines(t *testing.T) {
	l := `password = "Secret" + "123"`
	r := Classify(Input{Secret: l, Match: l, Line: l, FilePath: "app.py", RuleID: "custom-password"})
	if outcome(r) != "DETECT" || !has(r, "static_concatenation") {
		t.Errorf("concat: %+v", r)
	}
	l = `password = decode("U2VjcmV0MTIz")`
	r = Classify(Input{Secret: l, Match: l, Line: l, FilePath: "app.py", RuleID: "custom-password"})
	if outcome(r) == "SUPPRESS" || !has(r, "encoded_literal_argument") {
		t.Errorf("encoded: %+v", r)
	}
	r = Classify(Input{Secret: "test123", Match: `password = "test123"`, Line: `password = "test123"`, FilePath: "app.py", RuleID: "custom-password"})
	if outcome(r) == "SUPPRESS" {
		t.Errorf("test123: %+v", r)
	}
}

// An actionable reason never echoes the value; a dismissed reason never
// echoes another quoted literal from the same line.
func TestReasonsNeverEchoRealValues(t *testing.T) {
	secret := "Zk9x!q2LmP0vR7sT4wY1AbCd"
	r := run(tc{secret: secret, match: `API_KEY = "` + secret + `"`, line: `API_KEY = "` + secret + `"`, path: "config.py"})
	if strings.Contains(r.Reason, secret) || strings.Contains(r.Reason, "Zk9x") {
		t.Errorf("actionable reason leaks value: %s", r.Reason)
	}
	other := providerKey
	line := `password = login_data.password; stripe = "` + other + `"`
	r = run(tc{secret: "login_data.password", match: "password = login_data.password", line: line, path: "app.py", ruleID: "Hardcoded Password"})
	if strings.Contains(r.Reason, other) {
		t.Errorf("dismissed reason leaks a second literal: %s", r.Reason)
	}
}

func TestClassifyIsTotal(t *testing.T) {
	// odd inputs must never panic or yield an empty verdict
	for _, in := range []Input{{}, {Secret: "("}, {Line: "\x00\xff"}, {Secret: "a", FilePath: "/"}, {Match: "password=", Line: "password="}} {
		if r := Classify(in); r.Verdict == "" {
			t.Errorf("%+v: empty verdict", in)
		}
	}
}

func TestTag(t *testing.T) {
	r := run(tc{secret: "<your-api-key>", line: `api_key = "<your-api-key>"`, path: "a.py"})
	if r.Tag() != "placeholder" {
		t.Errorf("tag = %q", r.Tag())
	}
}

func BenchmarkClassify(b *testing.B) {
	in := Input{Secret: "Zk9x!q2LmP0vR7sT4wY1", Match: `DB_PASSWORD = "Zk9x!q2LmP0vR7sT4wY1"`,
		Line: `DB_PASSWORD = "Zk9x!q2LmP0vR7sT4wY1"`, FilePath: "settings.py", RuleID: "generic-api-key"}
	for i := 0; i < b.N; i++ {
		Classify(in)
	}
}

// Regression tests for the independent review of the port. Each case was a
// real secret dismissed, or raw material echoed, before the fix.
func TestReviewRegressions(t *testing.T) {
	const k = "q8Xk9mP2qR7vT4wZ8nB3cF6hJ1aL5s"
	const other = "Zq8Xk9mP2qR7vT4wZ8nB3cF6hJ1aL5sQ"

	// 1. Private-key names are not non-secret names; a generated literal is
	// never dismissed on its name alone.
	for _, c := range []tc{
		{secret: k, line: `ENCRYPTION_KEY = "` + k + `"`, path: "settings.py"},
		{secret: k, line: `JWT_SIGNING_KEY = "` + k + `"`, path: "settings.py"},
		{secret: k, line: `SSH_KEY=` + k, path: ".env"},
		{secret: k, line: `gpg_key: "` + k + `"`, path: "c.yml"},
		{secret: k, line: `api_id = "` + k + `"`, path: "c.py"}, // non-secret name, generated value
	} {
		if r := run(c); r.Verdict != LikelySecret || !r.Actionable {
			t.Errorf("%q must stay a likely secret: %+v", c.line, r)
		}
	}

	// 2. A context word on the line never dismisses a high-entropy value.
	for _, line := range []string{
		`api_key = "` + k + `"  # TODO: move to vault`,
		`requests.get("https://api.example.com/v1", headers={"api_key": "` + k + `"})`,
		`API_KEY_V2 = "` + k + `"  # api version 2`,
	} {
		if r := run(tc{secret: k, line: line, path: "a.py"}); !r.Actionable || suppressed(r) {
			t.Errorf("%q must stay counted: %+v", line, r)
		}
	}
	// ...but still dismisses a word-like value
	if r := run(tc{secret: "my-sample-value", line: `api_key = "my-sample-value"  # example`, path: "a.py"}); r.Actionable {
		t.Errorf("word-like value on an example line should be dismissed: %+v", r)
	}

	// 3 + 4. Reasons never carry source-line text or a clipped prefix of a
	// literal, whatever the verdict.
	for _, c := range []tc{
		{secret: "user_password", line: "password = user_password  # old: " + other, path: "x.py"},
		{secret: "password:", match: "password:", line: "if password: login(user, password); other_api_key = " + other, path: "x.py"},
		{secret: "", line: `the_very_long_database_password_variable_name = os.environ.get("DATABASE_PASSWORD", "` + other + `")`, path: "a.py"},
		{secret: "", line: `token = get_password("` + strings.Repeat("a", 60) + `", "` + other + `")`, path: "a.py"},
		{secret: "logger.info(", line: "logger.info(password) # " + other, path: "a.py"},
	} {
		c.ruleID = "Hardcoded Password"
		if c.match == "" {
			c.match = c.line
		}
		r := run(c)
		for n := 6; n <= len(other); n++ {
			if strings.Contains(r.Reason, other[:n]) {
				t.Errorf("reason leaks %d chars of a literal for %q: %s", n, c.line, r.Reason)
				break
			}
		}
	}
}

// Second review round: shapes the first fixes still mishandled.
func TestReviewRound2(t *testing.T) {
	const hex64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	const lower = "k3j9x8v2m4n7b5q1w6e0r8t2y4u9i3o7"
	const gen = "q8Xk9mP2qR7vT4wZ8nB3cF6hJ1aL5s"
	counted := func(r Result) bool { return r.Actionable && !suppressed(r) }

	// 1. A line word never dismisses a value it is not in.
	for _, c := range []struct{ value, rule, word string }{
		{"Tr0ub4dor&3", "generic-password", "# TODO: rotate"},
		{"hunter2xyz99", "generic-password", "# TODO: rotate"},
		{"Tr0ub4dor&3", "generic-api-key", "# example"},
		{"Xk9#mP2:qR7vT4wZ8nB3cF6", "generic-api-key", "# TODO: move to vault"},
		{"Xk9#mP2:qR7vT4wZ8nB3cF6", "generic-password", "# sample"},
		{hex64, "generic-api-key", "# example"},
		{lower, "generic-api-key", "# version 2"},
	} {
		key := "api_key"
		if strings.Contains(c.rule, "password") {
			key = "password"
		}
		line := key + ` = "` + c.value + `"  ` + c.word
		for _, in := range []Input{
			{Secret: c.value, Match: key + ` = "` + c.value + `"`, Line: line, FilePath: "a.py", RuleID: c.rule},
			{Match: line, Line: line, FilePath: "a.py", RuleID: c.rule},
		} {
			if r := Classify(in); !counted(r) {
				t.Errorf("%q (secret %q): %+v", line, in.Secret, r)
			}
		}
	}
	if r := run(tc{secret: "api-example-value-01", line: `api_key = "api-example-value-01"`, path: "a.py"}); r.Actionable {
		t.Errorf("a banlist word inside the value still dismisses: %+v", r)
	}

	// 2. A concatenated private key is judged by its real body and never quoted.
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4M2bS1GB4t7NXp98C3SC6dVM" +
		"vDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s"
	header, footer := "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
	line := `const k = "` + header + `\n" + "` + body + `\n" + "` + footer + `";`
	if r := run(tc{secret: line, match: line, line: line, path: "a.js", ruleID: "private-key"}); r.Verdict != LikelySecret ||
		!r.Actionable || strings.Contains(r.Reason, body[:8]) {
		t.Errorf("concatenated key: %+v", r)
	}
	pem := header + `\nNOTAREALKEY123\n` + footer
	if r := run(tc{secret: pem, match: pem, line: `"k": "` + pem + `"`, path: "c.json", ruleID: "private-key"}); r.Actionable ||
		strings.Contains(r.Reason, "NOTAREALKEY") {
		t.Errorf("short placeholder body: %+v", r)
	}

	// 3. Public halves, locators and cache keys are not secrets.
	for _, c := range []struct{ line, signal string }{
		{`verify_key = "` + hex64 + `"`, "non_secret_key_name"},
		{`verification_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"`, "non_secret_key_name"},
		{`ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl u@h"`, "public_key_material"},
		{`host_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY"`, "public_key_material"},
		{`kms_key = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"`, "non_secret_value"},
		{`encryption_key = "alias/aws/s3"`, "non_secret_value"},
		{`ssh_key = "~/.ssh/id_rsa"`, "non_secret_value"},
		{`cache_key = f"user:{uid}:profile"`, "non_secret_key_name"},
		{`CACHE_KEY = "users:list:v2"`, "non_secret_key_name"},
	} {
		if r := run(tc{match: c.line, line: c.line, path: "a.py"}); r.Actionable || !has(r, c.signal) {
			t.Errorf("%q: %+v", c.line, r)
		}
	}

	// 4. Key material under id-style names is not dismissed; hex ids are.
	for _, c := range []tc{
		{line: "SECRET_ID=" + lower, path: ".env"},
		{line: `vault_secret_id = "` + hex64 + `"`, path: "a.py"},
		{line: "ROLE_SECRET_ID=7c1e9d42-4f1a-4b8e-9a3d-2f6b8c0e1d57", path: ".env"},
		{line: `token_hash = "` + gen + `"`, path: "a.py"},
		{line: `secret_key_version: "` + gen + `"`, path: "c.yml"},
		{line: `cache_key = "` + gen + `"`, path: "a.py"},
	} {
		c.match = c.line
		if r := run(c); !counted(r) {
			t.Errorf("%q: %+v", c.line, r)
		}
	}
	if r := run(tc{match: `user_id = "` + hex64[:32] + `"`, line: `user_id = "` + hex64[:32] + `"`, path: "a.py"}); r.Actionable {
		t.Errorf("hex id under user_id should stay dismissed: %+v", r)
	}

	// Placeholder- or hash-looking values under credential names stay counted.
	for _, l := range []string{`db_password = "changeme9"`, `password = "your_Zx9kq2Lmw"`, `api_key = "` + hex64 + `"  # sha256 checksum`} {
		if r := run(tc{match: l, line: l, path: "a.py", ruleID: "generic-password"}); !counted(r) {
			t.Errorf("%q: %+v", l, r)
		}
	}
}

func TestMaskRevealsLittle(t *testing.T) {
	for _, c := range []struct {
		v     string
		shown int
	}{{"short1", 0}, {"elevenchars", 0}, {"twelve_chars", 2}, {"nineteen_characters", 2}, {"twenty_characters_x1", 4}} {
		m := mask(c.v)
		revealed := strings.NewReplacer("…", "", "***", "").Replace(strings.SplitN(m, " (", 2)[0])
		if len([]rune(revealed)) != c.shown || !strings.Contains(m, "("+strconv.Itoa(len(c.v))+" chars)") {
			t.Errorf("mask(%q) = %q", c.v, m)
		}
	}
}

func TestExtractStripsTrailingComment(t *testing.T) {
	for _, c := range []struct{ match, want string }{
		{"password = hunter2xyz99  # TODO: rotate", "hunter2xyz99"},
		{"password = hunter2xyz99 // old", "hunter2xyz99"},
		{`password = "a#b c"  # note`, "a#b c"},
		{"password = abc#123", "abc#123"},
	} {
		if got := ExtractCandidateValue("", c.match); got != c.want {
			t.Errorf("ExtractCandidateValue(%q) = %q, want %q", c.match, got, c.want)
		}
	}
}

// Third review round.
func TestReviewRound3(t *testing.T) {
	const gen = "q8Xk9mP2qR7vT4wZ8nB3cF6hJ1aL5s"
	counted := func(r Result) bool { return r.Actionable && !suppressed(r) }
	for _, c := range []struct{ key, value, rule string }{
		{"aws_secret_access_key", "/" + gen + "Wq9Yt2Zb4", "generic-api-key"}, // base64 secret starting with "/"
		{"secret", "/Xk9mP2qR7vT4wZ8nB3c/F6hJ1aL5sWq9Yt2Zb4dE", "generic-api-key"},
		{"password", "/Summer2024", "generic-password"},
		{"password", "./Passw0rd-x", "generic-password"},
		{"api_key", "alias/" + gen, "generic-api-key"},
		{"token", "arn:aws:x:" + gen, "generic-api-key"},
		{"password", "arn:aws:Summer2024", "generic-password"},
		{"api_key", "q8Xk9mP2qR7vT4/wZ8nB3cF6hJ1aL5s.key", "generic-api-key"},
		{"client_secret", "abc/" + gen + ".json", "generic-api-key"},
		{"password", "ssh-rsa AAAA" + gen, "generic-password"}, // no rsa wire prefix
		{"api_key", "q8Xk9mP2qR7vT4-example-wZ8nB3cF6hJ1aL5s", "generic-api-key"},
		{"api_key", "sk_live_q8Xk9mP2qR7vT4wZ8nB3c-fake-F6hJ1aL5s", "generic-api-key"},
		{"password", "Fake-Summer2024!", "generic-password"},
		{"password", "MyVersion-9xQ!", "generic-password"},
	} {
		line := c.key + ` = "` + c.value + `"`
		if r := Classify(Input{Secret: c.value, Match: line, Line: line, FilePath: "a.py", RuleID: c.rule}); !counted(r) {
			t.Errorf("%q: %+v", line, r)
		}
	}
	// a Secrets Manager SecretId holds a secret NAME
	for _, l := range []string{`SecretId = "prod/db/credentials"`, `secret_id = "prod/db/creds"`} {
		if r := run(tc{match: l, line: l, path: "a.py"}); r.Actionable {
			t.Errorf("%q: %+v", l, r)
		}
	}
	// actionable reasons keep backtick spans intact
	r := run(tc{secret: "changeme", match: `password = "changeme"`, line: `password = "changeme"`, path: "config.py"})
	if !strings.Contains(r.Reason, "`*** (8 chars)`") || strings.Contains(r.Reason, "…`") {
		t.Errorf("mangled reason: %s", r.Reason)
	}
}

// Fourth review round: generated secrets shaped like locators.
func TestReviewRound4(t *testing.T) {
	const gen = "q8Xk9mP2qR7vT4wZ8nB3cF6hJ1aL5s"
	counted := func(r Result) bool { return r.Actionable && !suppressed(r) }
	for _, c := range []struct{ key, value string }{
		{"aws_secret_access_key", "/q8Xk9mP2/qR7vT4wZ/8nB3cF6h/J1aL5sWq/9Yt2"},
		{"api_secret", "/q8Xk9mP2qR/vT4wZ8nB3c"},
		{"secret", "/Summer2024"},
		{"client_secret", "~/Xk9mP2qR7v/T4wZ8nB3cF"},
		{"api_key", "alias/q8Xk9mP2/qR7vT4wZ8/nB3cF6hJ1"},
		{"api_key", "arn:aws:s3:::" + gen},
		{"api_key", "arn:aws:iam::123456789012:" + gen},
		{"api_key", "q8Xk9mP2/qR7vT4wZ8.key"},
		{"password", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5" + gen},
		{"token", "ssh-rsa AAAAB3NzaC1yc2E" + gen},
		{"secret_id", "7c1e9d42-4f1a-4b8e-9a3d-2f6b8c0e1d57"},
	} {
		rule := "generic-api-key"
		if c.key == "password" {
			rule = "generic-password"
		}
		line := c.key + ` = "` + c.value + `"`
		if r := Classify(Input{Secret: c.value, Match: line, Line: line, FilePath: "a.py", RuleID: rule}); !counted(r) {
			t.Errorf("%q: %+v", line, r)
		}
	}
	for _, c := range []struct{ line, signal string }{
		{`kms_key = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"`, "non_secret_value"},
		{`encryption_key = "alias/aws/s3"`, "non_secret_value"},
		{`ssh_key = "~/.ssh/id_rsa"`, "non_secret_value"},
		{`SecretId = "prod/db/credentials"`, "non_secret_key_name"},
	} {
		if r := run(tc{match: c.line, line: c.line, path: "a.py"}); r.Actionable || !has(r, c.signal) {
			t.Errorf("%q: %+v", c.line, r)
		}
	}
}
