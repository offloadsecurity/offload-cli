package verdict

import "regexp"

// All patterns are compiled once at package init. Go's RE2 engine has no
// lookaround or backreferences, so the few rules that need them are written
// with explicit boundary groups or quote alternatives, and the caller reads
// the relevant submatch.

var re = regexp.MustCompile

// referenceRes: environment-variable, template and secret-store references.
// The credential is resolved at runtime; the literal in source is a name.
var referenceRes = []*regexp.Regexp{
	re(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`), // $VAR / ${VAR}
	re(`^\$\{[^}]+\}$`),                    // ${VAR:-default}
	re(`\$\{\{\s*[\w.\-]+\s*\}\}`),         // ${{ secrets.X }}
	re(`\{\{[^{}]*\}\}`),                   // {{ .Values.x }} / Jinja
	re(`^%[A-Za-z_][A-Za-z0-9_]*%$`),       // %VAR% (Windows)
	re(`<%=?[^%]*%>`),                      // ERB / EJS
	re(`^\$\([^)]*\)$`),                    // $(cat file)
	re("^`[^`]*`$"),                        // `cmd`
	re(`\bprocess\.env\.[A-Za-z_]`),
	re(`\bimport\.meta\.env\.[A-Za-z_]`),
	re(`\bos\.(environ|getenv)\b`),
	re(`\bSystem\.getenv\b`),
	re(`\bENV\[|\bENV\.fetch\b|\bgetenv\(`),
	re(`\bsecrets\.[A-Za-z_]`),                   // GitHub Actions
	re(`\b(secretKeyRef|secretRef|valueFrom)\b`), // Kubernetes
	re(`(?i)\barn:aws:secretsmanager:`),
	re(`(?i)\bprojects/[^/\s]+/secrets/`), // GCP Secret Manager
	re(`(?i)\bvault:|\bvault\.|\bkv/`),
	re(`(?i)^!Ref\b|^!Sub\b|\{\{resolve:`),                      // CloudFormation
	re(`\bvar\.[A-Za-z_]|\blocal\.[A-Za-z_]|\bdata\.[A-Za-z_]`), // Terraform
	re(`(?i)@Value\(\s*['"]\$\{`),                               // Spring
	// config.get(...) is deliberately not a reference: a config file may
	// itself be committed, so it stays a candidate (unresolved call).
}

// formatPlaceholderRes (gitleaks global allowlist): values a template, format
// string or positional mechanism fills in at runtime, or that are not values.
var formatPlaceholderRes = []*regexp.Regexp{
	re(`^(?i:true|false|null|none|nil|undefined)$`),
	re(`^\$(?:\d+|\{\d+\})$`),                // $1 / ${1}
	re(`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`), // %s / %d
	re(`^\{\d{0,2}\}$`),                      // {0} / {}
	re(`^@[A-Za-z_][A-Za-z0-9_]*@$`),         // @VAR@ (autoconf)
	re(`^/Users/[A-Za-z0-9._-]+/[\w ./-]+$`), // local paths
	re(`^/(?:bin|etc|home|opt|tmp|usr|var|srv|mnt|root)/[\w ./-]+$`),
	re(`^[A-Za-z]:\\[\w \\./-]+$`),   // C:\path
	re(`^\?[A-Za-z_][A-Za-z0-9_]*$`), // ?param (SQL)
}

// nonSecretKeyRe (gitleaks generic-api-key allowlist): assignment names that
// contain a credential word but never hold one.
var nonSecretKeyRe = re(`(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version|` +
	`url|uri|endpoint|host|base|path|root|prefix|docs?)|(?:credentials?|token|key|secret)[_.-]?` +
	`(?:id|name|file|path|url|uri|endpoint|length|size|ref|arn|alias|type|kind|version|ttl|` +
	`expiry|expires?|expiration|prefix|suffix|header|param|field|column|index|hash|digest|` +
	`fingerprint|store|storetype|vault|manager|provider)|(?:bucket|foreign|hot|idx|natural|` +
	`primary|pub(?:lic)?|schema|sequence|sort|partition|shard|cache|composite|unique|verify|verification)` +
	`[_.-]?key|key[_.-]?(?:board|` +
	`code|frame|mesh|pair|press(?:ed)?|ring|selector|signature|stone|word|up|down|left|right|` +
	`stroke|map|set|space|binding|combo|event|handler)|key(?:store|tab)[_.-]?(?:file|path)|` +
	`issuerkeyhash|[dm]onkey|keying|UserSecretsId|csrf[_.-]?token|xsrf[_.-]?token|` +
	`(?:api|credentials|token|auth)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|` +
	`token[_.-]?(?:type|count|limit|max|min|budget|usage|ization|izer|ise|ize)|` +
	`(?:max|min|num|n)[_.-]?tokens|password[_.-]?(?:field|input|hash|hint|policy|rules?|` +
	`length|min|max|strength|reset|change|confirm|form|label|error|invalid|expired|required|` +
	`placeholder|prompt|regex|pattern|validator)|hash(?:ed)?[_.-]?password|` +
	`(?:^|[_.-])(?:id|uuid|guid)$)`)

// Private-key names (encryption, signing, ssh, gpg, pgp, kms, host keys) are
// deliberately absent from the [_.-]?key group above: they name real secret
// material. A verify/verification key is the public half and a cache key is a
// lookup key; key material under any of these names still overrides.

// publicKeyNameRe: names of public material, which keep the key-name
// dismissal even for a generated-looking value.
var literalTokenRe = re(`^[A-Za-z0-9+/_\-=.~!@#$%^&*]+$`)

var publicKeyNameRe = re(`(?i)pub(?:lic)?[_.-]?(?:key|token)|verif(?:y|ication)[_.-]?key`)

// secretIDKeyRe: a secret_id (e.g. a Vault AppRole SecretID) is a credential,
// never an identifier.
var secretIDKeyRe = re(`(?i)secret[_.-]?ids?$`)

// publicSSHKeyRe: an SSH/ECDSA public key value. The wire format starts with
// the key type, so a real key's base64 blob has a type-specific prefix; a
// bare "AAAA" is not enough.
var publicSSHKeyRe = re(`^(?:ssh-rsa\s+AAAAB3NzaC1yc2E|ssh-dss\s+AAAAB3NzaC1kc3M|ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5|` +
	`ecdsa-sha2-nistp\d+\s+AAAAE2VjZHNhLXNoYTItbmlzdHA)[A-Za-z0-9+/=]*(?:\s|$)`)

// arnRe: a real ARN (arn:partition:service:region:account-or-empty:resource).
var arnRe = re(`^arn:aws[\w-]*:[a-z0-9-]+:[a-z0-9-]*:(?:\d{12})?:`)

// locatorRe: a key alias or a path to key material (see nonSecretValue).
var locatorRe = re(`^(?:alias/[\w/.-]+|(?:~|\.{1,2})?/[\w ./-]+|` +
	`[\w.-]+(?:/[\w.-]+)+\.(?:pem|key|pub|crt|cer|der|p12|pfx|jks|json|txt|asc|gpg))$`)

var segmentSepRe = re(`[/:]`)

// locatorSepRe: separators removed before judging a locator as a whole.
var locatorSepRe = re(`[/:.~\-]`)

// uuidAnyRe: a UUID anywhere (a KMS key id in an ARN resource).
var uuidAnyRe = re(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// pemJointRe: joints left by a PEM block written as concatenated literals.
var pemJointRe = re("[\"'`]\\s*(?:\\+|\\.{1,2}|&|~)\\s*[\"'`]")

// pemQuoteWSRe: whitespace and quotes inside a PEM body.
var pemQuoteWSRe = re("[\\s'\"`]")

// idKeyRe (detect-secrets is_likely_id_string): the variable is an identifier.
var idKeyRe = re(`(?i)(?:^(?:id|myid|userid)|_id)s?$`)

// sequences (detect-secrets is_sequential_string): a value that is a run of
// one of these alphabets.
var sequences = []string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ+/",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"012345678901234567890123456789",
	"0123456789ABCDEF0123456789ABCDEF",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ=/",
	"QWERTYUIOPASDFGHJKLZXCVBNM",
	"!@#$%^&*()_+",
}

// hashedOrEncryptedRe: hashed / encrypted forms are not plaintext credentials
// (a bcrypt digest cannot be presented as a password).
var hashedOrEncryptedRe = re(`(?i)^(?:\$2[abxy]?\$\d{2}\$|\$argon2(?:i|d|id)\$|\$(?:1|5|6|7|y|gy|md5|sha1|apr1)\$|` +
	`\{(?:SHA|SSHA|MD5|SMD5|CRYPT|bcrypt|pbkdf2|argon2|noop|cipher|sha256|ssha256|sha512)\}|` +
	`ENC\(|ENC\[AES256_GCM|vault:v\d+:|AQICAHh|pbkdf2[_:$]|scrypt[_:$]|md5\$|sha1\$|` +
	`sha256\$|AES\b|RSA\b|\{aes\}|\{rsa\}|age1|-----BEGIN PGP MESSAGE|` +
	`\{\{\s*resolve:secretsmanager)`)

// contextBanlistRe: words near the match that mark an example or a version
// string rather than a credential. Group 1 is the word.
var contextBanlistRe = re(`(?i)(?:^|[^A-Za-z0-9])(example|sample|dummy|placeholder|fake|mock|for[_ -]?testing|` +
	`e\.g\.|i\.e\.|version|changelog|deprecated|todo:|fixme:|lorem|ipsum|` +
	`password\s+(?:is|was)\s+(?:invalid|incorrect|wrong|required|too|must))(?:[^A-Za-z0-9]|$)`)

// ghChecksumTokenRe: GitHub-family tokens carry a base62 CRC32 of the body.
var ghChecksumTokenRe = re(`^(gh[pousr]_|npm_)([0-9A-Za-z]{30})([0-9A-Za-z]{6})$`)

var swaggerPathRe = re(`(?i)swagger`)

// fallbackRule: a literal default next to an external lookup is a usable
// credential the repository controls:
//
//	os.getenv("X", "Secret123")   get_secret("X") or "Secret123"
//	process.env.X || "Secret123"  ${X:-Secret123}   x ?? "Secret123"
type fallbackRule struct {
	re     *regexp.Regexp
	callee int   // submatch index of the callee, 0 when the rule has none
	fb     []int // submatch indexes holding the fallback (first non-empty wins)
}

var fallbackRules = []fallbackRule{
	{re(`([\w.]+)\(\s*['"][^'"]*['"]\s*,\s*(?:'([^'"]+)'|"([^'"]+)")\s*\)`), 1, []int{2, 3}},
	{re(`([\w.]+)\([^()]*\)\s*(?:\bor\b|\|\||\?\?)\s*(?:'([^'"]+)'|"([^'"]+)")`), 1, []int{2, 3}},
	{re(`\b(?:process\.env|os\.environ|ENV)[.\[][\w'"\]]+\s*(?:\|\||\?\?|or)\s*(?:'([^'"]+)'|"([^'"]+)")`), 0, []int{1, 2}},
	{re(`\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]+)\}`), 0, []int{1}},
	{re(`\bdefault\s*[:=]\s*(?:'([^'"]+)'|"([^'"]+)")`), 0, []int{1, 2}},
}

// runtimeCalleeRe: calls whose result is not repository-controlled (runtime
// input, generated, environment, secret store).
var runtimeCalleeRe = re(`(?i)\b(getpass|input|prompt|read[_-]?line|readline|stdin|read-host|console\.read|` +
	`request\.|req\.|form\.|params|args\.|argv|flags\.|cli\.|generate|random|urandom|` +
	`secrets\.token|token_(?:hex|urlsafe|bytes)|uuid|nanoid|crypto\.random|` +
	`getenv|environ|env\.get|process\.env|system\.getenv|` +
	`get_?secret|secret_?(?:client|manager|store|value)|secretsmanager|fetch_?secret|` +
	`read_?secret|vault|keyvault|key_?vault|ssm|get_?parameter|parameter_?store|credential_?provider|` +
	`kms|decrypt_?with_?kms|from_?keychain|keychain|keyring)`)

// unresolvedCalleeRe: calls that read from somewhere that may itself be
// committed. Kept as a candidate, never a confident dismissal.
var unresolvedCalleeRe = re(`(?i)\b(config|conf|cfg|settings?|props|properties|options|decode|decrypt|unhex|` +
	`b64|base64|hex|deobfuscate|unscramble|rot13|load|read|parse|fetch|lookup|resolve|` +
	`get|find|obtain|retrieve)`)

// varArgRe: one call argument that is a variable reference.
var varArgRe = re(`^(?:[A-Za-z_]\w*\s*=\s*)?[$@]?[A-Za-z_][\w$]*(?:(?:\.|->|::)[A-Za-z_][\w$]*)*$`)

var verifyCalleeRe = re(`(?i)\b(bcrypt|argon2|scrypt|pbkdf2|hashpw|checkpw|check_?password|verify|matches|compare|` +
	`authenticate|validate|is_?valid|hash|digest|hmac|encode|encrypt|cipher|make_?password|set_?password|` +
	`password_?encoder|passwordencoder|login|sign_?in|signin|auth)`)

// encodedLiteralArgRe: an encoded literal passed straight into a call.
// The material is in submatch 1 or 2.
var encodedLiteralArgRe = re(`\(\s*(?:b|r|u)?(?:'([A-Za-z0-9+/=_-]{8,}|[0-9a-fA-F]{16,})'|"([A-Za-z0-9+/=_-]{8,}|[0-9a-fA-F]{16,})")\s*[,)]`)

var concatRe = re(`(?:'[^'"]+'|"[^'"]+")\s*(?:\+|\.|\.\.|&|~)\s*(?:'[^'"]+'|"[^'"]+")`)

var passwordRuleRe = re(`(?i)pass(word|wd|phrase)?|pwd`)

var passwordFlagRe = re(`(?:^|[^A-Za-z])(?:-p|--password|--pass|-pw)[\s=]`)

// structuralPlaceholderRe: placeholders by shape (not by being a common
// word). These stay a confident dismissal even under password rules.
var structuralPlaceholderRe = re(`(?i)^(?:x{3,}|\*{3,}|#{3,}|\.{3,}|-{3,}|_{3,}|<[^<>]+>|\[[^\[\]]+\]|\{[^{}]+\}|` +
	`your[_ -].*|.*[_ -]here$|insert[_ -].*|enter[_ -].*|replace[_ -].*|` +
	`\$\{.*\}|redacted|\[redacted\]|<redacted>|removed|\*+removed\*+)$`)

var (
	anglePlaceholderRe  = re(`^<[^<>]{1,80}>$`)
	squarePlaceholderRe = re(`^\[[^\[\]]{1,120}\]$`)
	bracePlaceholderRe  = re(`^\{[^{}]{1,80}\}$`)
)

// placeholderWords carry an explicit "this is not real" marker. Credential
// nouns (password, secret, token) and common weak passwords (admin, root,
// test, default) are deliberately absent: password = "admin" IS a hardcoded
// credential.
var placeholderWords = toSet(
	"changeme", "change_me", "change-me", "changeit", "change_this", "replace_me",
	"replaceme", "placeholder", "example", "sample", "dummy", "fake", "redacted",
	"removed", "todo", "fixme", "tbd", "null", "none", "nil", "undefined", "empty",
	"value", "string", "xxx", "yyy", "zzz", "foo", "bar", "baz", "insert_here",
	"your_password_here", "your_api_key_here", "your_key_here", "your_token_here",
	"enter_password", "enter_your_password", "your-password", "your_password",
	"n/a", "na", "unset", "notset", "not_set", "<none>", "***", "****",
)

var (
	placeholderPrefixRe = re(`(?i)^(your|my|the|insert|enter|replace|put|add|set|paste|type)[_\-\s]`)
	placeholderSubstrRe = re(`(?i)(example|placeholder|dummy|changeme|change[_-]me|redacted|your[_-]?(api[_-]?)?` +
		`(key|token|secret|password|pass)|xxxx|not[_-]?a[_-]?real|fake[_-]?(key|token|secret))`)
	maskedRe     = re(`^[*xX#\-_.•]{3,}$`)
	sequentialRe = re(`(?i)^(0123456789|1234567890|123456|abcdefgh|abcdefghijklmnop|qwerty|asdfgh)`)
	proseRe      = re(`^[A-Za-z][A-Za-z' ,.\-]*$`)
)

var proseStopwords = toSet("the", "you", "your", "a", "an", "this", "that", "here", "enter", "please",
	"is", "are", "to", "of", "in", "for", "with", "was", "entered", "provided")

var (
	identifierRe = re(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// member access / call / subscript / arrow / scope: login_data.password,
	// request.form['password'], getpass(), $this->password, Config::get('x')
	expressionRe = re(`^[A-Za-z_$@][A-Za-z0-9_$]*(\s*(\.|->|::)\s*[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\]|\([^()]*\))+\s*;?$`)
	callRe       = re(`^[A-Za-z_][A-Za-z0-9_.]*\([^()]*\)$`)
	logicLineRe  = re(`(?i)^\s*(if|elif|else\s+if|while|unless|until|return|assert|raise|throw|for|foreach|` +
		`when|case|switch|and|or|not|def|fn|func|function|public|private|protected|static|` +
		`async|export|const|let|var|val|lambda)\b`)
	signatureRe  = re(`\b(def|function|fn|func)\s+\w+\s*\(|=>\s*\{?$|\)\s*(\{|:)\s*$`)
	comparisonRe = re(`(==|!=|===|!==|<=|>=|\bis\b|\bin\b|\bnot\b|\band\b|\bor\b|&&|\|\|)`)
)

const keyedAssignBody = `(?P<key>[\w\-.]*?(pass(word|wd|phrase)?|pwd|secret|token|key|auth|credential|cred|api)` +
	`[\w\-.]*)\s*(?P<op>[:=]|=>|:=)\s*(?P<val>[^\r\n]*?)\s*[,;]?\s*$`

var (
	// keyedAssignRe: password = value / password: value with a credential-named
	// key. A whole-statement match hands us this; gitleaks' Secret never has a key.
	keyedAssignRe       = re(`(?i)^` + keyedAssignBody)
	keyedAssignSearchRe = re(`(?i)(?:^|[^A-Za-z0-9_])` + keyedAssignBody)
	// tokenBlobRe: a bare token, never an assignment.
	tokenBlobRe   = re(`^[A-Za-z0-9+/_\-]+={0,2}$`)
	urlCredRe     = re(`^[A-Za-z][A-Za-z0-9+.\-]*://[^/\s:@]+:(?P<cred>[^@\s]+)@`)
	stmtSepRe     = re(`[\s=:]`)
	bearerRe      = re(`(?i)^bearer\s+`)
	pemHeaderRe   = re(`(?i)-----BEGIN (?P<label>[A-Z0-9 _-]*?)(?P<kind>PRIVATE KEY|PUBLIC KEY|CERTIFICATE|EC PARAMETERS)[A-Z ]*-----`)
	pemFullRe     = re(`(?is)-----BEGIN (?P<label>[A-Z0-9 _-]*?)(?P<kind>PRIVATE KEY|PUBLIC KEY|CERTIFICATE|EC PARAMETERS)[A-Z ]*-----(?P<body>.*?)-----END`)
	escapedWSRe   = re(`\\[nrt]`)
	whitespaceRe  = re(`\s+`)
	base64BodyRe  = re(`^[A-Za-z0-9+/=_\-]+$`)
	hexRe         = re(`^[0-9a-fA-F]+$`)
	hex16Re       = re(`^[0-9a-fA-F]{16,}$`)
	base64ishRe   = re(`^[A-Za-z0-9+/]{12,}={0,2}$`)
	lettersOnlyRe = re(`^[A-Za-z_.\-]+$`)
	uuidRe        = re(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// hashContextRe: "_" counts as a separator (integrity_hash). Group 1 is the word.
	hashContextRe = re(`(?i)(?:^|[^A-Za-z0-9])(sha\d*|hash|digest|checksum|integrity|commit|etag|md5|crc|blake|` +
		`fingerprint|revision|rev)(?:[^A-Za-z0-9]|$)`)
	credKeywordRe = re(`(?i)(secret|token|api[_-]?key|password|passwd|pwd|credential)`)
	commentLineRe = re(`(?i)^\s*(#|//|/\*|\*|--|<!--|;|rem\b|"""|''')`)
	logLineRe     = re(`(?i)^\s*(echo|print(ln|f)?|console\.\w+|log(ger)?\.\w+|logging\.\w+|puts|fmt\.Print\w*|` +
		`System\.out\.print\w*|printf|write(ln)?|Write-Host|raise|throw|return)\b`)
	// quotedLiteralRe: a quoted literal longer than 8 characters, for masking.
	quotedLiteralRe = re("'[^'\"`\\n]{9,}'|\"[^'\"`\\n]{9,}\"|`[^'\"`\\n]{9,}`")
	// assignKeyLeftRe / assignKeyStmtRe: the name on the left of an assignment.
	assignKeyLeftRe = re("([A-Za-z_][\\w.\\-\\[\\]'\"]*)\\s*(?:[:=]|=>|:=|\\|\\|)\\s*[`'\"]?\\s*$")
	assignKeyStmtRe = re(`^\s*(?:export\s+|ENV\s+|ARG\s+|const\s+|let\s+|var\s+|val\s+|final\s+)?` +
		`([A-Za-z_][\w.\-]*)\s*(:=|=>|[:=])`)
)

// codeExts: languages where an unquoted right-hand side is a variable.
var codeExts = toSet(
	".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".scala",
	".go", ".rb", ".php", ".cs", ".fs", ".vb", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp",
	".m", ".mm", ".swift", ".dart", ".lua", ".pl", ".pm", ".r", ".jl", ".ex", ".exs",
	".erl", ".hs", ".clj", ".groovy", ".gradle", ".vue", ".svelte", ".sql", ".tf",
)

var docExts = toSet(".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt", ".html", ".htm")

var docNames = toSet("readme", "changelog", "changes", "history", "license", "licence", "contributing",
	"authors", "notice", "security", "install", "upgrade", "faq")

var docDirs = []string{"/docs/", "/doc/", "/documentation/", "/wiki/", "/guides/", "/man/"}

var testDirs = []string{"/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/__mocks__/",
	"/fixtures/", "/fixture/", "/mocks/", "/mock/", "/testdata/", "/test_data/",
	"/e2e/", "/integration/", "/cypress/", "/examples/", "/example/", "/samples/",
	"/sample/", "/demo/", "/demos/", "/stubs/", "/snapshots/", "/__snapshots__/"}

var testFileRe = re(`(?i)(^|[/_.\-])(test|tests|spec|specs|fixture|fixtures|mock|mocks|stub|stubs|example|` +
	`examples|sample|samples|demo|fake)([/_.\-]|$)`)

var lockFiles = toSet("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
	"cargo.lock", "poetry.lock", "pipfile.lock", "gemfile.lock", "go.sum",
	"packages.lock.json", "mix.lock", "pubspec.lock", "flake.lock")

var vendoredDirs = []string{"/node_modules/", "/vendor/", "/dist/", "/build/", "/.venv/", "/venv/",
	"/site-packages/", "/bower_components/", "/third_party/", "/thirdparty/"}

// genericRuleTokens: rule ids whose regex targets a shape ("something after
// password=") rather than a provider's credential format.
var genericRuleTokens = []string{
	"generic", "password", "passwd", "hardcoded", "secret key", "secret-key", "secret_key",
	"api key", "api-key", "api_key", "apikey", "bearer", "credential", "connection string",
	"connection-string", "basic-auth", "basic auth", "custom", "high-entropy", "entropy",
	"authorization", "auth-token", "auth token", "jwt",
}

func toSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}
