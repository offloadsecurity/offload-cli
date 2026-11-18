// Package verdict decides whether a secrets-scanner match is a credential or
// code that merely mentions one.
//
// A pattern that matches `password` also matches `--password="${MONGO_PASS}"`,
// `password = login_data.password` and `if username and password:`, none of
// which put a credential in source. Classify turns a match into a verdict a
// reviewer can audit: a verdict, a confidence, the signals that fired, and a
// one-sentence reason.
//
// Evidence, in priority order: private-key body sanity, the value's kind
// (env/template reference, runtime expression, control flow, placeholder,
// prose), hash and identifier look-alikes, file context (docs, tests,
// lockfiles), then credential format and entropy.
//
// Safety rules:
//   - No confident non-secret without cited evidence. A hardcoded literal that
//     merely looks weak stays likely_secret: a weak password in source is still
//     a leaked password. Only a reference, an expression, control flow or a
//     recognised placeholder earns a high-confidence dismissal.
//   - The reason never echoes a value the verdict says may be real: an
//     actionable verdict's reason has the value masked and every quoted literal
//     shortened to a stub.
//   - Pure: Classify does no I/O.
//
// The rules draw on public sources: the gitleaks default configuration (MIT;
// its global allowlist, the generic-api-key letters-only and key-name
// allowlists, and its stopword list, see NOTICE), the heuristic filters
// documented by Yelp detect-secrets, GitGuardian's documented post-validators
// for generic password detectors, and GitHub's published token format with its
// built-in CRC32 checksum.
package verdict

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Verdict uses the Offload platform's verdict vocabulary. (confirmed_secret,
// which needs live provider validation, is never produced by the CLI.)
type Verdict string

const (
	// LikelySecret: treat as a real credential.
	LikelySecret Verdict = "likely_secret"
	// LikelyFalsePositive: probably not a credential.
	LikelyFalsePositive Verdict = "likely_false_positive"
	// NotASecret: the match is code, a reference or a non-secret value.
	NotASecret Verdict = "not_a_secret"
)

// Confidence is high, medium or low, derived from Score.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Version identifies the heuristic set, so a stored verdict can be told apart
// from one produced by later rules.
const Version = 4

var labels = map[Verdict]string{
	LikelySecret:        "Likely secret",
	LikelyFalsePositive: "Likely false positive",
	NotASecret:          "Not a secret",
}

// Input is one secrets match, before redaction.
type Input struct {
	Secret   string   // the captured secret (gitleaks "Secret")
	Match    string   // the whole regex match (gitleaks "Match")
	Line     string   // the source line the match is on, if known
	Context  string   // optional surrounding lines (used for PEM bodies)
	FilePath string   // path of the file, relative or absolute
	RuleID   string   // scanner rule id
	Entropy  *float64 // scanner-reported entropy; computed when nil
}

// Result is a verdict a reviewer can audit. It never carries the raw value
// of a finding that may be real.
type Result struct {
	Verdict    Verdict    `json:"verdict"`
	Label      string     `json:"label"`
	Confidence Confidence `json:"confidence"`
	Score      float64    `json:"score"`
	Reason     string     `json:"reason"`
	Signals    []string   `json:"signals"`
	// Actionable is false only for a high-confidence likely_false_positive
	// or not_a_secret. Those findings stay visible but are dismissed: they
	// do not count toward the CI gate.
	Actionable bool   `json:"actionable"`
	Method     string `json:"method"`
	Version    int    `json:"version"`
}

// Dismissed reports whether the verdict dismisses the finding.
func (r Result) Dismissed() bool { return !r.Actionable }

// NonSecret reports whether the verdict is one of the non-secret verdicts
// (at any confidence).
func (r Result) NonSecret() bool {
	return r.Verdict == LikelyFalsePositive || r.Verdict == NotASecret
}

func confidenceFor(score float64) Confidence {
	switch {
	case score >= 0.8:
		return High
	case score >= 0.55:
		return Medium
	default:
		return Low
	}
}

func result(v Verdict, score float64, reason string, signals []string, extra []string) Result {
	seen := map[string]bool{}
	sigs := make([]string, 0, len(signals)+len(extra))
	for _, s := range append(append([]string{}, signals...), extra...) {
		if !seen[s] {
			seen[s] = true
			sigs = append(sigs, s)
		}
	}
	conf := confidenceFor(score)
	nonSecret := v == LikelyFalsePositive || v == NotASecret
	return Result{
		Verdict:    v,
		Label:      labels[v],
		Confidence: conf,
		Score:      round2(score),
		Reason:     reason,
		Signals:    sigs,
		Actionable: !(nonSecret && conf == High),
		Method:     "heuristic",
		Version:    Version,
	}
}

func fmtFloat(f float64) string { return strconv.FormatFloat(round2(f), 'f', -1, 64) }

// Classify returns the verdict for one secrets match. It never panics: an
// internal error yields a low-confidence likely_secret, so a verdict failure
// can never hide a finding.
func Classify(in Input) (res Result) {
	defer func() {
		if recover() != nil {
			res = result(LikelySecret, 0.5, "Verdict could not be computed; treat as a possible secret until reviewed.",
				[]string{"verdict_error"}, nil)
		}
	}()
	res = classify(in)
	judged := ExtractCandidateValue(in.Secret, in.Match)
	if res.Actionable || !res.NonSecret() {
		// Anything a reviewer will act on is redacted: the raw inputs and the
		// value the classifier judged are masked, quoted literals stubbed.
		// Backtick spans are the reason's own quoting (masks, words): kept.
		res.Reason = stubLiterals(maskValues(res.Reason, in.Secret, in.Match, judged), false)
	} else {
		// Even a dismissal never quotes the scanner's raw value: a verdict
		// is a heuristic, and output must not carry a credential if it is
		// wrong. The value is masked (the tag and signals still say what it
		// is), and quoted literals from the source line are stubbed, so a
		// second secret sharing the line is never echoed either.
		raw := in.Secret
		if strings.Contains(raw, judged) {
			raw = "" // a whole statement around the judged value: masking the value is enough
		}
		res.Reason = stubLiterals(maskValues(res.Reason, raw, judged), false)
	}
	return res
}

func classify(in Input) Result {
	line := norm(in.Line)
	if line == "" {
		line = norm(in.Match)
	}
	line = firstLine(line)
	value := completeExpression(ExtractCandidateValue(in.Secret, in.Match), line)
	fp := strings.ReplaceAll(in.FilePath, `\`, "/")
	ext := pyExt(fp)
	base := strings.ToLower(baseName(fp))
	sl := slashed(fp)
	generic := IsGenericRule(in.RuleID)
	var ctx []string

	if commentLineRe.MatchString(line) && !strings.HasPrefix(strings.ToUpper(strings.TrimLeft(line, " \t")), "-----BEGIN") {
		ctx = append(ctx, "in_comment")
	}
	if containsAny(sl, vendoredDirs) {
		ctx = append(ctx, "vendored_path")
	}

	// PEM blocks are judged by their body, whatever the value kind says.
	if r, ok := pemAssessment(value, in.Context, ctx); ok {
		return r
	}

	// Reasons never quote the source line (it can carry a second, unquoted
	// secret) and describe the value only by its mask, built from the whole
	// value, so clipping can never cut a literal out from under the masking.
	shown := describe(value)
	// "Password" context comes from the rule, the key, the line, or a URL
	// credential: a human-chosen password may be a dictionary word, so it is
	// medium at most, never a confident dismissal.
	urlCred := isURLCredential(in.Secret, in.Match)
	key := assignmentKey(line, value)
	passwordRule := urlCred || passwordRuleRe.MatchString(norm(in.RuleID)) ||
		passwordRuleRe.MatchString(norm(key)) || passwordFlagRe.MatchString(line)

	// The assignment name says it is not a credential: api_version, key_file,
	// public_key, csrf_token, user_id.
	// A generated-looking literal (long, mixed case + digits, high entropy)
	// is judged on its value, whatever the name: the name alone never
	// dismisses key material. Public-key names keep the dismissal.
	if publicSSHKeyRe.MatchString(value) {
		return result(NotASecret, 0.92, "Value is an SSH public key, not a private credential.",
			[]string{"public_key_material"}, ctx)
	}
	// A secret_id holding key material is a credential (Vault AppRole); one
	// holding a name (Secrets Manager "prod/db/credentials") is not.
	secretID := secretIDKeyRe.MatchString(key) &&
		(keyMaterial(value) || uuidRe.MatchString(value) || (hexRe.MatchString(value) && len(value) >= 32))
	nameOnly := (!keyMaterial(value) || publicKeyNameRe.MatchString(key)) && !secretID
	if key != "" && generic && nameOnly && (nonSecretKeyRe.MatchString(key) || idKeyRe.MatchString(key)) {
		return result(NotASecret, 0.9, fmt.Sprintf("`%s` names a non-secret (an identifier, version, path, "+
			"public key, endpoint or setting), not a credential.", describeName(key)), []string{"non_secret_key_name"}, ctx)
	}

	// Repository-controlled material next to an external lookup: a literal
	// fallback/default, a static concatenation, or an encoded literal
	// argument. Judged on the line, because the captured value is the lookup.
	for _, rule := range fallbackRules {
		m := rule.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if rule.callee > 0 {
			callee := m[rule.callee]
			if !runtimeCalleeRe.MatchString(callee) && !unresolvedCalleeRe.MatchString(callee) {
				continue // os.path.join("a", "b") is not a lookup with a default
			}
		}
		fb := ""
		for _, i := range rule.fb {
			if m[i] != "" {
				fb = norm(m[i])
				break
			}
		}
		if fb != "" {
			if k, _ := valueKind(fb, `x = "`+fb+`"`, in.FilePath, false); k == "literal" && !structuralPlaceholderRe.MatchString(fb) {
				return result(LikelySecret, 0.78, fmt.Sprintf("A hardcoded fallback/default sits next to the external lookup on "+
					"this line; the literal is usable whenever the lookup is unset. Remove the default; fail closed instead."),
					[]string{"hardcoded_fallback_literal"}, ctx)
			}
		}
		break
	}
	if concatRe.MatchString(line) && credKeywordRe.MatchString(line) {
		return result(LikelySecret, 0.7, fmt.Sprint("The line builds the value by concatenating string literals, a "+
			"statically reconstructable credential."), []string{"static_concatenation"}, ctx)
	}
	if strings.Contains(line, "(") {
		if loc := encodedLiteralArgRe.FindStringSubmatchIndex(line); loc != nil {
			enc := ""
			if loc[2] >= 0 {
				enc = line[loc[2]:loc[3]]
			} else {
				enc = line[loc[4]:loc[5]]
			}
			// config.get("db_password_v2") is a key name, not material
			if looksEncoded(enc) && !runtimeCalleeRe.MatchString(line[:loc[0]]) {
				return result(LikelySecret, 0.6, fmt.Sprint("The line passes an encoded literal to a call; base64/hex material "+
					"committed in source may decode to a credential. Review the decoded value."),
					[]string{"encoded_literal_argument"}, ctx)
			}
		}
	}

	// Offline checksum (GitHub / npm tokens). A failing checksum is fabricated.
	chkValid, chkOK := GitHubTokenChecksum(value)
	if chkOK && !chkValid {
		// Medium, not a dismissal: the checksum algorithm is verified only
		// against a published example, and if it were wrong every real token
		// would be dismissed. Still counted toward --fail-on.
		return result(LikelyFalsePositive, 0.7, "Token has a GitHub/npm prefix but fails the format's built-in CRC32 "+
			"checksum: likely fabricated, redacted or mistyped. Verify before ignoring.", []string{"checksum_invalid"}, ctx)
	}

	// Hashed / encrypted forms are not plaintext credentials.
	if hm := hashedOrEncryptedRe.FindString(value); hm != "" {
		return result(LikelyFalsePositive, 0.88, fmt.Sprintf("Value is a hashed or encrypted form (`%s…`), not a "+
			"plaintext credential; it cannot be presented to a service as-is.", clip(hm, 14)),
			[]string{"hashed_or_encrypted_value"}, ctx)
	}

	// What kind of thing is the value?
	kind, ks := valueKind(value, line, fp, urlCred)
	switch kind {
	case "reference":
		return result(LikelyFalsePositive, 0.95, fmt.Sprintf("Value references an environment variable or secret store (`%s`); "+
			"no credential is hardcoded in source.", shown), ks, ctx)
	case "expression":
		if contains(ks, "logs_variable") || (logLineRe.MatchString(line) && contains(ks, "variable_assignment")) {
			return result(NotASecret, 0.9, fmt.Sprint("The line logs or prints a variable: possible sensitive-data "+
				"logging, but no credential is hardcoded here."), []string{"logs_variable"}, ctx)
		}
		what := "another variable"
		if contains(ks, "runtime_expression") {
			what = "a runtime value"
		}
		return result(NotASecret, 0.93, fmt.Sprintf("The line assigns %s (`%s`); no credential is hardcoded.", what, shown), ks, ctx)
	case "unresolved_call":
		return result(NotASecret, 0.6, fmt.Sprintf("The line takes the value from a call (`%s`) whose source is not "+
			"on this line; it may read a committed config or decode embedded material. Not hardcoded here; verify the source.",
			shown), ks, ctx)
	case "control_flow":
		return result(NotASecret, 0.93, fmt.Sprint("The line handles a variable named like a credential (control flow or a "+
			"signature); no credential value appears in source."), ks, ctx)
	case "empty":
		return result(LikelyFalsePositive, 0.85, fmt.Sprint("The pattern matched a credential-named key but no "+
			"value follows it on that line."), ks, ctx)
	case "placeholder":
		varied := hasDigit(value) && hasAlpha(value) && highEntropyValue(value)
		if contains(ks, "placeholder_marker_in_value") && varied && hasLower(value) && hasUpper(value) &&
			utf8.RuneCountInString(value) >= 20 {
			// a long generated-looking value that merely contains a marker
			// word ("q8Xk…-example-…") is not dismissed on the word
			return result(LikelyFalsePositive, 0.65, fmt.Sprintf("Value contains a placeholder word but is long and "+
				"generated-looking (`%s`); it may still be a real credential. Review.", shown), ks, ctx)
		}
		if passwordRule && ((contains(ks, "placeholder_value") && (!structuralPlaceholderRe.MatchString(value) || varied)) ||
			contains(ks, "placeholder_marker_in_value")) {
			// password = "changeme" / "changeme9" / "your_Zx9kq2Lmw": a default
			// or placeholder-looking word may be the effective password.
			// Visible and actionable; a reviewer decides.
			return result(LikelyFalsePositive, 0.65, fmt.Sprintf("Value is a common default (`%s`). Usually a placeholder, but a "+
				"default that is actually in use is a real credential. Verify.", shown), []string{"common_default_value"}, ctx)
		}
		return result(LikelyFalsePositive, 0.9, fmt.Sprintf("Value is a placeholder (`%s`), not a credential.", shown), ks, ctx)
	case "prose":
		how := "natural-language text"
		if logLineRe.MatchString(line) {
			how = "printed/instructional text"
		}
		return result(LikelyFalsePositive, 0.9, fmt.Sprintf("Value is %s (`%s`), not a credential.", how, shown), ks, ctx)
	}

	// Look-alikes a generic pattern trips on.
	if generic && nonSecretValue(value, passwordRule) {
		return result(NotASecret, 0.88, "Value is a resource identifier or a file path (an ARN, a key alias or a "+
			"path to key material), not the credential itself.", []string{"non_secret_value"}, ctx)
	}
	if lockFiles[base] || ext == ".sum" || ext == ".lock" {
		return result(LikelyFalsePositive, 0.9, fmt.Sprintf("Match is in a dependency lockfile (`%s`): integrity hashes and "+
			"resolved URLs, not credentials.", base), []string{"lockfile"}, ctx)
	}
	if swaggerPathRe.MatchString(fp) && generic {
		return result(LikelyFalsePositive, 0.85, "Match is in a Swagger/OpenAPI artifact: example values in API "+
			"documentation, not credentials.", []string{"swagger_file"}, ctx)
	}
	if generic && !hasDigit(value) && lettersOnlyRe.MatchString(value) {
		// Generated keys carry digits, so a letters-only value is a word, a
		// name or a placeholder. For a password it is only medium: a
		// dictionary-word password in source is still a password.
		sw := stopwordIn(value)
		why := "has no digits"
		sigs := []string{"letters_only_value"}
		if sw != "" {
			why = "contains the common word `" + sw + "`"
			sigs = append(sigs, "stopword_in_value")
		}
		if passwordRule {
			return result(LikelyFalsePositive, 0.65, fmt.Sprintf("Letters-only password that %s: reads as a dictionary word or "+
				"default rather than a set credential. Review; not dismissed outright.", why), sigs, ctx)
		}
		score := 0.7
		if sw != "" || len([]rune(value)) <= 16 {
			score = 0.86
		}
		return result(LikelyFalsePositive, score, fmt.Sprintf("Letters-only value that %s: generated keys and tokens carry digits; "+
			"this reads as a word or name, not a secret.", why), sigs, ctx)
	}
	if generic && !passwordRule {
		if sw := stopwordIn(value); sw != "" && ShannonEntropy(value) < 3.5 {
			return result(LikelyFalsePositive, 0.8, fmt.Sprintf("Value contains the common word `%s` and has low entropy; generic "+
				"patterns trip on names and phrases, not a generated credential.", sw), []string{"stopword_in_value", "low_entropy"}, ctx)
		}
	}
	if m := contextBanlistRe.FindStringSubmatch(line); m != nil && generic {
		// The word dismisses only when it is inside the value itself
		// ("my-example-key"). Anywhere else on the line (a comment, a URL) it
		// is weak evidence: a real key often sits next to "# TODO: move to
		// vault". Medium confidence, still counted.
		score, why := 0.8, "The line marks this as an example or non-credential (`%s`)."
		switch {
		case !contextBanlistRe.MatchString(value):
			score, why = 0.65, "The line mentions `%s`, but not in the value itself; it may still be a real credential. Review."
		case passwordRule || highEntropyValue(value) || keyMaterial(value):
			// inside the value, but a password or a generated-looking value
			// may still be real ("Fake-Summer2024!"): medium, still counted
			score, why = 0.65, "The value contains `%s`, but it may still be a real credential. Review."
		}
		return result(LikelyFalsePositive, score, fmt.Sprintf(why, clip(m[1], 20)), []string{"context_banlist_word"}, ctx)
	}
	if key != "" && generic {
		k := strings.ToLower(key)
		if i := strings.LastIndexByte(k, '.'); i >= 0 {
			k = k[i+1:]
		}
		if strings.ToLower(value) == k {
			return result(LikelyFalsePositive, 0.85, fmt.Sprintf("Value equals its own key name (`%s`): a template default, "+
				"not a credential.", describeName(key)), []string{"value_equals_key"}, ctx)
		}
	}
	if generic && hexRe.MatchString(value) {
		switch n := len(value); n {
		case 32, 40, 64, 128:
			if m := hashContextRe.FindStringSubmatch(line); m != nil {
				// under a credential-named key the line word is weak evidence
				score := 0.88
				if key != "" && credKeywordRe.MatchString(key) {
					score = 0.65
				}
				return result(NotASecret, score, fmt.Sprintf("%d-character hex value on a line about hashes/checksums "+
					"(`%s`): a content hash, not a credential.", n, clip(m[1], 20)), []string{"hash_lookalike"}, ctx)
			}
		}
	}
	if generic && uuidRe.MatchString(value) && !credKeywordRe.MatchString(line) {
		return result(LikelyFalsePositive, 0.75, "Value is a UUID with no credential keyword on the line: usually an "+
			"identifier, not a secret.", []string{"uuid_lookalike"}, ctx)
	}

	// Format + entropy of a hardcoded literal.
	ent := ShannonEntropy(value)
	if in.Entropy != nil {
		ent = *in.Entropy
	}
	n := len([]rune(value))
	isDoc := docExts[ext] || docNames[strings.SplitN(base, ".", 2)[0]] || containsAny(sl, docDirs)
	isTest := containsAny(sl, testDirs) || testFileRe.MatchString(base)
	if isDoc {
		ctx = append(ctx, "documentation_file")
	}
	if isTest {
		ctx = append(ctx, "test_or_fixture_path")
	}
	strongFormat := !generic
	highEntropy := ent >= 3.5 && n >= 16
	midEntropy := ent >= 3.0 && n >= 8
	ruleName := norm(in.RuleID)
	if ruleName == "" {
		ruleName = "secret pattern"
	}
	es := fmtFloat(ent)

	switch {
	case isDoc && !strongFormat && !highEntropy:
		// Path lowers confidence; it never dismisses a literal on its own.
		return result(LikelySecret, 0.6, fmt.Sprintf("Hardcoded literal (%s bits/char) in documentation (`%s`); often an "+
			"illustrative example, but docs do carry pasted real values. Verify.", es, base), []string{"documentation_low_entropy"}, ctx)
	case isTest && !strongFormat && !highEntropy:
		return result(LikelySecret, 0.6, fmt.Sprintf("Hardcoded literal (%s bits/char) in a test/fixture path; often mock "+
			"data, but test credentials are sometimes the real ones. Verify.", es), []string{"test_fixture_low_entropy"}, ctx)
	case chkOK && chkValid:
		return result(LikelySecret, 0.9, fmt.Sprintf("Token passes the GitHub/npm format's built-in CRC32 checksum: an issued "+
			"token (%d chars). Verify and rotate.", n), []string{"provider_format_match", "checksum_valid"}, ctx)
	case strongFormat:
		where, score := "", 0.8
		if isTest {
			where, score = " in a test/fixture path; real keys do ship in tests", 0.7
		} else if isDoc {
			where, score = " in documentation; real keys do get pasted into docs", 0.7
		}
		return result(LikelySecret, score, fmt.Sprintf("Hardcoded literal matches the %s credential format "+
			"(%d chars, entropy %s)%s. Verify and rotate.", ruleName, n, es, where), []string{"provider_format_match"}, ctx)
	case highEntropy:
		return result(LikelySecret, 0.82, fmt.Sprintf("Hardcoded high-entropy literal (%d chars, entropy %s bits/char) "+
			"assigned to a credential-named key; consistent with a generated secret.", n, es), []string{"high_entropy_literal"}, ctx)
	case midEntropy:
		return result(LikelySecret, 0.62, fmt.Sprintf("Hardcoded literal (%d chars, entropy %s bits/char) assigned to a "+
			"credential-named key. Not a recognised provider format; review.", n, es), []string{"hardcoded_literal"}, ctx)
	}
	return result(LikelySecret, 0.55, fmt.Sprintf("Hardcoded low-entropy literal (%d chars, entropy %s bits/char) assigned "+
		"to a credential-named key; looks like a weak or default password, which is still a credential in source. Review.", n, es),
		[]string{"hardcoded_literal", "low_entropy"}, ctx)
}

// pemAssessment judges PEM blocks by their body, not their header.
func pemAssessment(value, context string, ctx []string) (Result, bool) {
	var texts []string
	for _, t := range []string{value, context} {
		if t != "" && strings.Contains(strings.ToUpper(t), "-----BEGIN") {
			texts = append(texts, t)
		}
	}
	if len(texts) == 0 {
		return Result{}, false
	}
	text := texts[0]
	for _, t := range texts {
		if strings.Contains(strings.ToUpper(t), "-----END") {
			text = t
			break
		}
	}
	full := pemFullRe.FindStringSubmatch(text)
	header := full
	if header == nil {
		header = pemHeaderRe.FindStringSubmatch(text)
	}
	if header == nil {
		return Result{}, false
	}
	switch kind := strings.ToUpper(header[pemHeaderRe.SubexpIndex("kind")]); kind {
	case "PUBLIC KEY", "CERTIFICATE", "EC PARAMETERS":
		what := "public-key material"
		if kind == "CERTIFICATE" {
			what = "a certificate"
		}
		return result(NotASecret, 0.95, "Block is "+what+", not a private credential.", []string{"public_key_material"}, ctx), true
	}
	if full == nil {
		return result(LikelySecret, 0.6, "Private-key header found but the key body was not captured; treat as "+
			"a possible embedded key until reviewed.", []string{"pem_header_body_unknown"}, ctx), true
	}
	body := full[pemFullRe.SubexpIndex("body")]
	// literal "\n" sequences (JSON) and real whitespace both separate lines;
	// a key written as concatenated literals leaves quote/operator joints
	body = escapedWSRe.ReplaceAllString(body, "")
	body = pemQuoteWSRe.ReplaceAllString(pemJointRe.ReplaceAllString(body, ""), "")
	if len(body) < 64 {
		// The body is never quoted: only its length (it may be key material).
		return result(LikelyFalsePositive, 0.92, fmt.Sprintf("Private-key block has a %d-character body; a real "+
			"PEM key body is hundreds of base64 characters. This is a placeholder.", len(body)),
			[]string{"pem_placeholder_body"}, ctx), true
	}
	if !base64BodyRe.MatchString(body) {
		// Long but not plain base64: never dismissed, a reviewer decides.
		return result(LikelySecret, 0.6, fmt.Sprintf("Private-key block with a %d-character body that is not plain "+
			"base64; treat as a possible embedded key until reviewed.", len(body)), []string{"pem_body_unrecognised"}, ctx), true
	}
	return result(LikelySecret, 0.9, fmt.Sprintf("PEM private-key block with a %d-character base64 body: a real "+
		"key format embedded in source.", len(body)), []string{"pem_private_key_body"}, ctx), true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// tags maps the deciding signal to a short phrase for the table view.
var tags = []struct{ signal, tag string }{
	{"common_default_value", "common default"},
	{"verifies_or_hashes_variable", "hashes a variable"},
	{"logs_variable", "logs a variable"},
	{"env_var_reference", "env/secret-store reference"},
	{"runtime_expression", "runtime value"},
	{"variable_assignment", "variable"},
	{"unresolved_source_call", "value from a call"},
	{"control_flow_over_variable", "code, not a value"},
	{"key_name_without_value", "no value"},
	{"non_secret_key_name", "non-secret key name"},
	{"checksum_invalid", "fails token checksum"},
	{"hashed_or_encrypted_value", "hashed/encrypted"},
	{"natural_language_text", "prose"},
	{"bracketed_placeholder", "placeholder"},
	{"format_or_positional_placeholder", "placeholder"},
	{"placeholder_value", "placeholder"},
	{"sequential_string", "placeholder"},
	{"no_alphanumeric_characters", "placeholder"},
	{"placeholder_marker_in_value", "placeholder"},
	{"pem_placeholder_body", "placeholder key"},
	{"public_key_material", "public key/certificate"},
	{"lockfile", "lockfile"},
	{"swagger_file", "API docs example"},
	{"letters_only_value", "word, not a key"},
	{"stopword_in_value", "common word"},
	{"context_banlist_word", "marked as example"},
	{"value_equals_key", "template default"},
	{"hash_lookalike", "content hash"},
	{"uuid_lookalike", "UUID"},
}

// Tag is a short phrase naming why the verdict was reached, e.g.
// "placeholder" or "env/secret-store reference".
func (r Result) Tag() string {
	for _, t := range tags {
		if contains(r.Signals, t.signal) {
			return t.tag
		}
	}
	return strings.ToLower(r.Label)
}
