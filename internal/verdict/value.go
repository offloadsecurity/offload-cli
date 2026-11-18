package verdict

import (
	"hash/crc32"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func norm(s string) string { return strings.TrimSpace(s) }

// clip shortens s to n characters for display in a reason.
func clip(s string, n int) string {
	s = strings.ReplaceAll(norm(s), "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", "")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// mask renders a possibly-real credential the way it may appear in a reason:
// recognisable, never usable. Nothing of a value under 12 characters, at most
// four characters overall, and a prefix only from 20.
func mask(value string) string {
	r := []rune(norm(value))
	n := strconv.Itoa(len(r))
	switch {
	case len(r) == 0:
		return "***"
	case len(r) < 12:
		return "*** (" + n + " chars)"
	case len(r) < 20:
		return "…" + string(r[len(r)-2:]) + " (" + n + " chars)"
	}
	return string(r[:2]) + "…" + string(r[len(r)-2:]) + " (" + n + " chars)"
}

// keyMaterial: a bare token that could be key material in any case:
// generated-looking, or 20+ characters with entropy >= 3.5. Pure hex and
// UUIDs are excluded (the usual shape of identifiers under id-style names; a
// *secret_id* is handled by name), as are paths, ARNs and aliases.
func keyMaterial(v string) bool {
	if !literalTokenRe.MatchString(v) {
		return false
	}
	if looksGenerated(v) {
		return true
	}
	if hexRe.MatchString(v) || uuidRe.MatchString(v) || nonSecretValueRe.MatchString(v) {
		return false
	}
	for _, rx := range formatPlaceholderRes {
		if rx.MatchString(v) {
			return false
		}
	}
	return utf8.RuneCountInString(v) >= 20 && ShannonEntropy(v) >= 3.5
}

// highEntropyValue judges the value alone, any characters: long and varied
// enough to be a generated credential rather than a word.
func highEntropyValue(v string) bool {
	return utf8.RuneCountInString(v) >= 12 && !strings.ContainsAny(v, " \t\r\n") && ShannonEntropy(v) >= 3.0
}

// stripTrailingComment drops a trailing "# ..." or "// ..." comment from a
// statement's right-hand side (outside quotes, after whitespace).
func stripTrailingComment(rhs string) string {
	var quote byte
	for i := 0; i < len(rhs); i++ {
		ch := rhs[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch {
		case isQuote(ch):
			quote = ch
		case i > 0 && (rhs[i-1] == ' ' || rhs[i-1] == '\t') && (ch == '#' || strings.HasPrefix(rhs[i:], "//")):
			return strings.TrimRightFunc(rhs[:i], unicode.IsSpace)
		}
	}
	return rhs
}

// describe renders the judged value for a reason: its mask, computed from the
// whole value. Values shorter than four characters (%s, $1) carry no
// credential and are shown as-is.
func describe(value string) string {
	v := norm(value)
	if utf8.RuneCountInString(v) < 4 {
		return v
	}
	return mask(v)
}

// describeName renders an assignment name for a reason. A name is normally an
// identifier; one that looks like key material (a JSON key that is itself a
// secret) is masked.
func describeName(name string) string {
	if looksGenerated(name) || (hasDigit(name) && ShannonEntropy(name) >= 3.5 && utf8.RuneCountInString(name) >= 16) {
		return mask(name)
	}
	return clip(name, 40)
}

// stubLiterals shortens every quoted literal longer than 8 characters to a
// three-character stub, so a credential that is not a plain substring of the
// match (split across literals, or a second secret on the same line) is
// never echoed. withBackticks also stubs `...` (the reason's own quoting).
func stubLiterals(text string, withBackticks bool) string {
	return quotedLiteralRe.ReplaceAllStringFunc(text, func(m string) string {
		q := m[:1]
		if q == "`" && !withBackticks {
			return m
		}
		inner := []rune(m[1 : len(m)-1])
		return q + string(inner[:3]) + "…" + q
	})
}

// maskValues replaces each value in text with its mask. Values shorter than
// four characters are skipped: they carry no credential, and replacing them
// would mangle ordinary words in the reason.
func maskValues(text string, values ...string) string {
	for _, v := range values {
		v = norm(v)
		if len(v) >= 4 && strings.Contains(text, v) {
			text = strings.ReplaceAll(text, v, mask(v))
		}
	}
	return text
}

// pyExt mirrors os.path.splitext: a leading dot (".env") is not an extension.
func pyExt(p string) string {
	b := baseName(p)
	t := strings.TrimLeft(b, ".")
	i := strings.LastIndexByte(t, '.')
	if i < 0 {
		return ""
	}
	return strings.ToLower(t[i:])
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func slashed(p string) string {
	return "/" + strings.ToLower(strings.Trim(strings.ReplaceAll(p, `\`, "/"), "/")) + "/"
}

// ShannonEntropy returns the per-character entropy of s, rounded to 2 places.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	n := 0
	for _, c := range s {
		freq[c]++
		n++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return round2(h)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// IsGenericRule reports whether the rule targets a shape rather than a
// provider's credential format. An unknown (empty) rule counts as generic.
func IsGenericRule(ruleID string) bool {
	r := strings.ToLower(norm(ruleID))
	if r == "" {
		return true
	}
	for _, t := range genericRuleTokens {
		if strings.Contains(r, t) {
			return true
		}
	}
	return false
}

func isQuote(b byte) bool { return b == '\'' || b == '"' || b == '`' }

func stripQuotes(v string) string {
	v = norm(v)
	for len(v) >= 2 && v[0] == v[len(v)-1] && isQuote(v[0]) {
		v = norm(v[1 : len(v)-1])
	}
	// an unbalanced quote from a truncated match (sk_live_…")
	if v != "" && isQuote(v[len(v)-1]) && !isQuote(v[0]) {
		v = strings.TrimRightFunc(v[:len(v)-1], unicode.IsSpace)
	}
	if v != "" && isQuote(v[0]) && !isQuote(v[len(v)-1]) {
		v = strings.TrimLeftFunc(v[1:], unicode.IsSpace)
	}
	return v
}

// quotedInLine: 1 if value appears in line wrapped in matching quotes, 0 if
// it appears only bare, -1 if it does not appear at all.
func quotedInLine(value, line string) int {
	if value == "" || line == "" {
		return -1
	}
	seen := false
	for start := 0; start <= len(line); {
		i := strings.Index(line[start:], value)
		if i < 0 {
			break
		}
		idx := start + i
		seen = true
		end := idx + len(value)
		if idx > 0 && end < len(line) && isQuote(line[idx-1]) && line[end] == line[idx-1] {
			return 1
		}
		start = idx + 1
	}
	if seen {
		return 0
	}
	return -1
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func namedGroup(m []string, rx interface{ SubexpIndex(string) int }, name string) string {
	return m[rx.SubexpIndex(name)]
}

// ExtractCandidateValue returns the thing to judge. gitleaks' Secret is
// already the captured credential; a whole-statement match (password = x)
// reduces to its right-hand side, and a connection string to its password.
func ExtractCandidateValue(secret, match string) string {
	value := norm(secret)
	if value == "" {
		value = norm(match)
	}
	first := norm(firstLine(value))
	if tokenBlobRe.MatchString(first) {
		// A base64 token that happens to spell key/api and ends in "="
		// padding must not be read as "<key>=" with an empty value.
		return stripQuotes(value)
	}
	m := keyedAssignRe.FindStringSubmatch(first)
	if m == nil && !strings.Contains(first, "://") && stmtSepRe.MatchString(first) {
		m = keyedAssignSearchRe.FindStringSubmatch(first)
	}
	switch {
	case m != nil && !strings.Contains(first, "://"):
		value = stripTrailingComment(namedGroup(m, keyedAssignRe, "val"))
	case strings.Contains(value, "\n"):
		value = first
	}
	value = bearerRe.ReplaceAllString(value, "")
	value = stripQuotes(value)
	if u := urlCredRe.FindStringSubmatch(value); u != nil {
		value = namedGroup(u, urlCredRe, "cred")
	}
	return value
}

// isURLCredential: the value came out of scheme://user:PASS@host, a literal
// by construction whatever the quoting looks like.
func isURLCredential(secret, match string) bool {
	raw := norm(secret)
	if raw == "" {
		raw = norm(match)
	}
	return urlCredRe.MatchString(firstLine(stripQuotes(raw)))
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func toBase62(n uint32) string {
	var out []byte
	for n > 0 {
		out = append([]byte{base62[n%62]}, out...)
		n /= 62
	}
	for len(out) < 6 {
		out = append([]byte{'0'}, out...)
	}
	return string(out)
}

// GitHubTokenChecksum validates a ghp_/gho_/ghu_/ghs_/ghr_/npm_ token offline
// (last 6 chars = base62(CRC32(30-char body))). ok is false when the value is
// not such a token.
func GitHubTokenChecksum(value string) (valid, ok bool) {
	m := ghChecksumTokenRe.FindStringSubmatch(value)
	if m == nil {
		return false, false
	}
	return toBase62(crc32.ChecksumIEEE([]byte(m[2]))) == m[3], true
}

// isSequential (detect-secrets is_sequential_string).
func isSequential(value string) bool {
	up := strings.ToUpper(value)
	if utf8.RuneCountInString(up) < 4 {
		return false
	}
	for _, seq := range sequences {
		if strings.Contains(seq, up) {
			return true
		}
	}
	return false
}

// stopwordIn returns the first gitleaks stopword the value contains.
func stopwordIn(value string) string {
	low := strings.ToLower(value)
	if utf8.RuneCountInString(low) < 4 {
		return ""
	}
	for _, w := range stopwords {
		if strings.Contains(low, w) {
			return w
		}
	}
	return ""
}

// assignmentKey: the name on the left of the assignment holding value.
func assignmentKey(line, value string) string {
	idx := -1
	if value != "" {
		idx = strings.Index(line, value)
	}
	left := line
	if idx > 0 {
		left = line[:idx]
	}
	if m := assignKeyLeftRe.FindStringSubmatch(left); m != nil {
		return strings.Trim(m[1], `'"[]`)
	}
	// The value sits inside an expression (api_version = getenv("V", "x")):
	// the statement's own left-hand side is still the name that matters.
	loc := assignKeyStmtRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return ""
	}
	if rest := line[loc[1]:]; rest != "" && rest[0] == '=' {
		return "" // a comparison (a == b), not an assignment
	}
	return line[loc[2]:loc[3]]
}

func hasDigit(s string) bool { return strings.IndexFunc(s, unicode.IsDigit) >= 0 }
func hasLower(s string) bool { return strings.IndexFunc(s, unicode.IsLower) >= 0 }
func hasUpper(s string) bool { return strings.IndexFunc(s, unicode.IsUpper) >= 0 }
func hasAlpha(s string) bool { return strings.IndexFunc(s, unicode.IsLetter) >= 0 }

// looksEncoded: base64 (mixed case + digit) or hex of 16+ chars; material,
// as opposed to a key name.
func looksEncoded(s string) bool {
	if hex16Re.MatchString(s) {
		return true
	}
	return base64ishRe.MatchString(s) && hasDigit(s) && hasLower(s) && hasUpper(s)
}

// completeExpression extends a truncated call (get_secret( ) to its balanced
// closing bracket on the line.
func completeExpression(value, line string) string {
	if value == "" || line == "" || !strings.ContainsRune("([.", rune(value[len(value)-1])) {
		return value
	}
	idx := strings.Index(line, value)
	if idx < 0 {
		return value
	}
	depth := 0
	for j := idx; j < len(line); j++ {
		switch ch := line[j]; {
		case ch == '(' || ch == '[':
			depth++
		case ch == ')' || ch == ']':
			depth--
			if depth == 0 {
				return norm(line[idx : j+1])
			}
		case (ch == ' ' || ch == '\t' || ch == ';' || ch == ',') && depth == 0 && j > idx+len(value):
			return value
		}
	}
	return value
}

// generatedLiteral: a bare token (no spaces, quotes or call syntax) that
// looks generated. Used so a name or a nearby word never dismisses key
// material on its own.
func generatedLiteral(v string) bool {
	return literalTokenRe.MatchString(v) && looksGenerated(v)
}

// looksGenerated: an identifier-shaped token that is really a key.
func looksGenerated(v string) bool {
	return utf8.RuneCountInString(v) >= 20 && hasDigit(v) && hasLower(v) && hasUpper(v) && ShannonEntropy(v) >= 3.5
}

// argsAreVariables is true only when every argument of f(...) is a variable
// reference: bcrypt.checkpw(password, hashed) consumes variables, while
// encrypt(12345678) embeds a literal and must stay actionable. A single
// trailing comma is allowed.
func argsAreVariables(call string) bool {
	inner := ""
	if i := strings.IndexByte(call, '('); i >= 0 {
		inner = call[i+1:]
	}
	if i := strings.LastIndexByte(inner, ')'); i >= 0 {
		inner = inner[:i]
	}
	inner = norm(inner)
	inner = strings.TrimSuffix(inner, ",")
	for _, a := range strings.Split(inner, ",") {
		a = norm(a)
		if a == "" || !varArgRe.MatchString(a) {
			return false
		}
	}
	return true
}

func isRepeatedChar(v string) bool {
	r := []rune(v)
	if len(r) < 5 {
		return false
	}
	for _, c := range r[1:] {
		if c != r[0] {
			return false
		}
	}
	return true
}

func isCodeLine(line string) bool {
	return logicLineRe.MatchString(line) || signatureRe.MatchString(line) || comparisonRe.MatchString(line)
}

// valueKind classifies the judged value: reference | expression |
// unresolved_call | control_flow | placeholder | prose | empty | literal.
// literalContext means the value is known to be a literal (the password of a
// connection string), so bare-identifier logic must not read it as a variable.
func valueKind(value, line, filePath string, literalContext bool) (string, []string) {
	if value == "" {
		if isCodeLine(line) {
			return "control_flow", []string{"control_flow_over_variable"}
		}
		return "empty", []string{"key_name_without_value"}
	}
	for _, rx := range referenceRes {
		if rx.MatchString(value) {
			return "reference", []string{"env_var_reference"}
		}
	}
	if anglePlaceholderRe.MatchString(value) || squarePlaceholderRe.MatchString(value) || bracePlaceholderRe.MatchString(value) {
		return "placeholder", []string{"bracketed_placeholder"}
	}
	for _, rx := range formatPlaceholderRes {
		if rx.MatchString(value) {
			return "placeholder", []string{"format_or_positional_placeholder"}
		}
	}

	quoted := 1
	if !literalContext {
		quoted = quotedInLine(value, line)
	}
	codeFile := codeExts[pyExt(filePath)]
	switch {
	case quoted == 0:
		if expressionRe.MatchString(value) || callRe.MatchString(value) {
			if !strings.Contains(value, "(") {
				return "expression", []string{"runtime_expression"}
			}
			callee := value[:strings.IndexByte(value, '(')]
			if runtimeCalleeRe.MatchString(callee) {
				return "expression", []string{"runtime_expression"}
			}
			hasQuote := strings.ContainsAny(value, "'\"`")
			if logLineRe.MatchString(line) && !strings.ContainsAny(value, `'"`) {
				// logger.info(password): a variable is printed, none is set
				return "expression", []string{"variable_assignment", "logs_variable"}
			}
			method := lastSegment(callee)
			if verifyCalleeRe.MatchString(method) && !hasQuote && argsAreVariables(value) {
				// bcrypt.checkpw(password, hashed): the variable is consumed
				return "expression", []string{"runtime_expression", "verifies_or_hashes_variable"}
			}
			// any other call: the origin of the value is not on this line
			return "unresolved_call", []string{"unresolved_source_call"}
		}
		if identifierRe.MatchString(value) && !looksGenerated(value) {
			if isCodeLine(line) {
				return "control_flow", []string{"control_flow_over_variable"}
			}
			// password = other_var in code is a variable; password: hunter2
			// in YAML/.env/shell is a bare literal: decide by file type.
			if codeFile {
				return "expression", []string{"variable_assignment"}
			}
		}
	case quoted == -1 && identifierRe.MatchString(value) && logicLineRe.MatchString(line):
		return "control_flow", []string{"control_flow_over_variable"}
	}
	if quoted != 1 && strings.ContainsAny(value, " \t\n\r\f\v()") && (logicLineRe.MatchString(line) || signatureRe.MatchString(line)) {
		// the whole statement matched (def login(user, password):)
		return "control_flow", []string{"control_flow_over_variable"}
	}

	low := strings.ToLower(value)
	if placeholderWords[low] || placeholderPrefixRe.MatchString(value) || isRepeatedChar(value) ||
		maskedRe.MatchString(value) || sequentialRe.MatchString(value) || value == "..." || value == "…" {
		return "placeholder", []string{"placeholder_value"}
	}
	if isSequential(value) {
		return "placeholder", []string{"sequential_string"}
	}
	if !hasAlpha(value) && !hasDigit(value) {
		return "placeholder", []string{"no_alphanumeric_characters"}
	}
	if words := strings.Fields(value); len(words) >= 3 && proseRe.MatchString(value) {
		prose := logLineRe.MatchString(line)
		for _, w := range words {
			if proseStopwords[strings.Trim(strings.ToLower(w), ",.")] {
				prose = true
			}
		}
		if prose {
			return "prose", []string{"natural_language_text"}
		}
	}
	if placeholderSubstrRe.MatchString(value) {
		return "placeholder", []string{"placeholder_marker_in_value"}
	}
	return "literal", nil
}

func lastSegment(callee string) string {
	s := callee
	for _, sep := range []string{".", "->", "::"} {
		if i := strings.LastIndex(s, sep); i >= 0 {
			s = s[i+len(sep):]
		}
	}
	return s
}
