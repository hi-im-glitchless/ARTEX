package membrane

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// secretDetector finds credentials by known format (PEM, JWT, AWS, ...) and
// by context: HTTP header lines, JSON keys, key=value pairs, URL userinfo
// and Basic auth.
//
// Context regexps run line by line, and only on lines holding their anchor
// (':' , '=', "://", a keyword), because Go's regexp has no DFA. None of the
// context forms spans a newline; PEM blocks are matched on the whole text.
type secretDetector struct{}

func (secretDetector) Detect(text string) []Span {
	var out []Span
	low := lowerASCII(text) // same byte offsets as text
	out = secretFormats(text, low, out)
	out = headerSecrets(text, out)
	out = jsonKeySecrets(text, out)
	out = kvSecrets(text, out)
	out = userinfoSecrets(text, out)
	return out
}

// lineMatches runs re on every line of text for which pre(lineStart,
// lineEnd) holds and returns submatch indices into text.
func lineMatches(re *regexp.Regexp, text string, pre func(s, e int) bool) [][]int {
	var out [][]int
	for s := 0; s < len(text); {
		e := strings.IndexByte(text[s:], '\n')
		if e < 0 {
			e = len(text)
		} else {
			e += s
		}
		if pre(s, e) {
			out = append(out, findIn(re, text, s, e)...)
		}
		s = e + 1
	}
	return out
}

func lineHas(text, anchor string) func(s, e int) bool {
	return func(s, e int) bool { return strings.Contains(text[s:e], anchor) }
}

func lineHasAny(text string, anchors ...string) func(s, e int) bool {
	return func(s, e int) bool {
		for _, a := range anchors {
			if strings.Contains(text[s:e], a) {
				return true
			}
		}
		return false
	}
}

// Key-name rules ported from middlehack redactor.py.
var (
	passwordKeyRE = regexp.MustCompile(`(?i)(passw(or)?d|passwd|pass\b|pwd)`)
	emailKeyRE    = regexp.MustCompile(`(?i)(e-?mail)`)
	usernameKeyRE = regexp.MustCompile(`(?i)(username|user|login|account|usr)`)
	// secretKeyRE is SECRET_KEY_RE with "auth(?!or)" written as "auth"; the
	// negative lookahead is applied in secretKey (RE2 has no lookahead).
	secretKeyRE = regexp.MustCompile(`(?i)(session|token|auth|secret|key|credential|bearer|csrf|xsrf|jwt|signature|\bsid\b)`)
)

// secretKey reports whether key names a secret: a SECRET_KEY_RE match other
// than an "auth" immediately followed by "or" (author, authorization).
func secretKey(key string) bool {
	low := strings.ToLower(key)
	for i := 0; i < len(low); {
		m := secretKeyRE.FindStringIndex(low[i:])
		if m == nil {
			return false
		}
		s, e := i+m[0], i+m[1]
		if low[s:e] != "auth" || !strings.HasPrefix(low[e:], "or") {
			return true
		}
		i = s + 1
	}
	return false
}

// keyAnchors holds a literal every key regexp match contains.
var keyAnchors = []string{"pass", "pwd", "mail", "user", "login", "account", "usr", "session", "token",
	"auth", "secret", "key", "credential", "bearer", "csrf", "xsrf", "jwt", "signature", "sid"}

// keyKind classifies a field name. Email keys yield nothing: the email
// detector handles the value by shape.
func keyKind(key string) (Kind, bool) {
	low := lowerASCII(key)
	hit := false
	for _, a := range keyAnchors {
		if strings.Contains(low, a) {
			hit = true
			break
		}
	}
	if !hit {
		return "", false // fast path: no key regexp can match
	}
	switch {
	case passwordKeyRE.MatchString(key):
		return KindPassword, true
	case emailKeyRE.MatchString(key):
		return "", false
	case usernameKeyRE.MatchString(key):
		return KindUsername, true
	case secretKey(key), strings.Contains(strings.ToLower(key), "authorization"):
		// auth(?!or) keeps "author" out but also "authorization", which is
		// a credential header name.
		return KindToken, true
	}
	return "", false
}

// shapedValue reports whether v is left to the shape detectors (middlehack:
// IP- or email-shaped values win over the key name). Unlike middlehack, a
// value merely containing '@' (p@ssw0rd) is still a credential.
func shapedValue(v string) bool {
	t := strings.TrimSpace(v)
	if m := emailRE.FindStringIndex(t); m != nil && m[0] == 0 && m[1] == len(t) {
		return true
	}
	_, err := netip.ParseAddr(t)
	return err == nil
}

// valueSpan builds a context secret span, or reports false when the value is
// too short (min length 3) or shaped.
func valueSpan(text string, s, e int, k Kind) (Span, bool) {
	v := text[s:e]
	if utf8.RuneCountInString(v) < minLiteralLen || shapedValue(v) {
		return Span{}, false
	}
	return Span{Start: s, End: e, Kind: k, Value: v}, true
}

// Known secret formats (cockpit _SECRET_RES plus common vendor prefixes).
var (
	// PEM / PGP armour: "PRIVATE KEY" or "PRIVATE KEY BLOCK" (PGP).
	pemBeginRE = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)
	pemEndRE   = regexp.MustCompile(`-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)
	// pemBodyLineRE: lines a (possibly truncated) armour body consists of —
	// base64 (incl. the PGP "=crc" line) or "Header: value" lines.
	pemBodyLineRE = regexp.MustCompile(`^(?:[A-Za-z0-9+/=]+|[A-Za-z][A-Za-z0-9-]*: .*)$`)
	// tokenFormats: each regexp runs only when its anchor occurs; a leading
	// literal lets regexp skip ahead with a substring search. wordStart
	// requires no word byte before the match (a \b written in code).
	tokenFormats = []struct {
		anchor    string
		re        *regexp.Regexp
		wordStart bool
	}{
		{"AKIA", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), true},
		{"eyJ", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`), true},
		{"CfDJ8", regexp.MustCompile(`CfDJ8[A-Za-z0-9+/_=-]{16,}`), false},
		{"gh", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), true},
		{"xox", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`), true},
		{"k_", regexp.MustCompile(`[sr]k_(?:live|test)_[A-Za-z0-9]{16,}`), true},
		{"AIza", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), true},
	}
	// bearerRE: cockpit BEARER (key[:=]value) and free-text "Bearer value".
	bearerRE = regexp.MustCompile(`(?i)\b(?:(?:bearer|token|api[_-]?key)\s*[:=]\s*['"]?|bearer\s+)([A-Za-z0-9._~+/-]{16,}=*)`)
	// secretKVRE: cockpit _SECRET_KV_RE for "key: value" in free text; the
	// "key=value" form is kvSecrets' (it also decodes URL encoding).
	// A quoted value is the whole inner string (spaces allowed).
	secretKVRE = regexp.MustCompile(`(?i)\b(secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|password|passwd|pwd|private[_-]?key)\s*:\s*` + quotedOr(`[A-Za-z0-9._\-/+!@#$^&*]{4,}`))
)

// quotedOr returns a regexp fragment with three value groups: a "double"
// quoted inner string, a 'single' quoted one, or bare.
func quotedOr(bare string) string {
	return `(?:"([^"\n]*)"|'([^'\n]*)'|(` + bare + `))`
}

// valueGroup returns the indices of the first matched group among the
// three quotedOr groups starting at group g.
func valueGroup(m []int, g int) (int, int) {
	for i := g; i < g+3; i++ {
		if m[2*i] >= 0 {
			return m[2*i], m[2*i+1]
		}
	}
	return -1, -1
}

// pemBlocks reports private key armour. A block without its END line (tool
// output is truncated) runs to the end of its armour body.
func pemBlocks(text string, out []Span) []Span {
	for pos := 0; pos < len(text); {
		b := pemBeginRE.FindStringIndex(text[pos:])
		if b == nil {
			break
		}
		s, e := pos+b[0], pos+b[1]
		if end := pemEndRE.FindStringIndex(text[e:]); end != nil {
			e += end[1]
		} else {
			e = pemBodyEnd(text, e)
		}
		out = append(out, rawSpan(text, s, e, KindPrivateKey))
		pos = e
	}
	return out
}

// pemBodyEnd returns the end of the last non-empty armour body line after
// position e (the end of the BEGIN line).
func pemBodyEnd(text string, e int) int {
	i := e
	switch {
	case strings.HasPrefix(text[i:], "\r\n"):
		i += 2
	case strings.HasPrefix(text[i:], "\n"):
		i++
	default:
		return e // body not on following lines (e.g. JSON-escaped; see views)
	}
	last := e
	for i < len(text) {
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			j = len(text)
		} else {
			j += i
		}
		line := strings.TrimSuffix(text[i:j], "\r")
		if line != "" {
			if !pemBodyLineRE.MatchString(line) {
				break
			}
			last = i + len(line)
		}
		i = j + 1
	}
	return last
}

// secretFormats finds known token formats and keyword-introduced secrets.
// low is text lowercased (ASCII), used for case-insensitive anchors.
func secretFormats(text, low string, out []Span) []Span {
	if strings.Contains(text, "-----BEGIN ") {
		out = pemBlocks(text, out)
	}
	for _, f := range tokenFormats {
		if !strings.Contains(text, f.anchor) {
			continue
		}
		for _, m := range f.re.FindAllStringIndex(text, -1) {
			if isWordByte(byteAfter(text, m[1])) || (f.wordStart && isWordByte(byteBefore(text, m[0]))) {
				continue
			}
			out = append(out, rawSpan(text, m[0], m[1], KindToken))
		}
	}
	for _, m := range lineMatches(bearerRE, text, lineHasAny(low, "bearer", "token", "api")) {
		out = append(out, rawSpan(text, m[2], m[3], KindToken))
	}
	pre := lineHasAny(low, "secret", "key", "pass", "pwd")
	for _, m := range lineMatches(secretKVRE, text, func(s, e int) bool {
		return strings.IndexByte(text[s:e], ':') >= 0 && pre(s, e)
	}) {
		k := KindToken
		if passwordKeyRE.MatchString(text[m[2]:m[3]]) {
			k = KindPassword
		}
		vs, ve := valueGroup(m, 2)
		if sp, ok := valueSpan(text, vs, ve, k); ok {
			out = append(out, sp)
		}
	}
	return out
}

// headerRE finds "Name: " at a line start, after a JSON-escaped newline
// (\n) or after a quote (curl -H "Name: v").
var headerRE = regexp.MustCompile(`(?m)(?:^|\\n|(["']))[ \t]*([A-Za-z][A-Za-z0-9_-]{1,40})[ \t]*:[ \t]*`)

// headerValueEnd returns the end of a header value starting at s: the line
// end, a JSON-escaped \r or \n, or the closing quote.
func headerValueEnd(text string, s int, quote byte) int {
	for i := s; i < len(text); i++ {
		c := text[i]
		if c == '\r' || c == '\n' || (quote != 0 && c == quote) {
			return trimEscape(text, s, i)
		}
		if c == '\\' && i+1 < len(text) && (text[i+1] == 'r' || text[i+1] == 'n' || text[i+1] == '"') {
			return i
		}
	}
	return len(text)
}

func trimEscape(text string, s, e int) int {
	if e > s && text[e-1] == '\\' {
		return e - 1
	}
	return e
}

func trimSpaces(text string, s, e int) (int, int) {
	for s < e && (text[s] == ' ' || text[s] == '\t') {
		s++
	}
	for e > s && (text[e-1] == ' ' || text[e-1] == '\t') {
		e--
	}
	return s, e
}

func headerSecrets(text string, out []Span) []Span {
	for _, m := range lineMatches(headerRE, text, lineHas(text, ":")) {
		var quote byte
		if m[2] >= 0 {
			quote = text[m[2]]
		}
		name := strings.ToLower(text[m[4]:m[5]])
		vs := m[1]
		ve := headerValueEnd(text, vs, quote)
		vs, ve = trimSpaces(text, vs, ve)
		if vs >= ve {
			continue
		}
		switch name {
		case "cookie":
			out = cookiePairs(text, vs, ve, out, false)
		case "set-cookie":
			out = cookiePairs(text, vs, ve, out, true)
		case "authorization", "proxy-authorization":
			out = authValue(text, vs, ve, out)
		default:
			k, ok := keyKind(name)
			if !ok {
				continue
			}
			// A quoted value (YAML "password: 'a b'") is the whole inner
			// string, quotes excluded.
			if q := text[vs]; q == '"' || q == '\'' {
				if c := strings.IndexByte(text[vs+1:ve], q); c >= 0 {
					if sp, ok := valueSpan(text, vs+1, vs+1+c, k); ok {
						out = append(out, sp)
					}
					continue
				}
			}
			if k == KindToken {
				out = authValue(text, vs, ve, out)
				continue
			}
			// Free-form "password: hunter2 (old)": the first word only.
			e := vs
			for e < ve && text[e] != ' ' && text[e] != '\t' {
				e++
			}
			if sp, ok := valueSpan(text, vs, e, k); ok {
				out = append(out, sp)
			}
		}
	}
	return out
}

func trimQuotes(text string, s, e int) (int, int) {
	if e-s >= 2 && (text[s] == '"' || text[s] == '\'') && text[e-1] == text[s] {
		return s + 1, e - 1
	}
	return s, e
}

// cookiePairs reports the values of "a=1; b=2". For Set-Cookie only the
// first pair is a value; the rest are attributes.
func cookiePairs(text string, s, e int, out []Span, setCookie bool) []Span {
	for s < e {
		end := strings.IndexByte(text[s:e], ';')
		if end < 0 {
			end = e
		} else {
			end += s
		}
		if eq := strings.IndexByte(text[s:end], '='); eq >= 0 {
			vs, ve := trimSpaces(text, s+eq+1, end)
			vs, ve = trimQuotes(text, vs, ve)
			if sp, ok := valueSpan(text, vs, ve, KindToken); ok {
				out = append(out, sp)
			}
		}
		if setCookie {
			break
		}
		s = end + 1
	}
	return out
}

// authValue handles an Authorization-style value: "Basic <b64>" becomes an
// EncBasicAuth span, "<Scheme> <credentials>" a token span on the
// credentials, and a bare value a token span on the whole value.
func authValue(text string, s, e int, out []Span) []Span {
	sp := strings.IndexAny(text[s:e], " \t")
	if sp < 0 {
		if v, ok := valueSpan(text, s, e, KindToken); ok {
			out = append(out, v)
		}
		return out
	}
	scheme := strings.ToLower(text[s : s+sp])
	cs, ce := trimSpaces(text, s+sp, e)
	if scheme == "basic" {
		if v, ok := basicAuthSpan(text, cs, ce); ok {
			return append(out, v)
		}
	}
	if v, ok := valueSpan(text, cs, ce, KindToken); ok {
		out = append(out, v)
	}
	return out
}

// basicAuthSpan decodes a Basic credential. Undecodable or colon-less values
// are reported as plain tokens by the caller.
func basicAuthSpan(text string, s, e int) (Span, bool) {
	b64 := text[s:e]
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(b64)
	}
	if err != nil || !utf8.Valid(dec) || !strings.Contains(string(dec), ":") {
		return Span{}, false
	}
	return Span{Start: s, End: e, Kind: KindPassword, Value: string(dec), Encoding: EncBasicAuth}, true
}

// plainValue reports an unencoded field value; token values may carry an
// auth scheme ("Bearer x", "Basic b64").
func plainValue(text string, s, e int, k Kind, out []Span) []Span {
	if k == KindToken {
		return authValue(text, s, e, out)
	}
	if sp, ok := valueSpan(text, s, e, k); ok {
		out = append(out, sp)
	}
	return out
}

// jsonKVRE matches "key": "value" pairs (string values only).
var jsonKVRE = regexp.MustCompile(`"([A-Za-z0-9_.\-]{1,40})"\s*:\s*"((?:[^"\\]|\\.)*)"`)

func jsonKeySecrets(text string, out []Span) []Span {
	for _, m := range lineMatches(jsonKVRE, text, lineHas(text, "\"")) {
		k, ok := keyKind(text[m[2]:m[3]])
		if !ok {
			continue
		}
		vs, ve := m[4], m[5]
		raw := text[vs:ve]
		if !strings.Contains(raw, `\`) {
			out = plainValue(text, vs, ve, k, out)
			continue
		}
		var dec string
		if json.Unmarshal([]byte(`"`+raw+`"`), &dec) != nil {
			continue
		}
		if utf8.RuneCountInString(dec) < minLiteralLen || shapedValue(dec) {
			continue
		}
		out = append(out, Span{Start: vs, End: ve, Kind: k, Value: dec, Encoding: EncJSONEscape})
	}
	return out
}

// kvRE matches query, form, env and assignment style key=value pairs,
// including `KEY = "quoted value"`. A bare value never starts with '='
// (comparisons such as "pass == x").
var kvRE = regexp.MustCompile(`(?:^|[?&;\s,(])([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,40})[ \t]*=[ \t]*` +
	quotedOr(`[^&\s;,"'<>#)=][^&\s;,"'<>#)]*`))

func kvSecrets(text string, out []Span) []Span {
	for _, m := range lineMatches(kvRE, text, lineHas(text, "=")) {
		k, ok := keyKind(text[m[2]:m[3]])
		if !ok {
			continue
		}
		vs, ve := valueGroup(m, 2)
		if vs != m[8] { // quoted: the inner string as written
			out = quotedValue(text, vs, ve, k, out)
			continue
		}
		raw := text[vs:ve]
		if !strings.ContainsAny(raw, "%+") {
			out = plainValue(text, vs, ve, k, out)
			continue
		}
		dec, err := url.QueryUnescape(raw)
		if err != nil || utf8.RuneCountInString(dec) < minLiteralLen || shapedValue(dec) {
			continue
		}
		out = append(out, Span{Start: vs, End: ve, Kind: k, Value: dec, Encoding: EncURL})
	}
	return out
}

// quotedValue reports a quoted field value; a token value that carries an
// auth scheme ("Bearer x") is split like a header.
func quotedValue(text string, s, e int, k Kind, out []Span) []Span {
	low := strings.ToLower(text[s:e])
	if k == KindToken && (strings.HasPrefix(low, "bearer ") || strings.HasPrefix(low, "basic ")) {
		return authValue(text, s, e, out)
	}
	if sp, ok := valueSpan(text, s, e, k); ok {
		out = append(out, sp)
	}
	return out
}

// userinfoRE matches scheme://user[:pass]@ in URLs. The userinfo classes
// exclude the delimiters inURLUserinfo stops at.
var userinfoRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^/\s:@'"<>,;|()\[\]{}]+)(?::([^/\s@'"<>,;|()\[\]{}]+))?@`)

func userinfoSecrets(text string, out []Span) []Span {
	for _, m := range lineMatches(userinfoRE, text, lineHas(text, "://")) {
		if sp, ok := valueSpan(text, m[2], m[3], KindUsername); ok {
			out = append(out, sp)
		}
		if m[4] < 0 {
			continue // username only (https://joao.silva@host)
		}
		if sp, ok := valueSpan(text, m[4], m[5], KindPassword); ok {
			out = append(out, sp)
		}
	}
	return out
}
