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
	out = optionSecrets(text, out)
	out = append(out, gluedFlagSpans(text)...)
	out = gitNameSpans(text, out)
	return settleUserIDs(out)
}

// Glued credential options: the MySQL client family takes -u<user> and
// -p<password> glued (mysql -ubob -pS3cret), sshpass takes -p<password>.
// Only options that belong to such a command are read: the command word
// must stand at command position (line start, after | ; && || $( or a
// backtick, after sudo/exec/time/nohup, or right after an opening quote:
// ssh host 'mysql -p...'), and its options run to the end of that command.
// Not credentials: ssh -p2222, psql -p5432, docker -p3306:3306, find
// -path/-print/-prune, mkdir -pv, and $VAR / ${VAR} / $(...) values.

var mysqlFamily = map[string]bool{
	"mysql": true, "mysqldump": true, "mysqladmin": true, "mysqlcheck": true, "mysqlimport": true,
	"mysqlshow": true, "mariadb": true, "mariadb-dump": true, "mariadb-admin": true,
}

var (
	cmdSepRE    = regexp.MustCompile("\\|\\||&&|[|;]|\\$\\(|`")
	gluedFlagRE = regexp.MustCompile(`(?:^|\s)-([pu])(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'|;&()]+))`)
	portMapRE   = regexp.MustCompile(`^[0-9]+(?::[0-9]+)+$`)
	promptRE    = regexp.MustCompile(`^[^\n]*?[$#>] `)
)

// gluedFlagSpans reports -p<password> and -u<user> glued to a MySQL-family
// command, and -p<password> glued to sshpass.
func gluedFlagSpans(text string) []Span {
	if !strings.Contains(text, "mysql") && !strings.Contains(text, "mariadb") && !strings.Contains(text, "sshpass") {
		return nil
	}
	var out []Span
	for ls := 0; ls < len(text); {
		le := strings.IndexByte(text[ls:], '\n')
		if le < 0 {
			le = len(text)
		} else {
			le += ls
		}
		segStart := ls
		seps := cmdSepRE.FindAllStringIndex(text[ls:le], -1)
		// A shell prompt ($ , # , > , user@h:~# ) may precede the first
		// command of a line; the text after it is tried as a command too.
		firstEnd := le
		if len(seps) > 0 {
			firstEnd = ls + seps[0][0]
		}
		if p := promptRE.FindStringIndex(text[ls:firstEnd]); p != nil {
			out = commandFlags(text, ls+p[1], firstEnd, out)
		}
		for _, m := range seps {
			out = commandFlags(text, segStart, ls+m[0], out)
			segStart = ls + m[1]
		}
		out = commandFlags(text, segStart, le, out)
		ls = le + 1
	}
	return out
}

// commandFlags reads the credential options of the command in text[s:e],
// and of commands opened by a quote inside it (ssh host 'mysql -p...').
func commandFlags(text string, s, e int, out []Span) []Span {
	out = oneCommand(text, s, e, out)
	for q := s; q < e; q++ {
		if c := text[q]; c != '\'' && c != '"' {
			continue
		}
		qe := strings.IndexByte(text[q+1:e], text[q])
		end := e
		if qe >= 0 {
			end = q + 1 + qe
		}
		if w, _, _ := commandWord(text, q+1, end); mysqlFamily[w] || w == "sshpass" {
			out = oneCommand(text, q+1, end, out)
			q = end
		}
	}
	return out
}

// commandWord returns the base name of the command word of text[s:e] and
// its range. It walks the words of the command: blanks and '(' are
// skipped, and so are NAME=value environment assignments and wrappers
// with their own options and operands (sudo -u x, env, nice -n 10, watch,
// xargs, timeout 10, stdbuf, docker|podman [compose] exec [opts] CTR,
// docker run [opts] IMAGE, kubectl ... --, ssh [opts] HOST). The first
// other word is the command. Words that only name a file or an option
// argument (find /var/lib/mysql -user mysql) are never reached, because
// find is not a wrapper.
func commandWord(text string, s, e int) (string, int, int) {
	toks := words(text, s, e)
	for k := 0; k < len(toks); {
		tok := text[toks[k][0]:toks[k][1]]
		w, ok := wrappers[tok]
		switch {
		case envAssignRE.MatchString(tok) && k+1 < len(toks):
			k++
			continue
		case !ok:
			return tok[strings.LastIndexByte(tok, '/')+1:], toks[k][0], toks[k][1]
		case w.dashDash: // kubectl ... -- cmd
			k = afterDashDash(text, toks, k+1)
			continue
		case w.sub != nil: // docker exec / docker run
			k++
			for k < len(toks) && passThrough[text[toks[k][0]:toks[k][1]]] {
				k++ // docker compose exec, docker container exec
			}
			if k >= len(toks) || w.sub[text[toks[k][0]:toks[k][1]]] == nil {
				return "", e, e
			}
			w = *w.sub[text[toks[k][0]:toks[k][1]]]
		}
		k = skipOptions(text, toks, k+1, w)
	}
	return "", e, e
}

// wrapper describes a command that runs another command: argOpts are its
// short options that take an argument, argLong its long ones, operands
// the positional words before the command (ssh HOST, timeout DURATION).
type wrapper struct {
	argOpts  string
	argLong  map[string]bool
	operands int
	dashDash bool                // the command follows "--" (kubectl exec)
	sub      map[string]*wrapper // subcommands (docker exec, docker run)
}

var (
	envAssignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	passThrough = map[string]bool{"compose": true, "container": true}
	dockerExec  = &wrapper{argOpts: "euw", operands: 1,
		argLong: map[string]bool{"--env": true, "--user": true, "--workdir": true, "--env-file": true, "--detach-keys": true}}
	dockerRun = &wrapper{argOpts: "acehlmpuvw", operands: 1, argLong: map[string]bool{
		"--name": true, "--network": true, "--volume": true, "--env": true, "--publish": true, "--user": true,
		"--workdir": true, "--entrypoint": true, "--mount": true, "--label": true, "--hostname": true,
		"--memory": true, "--cpus": true, "--platform": true, "--restart": true, "--add-host": true,
		"--env-file": true, "--link": true, "--log-driver": true, "--log-opt": true, "--net": true}}
	containerCmds = map[string]*wrapper{"exec": dockerExec, "run": dockerRun}
	wrappers      = map[string]wrapper{
		"sudo": {argOpts: "ugpChDrtUT", argLong: map[string]bool{"--user": true, "--group": true}},
		"exec": {}, "time": {}, "nohup": {}, "command": {}, "builtin": {}, "doas": {argOpts: "uC"},
		"do": {}, "then": {}, "else": {}, "elif": {}, "{": {}, "!": {},
		"--": {}, // mysql> ... -- mysql -p...: read rather than guess

		"strace": {argOpts: "abeEIoOpPsSuX"}, "ltrace": {argOpts: "aAeEnoOpPsSuxX"},
		"env":     {argOpts: "uCS", argLong: map[string]bool{"--unset": true, "--chdir": true}},
		"nice":    {argOpts: "n"},
		"ionice":  {argOpts: "cnp"},
		"watch":   {argOpts: "n", argLong: map[string]bool{"--interval": true}},
		"xargs":   {argOpts: "IadEeLlnPsS"},
		"timeout": {argOpts: "sk", argLong: map[string]bool{"--signal": true, "--kill-after": true}, operands: 1},
		"stdbuf":  {argOpts: "ioe"},
		"chroot":  {operands: 1},
		"ssh":     {argOpts: "BbcDEeFIiJLlmOoPpQRSWw", operands: 1},
		"kubectl": {dashDash: true}, "oc": {dashDash: true},
		"docker": {sub: containerCmds}, "podman": {sub: containerCmds}, "nerdctl": {sub: containerCmds},
		"docker-compose": {sub: containerCmds},
	}
)

// words splits text[s:e] at blanks, dropping a word's leading '('.
func words(text string, s, e int) [][2]int {
	var out [][2]int
	for i := s; i < e; {
		for i < e && (text[i] == ' ' || text[i] == '\t' || text[i] == '(') {
			i++
		}
		j := i
		for j < e && text[j] != ' ' && text[j] != '\t' {
			j++
		}
		if i < j {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

// skipOptions skips a wrapper's options (with their arguments) and its
// operands from word k on, and returns the index of the next word.
// Options may also follow the operands (ssh HOST -p2222 cmd), so they are
// skipped again after them.
func skipOptions(text string, toks [][2]int, k int, w wrapper) int {
	k = skipFlags(text, toks, k, w)
	if w.operands == 0 || k >= len(toks) {
		return k
	}
	return skipFlags(text, toks, min(k+w.operands, len(toks)), w)
}

// skipFlags skips options (with their arguments) from word k on.
func skipFlags(text string, toks [][2]int, k int, w wrapper) int {
	for k < len(toks) {
		tok := text[toks[k][0]:toks[k][1]]
		if tok == "--" {
			k++
			break
		}
		if len(tok) < 2 || tok[0] != '-' {
			break
		}
		k++
		switch {
		case strings.HasPrefix(tok, "--"):
			if w.argLong[tok] {
				k++
			}
		case len(tok) == 2 && strings.IndexByte(w.argOpts, tok[1]) >= 0:
			k++ // -u user, -n 10
		}
	}
	return k
}

// afterDashDash returns the index after the first "--" word from k on, or
// len(toks) when there is none.
func afterDashDash(text string, toks [][2]int, k int) int {
	for ; k < len(toks); k++ {
		if text[toks[k][0]:toks[k][1]] == "--" {
			return k + 1
		}
	}
	return len(toks)
}

// oneCommand reads the options of one command in text[s:e].
func oneCommand(text string, s, e int, out []Span) []Span {
	w, _, we := commandWord(text, s, e)
	switch {
	case mysqlFamily[w]:
		return gluedOptions(text, we, e, true, out)
	case w == "sshpass":
		// sshpass's own options end at the command it runs.
		i := we
		for i < e {
			for i < e && (text[i] == ' ' || text[i] == '\t') {
				i++
			}
			if i >= e || text[i] != '-' {
				break
			}
			for i < e && text[i] != ' ' && text[i] != '\t' {
				i++
			}
		}
		out = gluedOptions(text, we, i, false, out)
		return oneCommand(text, i, e, out)
	}
	return out
}

// gluedOptions reports glued -p (and with user, -u) option values in
// text[s:e].
func gluedOptions(text string, s, e int, user bool, out []Span) []Span {
	for _, m := range gluedFlagRE.FindAllStringSubmatchIndex(text[s:e], -1) {
		k := KindPassword
		if text[s+m[2]:s+m[3]] == "u" {
			if !user {
				continue
			}
			k = KindUsername
		}
		vs, ve := valueGroup(m, 2)
		if vs < 0 {
			continue
		}
		vs, ve = vs+s, ve+s
		v := text[vs:ve]
		if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "`") || portMapRE.MatchString(v) {
			continue
		}
		if sp, ok := valueSpan(text, vs, ve, k); ok {
			out = append(out, sp)
		}
	}
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
	passwordKeyRE = regexp.MustCompile(`(?i)(passw(or)?d|passwd|pass\b|pwd|passphrase|passcode)`)
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
//
// A compound name (auth_type, tokenTtl, --user-namespace) is a credential
// only through its last credential component, and only when no qualifier
// follows it: auth_type, token_type, secret-name, user-pool-id and
// api-key-header name a setting, not a secret, and their values (basic,
// bearer, prod-db) must not be enrolled. Other followers keep it a
// credential (db_password_prod). "key" counts only after api, access,
// secret, private, signing, client, master, encryption, auth, consumer or
// app (ssh-key, public_key and key_id are not secrets); "id" only after
// session (session_id).
func keyKind(key string) (Kind, bool) {
	if lowerASCII(key) == "user.name" {
		return KindPerson, true // git's display name, not a login
	}
	comps := keyComponents(key)
	if len(comps) < 2 {
		return keyKindWord(key)
	}
	for i := len(comps) - 1; i >= 0; i-- {
		c := comps[i]
		var k Kind
		ok := false
		switch {
		case c == "key" || c == "keys":
			if i > 0 && keyPrefixes[comps[i-1]] {
				k, ok = KindToken, true
			}
		case c == "id" && i > 0 && (comps[i-1] == "session" || comps[i-1] == "sess"):
			k, ok = KindToken, true
		case keyQualifiers[c]:
		default:
			if emailKeyRE.MatchString(c) {
				return "", false
			}
			k, ok = keyKindWord(c)
		}
		if !ok {
			continue
		}
		for j, f := range comps[i+1:] {
			if keyQualifiers[f] && !qualifierExempt(key, comps[i], f, j == 0) {
				return "", false
			}
		}
		if k == KindUsername && c != "id" && i == len(comps)-2 && comps[i+1] == "id" {
			k = kindUserID // user_id: numeric values are not enrolled
		}
		return k, true
	}
	return "", false
}

// kindUserID is an internal kind for user_id-style keys. secretDetector
// drops numeric values (1042 would alias every 1042 in the text) and turns
// the rest into KindUsername.
const kindUserID Kind = "userid"

var numericIDRE = regexp.MustCompile(`^[0-9]+$`)

func settleUserIDs(spans []Span) []Span {
	out := spans[:0]
	for _, sp := range spans {
		if sp.Kind == kindUserID {
			if numericIDRE.MatchString(sp.Value) || uidRE.MatchString(sp.Value) {
				continue
			}
			sp.Kind = KindUsername
		}
		out = append(out, sp)
	}
	return out
}

// Git identity: `git config [opts] user.name <v>` and `name = <v>` inside a
// [user] section. The key=value forms go through keyKind ("user.name").
var gitNameRE = regexp.MustCompile(`(?:^|\s)user\.name[ \t]+` + quotedOr(`[^\s"'<>;|&()-][^\s"'<>;|&()]*`))

func gitNameSpans(text string, out []Span) []Span {
	if !strings.Contains(text, "name") {
		return out
	}
	for _, m := range lineMatches(gitNameRE, text, lineHasAny(text, "user.name")) {
		ls := strings.LastIndexByte(text[:m[0]], '\n') + 1
		le := strings.IndexByte(text[m[0]:], '\n')
		if le < 0 {
			le = len(text)
		} else {
			le += m[0]
		}
		if line := text[ls:le]; !strings.Contains(line, "git") || !strings.Contains(line, "config") {
			continue
		}
		if vs, ve := valueGroup(m, 1); vs >= 0 {
			if sp, ok := valueSpan(text, vs, ve, KindPerson); ok {
				out = append(out, sp)
			}
		}
	}
	// gitconfig sections.
	inUser := false
	for ls := 0; ls < len(text); {
		le := strings.IndexByte(text[ls:], '\n')
		if le < 0 {
			le = len(text)
		} else {
			le += ls
		}
		line := strings.TrimSpace(text[ls:le])
		switch {
		case strings.HasPrefix(line, "["):
			inUser = strings.EqualFold(line, "[user]")
		case inUser:
			if k, _, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") {
				vs := ls + strings.Index(text[ls:le], "=") + 1
				ve := le
				if ve > vs && text[ve-1] == '\r' {
					ve-- // CRLF line ending
				}
				vs, ve = trimSpaces(text, vs, ve)
				if vs < ve && (text[vs] == '"' || text[vs] == '\'') {
					if c := strings.IndexByte(text[vs+1:ve], text[vs]); c >= 0 {
						vs, ve = vs+1, vs+1+c // quoted: a trailing comment follows the quote
					}
				} else if c := strings.IndexAny(text[vs:ve], "#;"); c > 0 && (text[vs+c-1] == ' ' || text[vs+c-1] == '\t') {
					_, ve = trimSpaces(text, vs, vs+c) // unquoted: stop before " #" / " ;"
				}
				if vs < ve {
					if sp, ok := valueSpan(text, vs, ve, KindPerson); ok {
						out = append(out, sp)
					}
				}
			}
		}
		ls = le + 1
	}
	return out
}

// qualifierExempt: a qualifier that does not turn the credential into a
// setting. name/id directly after user, login, account or usr is the login
// itself (user_name, login_id); a dotted key (git's user.name) stays a
// setting. data after secret or token holds the secret (secret_data), and
// server/backend after a password names where the password is used
// (password_server=...).
func qualifierExempt(key, cred, q string, direct bool) bool {
	if !direct {
		return false
	}
	switch cred {
	case "user", "login", "account", "usr":
		return (q == "name" || q == "id") && !strings.Contains(key, ".")
	case "secret", "token":
		return q == "data"
	case "password", "passwd", "pwd":
		return q == "server" || q == "backend"
	}
	return false
}

// keyComponents splits a field name at '-', '_', '.', and lower-to-upper
// camelCase boundaries, lowercased: AWS_SECRET_ACCESS_KEY -> aws secret
// access key, apiKey -> api key, --user-pool-id -> user pool id.
func keyComponents(key string) []string {
	var out []string
	start := 0
	flush := func(e int) {
		if e > start {
			out = append(out, lowerASCII(key[start:e]))
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '-' || c == '_' || c == '.' || c == '[' || c == ']':
			flush(i)
			start = i + 1
		case c >= 'A' && c <= 'Z' && i > start && key[i-1] >= 'a' && key[i-1] <= 'z':
			flush(i)
			start = i
		}
	}
	flush(len(key))
	return out
}

// keyPrefixes make a following "key" component a secret key.
var keyPrefixes = map[string]bool{
	"api": true, "access": true, "secret": true, "private": true, "signing": true, "client": true,
	"master": true, "encryption": true, "auth": true, "consumer": true, "app": true,
}

// keyQualifiers: components that turn a credential name into the name of a
// setting about it (auth_type, token_ttl, secret_name, user_namespace).
var keyQualifiers = map[string]bool{
	"type": true, "types": true, "mode": true, "ttl": true, "name": true, "names": true, "id": true, "ids": true,
	"ref": true, "policy": true, "endpoint": true, "url": true, "uri": true, "namespace": true, "ns": true,
	"audience": true, "provider": true, "attribute": true, "attr": true, "header": true, "pool": true,
	"method": true, "methods": true, "file": true, "path": true, "dir": true, "store": true, "agent": true,
	"data": true, "arn": true, "length": true, "len": true, "expiry": true, "expires": true, "expiration": true,
	"lifetime": true, "timeout": true, "format": true, "scheme": true, "kind": true, "field": true,
	"param": true, "prefix": true, "hint": true, "enabled": true, "required": true, "version": true,
	"location": true, "issuer": true, "scope": true, "scopes": true, "strategy": true, "plugin": true,
	"backend": true, "server": true, "host": true, "port": true, "level": true, "count": true, "ip": true,
	"helper": true, "source": true, "class": true, "config": true, "manager": true, "group": true,
	"role": true, "home": true, "shell": true, "uid": true, "gid": true,
}

// keyKindWord classifies one name by the middlehack substring rules.
func keyKindWord(key string) (Kind, bool) {
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
	if utf8.RuneCountInString(v) < minLiteralLen || shapedValue(v) || placeholderValue(v) {
		return Span{}, false
	}
	return Span{Start: s, End: e, Kind: k, Value: v}, true
}

// placeholderWords are type names and stock example values that sit in
// secret fields of schemas, docs and templates ({"password": "string"}).
// Enrolling them would alias the word everywhere (`"type":"string"`).
var placeholderWords = map[string]bool{
	"string": true, "number": true, "integer": true, "int": true, "float": true,
	"boolean": true, "bool": true, "null": true, "nil": true, "true": true,
	"false": true, "none": true, "undefined": true, "object": true, "array": true,
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true,
	"api_key": true, "changeme": true, "change_me": true, "changeit": true,
	"example": true, "sample": true, "value": true, "redacted": true,
	"hidden": true, "masked": true, "placeholder": true, "dummy": true, "todo": true,
	"username": true, "user": true, "test": true, "empty": true,
	// Protocol and configuration words that sit in auth settings
	// (auth: basic, "token_type":"bearer", --auth-provider=oidc).
	"basic": true, "bearer": true, "digest": true, "ntlm": true, "negotiate": true, "kerberos": true,
	"oidc": true, "oauth": true, "oauth2": true, "saml": true, "ldap": true, "host": true, "md5": true,
	"scram-sha-256": true, "trust": true, "peer": true, "yes": true, "no": true, "on": true, "off": true,
	"enabled": true, "disabled": true, "required": true, "optional": true,
	// Service accounts: not client-identifying (--user=www-data).
	"www-data": true, "nobody": true, "daemon": true, "nginx": true, "apache": true,
}

// placeholderValue reports a value that is a template or placeholder, not a
// secret: a placeholder word, one character repeated (xxx, ****, ...), a
// value wrapped in <> {} {{}} ${} [] or %%, or "your_..." text.
func placeholderValue(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if placeholderWords[t] {
		return true
	}
	for _, p := range []string{"your_", "your-", "your ", "yourpass", "yourtoken", "yourkey", "yoursecret", "yourapi"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if t != "" && strings.Trim(t, t[:1]) == "" && strings.ContainsAny(t[:1], "x*.-_#?") {
		return true
	}
	return wrappedPlaceholderRE.MatchString(strings.TrimSpace(v))
}

// wrappedPlaceholderRE: template markers whose inner text is a name, not a
// secret (<password>, {{ api_token }}, ${DB_PASS}, %DB_PASSWORD%,
// [REDACTED], {token}, $(cat file)). {Xk9#mq2} or <Secr3t> are secrets.
var wrappedPlaceholderRE = regexp.MustCompile(`^(?:<[A-Za-z_ .-]+>|\{\{\s*[\w.]+\s*\}\}|\$\{[A-Za-z_][A-Za-z0-9_.:-]*\}|%[A-Z][A-Z0-9_]*%|\[[A-Z_][A-Z_ ]*\]|\{[a-z_][a-z0-9_.]*\}|\$\([^)]+\))$`)

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
	if placeholderValue(text[s:e]) {
		return out // checked whole, before a scheme split ({{ api_token }})
	}
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

// kvRE matches query, form, env and assignment style key=value pairs.
// Spaces around '=' are allowed only before a quoted value
// (`KEY = "value"`): a spaced bare value is code (`password = os.getenv(`),
// not a literal. A bare value never starts with '=' (`pass == x`).
// Groups: 1 key, 2 "double", 3 'single', 4 bare (the quotedOr layout).
var kvRE = regexp.MustCompile(`(?:^|[?&;\s,(])([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,40})` +
	`(?:[ \t]*=[ \t]*(?:"([^"\n]*)"|'([^'\n]*)')|=([^&\s;,"'<>#)=][^&\s;,"'<>#)]*))`)

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
		if placeholderValue(raw) {
			continue // %DB_PASSWORD% is a template marker, not %DB-escaped
		}
		if !strings.ContainsAny(raw, "%+") {
			out = plainValue(text, vs, ve, k, out)
			continue
		}
		dec, err := url.QueryUnescape(raw)
		if err != nil {
			// Not valid percent-encoding (%Pa55w0rd%): the value is literal.
			out = plainValue(text, vs, ve, k, out)
			continue
		}
		if utf8.RuneCountInString(dec) < minLiteralLen || shapedValue(dec) || placeholderValue(dec) {
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

// Command-line options: --password=v, --pass=v, -password=v, --user=v
// and the space-separated --password v. kvRE needs a separator before the
// key, so a dash-prefixed key is read here. The '=' form takes any key
// keyKind accepts; the space form only a double-dash name in spaceOptNames
// (most --flag v pairs are not credentials, psql --password takes no value,
// and find's -user takes a system user name).
var (
	optEqRE    = regexp.MustCompile(`(?:^|[\s'"(])--?([A-Za-z][A-Za-z0-9_.-]{0,40})=` + quotedOr(`[^\s"'<>;|&()]+`))
	optSpaceRE = regexp.MustCompile(`(?:^|[\s'"(])--([A-Za-z][A-Za-z0-9_-]{0,40})[ \t]+` + quotedOr(`[^\s"'<>;|&()-][^\s"'<>;|&()]*`))
	// envVarRE: a $NAME reference (the value comes from the environment).
	envVarRE = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
	// uidRE: a numeric user or user:group id (docker run --user 1000:1000).
	uidRE = regexp.MustCompile(`^[0-9]+(?::[0-9]+)?$`)
)

var spaceOptNames = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "user": true, "username": true,
	"login": true, "token": true, "api-key": true, "api_key": true, "apikey": true, "secret": true,
	"client-secret": true, "client_secret": true, "access-key": true, "secret-key": true,
	"auth-token": true, "access-token": true, "db-password": true, "db-user": true,
	"bearer": true, "oauth2-bearer": true, "passphrase": true, "bearer-token": true,
	"user-name": true, "login-name": true, "db-pass": true, "root-password": true,
}

func optionSecrets(text string, out []Span) []Span {
	if !strings.Contains(text, "-") {
		return out
	}
	pre := lineHas(text, "-")
	for _, m := range lineMatches(optEqRE, text, pre) {
		out = optionValue(text, m, false, out)
	}
	for _, m := range lineMatches(optSpaceRE, text, pre) {
		out = optionValue(text, m, true, out)
	}
	return out
}

func optionValue(text string, m []int, spaced bool, out []Span) []Span {
	name := lowerASCII(text[m[2]:m[3]])
	if spaced && !spaceOptNames[name] {
		return out
	}
	// Option names that hold a path, an agent string or a directory, not a
	// credential (--key-file, --user-agent, --user-data-dir, --ssh-key).
	for _, w := range []string{"agent", "file", "dir", "path", "ssh-key", "keyring", "store"} {
		if strings.Contains(name, w) {
			return out
		}
	}
	k, ok := keyKind(name)
	if !ok {
		return out
	}
	vs, ve := valueGroup(m, 2)
	if vs < 0 {
		return out
	}
	v := text[vs:ve]
	if envVarRE.MatchString(v) || strings.HasPrefix(v, "`") || strings.HasPrefix(v, "$(") || placeholderValue(v) {
		return out
	}
	if k == KindUsername && uidRE.MatchString(v) {
		return out
	}
	if k == KindToken && strings.ContainsAny(v[:1], "/~.") {
		return out // a path
	}
	if sp, ok := valueSpan(text, vs, ve, k); ok {
		out = append(out, sp)
	}
	return out
}

// URL userinfo. The scheme://user:pass@ form is unambiguous, so user and
// password take any byte but '/', whitespace, '@', quotes and <> (generated
// passwords use RFC 3986 sub-delims such as ",;()[]{}"). A username-only
// scheme://user@ is narrower and stops at the delimiters inURLUserinfo
// stops at, so "https://acme.pt,joao@gmail.com" stays an email.
var (
	userinfoPassRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^/\s:@'"<>]+):([^/\s@'"<>]+)@`)
	userinfoUserRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^/\s:@'"<>,;|()\[\]{}]+)@`)
	// userinfoPassTailRE: text ending in a scheme://user:pass@ authority.
	userinfoPassTailRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@'"<>]+:[^/\s@'"<>]+@$`)
)

func userinfoSecrets(text string, out []Span) []Span {
	pre := lineHas(text, "://")
	for _, m := range lineMatches(userinfoPassRE, text, pre) {
		if sp, ok := valueSpan(text, m[2], m[3], KindUsername); ok {
			out = append(out, sp)
		}
		if sp, ok := valueSpan(text, m[4], m[5], KindPassword); ok {
			out = append(out, sp)
		}
	}
	for _, m := range lineMatches(userinfoUserRE, text, pre) {
		if sp, ok := valueSpan(text, m[2], m[3], KindUsername); ok {
			out = append(out, sp)
		}
	}
	return out
}
