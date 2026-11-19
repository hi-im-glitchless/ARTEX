package membrane

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Live task 16, second run (2026-11-19 14:26-14:37): three request blocks
// that paused the task.
//
//  1. The model's own reasoning about the target's source code
//     ("password: currentPassword", "password: hash(...)",
//     "change-password: PUT/POST?") enrolled code words as passwords.
//  2. Those words also occur in ARTEX's tool definitions, which are sent
//     unchanged, so the leak check blocked every retry.
//  3. The model invented an alias-shaped username (user-b3f6), registered
//     it on the target, and the echo enrolled it: the transform then kept
//     it inside an email while the leak check flagged it.

// Assistant-authored text and thinking never enrol new credentials: the
// model only sees aliases, so a credential it writes is one it made up or
// quotes from public code. Credentials already enrolled are still replaced.
func TestAssistantTextEnrolsNoCredentials(t *testing.T) {
	for _, in := range []string{
		"UserModel.findOne({ where: { id, password: currentPassword } })",
		"const where = currentPassword ? { id, password: hash(currentPassword) } : { id }",
		"if `current` is empty, the query `where: {id, password: current}` matches",
		"2. /rest/user/change-password: PUT/POST? In Juice Shop it's GET?",
		"I will register with password: bmoigsb742! and user: iptdo1",
	} {
		e, s := newTestEngine(t)
		before := len(storeOriginals(s))
		if _, _, err := e.toModelRole(in, Provenance{TaskIDs: []int64{9}}, true); err != nil {
			t.Fatal(err)
		}
		if got := storeOriginals(s); len(got) != before {
			t.Errorf("assistant text %q enrolled values (%d -> %d)", in, before, len(got))
		}
	}
	e, s := newTestEngine(t)
	out, _, err := e.toModelRole("log in as jsilva with password: Hunter2024!", Provenance{TaskIDs: []int64{9}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "jsilva") || strings.Contains(out, "Hunter2024!") {
		t.Errorf("known credentials not replaced in assistant text: %q", out)
	}
	_ = s
}

// A path segment ending in "-password" is not a credential label.
func TestPathSuffixIsNotACredentialLabel(t *testing.T) {
	e, s := newTestEngine(t)
	for _, o := range enrolledBy(t, e, s, "Check /rest/user/change-password: PUT/POST? and reset-password: GET", false) {
		t.Errorf("enrolled %q from a path label", o)
	}
}

// Tool definitions are ARTEX's own constants, sent unchanged: a credential
// value that matches a word in them is host vocabulary, not a leak. Client
// names (domains, orgs) in a tool definition still block.
func TestLeakCheckIgnoresCredentialWordsInTools(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.Enroll(KindPassword, "current", Provenance{TaskIDs: []int64{9}}); err != nil {
		t.Fatal(err)
	}
	req := llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("hello")},
		Tools: []llm.ToolSchema{{Name: "http", Description: "Send a request; returns the current status and hash",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"current": map[string]any{"type": "string"}}}}},
		MaxTokens: 1000,
	}
	body, _ := json.Marshal(req)
	if hits := e.LeakCheck(body); len(hits) != 0 {
		t.Errorf("canonical body: credential word in tool definitions blocked: %v", hits)
	}
	wire := `{"model":"k","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"http","description":"returns the current status"}}]}`
	if hits := e.LeakCheck([]byte(wire)); len(hits) != 0 {
		t.Errorf("wire body: credential word in tool definitions blocked: %v", hits)
	}
	// Outside the tool definitions the same word still counts.
	req.Messages = []llm.Message{llm.UserText("password is current")}
	body, _ = json.Marshal(req)
	if hits := e.LeakCheck(body); len(hits) == 0 {
		t.Error("credential in a message was not caught")
	}
	// A client name inside a tool definition still blocks.
	req.Messages = []llm.Message{llm.UserText("hello")}
	req.Tools[0].Description = "Scan portal.acmebank.pt"
	body, _ = json.Marshal(req)
	if hits := e.LeakCheck(body); len(hits) == 0 {
		t.Error("client domain in a tool definition was not caught")
	}
}

// The model reused the local part of an email alias (user-b3f6 of
// user-b3f6@541650.example) as a login; the target echoed it alone and it
// was enrolled as a real username (ruling R11). The email alias itself is
// still alias space: the leak check must not flag its local part, while
// the bare token still counts.
func TestEmailAliasLocalPartEnrolledAsUsername(t *testing.T) {
	e, s := newTestEngine(t)
	prov := Provenance{TaskIDs: []int64{9}}
	email, err := s.Enroll(KindEmail, "ana.costa@acmebank.pt", prov)
	if err != nil {
		t.Fatal(err)
	}
	at := strings.IndexByte(email, '@')
	if at < 0 || !shapeKeywordRE.MatchString(email[:at]) {
		t.Skipf("email alias %q has no keyword-shaped local part", email)
	}
	local := email[:at]
	if _, err := s.enrollLookalike(KindUsername, local, prov); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		email,
		`{"username":"` + email + `"}`,
		`{\"username\":\"` + email + `\"}`,
		`"users: 61\n` + email + `:3c2abc04\nnext"`, // JSON-escaped newline before the alias
	} {
		if hits := e.LeakCheck([]byte(in)); len(hits) != 0 {
			t.Errorf("email alias in %q flagged: %v", in, hits)
		}
	}
	if hits := e.LeakCheck([]byte("login " + local + " ok")); len(hits) == 0 {
		t.Error("bare enrolled token not flagged")
	}
}

// An alias-shaped value the model invented and the target echoed is enrolled
// (ruling R11); the transform must then replace it everywhere the leak check
// looks, including the local part of an email.
func TestEnrolledLookalikeInEmailIsReplaced(t *testing.T) {
	e, _ := newTestEngine(t)
	prov := Provenance{TaskIDs: []int64{9}}
	for _, in := range []string{
		`{"umail":"user-b3f6@acmebank.pt"}`,
		`{"username":"user-b3f6@acmebank.pt"}`,
		`{"email":"user-b3f6@acmebank.pt","password":"x9Kq2!pz"}`,
		"  6 user-b3f6@acmebank.pt admin\n  7 user-b3f6@owasp.org deluxe",
	} {
		out, _, err := e.ToModel(in, prov)
		if err != nil {
			t.Fatal(err)
		}
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
			t.Errorf("ToModel(%q) = %q still leaks %v", in, out, hits)
		}
	}
}

// JSON-escaped fragments are not credentials: "\u003cunsigned\u003e" (an
// escaped placeholder) and "1\n\n" (a digit and escaped newlines) were
// enrolled from raw JSON text in the live run.
func TestEscapedFragmentsAreNotEnrolled(t *testing.T) {
	for _, in := range []string{
		`{"cmd":"curl -H \"Authorization: Bearer \u003cunsigned\u003e\" https://portal.acmebank.pt/"}`,
		`Authorization: Bearer \u003cunsigned\u003e`,
		`- viewport=width=device-width, initial-scale=1\n\n\n## LINKS`,
		`{"username":"1\n\n"}`,
	} {
		e, s := newTestEngine(t)
		for _, o := range enrolledBy(t, e, s, in, false) {
			if o != "portal.acmebank.pt" {
				t.Errorf("enrolled %q from %q", o, in)
			}
		}
	}
}

// Values enrolled as tokens in the live run that are not tokens.
func TestNonTokensAreNotEnrolled(t *testing.T) {
	for _, in := range []string{
		`{"evidence":"Token: POST /rest/user/login with layer8@portal.acmebank.pt/pentest123! (self-registered customer, JWT id=118 role=customer)."}`,
		`curl 'https://portal.acmebank.pt/rest/user/whoami' -H \"Authorization: Bearer $TOKEN\" -o whoami.json`,
		`{"session_id":"conv-164"}`,
	} {
		e, s := newTestEngine(t)
		for _, o := range enrolledBy(t, e, s, in, false) {
			if _, k, _ := s.AliasFor(o); isCredentialKind(k) {
				t.Errorf("enrolled %s %q from %q", k, o, in)
			}
		}
	}
}

func TestTokenNoiseValues(t *testing.T) {
	for _, v := range []string{"nftMintChallenge`", "$TOKEN", "conv-164", "task_12",
		"/rest/user/login with layer8@x.pt/p (self-registered customer, JWT id=118)."} {
		if !noiseValue(KindToken, v) {
			t.Errorf("%q not noise", v)
		}
	}
	for _, v := range []string{"abc123xyz", "a b c d", "tok_9f8e7d6c5b4a", "k3y-AbCdEf12345", "sess-8f3a9c2e"} {
		if noiseValue(KindToken, v) {
			t.Errorf("%q is a token", v)
		}
	}
}
