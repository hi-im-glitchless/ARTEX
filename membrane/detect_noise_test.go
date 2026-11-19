package membrane

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Live task 16 (2026-11-19): agent tool calls and their output enrolled
// curl write-out variables, shell variables, placeholders, HTTP status codes
// and code fragments as credentials. Each then matched everywhere: verify
// failed every earlier request and the leak check blocked requests.

// enrolledBy runs in through ToModel (text) and returns the originals it
// enrolled.
func enrolledBy(t *testing.T, e *Engine, s *Store, in string, asJSON bool) []string {
	t.Helper()
	before := map[string]bool{}
	for _, o := range storeOriginals(s) {
		before[o] = true
	}
	var err error
	if asJSON {
		_, _, err = e.ToModelJSON(json.RawMessage(in), Provenance{TaskIDs: []int64{9}})
	} else {
		_, _, err = e.ToModel(in, Provenance{TaskIDs: []int64{9}})
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range storeOriginals(s) {
		if !before[o] {
			out = append(out, o)
		}
	}
	return out
}

func storeOriginals(s *Store) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, e := range s.aliasExact {
		out = append(out, e.original)
	}
	return out
}

func TestNoiseIsNotEnrolled(t *testing.T) {
	for _, c := range []struct {
		name, in string
		json     bool
	}{
		{"curl write-out after a login label", `{"command": "curl -sk -o /dev/null -w \"login: %{http_code}\\n\" https://portal.acmebank.pt/rest/user/login"}`, true},
		{"curl write-out in single quotes", `{"command": "curl -sk https://portal.acmebank.pt/w -w 'whoami: %{http_code} user: %{size_download}\\n'"}`, true},
		{"curl write-out as text", "curl -w 'password: %{http_code}:%{size_download}' https://portal.acmebank.pt/", false},
		{"status code after login label", "login: 500 2320\nInvalid email or password.", false},
		{"status code after labelled login", "demo-login: 884\nadmin-pw-login: 030\nsqli-bypass:  030", false},
		{"numbers printed under credential labels", "email: 45044 \npassword: 640 \nid: 52285 \nusername: 62026 \n", false},
		{"python list comprehension", "users=[n['id'] for r in rows if r]", false},
		{"shell variable inside escaped JSON", `{"cmd": "echo \\\"$TOK\\\" > tok.txt && curl -H \\\"Authorization: Bearer $TOKEN\\\" https://portal.acmebank.pt/"}`, false},
		{"shell variable in nested tool JSON", `{"command": "curl -H \"Authorization: Bearer $TOKEN\" -o w.json https://portal.acmebank.pt/"}`, true},
		{"placeholder with digits", "Use the token: <token from step 2>", false},
		{"instruction note under a credentials key", `{"task_credentials_note":"test accounts for this task; use the matching entry for authenticated testing instead of registering a new account"}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, s := newTestEngine(t)
			for _, o := range enrolledBy(t, e, s, c.in, c.json) {
				if o != "portal.acmebank.pt" {
					t.Errorf("enrolled %q from %q", o, c.in)
				}
			}
		})
	}
}

// The fixes above must not stop real credentials from being aliased.
func TestRealCredentialsStillAliased(t *testing.T) {
	e, _ := newTestEngine(t)
	assertNoClear(t, e, `{"email":"demo","password":"qkik9"}`, "qkik9")
	assertNoClear(t, e, `{"email":"a@b.pt","username":"uuqzz3","password":"Zk2#pQ9w"}`, "uuqzz3", "Zk2#pQ9w")
	assertNoClear(t, e, "login: jdoe2024\npassword: S3cret!x", "jdoe2024", "S3cret!x")
	assertNoClear(t, e, `{"pin":482913}`, "482913")
	assertNoClear(t, e, `{"pin_code": 7391}`, "7391")
	assertNoClear(t, e, "Authorization: Bearer abcdefghijklmnop1234", "abcdefghijklmnop1234")
	assertNoClear(t, e, `{"password":"$ummer2024"}`, "$ummer2024")
	assertNoClear(t, e, "password: 83920174", "83920174")
}

// The goal of task 16: the username next to the password was sent in clear.
func TestGoalUsernameSlashPassword(t *testing.T) {
	e, _ := newTestEngine(t)
	assertNoClear(t, e, "if you create user do it with username: layer8 / password: pentest123!", "layer8", "pentest123!")
	assertNoClear(t, e, "use user: ana.costa / pass: Qw3rty!9", "ana.costa", "Qw3rty!9")
}

// An enrolled number equal to a request setting (max_tokens) is not a leak:
// the setting carries no client data, and the rewriter cannot touch it.
func TestLeakCheckIgnoresEnvelopeNumbers(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.Enroll(KindPassword, "4096", Provenance{TaskIDs: []int64{9}}); err != nil {
		t.Fatal(err)
	}
	req := llm.CompletionRequest{System: []string{"sys"}, MaxTokens: 4096,
		Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: "text", Text: "pin is 4096"}}}}}
	out, _, err := e.ToModelRequest(req, Provenance{TaskIDs: []int64{9}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(out)
	if hits := e.LeakCheck(body); len(hits) != 0 {
		t.Fatalf("envelope number flagged: %v in %s", hits, body)
	}
	for _, wire := range []string{
		`{"model":"k3","max_tokens":4096,"messages":[{"role":"user","content":"hi"}]}`,
		`{"max_completion_tokens": 4096, "temperature": 0.7}`,
	} {
		if hits := e.LeakCheck([]byte(wire)); len(hits) != 0 {
			t.Errorf("envelope number flagged in %s: %v", wire, hits)
		}
	}
	// The same number in content, or as a tool input value, still is one.
	for _, leak := range []string{
		`{"messages":[{"role":"user","content":"pin is 4096"}]}`,
		`{"tool_calls":[{"function":{"arguments":{"pin":4096}}}]}`,
	} {
		if hits := e.LeakCheck([]byte(leak)); len(hits) == 0 {
			t.Errorf("leak not flagged in %s", leak)
		}
	}
}
