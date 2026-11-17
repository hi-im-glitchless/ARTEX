package membrane

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Fix round 1 regressions, built from the reviewer's probe inputs.

func TestJWTKeysAndNumbersAliased(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.Enroll(KindNIF, "123456789", seedProv); err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"RS256","kid":"k1"}`))
	for _, pl := range []string{
		`{"sub":"auth0|1","https://acmebank.pt/roles":["admin"]}`,
		`{"sub":"x","nif":123456789,"phone":351912345678}`,
		`{"sub":"x","org":"Acme Bank"}`,
	} {
		tok := h + "." + enc([]byte(pl)) + ".c2lnbmF0dXJlc2lnbmF0dXJlc2ln"
		in := "Authorization: Bearer " + tok
		if len(e.LeakCheck([]byte(in))) == 0 {
			t.Fatalf("LeakCheck must decode JWT segments: %s", pl)
		}
		out := toModel(t, e, in)
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
			t.Fatalf("leak %+v for payload %s", hits, pl)
		}
		parts := strings.Split(strings.TrimPrefix(out, "Authorization: Bearer "), ".")
		if len(parts) == 3 {
			dec, _ := base64.RawURLEncoding.DecodeString(parts[1])
			if strings.Contains(string(dec), "acmebank") || strings.Contains(string(dec), "Acme Bank") || strings.Contains(string(dec), "123456789") {
				t.Fatalf("payload sent to model: %s", dec)
			}
		}
		if back, _ := e.ToReal(out); back != in {
			t.Fatalf("round trip %q", back)
		}
	}
}

func TestLeakCheckDecodesBasic(t *testing.T) {
	e, _ := newTestEngine(t)
	b := base64.StdEncoding.EncodeToString([]byte("jsilva:Hunter2024!"))
	if len(e.LeakCheck([]byte(`{"text":"Authorization: Basic `+b+`"}`))) == 0 {
		t.Fatal("LeakCheck must decode Basic credentials")
	}
	in := "WWW-Authenticate ok; Basic " + b
	out := toModel(t, e, in)
	if strings.Contains(out, b) || len(e.LeakCheck([]byte(out))) != 0 {
		t.Fatalf("Basic credential outside Authorization sent in clear: %q", out)
	}
	if back, _ := e.ToReal(out); back != in {
		t.Fatalf("round trip %q", back)
	}
}

func TestPlaceholderSecretsNotEnrolled(t *testing.T) {
	e, s := newTestEngine(t)
	in := `{"password": "string", "api_key": "string", "token": "<token>", "secret": "{{secret}}", "pwd": "changeme", "pass": "********"}`
	out := toModel(t, e, in)
	if out != in {
		t.Fatalf("placeholders aliased: %q", out)
	}
	for _, v := range []string{"string", "<token>", "{{secret}}", "changeme", "********"} {
		if _, _, ok := s.AliasFor(v); ok {
			t.Fatalf("placeholder %q enrolled", v)
		}
	}
	if got := toModel(t, e, "a substring here"); got != "a substring here" {
		t.Fatalf("prose mangled: %q", got)
	}
}

func TestShortCredentialsMatchAsTokens(t *testing.T) {
	e, s := newTestEngine(t)
	for _, v := range []struct {
		k Kind
		v string
	}{{KindPassword, "1234"}, {KindUsername, "bob"}} {
		if _, err := s.Enroll(v.k, v.v, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	pa, ua := mustAlias(t, s, "1234"), mustAlias(t, s, "bob")
	// Forward: no match inside longer words or numbers.
	if out := toModel(t, e, "bobby 12345 x1234 bob"); out != "bobby 12345 x1234 "+ua {
		t.Fatalf("forward %q", out)
	}
	if len(e.LeakCheck([]byte("bobby 12345"))) != 0 {
		t.Fatal("leak check matched inside words")
	}
	// Reverse: an alias glued to other alnum text is not an alias.
	for _, in := range []string{pa + "0", "x" + ua + "y"} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("over-resolved %q -> %q", in, back)
		}
	}
	if back, _ := e.ToReal("login " + ua + " / " + pa); back != "login bob / 1234" {
		t.Fatalf("got %q", back)
	}
}

func TestDomainAliasReversesOnlyAsHostSuffix(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	for _, in := range []string{"evil." + ra + ".attacker.com", ra + ".evil.com"} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("rewritten %q -> %q", in, back)
		}
	}
}

func TestProvenanceMergedOnReuse(t *testing.T) {
	e, s := newTestEngine(t)
	a := Provenance{CompanyIDs: []int64{1}, TaskIDs: []int64{10}}
	b := Provenance{CompanyIDs: []int64{2}, TaskIDs: []int64{20}}
	text := "contact joao.silva@acmebank.pt about Acme Bank"
	for _, p := range []Provenance{a, a, b, b} { // repeat: cache hits too
		if _, _, err := e.ToModel(text, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, orig := range []string{"joao.silva@acmebank.pt", "Acme Bank"} {
		_, kind, _ := s.AliasFor(orig)
		p := s.provenanceOf(kind, orig)
		if !slices.Contains(p.CompanyIDs, 2) || !slices.Contains(p.TaskIDs, 20) {
			t.Fatalf("%s provenance %+v lacks the second company", kind, p)
		}
	}
	// Tool-use input in an assistant message is not exempt from R11.
	req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "t", Name: "bash", Input: json.RawMessage(`{"cmd":"ping 240.7.7.7"}`)},
	}}}}
	if _, _, err := e.ToModelRequest(req, a); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.AliasFor("240.7.7.7"); !ok {
		t.Fatal("alias-shaped value in tool_use input not enrolled")
	}
}
