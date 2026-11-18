package membrane

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func bashInput(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func searchInput(q string) []byte {
	b, _ := json.Marshal(map[string]any{"query": q, "limit": 5})
	return b
}

const unknownAliasSuffix = " — use only names from your context"

func TestToolCheckBlocksUnresolvedAlias(t *testing.T) {
	e, _ := newTestEngine(t)
	block, reason := e.ToolCheck("Bash", bashInput("nmap 240.9.9.0/16"))
	if !block || reason != "unknown alias 240.9.9.0/16"+unknownAliasSuffix {
		t.Fatalf("got block=%v reason=%q", block, reason)
	}
	for _, in := range []string{
		`{"command":"curl https://ffffff.example/x"}`,
		`{"command":"curl https://api.ffffff.example/x"}`,
		`{"command":"echo ORG-ffff"}`,
		`{"command":"ping6 2001:db8:1a2b:3c4d:5e6f:7a8b:9c0d:e1f2"}`,
		`{"command":"nmap 240.9.9.9"}`,
		// JSON-escaped and URL-encoded forms are decoded first.
		"{\"command\":\"nmap \\u0032\\u0034\\u0030.9.9.9\"}",
		`{"url":"http://x/?h=240%2E9%2E9%2E9"}`,
		// Object keys count too.
		`{"240.9.9.9":"x"}`,
		// Not valid JSON: scanned as text.
		`nmap 240.9.9.9`,
	} {
		block, reason := e.ToolCheck("Bash", []byte(in))
		if !block || !strings.HasPrefix(reason, "unknown alias ") || !strings.HasSuffix(reason, unknownAliasSuffix) {
			t.Errorf("%s: got block=%v reason=%q", in, block, reason)
		}
	}
	// The rule applies to web_search too (alias reason first).
	if v := e.CheckTool("web_search", searchInput("ORG-ffff breach"), true); !v.Block || v.Rule != RuleUnresolvedAlias {
		t.Errorf("unresolved alias in a web_search query: %+v", v)
	}
	// R19 amended: an agent on a local provider never sees aliases; nothing
	// blocks there.
	if v := e.CheckTool("Bash", bashInput("nmap 240.9.9.9"), false); v.Block {
		t.Errorf("blocked for a local provider: %+v", v)
	}
	v := e.CheckTool("Bash", bashInput("nmap 240.9.9.9"), true)
	if v.Rule != RuleUnresolvedAlias {
		t.Errorf("rule %q", v.Rule)
	}
}

func TestToolCheckAllowsReal(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, in := range [][]byte{
		bashInput("nmap -sV 185.12.40.7 portal.acmebank.pt -p 443"),
		bashInput("curl -u jsilva:Hunter2024! https://vpn.acmebank.pt/ ; ip route add 10.0.0.0/8 via 192.168.1.1 ; ifconfig eth0 netmask 255.255.255.0"),
		[]byte(`{"file_path":"/tmp/report.md","content":"Acme Bank findings"}`),
		[]byte(`{}`),
		nil,
	} {
		if block, reason := e.ToolCheck("Bash", in); block {
			t.Errorf("%s blocked: %q", in, reason)
		}
	}
}

func TestToolCheckAllowsRealAliasShaped(t *testing.T) {
	e, s := newTestEngine(t)
	// Real alias-shaped values seen in target output are enrolled (R11).
	toModel(t, e, "target host 240.1.2.3 serves abcdef.example (ticket ORG-1234, login user-beef)")
	for _, cmd := range []string{
		"nmap -sV 240.1.2.3",
		"curl https://abcdef.example/login",
		"curl https://www.abcdef.example/login",
		"grep ORG-1234 notes.txt ; id user-beef",
	} {
		if block, reason := e.ToolCheck("Bash", bashInput(cmd)); block {
			t.Errorf("%q blocked: %q", cmd, reason)
		}
	}
	// A minted alias left in the input did not resolve: block.
	ra := mustAlias(t, s, "acmebank.pt")
	if block, _ := e.ToolCheck("Bash", bashInput("curl https://"+ra+"/")); !block {
		t.Error("minted alias left unresolved must block")
	}
}

func TestToolCheckBlocksQuarantinedAlias(t *testing.T) {
	s, p := newTestStore(t)
	if _, err := s.seedEnroll(KindDomain, "acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	old := s.deriver.RootDomain("okta.com")
	mac := s.indexHMAC(KindDomain, "okta.com")
	enc, err := s.encrypt(KindDomain, mac, "okta.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.InsertMembraneEntry(&db.MembraneEntry{Kind: string(KindDomain), OriginalHMAC: mac,
		OriginalEnc: enc, Alias: old, Source: "seed"}); err != nil {
		t.Fatal(err)
	}
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(s, NewPipeline(s))
	for _, cmd := range []string{"curl https://" + old + "/", "ping login." + old} {
		block, reason := e.ToolCheck("Bash", bashInput(cmd))
		if !block || strings.Contains(reason, "okta") {
			t.Errorf("%q: block=%v reason=%q", cmd, block, reason)
		}
	}
}

func TestWebSearchBlocksOriginal(t *testing.T) {
	e, _ := newTestEngine(t)
	const want = "search for the technology or CVE, not the target"
	for _, q := range []string{
		"acmebank.pt login portal",
		"portal.acmebank.pt exposed",
		"Acme Bank breach",
		"ACMEBANK vpn",
		"acmebankonline leaked credentials", // R10: long keyword as substring
		"jsilva password",
	} {
		v := e.CheckTool("web_search", searchInput(q), true)
		if !v.Block || v.Reason != want || v.Rule != RuleWebSearchOriginal {
			t.Errorf("%q: got %+v", q, v)
		}
		if block, reason := e.ToolCheck("web_search", searchInput(q)); !block || reason != want {
			t.Errorf("ToolCheck %q: block=%v reason=%q", q, block, reason)
		}
		// Escaped in the JSON input: still caught.
		esc := []byte(`{"query":"` + strings.ReplaceAll(q, "a", "\\u0061") + `"}`)
		if v := e.CheckTool("web_search", esc, true); !v.Block {
			t.Errorf("escaped %q not blocked", q)
		}
		// R19: a local provider's searches are not checked.
		if v := e.CheckTool("web_search", searchInput(q), false); v.Block {
			t.Errorf("%q blocked without the web_search rule: %+v", q, v)
		}
		// Other tools may carry originals (they were de-aliased on purpose).
		if block, _ := e.ToolCheck("Bash", bashInput("echo "+q)); block {
			t.Errorf("Bash %q blocked", q)
		}
	}
}

func TestWebSearchAllowsTech(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, q := range []string{"Spring Boot actuator CVE", "CVE-2024-3400 PAN-OS exploit", "nginx 1.18 path traversal"} {
		if block, reason := e.ToolCheck("web_search", searchInput(q)); block {
			t.Errorf("%q blocked: %q", q, reason)
		}
	}
}
