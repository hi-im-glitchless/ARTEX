package membrane

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The block reason echoes the invented token. When it comes back as a
// tool_result, ToModel must not enrol the token as a real value (R11): the
// model sees the same token, a retry still blocks, the dictionary stays
// clean. Covered in process (rejected set) and after a restart (reason text,
// raw or JSON-escaped).
func TestToolCheckRejectedAliasNotLaundered(t *testing.T) {
	for _, inv := range []string{"240.9.9.9", "240.9.9.0/16", "ORG-ffff", "ffffff.example", "api.ffffff.example", "2001:db8:1a2b:3c4d:5e6f:7a8b:9c0d:e1f2"} {
		e, s := newTestEngine(t)
		v := e.CheckTool("Bash", bashInput("nmap "+inv), true)
		if !v.Block || v.Reason != "unknown alias "+inv+unknownAliasSuffix {
			t.Fatalf("%s: first call %+v", inv, v)
		}
		for _, msg := range []string{
			"Blocked by hook: " + v.Reason,
			// Plain mention elsewhere in the same tool_result (in-process set).
			"Blocked by hook: " + v.Reason + "\nnote: " + inv + " was rejected",
		} {
			if out := toModel(t, e, msg); out != msg {
				t.Errorf("%s: model sees %q", inv, out)
			}
		}
		// As a JSON tool_result body.
		raw, _ := json.Marshal(map[string]string{"error": v.Reason})
		out, _, err := e.ToModelJSON(raw, Provenance{TaskIDs: []int64{7}})
		if err != nil || string(out) != string(raw) {
			t.Errorf("%s: JSON tool_result became %s (%v)", inv, out, err)
		}
		if _, _, ok := s.AliasFor(inv); ok {
			t.Errorf("%s enrolled as an original", inv)
		}
		if v2 := e.CheckTool("Bash", bashInput("nmap "+inv), true); !v2.Block {
			t.Errorf("%s: retry allowed", inv)
		}

		// After a restart (fresh engine, empty rejected set): the reason text
		// alone keeps the token out, with the dash raw or JSON-escaped.
		fresh := NewEngine(s, NewPipeline(s))
		escaped := strings.Replace(v.Reason, "—", "\\u2014", 1)
		for _, msg := range []string{"Blocked by hook: " + v.Reason, `{"error":"` + escaped + `"}`} {
			req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: msg}}}}}
			got, _, err := fresh.ToModelRequest(req, Provenance{TaskIDs: []int64{7}})
			if err != nil || got.Messages[0].Content[0].Text != msg {
				t.Errorf("%s after restart: %q (%v)", inv, got.Messages[0].Content[0].Text, err)
			}
		}
		if _, _, ok := s.AliasFor(inv); ok {
			t.Errorf("%s enrolled after restart", inv)
		}
		if v3 := fresh.CheckTool("Bash", bashInput("nmap "+inv), true); !v3.Block {
			t.Errorf("%s: retry allowed after restart", inv)
		}
	}
	// A real value elsewhere is still enrolled (R11 unchanged).
	e, s := newTestEngine(t)
	toModel(t, e, "target answered from 240.1.2.3")
	if _, _, ok := s.AliasFor("240.1.2.3"); !ok {
		t.Error("real lookalike no longer enrolled")
	}
}

// Fix round 1, ruling 3: documentation IPv6 addresses and local file writes
// do not trip the alias rule; exec/network tools and bare user-xxxx still do.
func TestToolCheckNoiseNarrowing(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, c := range []string{"2001:db8::1", "2001:db8::/32", "2001:db8:85a3::8a2e:370:7334", "fe80::1 and 2001:DB8::", "2001:db8::dead"} {
		if v := e.CheckTool("Bash", bashInput("ping6 "+c), true); v.Block {
			t.Errorf("%q blocked: %+v", c, v)
		}
	}
	if v := e.CheckTool("Bash", bashInput("ping6 2001:db8:1a2b:0:5e6f:7a8b:9c0d:e1f2"), true); !v.Block {
		t.Error("IPv6 alias with one zero group allowed")
	}
	write := func(k, c string) []byte {
		b, _ := json.Marshal(map[string]string{"file_path": "/tmp/r.md", k: "example: " + c})
		return b
	}
	for _, tool := range []string{"Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite"} {
		for _, c := range []string{"user-1234", "ORG-0001", "240.9.9.9", "ffffff.example"} {
			if v := e.CheckTool(tool, write("content", c), true); v.Block {
				t.Errorf("%s %q blocked: %+v", tool, c, v)
			}
		}
	}
	for _, tool := range []string{"Bash", "shell_open", "WebFetch", "web_search", "mcp__x__y", "add_task_scope"} {
		if v := e.CheckTool(tool, write("command", "id user-1234"), true); !v.Block {
			t.Errorf("%s with user-1234 allowed", tool)
		}
	}
}

// Fix round 1, ruling 4: every brand spelling is caught in a query, both with
// only "Acme Bank"/"acmebank" enrolled and with the Task 9 seeded variants.
func TestWebSearchBrandVariants(t *testing.T) {
	e, s := newTestEngine(t)
	qs := []string{"acme-bank breach", "acme_bank leak", "Acme.Bank login", "ACME-BANK", "acme+bank", "AcmeBank portal"}
	for _, q := range qs {
		if v := e.CheckTool("web_search", searchInput(q), true); !v.Block || v.Rule != RuleWebSearchOriginal {
			t.Errorf("%q: %+v", q, v)
		}
	}
	for _, b := range BrandVariants("Acme Bank") {
		if _, err := s.seedEnroll(KindOrg, b, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range append(qs, "acme-bank") {
		if v := e.CheckTool("web_search", searchInput(q), true); !v.Block {
			t.Errorf("seeded %q: %+v", q, v)
		}
	}
	for _, q := range []string{"Spring Boot actuator CVE", "certbot ACME challenge bypass", "online banking CVE-2024-1234", "spring-boot actuator"} {
		if v := e.CheckTool("web_search", searchInput(q), true); v.Block {
			t.Errorf("tech query %q blocked", q)
		}
	}
}
