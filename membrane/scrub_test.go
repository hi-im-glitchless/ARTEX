package membrane

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// A transform that leaves an enrolled original (stubEngine: no transform at
// all) is repaired by the scrub: the request is forwarded with aliases, not
// blocked, and the event is flagged.
func TestLeakScrubbedInsteadOfBlocked(t *testing.T) {
	e, _ := newTestEngine(t)
	f := &fakeProvider{}
	aud := &memAuditor{}
	p := wrap(f, stubEngine{e}, aud, "kimi")
	req := llm.CompletionRequest{
		System: []string{"You test acmebank.pt"},
		Messages: []llm.Message{
			llm.UserText("log in as jsilva / Hunter2024!"),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "use jsilva on acmebank.pt"},
				{Type: llm.BlockToolUse, ID: "t1", Name: "http", Input: json.RawMessage(`{"url":"https://acmebank.pt/login","user":"jsilva"}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("t1", "welcome jsilva", false)}},
		},
		MaxTokens: 1000,
	}
	if _, _, _, err := p.Complete(testCtx(), req); err != nil {
		t.Fatalf("want forwarded, got %v", err)
	}
	if f.calls() != 1 {
		t.Fatalf("inner called %d times", f.calls())
	}
	assertNoOriginals(t, "forwarded request", f.raw[0])
	evs := aud.events()
	if len(evs) != 1 || evs[0].Blocked || !strings.Contains(strings.Join(evs[0].Report.Flags, ","), "leak_scrubbed") {
		t.Fatalf("event: %+v", evs)
	}
}

// The scrub keeps minted aliases, request settings, signed thinking and
// tool definitions as they are.
func TestScrubKeepsAliasesAndSignedThinking(t *testing.T) {
	e, s := newTestEngine(t)
	alias := mustAlias(t, s, "jsilva")
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			llm.UserText("already " + alias + " and jsilva"),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "jsilva", Signature: "sig"},
			}},
		},
		Tools:     []llm.ToolSchema{{Name: "t", Description: "jsilva"}},
		MaxTokens: 1000,
	}
	out, n := e.ScrubRequest(req)
	if n != 1 {
		t.Fatalf("replaced %d, want 1", n)
	}
	if got := out.Messages[0].Content[0].Text; got != "already "+alias+" and "+alias {
		t.Errorf("text = %q", got)
	}
	if out.Messages[1].Content[0].Thinking != "jsilva" {
		t.Error("signed thinking changed")
	}
	if out.Tools[0].Description != "jsilva" {
		t.Error("tool definition changed")
	}
	if req.Messages[0].Content[0].Text != "already "+alias+" and jsilva" {
		t.Error("input request mutated")
	}
}
