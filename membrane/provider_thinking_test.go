package membrane

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Final review I1: the model guesses a value in signed thinking, a later
// tool result reveals it is real (enrolled). The replayed alias-space
// thinking then carries an original; the request must not be blocked
// forever: the signed block is dropped (and audited), the rest goes out.
func TestSignedThinkingWithLaterEnrolledValueIsDropped(t *testing.T) {
	e, s := newTestEngine(t)
	think := "I will try usernames mferreira and admin against the portal"
	fp := &fakeProvider{complete: func(req llm.CompletionRequest) (llm.Message, string, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: think, Signature: "sig-1"},
			{Type: llm.BlockText, Text: "ok"},
		}}, "", nil
	}}
	a := &memAuditor{}
	w := wrap(fp, e, a, "p")
	ctx := context.Background()
	msg, _, _, err := w.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(KindUsername, "mferreira", Provenance{TaskIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go"), msg,
		{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "x",
			Content: []llm.ContentBlock{llm.TextBlock("login ok for mferreira")}}}}}}
	for i := 0; i < 2; i++ {
		if _, _, _, err := w.Complete(ctx, req); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	sent := fp.raw[len(fp.raw)-1]
	if strings.Contains(string(sent), "mferreira") {
		t.Fatalf("original sent: %s", sent)
	}
	if strings.Contains(string(sent), "sig-1") {
		t.Fatalf("leaking signed block was replayed: %s", sent)
	}
	last := fp.reqs[len(fp.reqs)-1]
	if got := len(last.Messages[1].Content); got != 1 || last.Messages[1].Content[0].Text != "ok" {
		t.Fatalf("assistant message = %+v, want only the text block", last.Messages[1].Content)
	}
	ev := a.evs[len(a.evs)-1]
	if ev.Blocked || !slices.Contains(ev.Report.Flags, "signed_thinking_dropped") {
		t.Fatalf("event = %+v, want forwarded with signed_thinking_dropped flag", ev)
	}
}

// A thinking-only assistant message keeps a (transformed, unsigned) text
// block so the message is not empty.
func TestSignedThinkingOnlyMessageKeepsTransformedText(t *testing.T) {
	e, s := newTestEngine(t)
	think := "maybe the account is mferreira"
	fp := &fakeProvider{complete: func(req llm.CompletionRequest) (llm.Message, string, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: think, Signature: "sig-2"},
		}}, "", nil
	}}
	a := &memAuditor{}
	w := wrap(fp, e, a, "p")
	ctx := context.Background()
	msg, _, _, err := w.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(KindUsername, "mferreira", Provenance{TaskIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go"), msg, llm.UserText("next")}}
	if _, _, _, err := w.Complete(ctx, req); err != nil {
		t.Fatal(err)
	}
	sent := fp.reqs[len(fp.reqs)-1]
	c := sent.Messages[1].Content
	if len(c) != 1 || c[0].Type != llm.BlockText || c[0].Signature != "" || c[0].Text == "" {
		t.Fatalf("assistant content = %+v", c)
	}
	if strings.Contains(string(fp.raw[len(fp.raw)-1]), "mferreira") {
		t.Fatal("original sent")
	}
}
