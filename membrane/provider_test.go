package membrane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// fakeProvider is a scripted llm.Provider. It records every request it
// receives (and its json.Marshal bytes) and answers from complete / events.
type fakeProvider struct {
	mu       sync.Mutex
	reqs     []llm.CompletionRequest
	raw      [][]byte
	complete func(req llm.CompletionRequest) (llm.Message, string, error)
	events   []llm.StreamEvent
}

func (f *fakeProvider) record(req llm.CompletionRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(req)
	f.reqs = append(f.reqs, req)
	f.raw = append(f.raw, b)
}

func (f *fakeProvider) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.record(req)
	if f.complete == nil {
		return llm.Message{Role: llm.RoleAssistant}, "", llm.Usage{}, nil
	}
	m, s, err := f.complete(req)
	return m, s, llm.Usage{OutputTokens: 1}, err
}

func (f *fakeProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		f.record(req)
		for _, ev := range f.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// memAuditor records events; err, when set, fails every Record.
type memAuditor struct {
	mu  sync.Mutex
	evs []Event
	err error
}

func (a *memAuditor) Record(_ context.Context, ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.evs = append(a.evs, ev)
	return nil
}

func (a *memAuditor) events() []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.evs)
}

// realValues are the fixture originals no request may carry.
var realValues = []string{"acmebank", "Acme Bank", "jsilva", "Hunter2024", "185.12.4", "joao.silva"}

func assertNoOriginals(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, r := range realValues {
		if strings.Contains(strings.ToLower(string(b)), strings.ToLower(r)) {
			t.Fatalf("%s carries an original (len %d): %s", what, len(r), b)
		}
	}
}

func testCtx() context.Context {
	ctx := transcript.WithSessionID(context.Background(), "exp3-worker-i7")
	return llmrec.WithTaskID(ctx, "42")
}

func userReq(text string) llm.CompletionRequest {
	return llm.CompletionRequest{
		System:   []string{"You test acmebank.pt. Credentials: username=jsilva password=Hunter2024!"},
		Messages: []llm.Message{llm.UserText(text)},
		Tools: []llm.ToolSchema{{Name: "http", Description: "fetch a URL",
			InputSchema: map[string]any{"type": "object"}}},
		MaxTokens: 100,
	}
}

func TestWrapCompleteRoundTrip(t *testing.T) {
	e, s := newTestEngine(t)
	root := mustAlias(t, s, "acmebank.pt")
	user := mustAlias(t, s, "jsilva")
	f := &fakeProvider{complete: func(req llm.CompletionRequest) (llm.Message, string, error) {
		in := fmt.Sprintf(`{"url":"https://portal.%s/login","user":%q}`, root, user)
		txt := "Next I log in to portal." + root + " as " + user + "."
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			llm.TextBlock(txt),
			{Type: llm.BlockToolUse, ID: "t1", Name: "http", Input: json.RawMessage(in)},
		}}, txt, nil
	}}
	aud := &memAuditor{}
	p := Wrap(f, e, aud, "kimi")
	msg, text, usage, err := p.Complete(testCtx(), userReq("Check https://portal.acmebank.pt for Acme Bank"))
	if err != nil {
		t.Fatal(err)
	}
	if f.calls() != 1 {
		t.Fatalf("inner called %d times", f.calls())
	}
	assertNoOriginals(t, "forwarded request", f.raw[0])
	if usage.OutputTokens != 1 {
		t.Fatalf("usage not passed through: %+v", usage)
	}
	if want := "Next I log in to portal.acmebank.pt as jsilva."; text != want || msg.Content[0].Text != want {
		t.Fatalf("text not de-aliased: %q / %q", text, msg.Content[0].Text)
	}
	var in struct{ URL, User string }
	if err := json.Unmarshal(msg.Content[1].Input, &in); err != nil {
		t.Fatal(err)
	}
	if in.URL != "https://portal.acmebank.pt/login" || in.User != "jsilva" {
		t.Fatalf("tool input not de-aliased: %s", msg.Content[1].Input)
	}
	evs := aud.events()
	if len(evs) != 1 || evs[0].Blocked || evs[0].Direction != "request" {
		t.Fatalf("want one forwarded request event, got %+v", evs)
	}
}

// mergeTypes collapses consecutive deltas of the same type.
func mergeTypes(evs []llm.StreamEvent) []llm.StreamEventType {
	var out []llm.StreamEventType
	for _, ev := range evs {
		isDelta := ev.Type == llm.SETextDelta || ev.Type == llm.SEThinkingDelta || ev.Type == llm.SEToolInputJSON
		if isDelta && len(out) > 0 && out[len(out)-1] == ev.Type {
			continue
		}
		out = append(out, ev.Type)
	}
	return out
}

func collect(t *testing.T, seq iter.Seq2[llm.StreamEvent, error]) []llm.StreamEvent {
	t.Helper()
	var out []llm.StreamEvent
	for ev, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func accumulate(evs []llm.StreamEvent) llm.Message {
	a := llm.NewAccumulator()
	for _, ev := range evs {
		a.Add(ev)
	}
	return a.Message()
}

func TestStreamAliasSplitAcrossDeltas(t *testing.T) {
	e, s := newTestEngine(t)
	root := mustAlias(t, s, "acmebank.pt")
	user := mustAlias(t, s, "jsilva")
	host := "portal." + root
	inner := []llm.StreamEvent{
		{Type: llm.SEMessageStart},
		{Type: llm.SEThinkingDelta, Text: "I should look at " + host[:9]},
		{Type: llm.SEThinkingDelta, Text: host[9:] + " first"},
		{Type: llm.SETextDelta, Text: "Scanning " + host[:10]},
		{Type: llm.SETextDelta, Text: host[10:] + " now."},
		{Type: llm.SEToolUseStart, ToolID: "t1", ToolName: "http"},
		{Type: llm.SEToolInputJSON, Text: `{"url":"https://portal.` + root[:3]},
		{Type: llm.SEToolInputJSON, Text: root[3:] + `/","user":"`},
		{Type: llm.SEToolInputJSON, Text: user + `"}`},
		{Type: llm.SEToolUseStart, ToolID: "t2", ToolName: "http", ToolIndex: 1},
		{Type: llm.SEToolInputJSON, Text: `{"url":"https://` + root + `"}`},
		{Type: llm.SEMessageDelta, StopReason: "tool_use"},
		{Type: llm.SEMessageStop},
	}
	f := &fakeProvider{events: inner}
	p := Wrap(f, e, &memAuditor{}, "kimi")
	got := collect(t, p.Stream(testCtx(), userReq("hi")))

	if g, w := mergeTypes(got), mergeTypes(inner); !slices.Equal(g, w) {
		t.Fatalf("event types\n got %v\nwant %v", g, w)
	}
	m := accumulate(got)
	if len(m.Content) != 4 {
		t.Fatalf("blocks: %+v", m.Content)
	}
	if m.Content[0].Thinking != "I should look at portal.acmebank.pt first" {
		t.Fatalf("thinking: %q", m.Content[0].Thinking)
	}
	if m.Content[1].Text != "Scanning portal.acmebank.pt now." {
		t.Fatalf("text: %q", m.Content[1].Text)
	}
	if string(m.Content[2].Input) != `{"url":"https://portal.acmebank.pt/","user":"jsilva"}` {
		t.Fatalf("tool 1 input: %s", m.Content[2].Input)
	}
	if string(m.Content[3].Input) != `{"url":"https://acmebank.pt"}` {
		t.Fatalf("tool 2 input: %s", m.Content[3].Input)
	}
	if m.Content[2].ID != "t1" || m.Content[3].ID != "t2" {
		t.Fatalf("tool ids: %+v", m.Content)
	}
	n := 0
	for _, ev := range got {
		if ev.Type == llm.SEToolInputJSON {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want one merged tool_input_delta per tool, got %d", n)
	}
}

// TestStreamLongTokensAndDelimitedAliases: hosts longer than maxAliasLen and
// aliases containing delimiters survive a character-by-character stream,
// while ordinary prose is still emitted before the stream ends.
func TestStreamLongTokensAndDelimitedAliases(t *testing.T) {
	e, s := newTestEngine(t)
	const pw = "open sesame, (please) [now] 99"
	if _, err := s.seedEnroll(KindPassword, pw, seedProv); err != nil {
		t.Fatal(err)
	}
	pwAlias := mustAlias(t, s, pw)
	ipA, err := s.IPv4Alias(netip.MustParseAddr("185.12.41.7"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	root := mustAlias(t, s, "acmebank.pt")
	long := "very-long-subdomain-label.another-long-label.yet-another.portal." + root
	if len(long) <= maxAliasLen {
		t.Fatalf("fixture host too short: %d", len(long))
	}
	prose := strings.Repeat("lorem ipsum dolor ", 20)
	text := prose + "visit https://" + long + "/x?u=1 then type " + pwAlias + " on " + ipA.String() + " and " + prose + "done"
	var inner []llm.StreamEvent
	for _, r := range text {
		inner = append(inner, llm.StreamEvent{Type: llm.SETextDelta, Text: string(r)})
	}
	inner = append(inner, llm.StreamEvent{Type: llm.SEMessageStop})
	f := &fakeProvider{events: inner}
	p := Wrap(f, e, &memAuditor{}, "kimi")

	var got []llm.StreamEvent
	firstEmitBeforeEnd := false
	for ev, err := range p.Stream(testCtx(), userReq("hi")) {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == llm.SETextDelta && len(got) == 0 {
			firstEmitBeforeEnd = true
		}
		got = append(got, ev)
	}
	m := accumulate(got)
	wantLong := "very-long-subdomain-label.another-long-label.yet-another.portal.acmebank.pt"
	want := prose + "visit https://" + wantLong + "/x?u=1 then type " + pw + " on 185.12.41.7 and " + prose + "done"
	if m.Content[0].Text != want {
		t.Fatalf("text\n got %q\nwant %q", m.Content[0].Text, want)
	}
	if !firstEmitBeforeEnd || len(got) < 4 {
		t.Fatalf("hold-back emitted %d events; prose must stream incrementally", len(got))
	}
}

// TestStreamForceFlushesLongRuns: a run with no boundary is flushed once it
// exceeds maxHoldBytes instead of being held to the end.
func TestStreamForceFlushesLongRuns(t *testing.T) {
	e, _ := newTestEngine(t)
	run := strings.Repeat("a", 3000)
	var inner []llm.StreamEvent
	for i := 0; i < len(run); i += 100 {
		inner = append(inner, llm.StreamEvent{Type: llm.SETextDelta, Text: run[i : i+100]})
	}
	inner = append(inner, llm.StreamEvent{Type: llm.SEMessageStop})
	p := Wrap(&fakeProvider{events: inner}, e, &memAuditor{}, "kimi")
	got := collect(t, p.Stream(testCtx(), userReq("hi")))
	if len(got) < 3 {
		t.Fatalf("want forced flushes before message_stop, got %d events", len(got))
	}
	if m := accumulate(got); m.Content[0].Text != run {
		t.Fatal("text changed")
	}
}

// stubEngine leaves the request untransformed (a bug the leak check must catch).
type stubEngine struct{ *Engine }

func (stubEngine) ToModelRequest(req llm.CompletionRequest, _ Provenance) (llm.CompletionRequest, Report, error) {
	return req, newReport(), nil
}

func TestLeakBlocked(t *testing.T) {
	e, _ := newTestEngine(t)
	f := &fakeProvider{}
	aud := &memAuditor{}
	p := wrap(f, stubEngine{e}, aud, "kimi")
	_, _, _, err := p.Complete(testCtx(), userReq("scan acmebank.pt"))
	if !errors.Is(err, ErrLeakBlocked) {
		t.Fatalf("want ErrLeakBlocked, got %v", err)
	}
	assertNoOriginals(t, "error", []byte(err.Error()))
	for _, ev := range collectErr(p.Stream(testCtx(), userReq("scan acmebank.pt"))) {
		if !errors.Is(ev, ErrLeakBlocked) {
			t.Fatalf("stream: want ErrLeakBlocked, got %v", ev)
		}
	}
	if f.calls() != 0 {
		t.Fatalf("inner called %d times", f.calls())
	}
	evs := aud.events()
	if len(evs) != 2 {
		t.Fatalf("want one event per attempt, got %d", len(evs))
	}
	for _, ev := range evs {
		if !ev.Blocked || ev.Direction != "request" || ev.BlockReason == "" {
			t.Fatalf("event: %+v", ev)
		}
		b, _ := json.Marshal(ev)
		assertNoOriginals(t, "audit event", b)
	}
}

func collectErr(seq iter.Seq2[llm.StreamEvent, error]) []error {
	var errs []error
	for _, err := range seq {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func TestEngineErrorFailsClosed(t *testing.T) {
	s, fp := newTestStore(t)
	e := NewEngine(s, nil)
	fp.failInserts = 100
	f := &fakeProvider{}
	aud := &memAuditor{}
	p := Wrap(f, e, aud, "kimi")
	_, _, _, err := p.Complete(testCtx(), userReq("contact joao.silva@acmebank.pt"))
	if err == nil {
		t.Fatal("want an error")
	}
	assertNoOriginals(t, "error", []byte(err.Error()))
	if errs := collectErr(p.Stream(testCtx(), userReq("contact joao.silva@acmebank.pt"))); len(errs) != 1 {
		t.Fatalf("stream errors: %v", errs)
	}
	if f.calls() != 0 {
		t.Fatal("inner must not be called")
	}
	evs := aud.events()
	if len(evs) != 2 || !evs[0].Blocked || !evs[1].Blocked {
		t.Fatalf("events: %+v", evs)
	}
}

func TestAuditFailureBlocksRequest(t *testing.T) {
	e, _ := newTestEngine(t)
	f := &fakeProvider{}
	p := Wrap(f, e, &memAuditor{err: errors.New("db down")}, "kimi")
	if _, _, _, err := p.Complete(testCtx(), userReq("hi")); err == nil {
		t.Fatal("want an error")
	}
	if errs := collectErr(p.Stream(testCtx(), userReq("hi"))); len(errs) != 1 {
		t.Fatalf("stream errors: %v", errs)
	}
	if f.calls() != 0 {
		t.Fatal("inner must not be called when the audit fails")
	}
	if _, _, _, err := Wrap(f, e, nil, "kimi").Complete(testCtx(), userReq("hi")); err == nil || f.calls() != 0 {
		t.Fatal("a nil auditor must fail closed")
	}
}

func TestSignedThinkingReplayedVerbatim(t *testing.T) {
	e, s := newTestEngine(t)
	root := mustAlias(t, s, "acmebank.pt")
	org := strings.ToLower(mustAlias(t, s, "Acme Bank"))
	// The model writes the keyword alias in lowercase; it de-aliases to
	// lowercase text, which ToModel would re-alias in upper case, so only a
	// verbatim replay reproduces the signed bytes.
	aliased := "Plan: " + org + " runs portal." + root + "; try it."
	f := &fakeProvider{complete: func(req llm.CompletionRequest) (llm.Message, string, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: aliased, Signature: "sig-complete"},
			llm.TextBlock("ok"),
		}}, "ok", nil
	}}
	f.events = []llm.StreamEvent{
		{Type: llm.SEMessageStart},
		{Type: llm.SEThinkingDelta, Text: aliased[:12]},
		{Type: llm.SEThinkingDelta, Text: aliased[12:]},
		{Type: llm.SEThinkingSignature, Text: "sig-stream"},
		{Type: llm.SETextDelta, Text: "ok"},
		{Type: llm.SEMessageStop},
	}
	p := Wrap(f, e, &memAuditor{}, "anthropic")
	msg, _, _, err := p.Complete(testCtx(), userReq("go"))
	if err != nil {
		t.Fatal(err)
	}
	streamed := accumulate(collect(t, p.Stream(testCtx(), userReq("go"))))
	for _, m := range []llm.Message{msg, streamed} {
		th := m.Content[0]
		if strings.Contains(th.Thinking, root) || !strings.Contains(th.Thinking, "portal.acmebank.pt") {
			t.Fatalf("thinking not de-aliased: %q", th.Thinking)
		}
		req := userReq("go")
		req.Messages = append(req.Messages, m, llm.UserText("continue"))
		if _, _, _, err := p.Complete(testCtx(), req); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		last := f.reqs[len(f.reqs)-1]
		f.mu.Unlock()
		if got := last.Messages[1].Content[0]; got.Thinking != aliased || got.Signature != th.Signature {
			t.Fatalf("signed thinking not replayed verbatim:\n got %q\nwant %q", got.Thinking, aliased)
		}
	}
	// An unknown signature (e.g. after a restart) is transformed normally.
	req := userReq("go")
	req.Messages = append(req.Messages, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "look at portal.acmebank.pt", Signature: "unknown"},
	}}, llm.UserText("continue"))
	if _, _, _, err := p.Complete(testCtx(), req); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	raw := f.raw[len(f.raw)-1]
	f.mu.Unlock()
	assertNoOriginals(t, "unknown-signature request", raw)
}

func TestAuditHasRequestHashNotOriginals(t *testing.T) {
	e, _ := newTestEngine(t)
	f := &fakeProvider{}
	aud := &memAuditor{}
	p := Wrap(f, e, aud, "kimi")
	if _, _, _, err := p.Complete(testCtx(), userReq("Acme Bank owns acmebank.pt, try https://Acme Corp Labs")); err != nil {
		t.Fatal(err)
	}
	evs := aud.events()
	if len(evs) != 1 {
		t.Fatalf("events: %+v", evs)
	}
	ev := evs[0]
	sum := sha256.Sum256(f.raw[0])
	if ev.RequestSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("RequestSHA256 is not the hash of the serialised forwarded request")
	}
	if ev.TaskID != "42" || ev.Session != "exp3-worker-i7" || ev.Role != "worker" || ev.Profile != "kimi" || ev.Direction != "request" || ev.Blocked {
		t.Fatalf("event fields: %+v", ev)
	}
	if ev.Report.Counts[KindDomain] == 0 || ev.Report.Counts[KindOrg] == 0 {
		t.Fatalf("report counts: %+v", ev.Report)
	}
	b, _ := json.Marshal(ev)
	assertNoOriginals(t, "audit event", b)
}

func TestUnresolvedAliasesPassThroughAndAreCounted(t *testing.T) {
	e, _ := newTestEngine(t)
	const ghost = "portal.abcdef.example"
	f := &fakeProvider{complete: func(llm.CompletionRequest) (llm.Message, string, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("try " + ghost)}}, "try " + ghost, nil
	}}
	f.events = []llm.StreamEvent{{Type: llm.SETextDelta, Text: "try " + ghost}, {Type: llm.SEMessageStop}}
	aud := &memAuditor{}
	p := Wrap(f, e, aud, "kimi")
	msg, text, _, err := p.Complete(testCtx(), userReq("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if text != "try "+ghost || msg.Content[0].Text != "try "+ghost {
		t.Fatalf("unresolved alias must pass through: %q", text)
	}
	m := accumulate(collect(t, p.Stream(testCtx(), userReq("hi"))))
	if m.Content[0].Text != "try "+ghost {
		t.Fatalf("stream: %q", m.Content[0].Text)
	}
	var flagged int
	for _, ev := range aud.events() {
		if ev.Direction == "response" && slices.Contains(ev.Report.Flags, "unresolved:1") {
			flagged++
		}
	}
	if flagged != 2 {
		t.Fatalf("want an unresolved:1 response event per call, got %+v", aud.events())
	}
}

func TestRoleFromSession(t *testing.T) {
	for id, want := range map[string]string{
		"exp3-planner":      "planner",
		"exp12-worker-i7":   "worker",
		"exp3-main":         "main",
		"exp3-main-s2":      "main",
		"exp3-goals":        "goals",
		"exp3-compactor":    "compactor",
		"conv-17":           "chat",
		"conv-":             "other",
		"exp3-btw-x":        "other",
		"exp-planner":       "other",
		"conntest-abc":      "other",
		"":                  "other",
		"exp3planner":       "other",
		"exp3-plannerextra": "other",
	} {
		if got := roleFromSession(id); got != want {
			t.Errorf("roleFromSession(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestProvenanceFromContext(t *testing.T) {
	if p := provenanceFrom(testCtx()); !slices.Equal(p.TaskIDs, []int64{42}) || p.Source != "auto" || len(p.CompanyIDs) != 0 {
		t.Fatalf("prov: %+v", p)
	}
	if p := provenanceFrom(llmrec.WithTaskID(context.Background(), "abc")); len(p.TaskIDs) != 0 {
		t.Fatalf("non-numeric task id must be dropped: %+v", p)
	}
}
