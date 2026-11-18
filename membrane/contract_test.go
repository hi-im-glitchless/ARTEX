package membrane

// End-to-end contract suite (spec §10.2). The evidence export cites it as
// `go test ./membrane/... -run Contract`. It drives a scripted synthetic
// multi-turn transcript (testdata/contract) through the real decorator: a
// fake provider plays the model and only sees alias space, the harness plays
// the tool runner and only sees real space. It asserts:
//  1. no forwarded request carries a fixture original, in raw, URL, JSON,
//     HTML, base64 (Basic) or JWT-segment form;
//  2. every tool input the harness executes holds exactly the expected real
//     values and no alias-shaped residue;
//  3. the /16 range and unknown aliases are blocked by the tool guard, also
//     when the block reason is fed back and reused;
//  4. request audit events equal the requests made, and the chain verifies;
//  5. re-running the conversation gives byte-identical forwarded requests.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"iter"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type contractScope struct {
	TaskID      string   `json:"task_id"`
	Session     string   `json:"session"`
	Company     string   `json:"company"`
	Roots       []string `json:"roots"`
	Hosts       []string `json:"hosts"`
	Keywords    []string `json:"keywords"`
	CIDRs       []string `json:"cidrs"`
	Credentials []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credentials"`
	System           string      `json:"system"`
	Goal             string      `json:"goal"`
	Originals        []string    `json:"originals"`
	Excluded         []string    `json:"excluded_originals"`
	BasicCredentials [][2]string `json:"basic_credentials"`
	NotEnrolled      []string    `json:"not_enrolled"`
	NotRoots         []string    `json:"not_roots"`
	PassThrough      []string    `json:"pass_through"`
}

type contractCall struct {
	Tool    string          `json:"tool"`
	Input   json.RawMessage `json:"input"`
	Expect  json.RawMessage `json:"expect"`
	Blocked bool            `json:"blocked"`
	Result  string          `json:"result"`
}

type contractStep struct {
	Label      string         `json:"label"`
	Text       string         `json:"text"`
	ExpectText string         `json:"expect_text"`
	Calls      []contractCall `json:"calls"`
}

type contractFixture struct {
	scope contractScope
	steps []contractStep
}

func loadContract(t *testing.T) contractFixture {
	t.Helper()
	var fx contractFixture
	var conv struct {
		Steps []contractStep `json:"steps"`
	}
	for name, dst := range map[string]any{"scope.json": &fx.scope, "conversation.json": &conv} {
		b, err := os.ReadFile("testdata/contract/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	fx.steps = conv.Steps
	if len(fx.steps) == 0 || len(fx.scope.Originals) == 0 {
		t.Fatal("empty contract fixture")
	}
	return fx
}

var contractProv = Provenance{CompanyIDs: []int64{1}, TaskIDs: []int64{42}, Source: "seed"}

// seedContract enrols the fixture the way the server seeder does (Task 9):
// declared roots opted in, company name and brand variants as org keywords,
// scope hosts, keywords, CIDRs, credentials, then the task text.
func seedContract(t *testing.T, p Persistence, sc contractScope) (*Engine, *Store) {
	t.Helper()
	s, err := OpenStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	enrol := func(k Kind, v string) {
		t.Helper()
		if _, err := s.Enroll(k, v, contractProv); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	for _, r := range sc.Roots {
		if _, err := s.EnrollRoot(r, contractProv); err != nil {
			t.Fatal(err)
		}
		enrol(KindDomain, r)
		for _, v := range BrandVariants(r) {
			enrol(KindOrg, v)
		}
	}
	enrol(KindOrg, sc.Company)
	for _, v := range BrandVariants(sc.Company) {
		enrol(KindOrg, v)
	}
	for _, kw := range sc.Keywords {
		enrol(KindOrg, kw)
		for _, v := range BrandVariants(kw) {
			enrol(KindOrg, v)
		}
	}
	for _, h := range sc.Hosts {
		enrol(KindDomain, h)
	}
	for _, c := range sc.CIDRs {
		if err := s.SeedCIDR(netip.MustParsePrefix(c), contractProv); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range sc.Credentials {
		enrol(KindUsername, c.Username)
		enrol(KindPassword, c.Password)
	}
	e := NewEngine(s, NewPipeline(s))
	if _, _, err := e.ToModel(sc.Goal, contractProv); err != nil {
		t.Fatal(err)
	}
	return e, s
}

// contractModel is the scripted fake model. It answers turn N with step N,
// resolving the templates against the request it received only.
type contractModel struct {
	mu    sync.Mutex
	steps []contractStep
	s     *Store
	turn  int
	raw   [][]byte
	err   error
}

var (
	templateRE = regexp.MustCompile(`\{\{(a|ip|jwt|reason)(?::([^}]*))?\}\}`)
	reasonRE   = regexp.MustCompile(regexp.QuoteMeta(reasonPrefix) + `(\S+)` + regexp.QuoteMeta(reasonSuffix))
)

func (m *contractModel) fail(format string, args ...any) {
	if m.err == nil {
		m.err = fmt.Errorf(format, args...)
	}
}

// resolve fills a template in alias space. jsonEsc writes values escaped for
// a JSON string literal (templates inside tool inputs).
func (m *contractModel) resolve(tmpl string, raw []byte, jsonEsc bool) string {
	return templateRE.ReplaceAllStringFunc(tmpl, func(ph string) string {
		g := templateRE.FindStringSubmatch(ph)
		var v string
		switch g[1] {
		case "a":
			a, _, ok := m.s.AliasFor(g[2])
			if !ok {
				m.fail("model: no alias for fixture value %q", g[2])
				return ph
			}
			if !strings.Contains(strings.ToLower(string(raw)), strings.ToLower(a)) {
				m.fail("model: alias of %q is not visible in the request it received", g[2])
			}
			v = a
		case "ip":
			real := netip.MustParseAddr(g[2])
			blk, ok := m.s.blockAlias(netip.PrefixFrom(real, 24).Masked())
			if !ok {
				m.fail("model: no alias block for %s", g[2])
				return ph
			}
			v = translate(netip.PrefixFrom(real, 24).Masked(), blk, real).String()
		case "jwt":
			v = jwtRE.FindString(string(raw))
			if v == "" {
				m.fail("model: no JWT in the request")
			}
		case "reason":
			var n int
			fmt.Sscan(g[2], &n)
			ms := reasonRE.FindAllStringSubmatch(string(raw), -1)
			if n >= len(ms) {
				m.fail("model: block reason %d not in the request (%d found)", n, len(ms))
				return ph
			}
			v = ms[n][1]
		}
		if jsonEsc {
			b, _ := json.Marshal(v)
			v = string(b[1 : len(b)-1])
		}
		return v
	})
}

func (m *contractModel) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := json.Marshal(req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	m.raw = append(m.raw, raw)
	if m.turn >= len(m.steps) {
		return llm.Message{}, "", llm.Usage{}, errors.New("model: script exhausted")
	}
	st := m.steps[m.turn]
	m.turn++
	msg := llm.Message{Role: llm.RoleAssistant}
	text := ""
	if st.Text != "" {
		text = m.resolve(st.Text, raw, false)
		msg.Content = append(msg.Content, llm.TextBlock(text))
	}
	for i, c := range st.Calls {
		in := m.resolve(string(c.Input), raw, true)
		msg.Content = append(msg.Content, llm.ContentBlock{Type: llm.BlockToolUse,
			ID: fmt.Sprintf("call_%d_%d", m.turn, i), Name: c.Tool, Input: json.RawMessage(in)})
	}
	if m.err != nil {
		return llm.Message{}, "", llm.Usage{}, m.err
	}
	return msg, text, llm.Usage{OutputTokens: 1}, nil
}

func (m *contractModel) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("contract model: streaming not scripted"))
	}
}

// chainAuditor is an in-memory hash chain shaped like membrane_events: each
// event's hash covers the previous hash and the canonical event.
type chainAuditor struct {
	mu  sync.Mutex
	evs []db.MembraneEvent
}

func chainHash(ev db.MembraneEvent) string {
	ev.Hash = ""
	b, _ := json.Marshal(ev)
	h := sha256.New()
	h.Write([]byte(ev.PrevHash))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *chainAuditor) Record(_ context.Context, ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := *toDBEvent(ev)
	d.ID = int64(len(a.evs) + 1)
	if len(a.evs) > 0 {
		d.PrevHash = a.evs[len(a.evs)-1].Hash
	}
	d.Hash = chainHash(d)
	a.evs = append(a.evs, d)
	return nil
}

func (a *chainAuditor) verify() (bool, int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := ""
	for _, ev := range a.evs {
		if ev.PrevHash != prev || chainHash(ev) != ev.Hash {
			return false, ev.ID
		}
		prev = ev.Hash
	}
	return true, 0
}

func (a *chainAuditor) events() []db.MembraneEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.evs)
}

// contractRun is what one pass of the conversation produced.
type contractRun struct {
	requests [][]byte // forwarded requests, as the provider received them
	executed []string // tool inputs the harness executed (real space)
	blocked  []string // tool guard block reasons
	final    string
}

func contractCtx(sc contractScope) context.Context {
	ctx := transcript.WithSessionID(context.Background(), sc.Session)
	return llmrec.WithTaskID(ctx, sc.TaskID)
}

func compactJSON(t *testing.T, b []byte) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return out.String()
}

// runContract drives the whole transcript once through Wrap(e).
func runContract(t *testing.T, e *Engine, s *Store, aud Auditor, fx contractFixture) contractRun {
	t.Helper()
	model := &contractModel{steps: fx.steps, s: s}
	p := Wrap(model, e, aud, "contract")
	ctx := contractCtx(fx.scope)
	req := llm.CompletionRequest{
		System:   []string{fx.scope.System},
		Messages: []llm.Message{llm.UserText(fx.scope.Goal)},
		Tools: []llm.ToolSchema{
			{Name: "bash", Description: "run a shell command", InputSchema: map[string]any{"type": "object"}},
			{Name: "http", Description: "send an HTTP request", InputSchema: map[string]any{"type": "object"}},
		},
		MaxTokens: 1024,
	}
	var run contractRun
	for i, st := range fx.steps {
		msg, text, _, err := p.Complete(ctx, req)
		if err != nil {
			t.Fatalf("step %d (%s): %v", i, st.Label, err)
		}
		uses := msg.ToolUses()
		if len(uses) != len(st.Calls) {
			t.Fatalf("step %d (%s): %d tool calls, want %d", i, st.Label, len(uses), len(st.Calls))
		}
		if len(st.Calls) == 0 {
			if text != st.ExpectText {
				t.Fatalf("step %d (%s): final text %q, want %q", i, st.Label, text, st.ExpectText)
			}
			assertNoResidue(t, e, s, st.Label, text)
			run.final = text
			break
		}
		results := llm.Message{Role: llm.RoleUser}
		for j, u := range uses {
			c := st.Calls[j]
			v := e.CheckTool(u.Name, u.Input, true)
			if c.Blocked {
				// Assertion 3: refused, never executed.
				if !v.Block || v.Rule != RuleUnresolvedAlias {
					t.Fatalf("step %d (%s) call %d: not blocked by the tool guard: %+v", i, st.Label, j, v)
				}
				run.blocked = append(run.blocked, v.Reason)
				results.Content = append(results.Content, llm.ToolResultText(u.ID, v.Reason, true))
				continue
			}
			if v.Block {
				t.Fatalf("step %d (%s) call %d: blocked: %s", i, st.Label, j, v.Reason)
			}
			// Assertion 2: exactly the expected real input, no residue.
			if got, want := compactJSON(t, u.Input), compactJSON(t, c.Expect); got != want {
				t.Fatalf("step %d (%s) call %d: executed input\n got %s\nwant %s", i, st.Label, j, got, want)
			}
			assertNoResidue(t, e, s, st.Label, string(u.Input))
			run.executed = append(run.executed, string(u.Input))
			results.Content = append(results.Content, llm.ToolResultText(u.ID, c.Result, false))
		}
		req.Messages = append(slices.Clone(req.Messages), msg, results)
	}
	if model.turn != len(fx.steps) {
		t.Fatalf("conversation stopped after %d of %d steps", model.turn, len(fx.steps))
	}
	run.requests = model.raw
	return run
}

// assertNoResidue: a real-space text holds nothing alias-shaped and no
// minted alias.
func assertNoResidue(t *testing.T, e *Engine, s *Store, label, text string) {
	t.Helper()
	if sh := e.AliasShaped(text); len(sh) > 0 {
		t.Fatalf("%s: alias-shaped residue %q in real-space text %s", label, sh, text)
	}
	if ms := s.ReverseDictionary().FindAll(text); len(ms) > 0 {
		t.Fatalf("%s: minted alias residue in real-space text %s (%d hits)", label, text, len(ms))
	}
	if rootAliasRE.MatchString(text) {
		t.Fatalf("%s: root alias residue in %s", label, text)
	}
}

// encodedForms returns the raw, URL, JSON and HTML forms of an original.
func encodedForms(o string) []string {
	forms := []string{o, url.QueryEscape(o), url.PathEscape(o), html.EscapeString(o)}
	jb, _ := json.Marshal(o)
	forms = append(forms, string(jb[1:len(jb)-1]))
	var dec, hx strings.Builder
	for _, r := range o {
		fmt.Fprintf(&dec, "&#%d;", r)
		fmt.Fprintf(&hx, "&#x%x;", r)
	}
	forms = append(forms, dec.String(), hx.String())
	// JSON \u escapes of every rune.
	var ju strings.Builder
	for _, r := range o {
		fmt.Fprintf(&ju, "\\u%04x", r)
	}
	forms = append(forms, ju.String())
	slices.Sort(forms)
	return slices.Compact(forms)
}

// jsonStrings collects every string (keys included) of a decoded JSON value.
func jsonStrings(v any, out []string) []string {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, e := range x {
			out = jsonStrings(e, out)
		}
	case map[string]any:
		for k, e := range x {
			out = append(out, k)
			out = jsonStrings(e, out)
		}
	}
	return out
}

var (
	pctRE   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	uescRE  = regexp.MustCompile(`\\u[0-9A-Fa-f]{4}`)
	plainRE = regexp.MustCompile(`\\[/"\\]`)
)

// lenientUnescape percent-decodes every valid %XX and leaves the rest.
func lenientUnescape(s string) string {
	return pctRE.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := hex.DecodeString(m[1:])
		return string(b)
	})
}

// jsonUnescape decodes \uXXXX and \" \\ \/ escapes inside free text (a
// JSON document quoted in a tool output).
func jsonUnescape(s string) string {
	s = uescRE.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := hex.DecodeString(m[2:])
		return string(rune(int(b[0])<<8 | int(b[1])))
	})
	return plainRE.ReplaceAllStringFunc(s, func(m string) string { return m[1:] })
}

// assertNoOriginalForms is assertion 1 over one forwarded request.
func assertNoOriginalForms(t *testing.T, e *Engine, sc contractScope, what string, raw []byte) {
	t.Helper()
	lower := strings.ToLower(string(raw))
	check := func(where, hay string) {
		t.Helper()
		for _, o := range sc.Originals {
			for _, f := range encodedForms(o) {
				if strings.Contains(hay, strings.ToLower(f)) {
					t.Fatalf("%s: %s carries a fixture original (len %d) in form %q", what, where, len(o), f)
				}
			}
		}
	}
	check("raw bytes", lower)
	// Every JSON string of the request, URL- and HTML-decoded: catches an
	// original written partly encoded (&#109;ferreira, ferreira%40acmebank).
	var doc any
	if json.Unmarshal(raw, &doc) == nil {
		for _, s := range jsonStrings(doc, nil) {
			for _, d := range []string{html.UnescapeString(s), lenientUnescape(s), html.UnescapeString(lenientUnescape(s)), jsonUnescape(s)} {
				if d != s {
					check("a URL/HTML-decoded string", strings.ToLower(d))
				}
			}
		}
	}
	// Base64 forms: Basic credentials and every original.
	var b64 []string
	for _, c := range sc.BasicCredentials {
		b64 = append(b64, c[0]+":"+c[1])
	}
	b64 = append(b64, sc.Originals...)
	for _, v := range b64 {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if f := enc.EncodeToString([]byte(v)); len(f) >= 6 && strings.Contains(string(raw), f) {
				t.Fatalf("%s: base64 form of a fixture original (len %d) present", what, len(v))
			}
		}
	}
	// JWT segments, decoded.
	for _, tok := range jwtRE.FindAllString(string(raw), -1) {
		for _, seg := range strings.Split(tok, ".")[:2] {
			dec, err := base64.RawURLEncoding.DecodeString(seg)
			if err != nil {
				continue
			}
			check("a decoded JWT segment", strings.ToLower(string(dec)))
			if hits := e.LeakCheck(dec); len(hits) > 0 {
				t.Fatalf("%s: decoded JWT segment fails LeakCheck: %+v", what, hits)
			}
		}
	}
	if hits := e.LeakCheck(raw); len(hits) > 0 {
		t.Fatalf("%s: LeakCheck hits %+v", what, hits)
	}
}

func TestContractConversation(t *testing.T) {
	fx := loadContract(t)
	sc := fx.scope
	e, s := seedContract(t, &fakePersistence{}, sc)
	aud := &chainAuditor{}
	run := runContract(t, e, s, aud, fx)

	// Assertion 1: no forwarded request carries an original in any form.
	for i, raw := range run.requests {
		assertNoOriginalForms(t, e, sc, fmt.Sprintf("request %d", i), raw)
	}
	// The offline verifier agrees (what `membrane verify` re-runs).
	recs := make([]VerifyRecord, len(run.requests))
	for i, raw := range run.requests {
		recs[i] = VerifyRecord{ID: int64(i + 1), Raw: string(raw)}
	}
	if v := Verify(e, recs); v.Checked != len(recs) || v.Failed != 0 {
		t.Fatalf("Verify over the forwarded requests: %+v", v)
	}
	// Runtime values were learned from tool output and enrolled.
	for _, o := range []string{"mferreira", "Lisboa#2025", "maria.ferreira@acmebank.pt",
		"9f2c4e7a1b3d5f6081a2c4e6b8d0f1a3", "DbR00t!2024", "Winter!Pass99", "svc_sync", "Joao Silva"} {
		if _, _, ok := s.AliasFor(o); !ok {
			t.Errorf("runtime original %q was not enrolled", o)
		}
	}
	// Excluded originals (fixture: enrolled, R3-stoplisted, not client
	// identifying) are deliberately outside the leak list.
	for _, x := range sc.Excluded {
		if slices.Contains(sc.Originals, x) {
			t.Errorf("%q is both an original and excluded", x)
		}
		if _, _, ok := s.AliasFor(x); !ok {
			t.Errorf("excluded value %q is expected to be enrolled", x)
		}
		if hits := e.LeakCheck([]byte("value " + x + " here")); len(hits) > 0 {
			t.Errorf("excluded value %q is expected to be stoplisted from the leak dictionary", x)
		}
	}

	// Scenario specifics.
	for _, v := range sc.NotEnrolled {
		if _, _, ok := s.AliasFor(v); ok {
			t.Errorf("%q must not be enrolled", v)
		}
	}
	for _, r := range sc.NotRoots {
		if s.HasRoot(r) {
			t.Errorf("%q must not be a client root", r)
		}
	}
	last := string(run.requests[len(run.requests)-1])
	for _, v := range sc.PassThrough {
		if !strings.Contains(last, v) {
			t.Errorf("%q must reach the model unchanged", v)
		}
	}
	// The API schema placeholder stays a placeholder.
	if ph, _ := json.Marshal(`"username":"string","password":"string"`); !strings.Contains(last, string(ph[1:len(ph)-1])) {
		t.Error("API schema example placeholder was rewritten")
	}
	// No root alias was derived into the third-party root.
	for _, x := range run.executed {
		if strings.Contains(x, "othercorp.") && strings.Contains(x, "okta.com") {
			t.Fatalf("alias derived into a third-party root: %s", x)
		}
	}

	// Assertion 3 (laundering): block reasons came back to the model with
	// the token verbatim, and reusing it was blocked again.
	if len(run.blocked) != 6 {
		t.Fatalf("blocked calls = %d, want 6", len(run.blocked))
	}
	for _, tok := range []string{"ffffff.example", "240.9.9.9"} {
		n := 0
		for _, r := range run.blocked {
			if strings.Contains(r, reasonPrefix+tok+reasonSuffix) {
				n++
			}
		}
		if n != 2 {
			t.Errorf("unknown alias %s blocked %d times, want 2 (original + laundered retry)", tok, n)
		}
		if !strings.Contains(last, reasonPrefix+tok) {
			t.Errorf("block reason for %s did not reach the model verbatim", tok)
		}
	}

	// Assertion 4: one request event per request, chain intact, no originals.
	evs := aud.events()
	var reqEvents, blockedReq int
	for _, ev := range evs {
		if ev.Direction != "request" {
			continue
		}
		reqEvents++
		if ev.Blocked {
			blockedReq++
		}
	}
	if blockedReq != 0 {
		t.Fatalf("%d requests were blocked by the leak check", blockedReq)
	}
	if reqEvents != len(run.requests)+blockedReq || reqEvents != len(fx.steps) {
		t.Fatalf("request events = %d, requests = %d, steps = %d", reqEvents, len(run.requests), len(fx.steps))
	}
	if ok, bad := aud.verify(); !ok {
		t.Fatalf("audit chain broken at %d", bad)
	}
	evJSON, _ := json.Marshal(evs)
	assertNoOriginalForms(t, e, sc, "audit events", evJSON)
}

// TestContractInMemoryChainDetectsTamper keeps the in-memory chain honest:
// it must fail when an event is altered.
func TestContractInMemoryChainDetectsTamper(t *testing.T) {
	a := &chainAuditor{}
	for range 3 {
		_ = a.Record(context.Background(), Event{Direction: "request", Report: newReport()})
	}
	if ok, _ := a.verify(); !ok {
		t.Fatal("fresh chain does not verify")
	}
	a.evs[1].Enrolled = 9
	if ok, bad := a.verify(); ok || bad != 2 {
		t.Fatalf("tampered chain verified (ok=%v bad=%d)", ok, bad)
	}
}

// TestContractDBAuditChain runs the conversation with the production
// DBAuditor and verifies the membrane_events chain in PostgreSQL.
func TestContractDBAuditChain(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no PostgreSQL DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	fx := loadContract(t)
	fx.scope.TaskID = "913013"
	before, err := d.MembraneTaskEvents(fx.scope.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	e, s := seedContract(t, &fakePersistence{}, fx.scope)
	run := runContract(t, e, s, NewDBAuditor(d), fx)
	after, err := d.MembraneTaskEvents(fx.scope.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, ev := range before {
		seen[ev.ID] = true
	}
	var reqEvents, blocked int
	for _, ev := range after {
		if seen[ev.ID] || ev.Direction != "request" {
			continue
		}
		reqEvents++
		if ev.Blocked {
			blocked++
		}
	}
	if reqEvents != len(run.requests)+blocked || blocked != 0 {
		t.Fatalf("request events = %d (blocked %d), requests = %d", reqEvents, blocked, len(run.requests))
	}
	ok, bad, err := d.VerifyMembraneChain()
	if err != nil || !ok {
		t.Fatalf("membrane_events chain: ok=%v first bad=%d err=%v", ok, bad, err)
	}
}

// clonePersistence copies the persisted store state.
func clonePersistence(p *fakePersistence) *fakePersistence {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := &fakePersistence{blocks: slices.Clone(p.blocks)}
	for _, e := range p.entries {
		e.OriginalEnc = slices.Clone(e.OriginalEnc)
		e.CompanyIDs = slices.Clone(e.CompanyIDs)
		e.TaskIDs = slices.Clone(e.TaskIDs)
		e.RetiredAliases = slices.Clone(e.RetiredAliases)
		c.entries = append(c.entries, e)
	}
	return c
}

func assertSameRequests(t *testing.T, what string, a, b contractRun) {
	t.Helper()
	if len(a.requests) != len(b.requests) {
		t.Fatalf("%s: %d vs %d requests", what, len(a.requests), len(b.requests))
	}
	for i := range a.requests {
		if string(a.requests[i]) != string(b.requests[i]) {
			t.Fatalf("%s: request %d differs\n%s\n%s", what, i, a.requests[i], b.requests[i])
		}
	}
	if !slices.Equal(a.executed, b.executed) {
		t.Fatalf("%s: executed tool inputs differ", what)
	}
}

// TestContractDeterministic is assertion 5.
func TestContractDeterministic(t *testing.T) {
	fx := loadContract(t)
	base := &fakePersistence{}
	seedContract(t, base, fx.scope)

	// Two fresh engines over the same persisted state.
	p1, p2 := clonePersistence(base), clonePersistence(base)
	e1, s1 := openContract(t, p1)
	e2, s2 := openContract(t, p2)
	r1 := runContract(t, e1, s1, &chainAuditor{}, fx)
	r2 := runContract(t, e2, s2, &chainAuditor{}, fx)
	assertSameRequests(t, "fresh engines", r1, r2)

	// Twice in the same engine.
	r1b := runContract(t, e1, s1, &chainAuditor{}, fx)
	assertSameRequests(t, "same engine, second run", r1, r1b)

	// A fresh engine over the state the first run persisted.
	e3, s3 := openContract(t, clonePersistence(p1))
	r3 := runContract(t, e3, s3, &chainAuditor{}, fx)
	assertSameRequests(t, "fresh engine after the run", r1, r3)
}

func openContract(t *testing.T, p Persistence) (*Engine, *Store) {
	t.Helper()
	s, err := OpenStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(s, NewPipeline(s)), s
}
