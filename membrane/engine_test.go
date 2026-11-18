package membrane

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// newTestEngine returns an engine over a fresh store seeded with the Acme
// Bank fixture: root domain, two org keywords, a /22 scope CIDR and the task
// credentials.
func newTestEngine(t *testing.T) (*Engine, *Store) {
	t.Helper()
	s, _ := newTestStore(t)
	for _, e := range []struct {
		k Kind
		v string
	}{
		{KindDomain, "acmebank.pt"},
		{KindOrg, "Acme Bank"},
		{KindOrg, "acmebank"},
		{KindUsername, "jsilva"},
		{KindPassword, "Hunter2024!"},
	} {
		if _, err := s.Enroll(e.k, e.v, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SeedCIDR(netip.MustParsePrefix("185.12.40.0/22"), seedProv); err != nil {
		t.Fatal(err)
	}
	return NewEngine(s, NewPipeline(s)), s
}

func mustAlias(t *testing.T, s *Store, original string) string {
	t.Helper()
	a, _, ok := s.AliasFor(original)
	if !ok {
		t.Fatalf("no alias for an expected original (len %d)", len(original))
	}
	return a
}

func toModel(t *testing.T, e *Engine, text string) string {
	t.Helper()
	out, _, err := e.ToModel(text, Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const fixtureGoal = `Assess Acme Bank's external perimeter: acmebank.pt, portal.acmebank.pt and vpn.acmebank.pt, plus 185.12.40.0/24 and 185.12.41.7.
Primary contact: joao.silva@acmebank.pt, +351 912 345 678.
Test account: username=jsilva password=Hunter2024!
Legacy API: curl -H "Authorization: Basic ` + "anNpbHZhOkh1bnRlcjIwMjQh" + `" https://api.acmebank.pt/v1/accounts?owner=joao.silva%40acmebank.pt
Do not touch 10.0.0.5 or okta.com.`

func TestRoundTripFixture(t *testing.T) {
	e, _ := newTestEngine(t)
	if hits := e.LeakCheck([]byte(fixtureGoal)); len(hits) == 0 {
		t.Fatal("leak check must flag the un-membraned fixture")
	}
	out, rep, err := e.ToModel(fixtureGoal, Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
		t.Fatalf("leak hits %+v in %q", hits, out)
	}
	for _, real := range []string{"acmebank", "Acme Bank", "185.12.4", "joao.silva", "912 345", "jsilva", "Hunter2024", "anNpbHZhOkh1bnRlcjIwMjQh"} {
		if strings.Contains(out, real) {
			t.Fatalf("output still contains a real value: %q", out)
		}
	}
	for _, keep := range []string{"10.0.0.5", "okta.com", "curl -H"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("output lost %q: %q", keep, out)
		}
	}
	if rep.Counts[KindDomain] == 0 || rep.Counts[KindIPv4] == 0 || rep.Counts[KindEmail] == 0 || rep.Enrolled == 0 {
		t.Fatalf("report %+v", rep)
	}
	back, unresolved := e.ToReal(out)
	if back != fixtureGoal {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q\n via %q", back, fixtureGoal, out)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved %v", unresolved)
	}
}

func TestKindConfusion(t *testing.T) {
	e, s := newTestEngine(t)
	const key = "sk_live_51HxAbCdEfGh"
	if _, err := s.Enroll(KindToken, key, seedProv); err != nil {
		t.Fatal(err)
	}
	in := `{"username":"svc","password":"` + key + `"}`
	out := toModel(t, e, in)
	if strings.Contains(out, key) {
		t.Fatalf("key not aliased: %s", out)
	}
	alias := mustAlias(t, s, key)
	if !strings.Contains(out, alias) {
		t.Fatalf("password field must use the token's alias %q: %s", alias, out)
	}
	back, _ := e.ToReal(`login with password ` + alias)
	if back != `login with password `+key {
		t.Fatalf("got %q", back)
	}
}

func TestDeriveSubdomain(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	back, unresolved := e.ToReal("nmap -sV dev." + ra + " and DEV2." + strings.ToUpper(ra))
	if back != "nmap -sV dev.acmebank.pt and DEV2.acmebank.pt" {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved %v", unresolved)
	}
	if a, kind, ok := s.AliasFor("dev.acmebank.pt"); !ok || kind != KindDomain || a != "dev."+ra {
		t.Fatalf("derived host not enrolled: %q %s %v", a, kind, ok)
	}
	// R4: enrolled with the root's provenance, source auto.
	p := s.provenanceOf(KindDomain, "dev.acmebank.pt")
	if !slices.Equal(p.CompanyIDs, seedProv.CompanyIDs) || p.Source != "auto" {
		t.Fatalf("provenance %+v", p)
	}
	// Keyword alias inside a label (lowercase DNS form) reverses too.
	ka := strings.ToLower(mustAlias(t, s, "acmebank"))
	back, unresolved = e.ToReal("https://" + ka + "-api." + ra + "/login")
	if back != "https://acmebank-api.acmebank.pt/login" || len(unresolved) != 0 {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
	// A keyword alias in a third-party host reverses to the lowercase original.
	back, _ = e.ToReal(ka + ".okta.com")
	if back != "acmebank.okta.com" {
		t.Fatalf("got %q", back)
	}
}

func TestDeriveIPInBlock(t *testing.T) {
	e, s := newTestEngine(t)
	a, err := s.IPv4Alias(netip.MustParseAddr("185.12.41.7"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	b := a.As4()
	b[3] = 55
	derived := netip.AddrFrom4(b).String()
	back, unresolved := e.ToReal("curl http://" + derived + ":8080/")
	if back != "curl http://185.12.41.55:8080/" || len(unresolved) != 0 {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
	if got, _, ok := s.AliasFor("185.12.41.55"); !ok || got != derived {
		t.Fatalf("derived IP not enrolled: %q %v", got, ok)
	}
	// Outside every block: unresolved and untouched.
	back, unresolved = e.ToReal("ping 250.9.9.9")
	if back != "ping 250.9.9.9" || !slices.Equal(unresolved, []string{"250.9.9.9"}) {
		t.Fatalf("got %q %v", back, unresolved)
	}
}

func TestDeriveCIDRNarrow(t *testing.T) {
	e, s := newTestEngine(t)
	a, err := s.IPv4Alias(netip.MustParseAddr("185.12.41.7"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	b := a.As4()
	b[3] = 16
	narrow := netip.AddrFrom4(b).String() + "/28"
	back, unresolved := e.ToReal("masscan " + narrow)
	if back != "masscan 185.12.41.16/28" || len(unresolved) != 0 {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
	b[2], b[3] = 0, 0
	wide := netip.AddrFrom4(b).String() + "/16"
	back, unresolved = e.ToReal("masscan " + wide)
	if back != "masscan "+wide || !slices.Equal(unresolved, []string{wide}) {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
	// Exactly the seeded /22 alias block reverses.
	blk, ok := s.blockAlias(netip.MustParsePrefix("185.12.40.0/22"))
	if !ok {
		t.Fatal("no seeded block")
	}
	back, unresolved = e.ToReal("scan " + blk.String())
	if back != "scan 185.12.40.0/22" || len(unresolved) != 0 {
		t.Fatalf("got %q (unresolved %v)", back, unresolved)
	}
}

func TestUnknownAliasUnresolved(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "curl https://ffffff.example/x and ask ORG-ffff about 2001:db8::dead"
	back, unresolved := e.ToReal(in)
	if back != in {
		t.Fatalf("unknown aliases must stay: %q", back)
	}
	want := []string{"ffffff.example", "ORG-ffff", "2001:db8::dead"}
	if !slices.Equal(unresolved, want) {
		t.Fatalf("unresolved %v, want %v", unresolved, want)
	}
	if got := e.AliasShaped(in); !slices.Equal(got, want) {
		t.Fatalf("AliasShaped %v", got)
	}
	// R12: replayed in assistant content (a fresh engine, as after a
	// restart), unminted alias-shaped tokens pass through and are not
	// enrolled; hosts under a minted root are alias space everywhere.
	s := e.s
	ra := mustAlias(t, s, "acmebank.pt")
	asst := in + " and org-ffff." + ra + " and dev.ffffff.example and 240.9.9.9"
	req := llm.CompletionRequest{Messages: []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: asst}, {Type: llm.BlockThinking, Thinking: asst}}},
	}}
	out, _, err := NewEngine(s, nil).ToModelRequest(req, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Messages[0].Content[0].Text; got != asst || out.Messages[0].Content[1].Thinking != asst {
		t.Fatalf("assistant aliases changed: %q", got)
	}
	for _, tok := range []string{"ffffff.example", "ORG-ffff", "240.9.9.9", "dev.ffffff.example"} {
		if _, _, ok := s.AliasFor(tok); ok {
			t.Fatalf("assistant token %q enrolled", tok)
		}
	}
	// In non-assistant content a host under a minted root is never enrolled
	// and never an error.
	user := "tool says org-ffff." + ra + " is down"
	if got := toModel(t, NewEngine(s, nil), user); got != user {
		t.Fatalf("host under minted root changed: %q", got)
	}
}

func TestModelIntroducedDomainPassthrough(t *testing.T) {
	e, s := newTestEngine(t)
	back, _ := e.ToReal("let's check status.newvendor.io next")
	if back != "let's check status.newvendor.io next" {
		t.Fatalf("got %q", back)
	}
	if !s.IsModelKnown("status.newvendor.io") {
		t.Fatal("model-introduced domain not marked model-known")
	}
	out := toModel(t, e, "status.newvendor.io answered 200")
	if out != "status.newvendor.io answered 200" {
		t.Fatalf("model-known domain was aliased: %q", out)
	}
	for _, sp := range e.Suspicious(out) {
		if strings.Contains(sp.Text, "newvendor") {
			t.Fatalf("model-known domain flagged: %+v", sp)
		}
	}
	// A domain under a client root is never model-known.
	e.ToReal("acmebank.pt")
	if s.IsModelKnown("acmebank.pt") {
		t.Fatal("client root marked model-known")
	}
}

func TestRealAliasShapedValueEnrolled(t *testing.T) {
	e, s := newTestEngine(t)
	in := "target host 240.1.2.3 serves abcdef.example (ticket ORG-1234, login user-beef)"
	out := toModel(t, e, in)
	for _, real := range []string{"240.1.2.3", "abcdef.example", "ORG-1234", "user-beef"} {
		if strings.Contains(out, real) {
			t.Fatalf("real alias-shaped value %q kept in %q", real, out)
		}
		if _, _, ok := s.AliasFor(real); !ok {
			t.Fatalf("real alias-shaped value %q not enrolled", real)
		}
	}
	back, unresolved := e.ToReal(out)
	if back != in || len(unresolved) != 0 {
		t.Fatalf("got %q (unresolved %v) via %q", back, unresolved, out)
	}
	// Minted aliases already in the input pass through unchanged.
	if _, err := s.Enroll(KindEmail, "joao.x@acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	ra := mustAlias(t, s, "acmebank.pt")
	minted := "see portal." + ra + " and " + mustAlias(t, s, "Acme Bank") + " and " + mustAlias(t, s, "joao.x@acmebank.pt")
	if got := toModel(t, e, minted); got != minted {
		t.Fatalf("minted aliases changed: %q -> %q", minted, got)
	}
}

func TestMultiEncodingSecret(t *testing.T) {
	e, s := newTestEngine(t)
	const secret = "s3cr3t@Vault9"
	if _, err := s.Enroll(KindPassword, secret, seedProv); err != nil {
		t.Fatal(err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("svc:" + secret))
	in := "raw: pw " + secret + "\n" +
		"url: https://x.io/?pw=s3cr3t%40Vault9\n" +
		`json: {"pw":"s3cr3t@Vault9"}` + "\n" +
		`html: <input value="s3cr3t&#64;Vault9">` + "\n" +
		"Authorization: Basic " + basic + "\n"
	out := toModel(t, e, in)
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
		t.Fatalf("leak hits %+v in %q", hits, out)
	}
	if strings.Contains(out, "s3cr3t") || strings.Contains(out, basic) {
		t.Fatalf("secret survived: %q", out)
	}
	pa := mustAlias(t, s, secret)
	for _, want := range []string{"pw " + pa, "pw=" + strings.ReplaceAll(pa, "@", "%40"), strings.ReplaceAll(pa, "@", "&#64;")} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	back, unresolved := e.ToReal(out)
	if back != in || len(unresolved) != 0 {
		t.Fatalf("round trip:\n got %q\nwant %q (unresolved %v)", back, in, unresolved)
	}
	// LeakCheck sees every encoding of an original.
	for _, enc := range []string{secret, "s3cr3t%40Vault9", `s3cr3t@Vault9`, "s3cr3t&#64;Vault9"} {
		if len(e.LeakCheck([]byte("x "+enc+" y"))) == 0 {
			t.Fatalf("leak check missed %q", enc)
		}
	}
}

func testRequest() llm.CompletionRequest {
	return llm.CompletionRequest{
		System: []string{"You test Acme Bank (acmebank.pt).", "Scope: 185.12.40.0/22"},
		Messages: []llm.Message{
			llm.UserText("Start with portal.acmebank.pt"),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "portal.acmebank.pt looks like a login page", Signature: "sig=="},
				{Type: llm.BlockText, Text: "Running curl."},
				{Type: llm.BlockToolUse, ID: "t1", Name: "bash", Input: json.RawMessage(`{"cmd": "curl -u jsilva:Hunter2024! https://portal.acmebank.pt/", "n": 3}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{
				{Type: llm.BlockToolResult, ToolUseID: "t1", Content: []llm.ContentBlock{
					llm.TextBlock("HTTP/1.1 200 OK\nServer: acmebank-edge\nX-Contact: joao.silva@acmebank.pt"),
				}},
			}},
		},
		Tools: []llm.ToolSchema{{Name: "bash", Description: "run a shell command", InputSchema: map[string]any{"type": "object"}}},
	}
}

func TestDeterministicAcrossCalls(t *testing.T) {
	e, s := newTestEngine(t)
	r1, _, err := e.ToModelRequest(testRequest(), Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	r2, rep2, err := e.ToModelRequest(testRequest(), Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(r1)
	b2, _ := json.Marshal(r2)
	if string(b1) != string(b2) {
		t.Fatalf("not byte-identical:\n%s\n%s", b1, b2)
	}
	if rep2.Enrolled != 0 {
		t.Fatalf("second call enrolled %d", rep2.Enrolled)
	}
	// A fresh engine (no cache) over the same store gives the same bytes.
	r3, _, err := NewEngine(s, nil).ToModelRequest(testRequest(), Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := json.Marshal(r3)
	if string(b1) != string(b3) {
		t.Fatalf("cached and uncached differ:\n%s\n%s", b1, b3)
	}
	if hits := e.LeakCheck(b1); len(hits) != 0 {
		t.Fatalf("leak hits %+v in %s", hits, b1)
	}
}

func TestToModelRequestDoesNotMutateInput(t *testing.T) {
	e, _ := newTestEngine(t)
	req := testRequest()
	before, _ := json.Marshal(req)
	toolsBefore := req.Tools
	out, rep, err := e.ToModelRequest(req, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(req)
	if string(before) != string(after) {
		t.Fatalf("input mutated:\n%s\n%s", before, after)
	}
	if !reflect.DeepEqual(out.Tools, toolsBefore) {
		t.Fatal("tools changed")
	}
	got, _ := json.Marshal(out)
	if strings.Contains(string(got), "acmebank") || strings.Contains(string(got), "Hunter2024") {
		t.Fatalf("not transformed: %s", got)
	}
	if out.Messages[1].Content[0].Signature != "sig==" || out.Messages[1].Content[2].ID != "t1" {
		t.Fatal("ids/signatures must be kept")
	}
	// tool_use input is still valid JSON with the non-string value intact.
	var in map[string]any
	if err := json.Unmarshal(out.Messages[1].Content[2].Input, &in); err != nil || in["n"] != float64(3) {
		t.Fatalf("input %s: %v", out.Messages[1].Content[2].Input, err)
	}
	if rep.Counts[KindDomain] == 0 {
		t.Fatalf("report %+v", rep)
	}
	// Mutating the output must not reach the input.
	out.Messages[2].Content[0].Content[0].Text = "x"
	out.System[0] = "x"
	if req.Messages[2].Content[0].Content[0].Text == "x" || req.System[0] == "x" {
		t.Fatal("output shares backing arrays with the input")
	}
	// And de-aliasing the message gives the real values back.
	m, unresolved := e.ToRealMessage(out.Messages[1])
	if len(unresolved) != 0 {
		t.Fatalf("unresolved %v", unresolved)
	}
	mb, _ := json.Marshal(m)
	wb, _ := json.Marshal(req.Messages[1])
	if string(mb) != string(wb) {
		t.Fatalf("ToRealMessage:\n got %s\nwant %s", mb, wb)
	}
}

func TestToModelJSONKeepsLayout(t *testing.T) {
	e, s := newTestEngine(t)
	in := json.RawMessage("{\n  \"host\" : \"portal.acmebank.pt\",\n  \"acmebank.pt\": [1, true, null, \"x\\/y\"]\n}")
	out, _, err := e.ToModelJSON(in, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"host\" : \"portal." + mustAlias(t, s, "acmebank.pt") + "\",\n  \"acmebank.pt\": [1, true, null, \"x\\/y\"]\n}"
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	same := json.RawMessage(`{"a": "nothing here"}`)
	out, _, _ = e.ToModelJSON(same, Provenance{})
	if string(out) != string(same) {
		t.Fatalf("unchanged JSON rewritten: %s", out)
	}
	back, unresolved := e.ToRealJSON(json.RawMessage(want))
	if len(unresolved) != 0 || !strings.Contains(string(back), `"portal.acmebank.pt"`) {
		t.Fatalf("got %s %v", back, unresolved)
	}
}

func TestJWTKeepsStructure(t *testing.T) {
	e, s := newTestEngine(t)
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc([]byte(`{"sub":"joao.silva@acmebank.pt","iss":"https:\/\/sso.acmebank.pt","n":1}`))
	jwt := header + "." + payload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	in := "Authorization: Bearer " + jwt
	out := toModel(t, e, in)
	if strings.Contains(out, payload) || strings.Contains(out, "SflKxwRJ") {
		t.Fatalf("jwt not transformed: %q", out)
	}
	tok := strings.TrimPrefix(out, "Authorization: Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != header {
		t.Fatalf("structure lost: %q", tok)
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	ra := mustAlias(t, s, "acmebank.pt")
	if !strings.Contains(string(claims), ra) || strings.Contains(string(claims), "acmebank") {
		t.Fatalf("claims %s", claims)
	}
	back, unresolved := e.ToReal(out)
	if back != in || len(unresolved) != 0 {
		t.Fatalf("round trip %q (unresolved %v)", back, unresolved)
	}
}

func TestToModelCacheSameReport(t *testing.T) {
	e, _ := newTestEngine(t)
	out1, rep1, err := e.ToModel(fixtureGoal, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	out2, rep2, _ := e.ToModel(fixtureGoal, Provenance{}) // uncached: enrolment bumped the generation
	out3, rep3, _ := e.ToModel(fixtureGoal, Provenance{}) // cached
	if out1 != out2 || out2 != out3 {
		t.Fatal("outputs differ")
	}
	if rep2.Enrolled != 0 || rep3.Enrolled != 0 {
		t.Fatalf("enrolled %d %d", rep2.Enrolled, rep3.Enrolled)
	}
	rep1.Enrolled = 0
	if !reflect.DeepEqual(rep1, rep2) || !reflect.DeepEqual(rep2, rep3) {
		t.Fatalf("reports differ: %+v %+v %+v", rep1, rep2, rep3)
	}
	if e.cache.len() == 0 {
		t.Fatal("nothing cached")
	}
	rep3.Counts[KindDomain] = 999 // caller mutation must not poison the cache
	_, rep4, _ := e.ToModel(fixtureGoal, Provenance{})
	if rep4.Counts[KindDomain] == 999 {
		t.Fatal("cache returned a shared map")
	}
}

func TestLeakCheckReportsKindAndOffsetOnly(t *testing.T) {
	e, _ := newTestEngine(t)
	body := []byte(`{"text":"ping 185.12.41.7 for Acme Bank"}`)
	if _, _, err := e.ToModel("185.12.41.7", Provenance{}); err != nil { // enrol the IP
		t.Fatal(err)
	}
	hits := e.LeakCheck(body)
	want := []LeakHit{{Kind: KindIPv4, Offset: 14}, {Kind: KindOrg, Offset: 30}}
	if !reflect.DeepEqual(hits, want) {
		t.Fatalf("hits %+v, want %+v", hits, want)
	}
}

func TestLeakCheckIgnoresOriginalsInsideAliases(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	short := ra[1:4] // a 3-char original that happens to occur inside the alias
	if _, err := s.Enroll(KindUsername, short, seedProv); err != nil {
		t.Fatal(err)
	}
	if hits := e.LeakCheck([]byte(`{"t":"see portal.` + ra + `"}`)); len(hits) != 0 {
		t.Fatalf("hit inside an alias: %+v", hits)
	}
	if hits := e.LeakCheck([]byte(`{"t":"user ` + short + `"}`)); len(hits) != 1 {
		t.Fatalf("real occurrence missed: %+v", hits)
	}
}

func TestSuspicious(t *testing.T) {
	e, _ := newTestEngine(t)
	text := "Meeting notes. Contact Maria Fernandes at the Lisbon office about shadow.example.org today. The server is fine."
	var got []string
	for _, sp := range e.Suspicious(text) {
		if text[sp.Start:sp.End] != sp.Text {
			t.Fatalf("bad offsets %+v", sp)
		}
		got = append(got, sp.Text)
	}
	want := []string{"Maria Fernandes", "shadow.example.org"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	_, rep, err := e.ToModel(text, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rep.Flags, []string{"suspicious_domain", "suspicious_name"}) {
		t.Fatalf("flags %v", rep.Flags)
	}
}

func TestEngineErrorsNeverContainOriginals(t *testing.T) {
	e, s := newTestEngine(t)
	s.p.(*fakePersistence).failInserts = 2
	_, _, err := e.ToModel("call secretperson@acmebank.pt", Provenance{})
	if err == nil {
		t.Fatal("expected enrolment error")
	}
	if strings.Contains(strings.ToLower(err.Error()), "secretperson") {
		t.Fatalf("error leaks original: %v", err)
	}
}

// FuzzEngineToModel checks that ToModel never panics, never leaves an
// enrolled original for LeakCheck to find, and that ToReal never panics on
// its output.
func FuzzEngineToModel(f *testing.F) {
	for _, s := range []string{fixtureGoal, "240.1.2.3/24 abcdef.example ORG-1234 user-beef@x.example",
		`{"pw":"Hunter2024!"} Basic anNpbHZhOkh1bnRlcjIwMjQh`, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
		"2001:db8::1 acmebank-vpn.acmebank.pt Acme Bank%27s", "&#97;cmebank.pt"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		e, _ := newTestEngine(t)
		out, _, err := e.ToModel(in, Provenance{})
		if err != nil {
			return // fail closed is allowed
		}
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 && survivesFrom(e, out) {
			t.Fatalf("leak %+v: in %q out %q", hits, in, out)
		}
		e.ToReal(out)
		e.ToReal(in)
	})
}

// survivesFrom reports whether a dictionary hit in out (raw or decoded)
// lies wholly outside the aliases written there, i.e. an original survived.
// Hits that only exist because an alias was glued to neighbouring bytes
// ("ORG-8fea"+"CmeBAnk" folds to the keyword acmebank) overlap an alias and
// are not leaks; LeakCheck still blocks them (fail closed).
//
// A hit that only a decoded view sees and whose raw bytes overlap an alias
// is a decoding artefact (%00000.<alias>: %00 decodes to NUL, leaving a
// standalone "000" from a preserved label); an encoded original that
// survived (s3cr3t%40Vault9) overlaps no alias and still counts.
func survivesFrom(e *Engine, out string) bool {
	e.s.mu.RLock()
	var all []string
	for a := range e.s.aliasExact {
		all = append(all, lowerASCII(a))
	}
	e.s.mu.RUnlock()
	occurrences := func(t string) []Match {
		var aliases []Match
		low := lowerASCII(t)
		for _, a := range all {
			for off := 0; ; {
				i := strings.Index(low[off:], a)
				if i < 0 {
					break
				}
				aliases = append(aliases, Match{Start: off + i, End: off + i + len(a)})
				off += i + 1
			}
		}
		return aliases
	}
	rawAliases := occurrences(out)
	straddles := func(aliases []Match, s, end int) bool {
		for _, a := range aliases {
			if a.Start < end && s < a.End && (s < a.Start || end > a.End) {
				return true
			}
		}
		return false
	}
	for _, m := range e.s.Dictionary().FindAll(out) {
		if !straddles(rawAliases, m.Start, m.End) {
			return true
		}
	}
	for _, v := range decodedViews(out) {
		viewAliases := occurrences(v.text)
	hits:
		for _, m := range e.s.Dictionary().FindAll(v.text) {
			if straddles(viewAliases, m.Start, m.End) {
				continue
			}
			rs, re := v.rs[m.Start], v.re[m.End-1]
			for _, a := range rawAliases {
				if a.Start < re && rs < a.End {
					continue hits // decoding artefact over an alias
				}
			}
			return true
		}
	}
	return false
}

func BenchmarkToModel(b *testing.B) {
	e, _ := newTestEngine(&testing.T{})
	text := strings.Repeat(fixtureGoal+"\nSome ordinary prose about the engagement plan and next steps.\n", 200)
	if _, _, err := e.ToModel(text, Provenance{}); err != nil {
		b.Fatal(err)
	}
	b.Run("uncached", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			if _, _, err := e.toModel(text, Provenance{}, false); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			_, _, _ = e.ToModel(text, Provenance{})
		}
	})
	out, _, _ := e.ToModel(text, Provenance{})
	b.Run("toreal", func(b *testing.B) {
		b.SetBytes(int64(len(out)))
		for b.Loop() {
			e.ToReal(out)
		}
	})
	b.Run("leakcheck", func(b *testing.B) {
		b.SetBytes(int64(len(out)))
		for b.Loop() {
			e.LeakCheck([]byte(out))
		}
	})
}

func TestPunctuationOnlySecretAliased(t *testing.T) {
	e, s := newTestEngine(t)
	in := `usr=!!! {"password":"#$%&*"}`
	out := toModel(t, e, in)
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 || strings.Contains(out, "!!!") || strings.Contains(out, "#$%&*") {
		t.Fatalf("punctuation-only secret kept: %q (hits %+v)", out, hits)
	}
	if a := mustAlias(t, s, "!!!"); len(a) != 3 {
		t.Fatalf("alias %q must keep the length", a)
	}
	if back, _ := e.ToReal(out); back != in {
		t.Fatalf("round trip %q", back)
	}
}

func TestHostLabelsCarryingLiteralsAreAliased(t *testing.T) {
	e, s := newTestEngine(t)
	// Username enrolled (fixture) before the host: substituted at mint.
	in := "workstation jsilva-pc.corp.acmebank.pt answered"
	out := toModel(t, e, in)
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 || strings.Contains(out, "jsilva") {
		t.Fatalf("username kept in labels: %q (hits %+v)", out, hits)
	}
	if back, u := e.ToReal(out); back != in || len(u) != 0 {
		t.Fatalf("round trip %q (unresolved %v)", back, u)
	}
	// A model-derived sibling host with the username alias in a label.
	ua := mustAlias(t, s, "jsilva")
	ra := mustAlias(t, s, "acmebank.pt")
	if back, u := e.ToReal(ua + "-laptop." + ra); back != "jsilva-laptop.acmebank.pt" || len(u) != 0 {
		t.Fatalf("derived %q (unresolved %v)", back, u)
	}
	// Host enrolled before the username: re-minted when the username is.
	out = toModel(t, e, "box mfaria-pc.acmebank.pt")
	if _, err := s.Enroll(KindUsername, "mfaria", seedProv); err != nil {
		t.Fatal(err)
	}
	out2 := toModel(t, e, "box mfaria-pc.acmebank.pt")
	if strings.Contains(out2, "mfaria") || len(e.LeakCheck([]byte(out2))) != 0 {
		t.Fatalf("not re-minted: %q", out2)
	}
	if back, _ := e.ToReal(out); back != "box mfaria-pc.acmebank.pt" {
		t.Fatalf("retired alias must still resolve: %q", back)
	}
}

func TestSubdomainLabelsContainingRootAreAliased(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.Enroll(KindDomain, "corpx.io", seedProv); err != nil { // no keyword covers it
		t.Fatal(err)
	}
	in := "internal host corpx.io.internal.corpx.io is up"
	out := toModel(t, e, in)
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 || strings.Contains(out, "corpx") {
		t.Fatalf("root name kept in labels: %q (hits %+v)", out, hits)
	}
	back, unresolved := e.ToReal(out)
	if back != in || len(unresolved) != 0 {
		t.Fatalf("round trip %q (unresolved %v)", back, unresolved)
	}
}
