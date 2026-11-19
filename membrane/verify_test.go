package membrane

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// verifyOriginals are fixture originals that must never appear in evidence
// or verify output.
var verifyOriginals = []string{"acmebank.pt", "Acme Bank", "acmebank", "jsilva", "Hunter2024!", "185.12.40.9", "joao.silva@acmebank.pt"}

func TestVerifyDetectsPlantedOriginal(t *testing.T) {
	e, _ := newTestEngine(t)
	clean := toModel(t, e, "login jsilva / Hunter2024! at portal.acmebank.pt (185.12.40.9) for Acme Bank")
	if hits := e.LeakCheck([]byte(clean)); len(hits) != 0 {
		t.Fatalf("fixture: aliased text has leak hits %v", hits)
	}
	recs := []VerifyRecord{
		{ID: 11, Raw: `{"messages":[{"content":` + jsonString(clean) + `}]}`},
		{ID: 12, Raw: `{"messages":[{"content":"call portal.acmebank.pt now"}]}`},
		{ID: 13, Raw: `{"messages":[{"content":"Hunter2024! in escapes"}]}`},
	}
	got := Verify(e, recs)
	if got.Checked != 3 || got.Failed != 2 || !slices.Equal(got.FailedIDs, []int64{12, 13}) {
		t.Fatalf("Verify = %+v, want checked 3, failed 2 [12 13]", got)
	}
	if got.FailedKinds["domain"] == 0 || got.FailedKinds["password"] == 0 {
		t.Fatalf("failed kinds = %v, want domain and password", got.FailedKinds)
	}
	b, _ := json.Marshal(got)
	for _, o := range verifyOriginals {
		if strings.Contains(string(b), o) {
			t.Fatalf("verify result carries an original (len %d)", len(o))
		}
	}
}

func TestVerifyEmptyRawSkipped(t *testing.T) {
	e, _ := newTestEngine(t)
	got := Verify(e, []VerifyRecord{{ID: 1, Raw: ""}, {ID: 2, Raw: "{}"}})
	if got.Checked != 1 || got.Failed != 0 || got.NoRaw != 1 {
		t.Fatalf("Verify = %+v", got)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// evidenceFixture builds events with originals planted in every free-text
// field an event can carry.
func evidenceFixture() EvidenceInput {
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	ev := func(id int64, dir string, blocked bool, reason string, flags []string, counts map[string]int, profile string) db.MembraneEvent {
		return db.MembraneEvent{ID: id, TS: t0.Add(time.Duration(id) * time.Minute), TaskID: "42", Session: "task-42-worker-acmebank",
			Role: "worker", Profile: profile, Direction: dir, Counts: counts, Enrolled: 2, Flags: flags,
			Blocked: blocked, BlockReason: reason, RequestSHA256: strings.Repeat("ab", 32), Hash: "h"}
	}
	return EvidenceInput{
		TaskID:      "42",
		GeneratedAt: t0.Add(time.Hour),
		Events: []db.MembraneEvent{
			ev(1, "request", false, "", []string{"suspicious_name"}, map[string]int{"domain": 3, "org": 1}, "kimi"),
			ev(2, "request", true, "leak check: domain@17, password@40, Hunter2024!", nil, map[string]int{"password": 1}, "kimi"),
			ev(3, "response", false, "", []string{"unresolved:2"}, nil, "kimi"),
			ev(4, "tool_block", true, "unresolved_alias", []string{"unresolved_alias", "acme bank"}, nil, ""),
			ev(5, "request", true, "seed sync failed", nil, nil, "Acme Bank profile"),
			ev(6, "request", false, "", []string{"suspicious_domain"}, map[string]int{"ipv4": 2}, "kimi"),
		},
		Boots:               []db.MembraneEvent{{ID: 9, TS: t0.Add(3 * time.Minute), Direction: DirectionStart, Flags: []string{StartFlagOverride}}},
		BootHistoryComplete: true,
		Verify:              VerifyResult{Result: VerifyInconclusive, Checked: 1, NoRaw: 1, Forwarded: 2, Paired: 1, Unpaired: 1, ChainOK: true},
		ChainHead:           db.MembraneChainHead{LastID: 77, Hash: strings.Repeat("c", 64), Count: 77},
	}
}

func TestEvidenceHasNoOriginals(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.seedEnroll(KindEmail, "joao.silva@acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IPv4Alias(netip.MustParseAddr("185.12.40.9"), seedProv); err != nil {
		t.Fatal(err)
	}
	in := evidenceFixture()
	in.Engine = e
	md, js := BuildEvidence(in)
	for name, out := range map[string]string{"markdown": md, "json": string(js)} {
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
			t.Errorf("%s evidence: leak check hits %v", name, hits)
		}
		for _, o := range verifyOriginals {
			if strings.Contains(strings.ToLower(out), strings.ToLower(o)) {
				t.Errorf("%s evidence contains an original (len %d)", name, len(o))
			}
		}
	}
	if !json.Valid(js) {
		t.Fatal("json evidence is not valid JSON")
	}
}

func TestEvidenceContent(t *testing.T) {
	e, _ := newTestEngine(t)
	in := evidenceFixture()
	in.Engine = e
	md, js := BuildEvidence(in)
	for _, want := range []string{
		"go test ./membrane/... -run Contract",
		"canonical request hash (pre-serialisation form that was leak-checked)",
		"request-hash",
		strings.Repeat("c", 64),            // chain head hash
		"base64/hex blobs, signed cookies", // §7.2 limits text
		"OVERRIDDEN",
		"leak_check",
		"INCONCLUSIVE",
		"Model-view excerpts are omitted by design",
		"dictionary as of the check",
		"still has hash = earlier head.hash",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	var doc EvidenceDoc
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.TaskID != "42" || doc.Requests.Total != 4 || doc.Requests.Blocked != 2 || doc.Requests.Forwarded != 2 {
		t.Fatalf("requests = %+v", doc.Requests)
	}
	if doc.CountsByKind["domain"] != 3 || doc.CountsByKind["ipv4"] != 2 || doc.Enrolled != 12 {
		t.Fatalf("counts = %v enrolled %d", doc.CountsByKind, doc.Enrolled)
	}
	if doc.Blocks.Reasons["leak_check"] != 1 || doc.Blocks.Reasons["seed_sync_failed"] != 1 ||
		doc.Blocks.Reasons["unresolved_alias"] != 1 || doc.Blocks.LeakKinds["password"] != 1 || doc.Blocks.LeakKinds["domain"] != 1 {
		t.Fatalf("blocks = %+v", doc.Blocks)
	}
	if doc.Flags["suspicious_name"] != 1 || doc.Flags["unresolved"] != 1 || doc.Flags["other"] != 1 {
		t.Fatalf("flags = %v", doc.Flags)
	}
	if doc.Proof.Level != "request-hash" || doc.Chain.Head.LastID != 77 || !doc.Override.InForce || len(doc.Override.Boots) != 1 {
		t.Fatalf("proof %+v chain %+v override %+v", doc.Proof, doc.Chain, doc.Override)
	}
	if !slices.Contains(doc.Profiles, "kimi") || len(doc.Profiles) != 2 {
		t.Fatalf("profiles = %v", doc.Profiles)
	}
	if doc.ContractTests != "go test ./membrane/... -run Contract" {
		t.Fatalf("contract tests = %q", doc.ContractTests)
	}

	// Every forwarded request has a raw record: raw-bytes proof.
	in.Verify = VerifyResult{Result: VerifyPass, Checked: 2, Forwarded: 2, Paired: 2, ChainOK: true}
	_, js = BuildEvidence(in)
	_ = json.Unmarshal(js, &doc)
	if doc.Proof.Level != "raw-bytes" {
		t.Fatalf("proof level = %q, want raw-bytes", doc.Proof.Level)
	}
	in.Verify = VerifyResult{Result: VerifyInconclusive, Checked: 2, Forwarded: 2, Paired: 1, Unpaired: 1, ChainOK: true}
	_, js = BuildEvidence(in)
	_ = json.Unmarshal(js, &doc)
	if doc.Proof.Level != "request-hash" {
		t.Fatalf("proof level with a missing raw record = %q", doc.Proof.Level)
	}
}

// The dry-run view derives the aliases a real run would mint, but persists
// nothing, leaves the live store and its generation untouched, and keeps
// its own cache.
func TestDryRunDoesNotEnroll(t *testing.T) {
	e, s := newTestEngine(t)
	p := s.p.(*fakePersistence)
	text := "Mail joao.silva@acmebank.pt about api.acmebank.pt, 185.12.40.9, 91.198.174.192 and user Mallory99 password=Zx9!kq77"
	beforeLen, beforeGen, beforeIns := s.Len(), s.generation(), p.inserts
	beforeBlocks := len(p.blocks)

	dry := e.WithDryRun()
	dout, drep, err := dry.ToModel(text, Provenance{CompanyIDs: []int64{1}, TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	if drep.Enrolled == 0 {
		t.Fatal("fixture: the dry run should mint new aliases")
	}
	if s.Len() != beforeLen || s.generation() != beforeGen || p.inserts != beforeIns || len(p.blocks) != beforeBlocks {
		t.Fatalf("dry run touched the live store: len %d->%d gen %d->%d inserts %d->%d blocks %d->%d",
			beforeLen, s.Len(), beforeGen, s.generation(), beforeIns, p.inserts, beforeBlocks, len(p.blocks))
	}
	if _, _, ok := s.AliasFor("91.198.174.192"); ok {
		t.Fatal("dry run enrolled into the live store")
	}
	if e.cache.len() != 0 {
		t.Fatal("dry run polluted the live engine cache")
	}
	// Spans locate the aliases in the dry output.
	spans := dry.AliasSpans(dout)
	if len(spans) == 0 {
		t.Fatal("no alias spans")
	}
	for _, sp := range spans {
		if _, _, ok := dry.s.OriginalFor(dout[sp.Start:sp.End]); !ok && sp.Kind != KindDomain && sp.Kind != KindIPv4 {
			t.Errorf("span %+v (%s) does not resolve", sp, sp.Kind)
		}
	}
	// The real run produces the same aliases.
	rout, _, err := e.ToModel(text, Provenance{CompanyIDs: []int64{1}, TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	if rout != dout {
		t.Fatalf("dry-run aliases differ from the real run:\n dry  %q\n real %q", dout, rout)
	}
}

func TestOpenReadOnlyStoreDoesNotWrite(t *testing.T) {
	s, p := newTestStore(t)
	if _, err := s.seedEnroll(KindDomain, "acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	ins := p.inserts
	ro, err := OpenReadOnlyStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Enroll(KindOrg, "Globex", seedProv); err != nil {
		t.Fatal(err)
	}
	if p.inserts != ins || len(p.entries) != 1 {
		t.Fatalf("read-only store wrote: inserts %d->%d", ins, p.inserts)
	}
	if _, _, ok := ro.AliasFor("acmebank.pt"); !ok {
		t.Fatal("read-only store did not load the mapping")
	}
}
