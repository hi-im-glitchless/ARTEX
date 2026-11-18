package server

import (
	"context"
	"iter"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/membrane"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

const seedTestGoal = "Assess the API at https://api.acmebank.pt/v2 and log in as joao.silva."

// seedFixture is a company "Acme Bank" (scope acmebank.pt, 185.12.40.0/24)
// and a task linked to it with a keyword scope and a credential.
type seedFixture struct {
	s      *Server
	m      *Manager
	cid    int64
	taskID int64
}

func newSeedFixture(t *testing.T) seedFixture {
	t.Helper()
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	if s.membraneStore() == nil {
		t.Fatalf("membrane not enabled: %+v", s.membraneStatus())
	}
	pg := m.pg
	var hadBlock bool
	if err := pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM membrane_ip_blocks WHERE real_prefix='185.12.40.0/24')`).Scan(&hadBlock); err != nil {
		t.Fatal(err)
	}
	cs := pg.Companies()
	if old, _ := cs.GetCompanyByName("Acme Bank"); old != nil {
		t.Fatalf("leftover company fixture %d from an earlier run", old.ID)
	}
	cid, _, err := cs.UpsertCompany("Acme Bank", "")
	if err != nil {
		t.Fatal(err)
	}
	f := seedFixture{s: s, m: m, cid: cid}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM membrane_entries WHERE $1::bigint = ANY(company_ids) OR $2::bigint = ANY(task_ids)`, f.cid, f.taskID)
		if !hadBlock {
			_, _ = pg.Exec(`DELETE FROM membrane_ip_blocks WHERE real_prefix='185.12.40.0/24'`)
		}
		if f.taskID > 0 {
			_ = pg.DeleteTask(f.taskID)
		}
		_ = cs.DeleteCompany(f.cid)
	})
	if _, _, invalid, errs := cs.AddScopeInputs(cid, []db.ScopeInput{
		{Kind: "domain", Value: "acmebank.pt"}, {Kind: "cidr", Value: "185.12.40.0/24"},
	}, "membrane seed test"); invalid > 0 {
		t.Fatalf("company scope: %v", errs)
	}
	tk, err := pg.CreateTaskWithOptions("membrane seed test", seedTestGoal, db.TaskCreateOptions{CompanyIDs: []int64{cid}})
	if err != nil {
		t.Fatal(err)
	}
	f.taskID = tk.ID
	if _, err := pg.Assets().AddAgentScope(tk.ID, "keyword", "AcmeOnline", "", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpsertTaskCredential(tk.ID, db.TaskCredentialInput{
		Domain: "acmebank.pt", Username: "joao.silva", Password: "hunter2", Source: "user",
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f seedFixture) id() string { return strconv.FormatInt(f.taskID, 10) }

func TestMembraneSyncTaskEnrollsEverything(t *testing.T) {
	f := newSeedFixture(t)
	companies, err := f.s.SyncTask(context.Background(), f.id())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(companies, []int64{f.cid}) {
		t.Fatalf("SyncTask companies = %v, want [%d]", companies, f.cid)
	}
	st := f.s.membraneStore()
	for _, v := range []string{"Acme Bank", "AcmeBank", "acme-bank", "acmebank", "acmebank.pt",
		"AcmeOnline", "joao.silva", "hunter2", "api.acmebank.pt"} {
		if _, _, ok := st.AliasFor(v); !ok {
			t.Errorf("no alias for a seeded value (len %d)", len(v))
		}
	}
	blocks, err := f.m.pg.ListMembraneBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(blocks, func(b db.MembraneBlock) bool { return b.RealPrefix == "185.12.40.0/24" }) {
		t.Error("scope CIDR has no alias block")
	}
	// The seeds carry company provenance; task-level seeds also the task.
	entries, err := f.m.pg.ListMembraneEntries()
	if err != nil {
		t.Fatal(err)
	}
	pwAlias, _, _ := st.AliasFor("hunter2")
	for _, e := range entries {
		if e.Alias == pwAlias {
			if !slices.Contains(e.CompanyIDs, f.cid) || !slices.Contains(e.TaskIDs, f.taskID) || e.Source != "seed" {
				t.Fatalf("credential provenance: companies %v tasks %v source %q", e.CompanyIDs, e.TaskIDs, e.Source)
			}
		}
	}

	e := f.s.membraneEngine()
	out, _, err := e.ToModel(seedTestGoal+" Acme Bank / AcmeOnline / hunter2 / 185.12.40.7", membrane.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if hits := e.LeakCheck([]byte(out)); len(hits) > 0 {
		t.Fatalf("leak check hits after sync: %v", hits)
	}
	for _, v := range []string{"acmebank", "acme bank", "acmeonline", "joao.silva", "hunter2", "185.12.40"} {
		if strings.Contains(strings.ToLower(out), v) {
			t.Fatalf("model view still carries an original (len %d)", len(v))
		}
	}
}

func TestMembraneSyncAttachSetsSyncer(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, _ := newMembraneTestServer(t)
	cfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	s.attachMembrane(&cfg, "kimi")
	if cfg.MembraneSyncer != membrane.Syncer(s) {
		t.Fatalf("attachMembrane must set the server as syncer: %v", cfg.MembraneSyncer)
	}
}

func TestMembraneSyncUnknownTask(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, _ := newMembraneTestServer(t)
	if c, err := s.SyncTask(context.Background(), "999999999999"); err != nil || len(c) != 0 {
		t.Fatalf("missing task: companies %v err %v", c, err)
	}
	if _, err := s.SyncTask(context.Background(), "conv-3"); err != nil {
		t.Fatalf("non-numeric id: %v", err)
	}
}

// seedTestProvider answers every request with an empty assistant message.
type seedTestProvider struct{}

func (seedTestProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant}, "", llm.Usage{}, nil
}

func (seedTestProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

// R16: a value auto-enrolled from a task's tool output carries the task's
// company id, and the company purge removes it once the task is gone.
func TestMembraneSyncCompanyProvenancePurge(t *testing.T) {
	f := newSeedFixture(t)
	secret := "Zr4q-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	w := membrane.Wrap(seedTestProvider{}, f.s.membraneEngine(), f.s.membraneAuditor(), "test", membrane.WithSyncer(f.s))
	ctx := llmrec.WithTaskID(transcript.WithSessionID(context.Background(), "exp1-worker-i1"), f.id())
	req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{
		llm.ToolResultText("t1", "config dump: db_password="+secret, false)}}}, MaxTokens: 10}
	if _, _, _, err := w.Complete(ctx, req); err != nil {
		t.Fatal(err)
	}
	alias, _, ok := f.s.membraneStore().AliasFor(secret)
	if !ok {
		t.Fatal("tool-output secret was not auto-enrolled")
	}
	find := func() *db.MembraneEntry {
		entries, err := f.m.pg.ListMembraneEntries()
		if err != nil {
			t.Fatal(err)
		}
		for i := range entries {
			if entries[i].Alias == alias {
				return &entries[i]
			}
		}
		return nil
	}
	e := find()
	if e == nil {
		t.Fatal("auto-enrolled entry not persisted")
	}
	if !slices.Equal(e.CompanyIDs, []int64{f.cid}) || !slices.Contains(e.TaskIDs, f.taskID) || e.Source != "auto" {
		t.Fatalf("auto-enrolled provenance: companies %v tasks %v source %q", e.CompanyIDs, e.TaskIDs, e.Source)
	}

	// While the task is alive (linked through task_scope) the purge guard
	// counts it.
	refs, err := f.m.pg.MembraneCompanyReferences(f.cid)
	if err != nil {
		t.Fatal(err)
	}
	if refs["tasks"] != 1 {
		t.Fatalf("guard must count the task linked through task_scope: %v", refs)
	}
	if err := f.m.pg.DeleteTask(f.taskID); err != nil {
		t.Fatal(err)
	}
	refs, err = f.m.pg.MembraneCompanyReferences(f.cid)
	if err != nil {
		t.Fatal(err)
	}
	if refs["tasks"] != 0 {
		t.Fatalf("deleted task still counted: %v", refs)
	}
	if _, err := f.m.pg.PurgeMembraneCompany(f.cid); err != nil {
		t.Fatal(err)
	}
	if find() != nil {
		t.Fatal("company purge left the auto-enrolled entry")
	}
}
