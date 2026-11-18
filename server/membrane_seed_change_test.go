package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func seedChangeServer(t *testing.T) (*Server, *Manager) {
	t.Helper()
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	if s.membraneStore() == nil {
		t.Fatalf("membrane not enabled: %+v", s.membraneStatus())
	}
	return s, m
}

func cleanupMembraneFor(t *testing.T, m *Manager, cid, taskID int64) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM membrane_entries WHERE $1::bigint = ANY(company_ids) OR $2::bigint = ANY(task_ids)`, cid, taskID)
	})
}

func jsonReq(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(method, path, bytes.NewReader(b))
}

// Final review I3: a company created or given scope after startup is
// seeded at once (spec §7.1), not only at the next startup.
func TestCompanyCreateAndScopeAddSeedMembrane(t *testing.T) {
	s, m := seedChangeServer(t)
	stamp := time.Now().UnixNano() % 1_000_000_000
	name := fmt.Sprintf("Globex Seedtest %d", stamp)
	dom := fmt.Sprintf("globexseed%d.pt", stamp)
	epoch := s.SyncEpoch()
	rec := httptest.NewRecorder()
	s.createCompany(rec, jsonReq(t, http.MethodPost, "/api/companies", map[string]any{
		"name": name, "scope": []map[string]string{{"kind": "domain", "value": dom}},
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.Companies().DeleteCompany(out.ID) })
	cleanupMembraneFor(t, m, out.ID, -1)
	st := s.membraneStore()
	for _, v := range []string{name, dom} {
		if _, _, ok := st.AliasFor(v); !ok {
			t.Errorf("company value not seeded on create (len %d)", len(v))
		}
	}
	if s.SyncEpoch() == epoch {
		t.Error("seed epoch unchanged after company create")
	}

	dom2 := fmt.Sprintf("globexextra%d.pt", stamp)
	req := jsonReq(t, http.MethodPost, "/api/companies/x/scope", map[string]any{
		"scope": []map[string]string{{"kind": "domain", "value": dom2}},
	})
	req.SetPathValue("id", fmt.Sprint(out.ID))
	rec = httptest.NewRecorder()
	s.addCompanyScope(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scope add status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, _, ok := st.AliasFor(dom2); !ok {
		t.Error("company scope domain not seeded on scope add")
	}
}

// Task scope and credential changes seed the task at once and expire the
// providers' throttled syncs.
func TestTaskScopeAndCredentialAddSeedMembrane(t *testing.T) {
	s, m := seedChangeServer(t)
	task, err := m.CreateTaskWithOptions("membrane seed change test", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	tid := mustTaskID(t, task.ID)
	cleanupMembraneFor(t, m, -1, tid)
	stamp := time.Now().UnixNano() % 1_000_000_000
	kw := fmt.Sprintf("Zorblax%d", stamp)
	epoch := s.SyncEpoch()
	req := jsonReq(t, http.MethodPost, "/api/tasks/x/scope", map[string]string{"kind": "keyword", "value": kw})
	req.SetPathValue("id", task.ID)
	rec := httptest.NewRecorder()
	s.taskScopeAdd(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("task scope add status=%d body=%s", rec.Code, rec.Body.String())
	}
	st := s.membraneStore()
	if _, _, ok := st.AliasFor(kw); !ok {
		t.Error("task scope keyword not seeded on add")
	}
	if s.SyncEpoch() == epoch {
		t.Error("seed epoch unchanged after task scope add")
	}
	pw := fmt.Sprintf("Qv7!seed%d", stamp)
	req = jsonReq(t, http.MethodPost, "/api/tasks/x/credentials", map[string]string{"domain": "seedcreds.pt", "username": "svc_seed", "password": pw})
	req.SetPathValue("id", task.ID)
	rec = httptest.NewRecorder()
	s.addTaskCredential(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("credential add status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, _, ok := st.AliasFor(pw); !ok {
		t.Error("task credential not seeded on add")
	}
}

// SyncGlobal (task-less requests) seeds companies the server has not
// seeded yet, e.g. created by another path.
func TestSyncGlobalSeedsCompanies(t *testing.T) {
	s, m := seedChangeServer(t)
	stamp := time.Now().UnixNano() % 1_000_000_000
	name := fmt.Sprintf("Initech Globaltest %d", stamp)
	cid, _, err := m.pg.Companies().UpsertCompany(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.Companies().DeleteCompany(cid) })
	cleanupMembraneFor(t, m, cid, -1)
	if _, _, ok := s.membraneStore().AliasFor(name); ok {
		t.Fatal("company seeded before SyncGlobal")
	}
	if err := s.SyncGlobal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.membraneStore().AliasFor(name); !ok {
		t.Fatal("SyncGlobal did not seed the company")
	}
}
