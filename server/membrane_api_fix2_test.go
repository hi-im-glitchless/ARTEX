package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

type failingAuditor struct{ dir string } // fails events of dir ("" = all)

func (a failingAuditor) Record(_ context.Context, ev membrane.Event) error {
	if a.dir == "" || ev.Direction == a.dir {
		return errors.New("audit down")
	}
	return nil
}

// An override that cannot be audited does not take effect: the membrane
// stays uninitialised and remote providers fail closed.
func TestMembraneAPIUnauditedOverrideRefused(t *testing.T) {
	membraneTestKeys(t)
	t.Setenv("ARTEX_MEMBRANE", "off")
	orig := membraneAuditorFor
	t.Cleanup(func() { membraneAuditorFor = orig; agent.SetMembraneOverrideRefused(false) })
	remote := func() error {
		cfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
		_, err := cfg.NewProvider()
		return err
	}
	check := func(name string, s *Server) {
		t.Helper()
		st := s.membraneStatus()
		if st.Enabled || st.Override || !strings.Contains(st.Error, "refused") || agent.MembraneOverride() {
			t.Fatalf("%s: status %+v override %v", name, st, agent.MembraneOverride())
		}
		if err := remote(); !errors.Is(err, agent.ErrMembraneNotInitialised) {
			t.Fatalf("%s: remote provider err = %v, want fail closed", name, err)
		}
	}
	for _, dir := range []string{membrane.DirectionStart, "override"} {
		membraneAuditorFor = func(*db.DB) membrane.Auditor { return failingAuditor{dir: dir} }
		s, _ := newMembraneTestServer(t)
		check("failing "+dir+" event", s)
	}
	// No database: nothing can be audited.
	s := &Server{m: &Manager{}}
	s.initMembrane(t.TempDir())
	check("no database", s)

	// Auditable again: the override takes effect.
	membraneAuditorFor = orig
	s, _ = newMembraneTestServer(t)
	if st := s.membraneStatus(); !st.Override || !agent.MembraneOverride() {
		t.Fatalf("audited override: %+v", st)
	}
	if err := remote(); err != nil {
		t.Fatalf("audited override must build remote providers: %v", err)
	}
}

// Deleting a company drops its task links, but a live task's values must
// not be purged (they would leave in clear until the next re-seed).
func TestDestroyRefusedLiveTask(t *testing.T) {
	f := newSeedFixture(t)
	if _, err := f.s.SyncTask(context.Background(), f.id()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.pg.Companies().DeleteCompany(f.cid); err != nil {
		t.Fatal(err)
	}
	before := countMembraneEntries(t, f.m)
	w := membraneAPICall(t, f.s, "POST", fmt.Sprintf("/api/companies/%d/membrane/destroy", f.cid), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("destroy %d: %s", w.Code, w.Body)
	}
	var body struct {
		References map[string]int `json:"references"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.References["live_tasks"] < 1 || body.References["company"] != 0 {
		t.Fatalf("references = %v", body.References)
	}
	if countMembraneEntries(t, f.m) != before {
		t.Fatal("refused destroy purged entries")
	}
}
