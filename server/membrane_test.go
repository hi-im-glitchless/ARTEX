package server

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

// membraneTestKeys pins the membrane keys for the server test database, so
// every test (and every run) opens the same encrypted table.
func membraneTestKeys(t *testing.T) {
	t.Helper()
	t.Setenv(membrane.EnvEncKey, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv(membrane.EnvHMACKey, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("h", 32))))
}

func newMembraneTestServer(t *testing.T) (*Server, *Manager) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if m.pg == nil {
		t.Skip("no postgres for this run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir()), m
}

func countOverrideEvents(t *testing.T, m *Manager) int {
	t.Helper()
	var n int
	if err := m.pg.QueryRow(`SELECT count(*) FROM membrane_events WHERE direction='override'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMembraneStartupEnabled(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, _ := newMembraneTestServer(t)
	st := s.membraneStatus()
	if !st.Enabled || st.Override || st.KeysSource != "env" || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
	if s.membraneEngine() == nil || s.membraneStore() == nil || s.membraneAuditor() == nil {
		t.Fatal("engine, store and auditor must be reachable")
	}
	// Remote providers built through the server's config paths are wrapped.
	cfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	s.attachMembrane(&cfg, "kimi")
	if cfg.Membrane == nil || cfg.MembraneAudit == nil || cfg.ProfileName != "kimi" {
		t.Fatalf("attachMembrane: %+v", cfg)
	}
	if _, err := cfg.NewProvider(); err != nil {
		t.Fatalf("remote provider with membrane: %v", err)
	}
}

func TestMembraneStartupOverride(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "off")
	membraneTestKeys(t)
	m0, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if m0.pg == nil {
		m0.Close()
		t.Skip("no postgres for this run")
	}
	before := countOverrideEvents(t, m0)
	m0.Close()

	s, m := newMembraneTestServer(t)
	if got := countOverrideEvents(t, m); got != before+1 {
		t.Fatalf("override events: before %d, after %d (want exactly one more)", before, got)
	}
	st := s.membraneStatus()
	if st.Enabled || !st.Override {
		t.Fatalf("status = %+v", st)
	}
	cfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	s.attachMembrane(&cfg, "kimi")
	if _, err := cfg.NewProvider(); err != nil {
		t.Fatalf("override must build remote providers: %v", err)
	}
}

func TestMembraneStartupFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	// Only one of the two env keys set: LoadKeys refuses, the store never opens.
	t.Setenv(membrane.EnvEncKey, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv(membrane.EnvHMACKey, "")
	s, _ := newMembraneTestServer(t)
	st := s.membraneStatus()
	if st.Enabled || st.Override || st.Error == "" {
		t.Fatalf("status = %+v", st)
	}
	cfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	s.attachMembrane(&cfg, "kimi")
	if _, err := cfg.NewProvider(); !errors.Is(err, agent.ErrMembraneNotInitialised) {
		t.Fatalf("remote provider must fail closed, err = %v", err)
	}
	// A local model still works.
	local := agent.ConfigFrom("anthropic", "m", "http://127.0.0.1:11434", "k", "")
	s.attachMembrane(&local, "local")
	if _, err := local.NewProvider(); err != nil {
		t.Fatalf("local provider: %v", err)
	}
}

func TestMembraneProfileConfigCarriesMembrane(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	pid, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "t-membrane-remote", Format: "anthropic", Model: "m",
		BaseURL: "https://api.kimi.com/coding/v1", APIKey: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec("DELETE FROM llm_profiles WHERE id=$1", pid) })
	cfg, ok := s.loadProfileConfig(pid)
	if !ok || cfg.Membrane == nil || cfg.MembraneAudit == nil || cfg.ProfileName != "t-membrane-remote" {
		t.Fatalf("loadProfileConfig: ok=%v cfg=%+v", ok, cfg)
	}
	if _, _, ok := s.providerForProfile(pid); !ok {
		t.Fatal("providerForProfile must build the wrapped remote provider")
	}
}

func TestMembraneDBAuditorRecords(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	// Audit rows are append-only: use a task id unique to this run.
	taskID := strconv.FormatInt(time.Now().UnixNano(), 10)
	ev := membrane.Event{
		TaskID: taskID, Session: "exp42-worker-i1", Role: "worker", Profile: "kimi", Direction: "request",
		Report:        membrane.Report{Counts: map[membrane.Kind]int{membrane.KindDomain: 2}, Enrolled: 1, Flags: []string{"suspicious_name"}},
		RequestSHA256: strings.Repeat("ab", 32),
	}
	if err := s.membraneAuditor().Record(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	evs, _, err := m.pg.ListMembraneEvents(taskID, 1, 5)
	if err != nil || len(evs) == 0 {
		t.Fatalf("list: %v %d", err, len(evs))
	}
	got := evs[0]
	if got.Counts["domain"] != 2 || got.Enrolled != 1 || len(got.Flags) != 1 || got.Role != "worker" ||
		got.Profile != "kimi" || got.RequestSHA256 != ev.RequestSHA256 || got.Session != ev.Session {
		t.Fatalf("stored event = %+v", got)
	}
}
