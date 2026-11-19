package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
	"github.com/Autumn-27/norma/llm"
)

func TestMembraneRequiredHosts(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	cases := []struct {
		url  string
		want bool
	}{
		{"https://api.kimi.com/coding/v1", true},
		{"http://127.0.0.1:11434/v1", false},
		{"http://10.0.0.5:8000", false},
		{"http://localhost:1234", false},
		{"http://[fd00::1]:8000", false},
		{"http://example.local", true},
		// Further cases: provider default endpoint, other private ranges,
		// lookalikes that must not be treated as local.
		{"", true},
		{"http://172.16.3.4", false},
		{"http://192.168.1.10:8080/v1", false},
		{"http://[::1]:8000", false},
		{"http://LOCALHOST:1234", false},
		{"http://localhost.attacker.com", true},
		{"http://127.0.0.1.nip.io", true},
		{"http://172.32.0.1", true},
		{"http://100.64.0.1", true},
		{"http://169.254.169.254", true},
		{"http://0.0.0.0:8000", true},
		{"127.0.0.1:11434", false}, // scheme-less base URL
		{"http://[::ffff:10.0.0.1]:80", false},
	}
	for _, c := range cases {
		if got := MembraneRequired(c.url); got != c.want {
			t.Errorf("MembraneRequired(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestMembraneRequiredOverride(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "off")
	if MembraneRequired("https://api.kimi.com/coding/v1") {
		t.Fatal("ARTEX_MEMBRANE=off must disable the requirement")
	}
	t.Setenv("ARTEX_MEMBRANE", "on")
	if !MembraneRequired("https://api.kimi.com/coding/v1") {
		t.Fatal("only the exact value off is an override")
	}
}

// The profile badge reads the host rule alone: the override must not turn
// a remote profile into "trusted local".
func TestMembraneRequiredByHostIgnoresOverride(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "off")
	if !MembraneRequiredByHost("https://api.kimi.com/coding/v1") {
		t.Fatal("the host rule must not apply the override")
	}
	if MembraneRequiredByHost("http://127.0.0.1:11434/v1") {
		t.Fatal("loopback is trusted local")
	}
	if !MembraneRequiredByHost("http://gw.ai.layer8.int/v1") {
		t.Fatal("hostnames other than localhost are remote")
	}
}

func TestNewProviderFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	c := ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	if _, err := c.NewProvider(); err == nil || err.Error() != "membrane required but not initialised" {
		t.Fatalf("remote provider without membrane: err = %v", err)
	}
	if _, err := c.NewProvider(); !errors.Is(err, ErrMembraneNotInitialised) {
		t.Fatalf("error must be ErrMembraneNotInitialised, got %v", err)
	}
	// An engine without an auditor is not initialised either.
	c.Membrane, _ = newTestEngine(t)
	if _, err := c.NewProvider(); !errors.Is(err, ErrMembraneNotInitialised) {
		t.Fatalf("engine without auditor: err = %v", err)
	}
	// TestConnection goes through NewProvider and fails the same way.
	if _, _, err := TestConnection(context.Background(), ConfigFrom("anthropic", "m", "https://api.kimi.com", "k", "")); !errors.Is(err, ErrMembraneNotInitialised) {
		t.Fatalf("TestConnection: err = %v", err)
	}
	// A local model needs no membrane.
	local := ConfigFrom("anthropic", "m", "http://127.0.0.1:11434", "k", "")
	if _, err := local.NewProvider(); err != nil {
		t.Fatalf("local provider: %v", err)
	}
	// The override builds remote providers unwrapped.
	t.Setenv("ARTEX_MEMBRANE", "off")
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("override: %v", err)
	}
}

func TestNewProviderWrapsRemote(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	prev := membraneRequiredFn
	membraneRequiredFn = func(string) bool { return true }
	t.Cleanup(func() { membraneRequiredFn = prev })

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(srv.Close)

	e, st := newTestEngine(t)
	aud := &recAuditor{}
	c := ConfigFrom("anthropic", "m", srv.URL, "k", "")
	c.Membrane, c.MembraneAudit, c.ProfileName = e, aud, "kimi-prof"
	prov, err := c.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = prov.Complete(context.Background(), llm.CompletionRequest{
		MaxTokens: 16,
		Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{{
			Type: llm.BlockText, Text: "scan vpn.acmebank.com, login with password=Hunter2Secret9",
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("want 1 request, got %d", len(bodies))
	}
	body := bodies[0]
	if strings.Contains(body, "acmebank") || strings.Contains(body, "Hunter2Secret9") {
		t.Fatalf("original reached the provider: %s", body)
	}
	alias, _, ok := st.AliasFor("acmebank.com")
	if !ok || !strings.Contains(body, "vpn."+alias) {
		t.Fatalf("request body lacks the domain alias %q: %s", alias, body)
	}
	if len(aud.events) != 1 || aud.events[0].Profile != "kimi-prof" || aud.events[0].Direction != "request" || aud.events[0].RequestSHA256 == "" {
		t.Fatalf("audit events: %+v", aud.events)
	}
}

type recAuditor struct {
	mu     sync.Mutex
	events []membrane.Event
}

func (a *recAuditor) Record(_ context.Context, ev membrane.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func newTestEngine(t *testing.T) (*membrane.Engine, *membrane.Store) {
	t.Helper()
	k1 := []byte(strings.Repeat("a", 32))
	k2 := []byte(strings.Repeat("b", 32))
	s, err := membrane.OpenStore(&memPersist{}, k1, k2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollRoot("acmebank.com", membrane.Provenance{Source: "seed"}); err != nil {
		t.Fatal(err)
	}
	return membrane.NewEngine(s, nil), s
}

// memPersist is a minimal in-memory membrane.Persistence (no IP blocks).
type memPersist struct {
	mu      sync.Mutex
	entries []db.MembraneEntry
}

func (f *memPersist) InsertMembraneEntry(e *db.MembraneEntry) (db.MembraneEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.entries {
		if x.Kind == e.Kind && x.OriginalHMAC == e.OriginalHMAC {
			return x, nil
		}
		if x.Alias == e.Alias {
			return db.MembraneEntry{}, errors.New("duplicate alias")
		}
	}
	n := *e
	n.ID = int64(len(f.entries) + 1)
	f.entries = append(f.entries, n)
	return n, nil
}

func (f *memPersist) ListMembraneEntries() ([]db.MembraneEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]db.MembraneEntry(nil), f.entries...), nil
}

func (f *memPersist) UpdateMembraneEntryAlias(id int64, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id {
			f.entries[i].Alias = alias
			return nil
		}
	}
	return errors.New("no such entry")
}

func (f *memPersist) AllocateMembraneBlock(string, int) (string, error) {
	return "", errors.New("no blocks in this test")
}

func (f *memPersist) ListMembraneBlocks() ([]db.MembraneBlock, error) { return nil, nil }

// A provider that skips the membrane because its base URL is a local model
// must not follow a redirect to a remote host: the 307/308 would carry the
// unmembraned body there. Redirects to another local host still work.
func TestNewProviderLocalRefusesRemoteRedirect(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	okBody := `{"id":"m","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
	var finalHits int
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okBody))
	}))
	t.Cleanup(final.Close)
	target := "http://remote-llm.invalid"
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)

	req := llm.CompletionRequest{MaxTokens: 16, Messages: []llm.Message{{Role: llm.RoleUser,
		Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "secret prompt"}}}}}
	c := ConfigFrom("anthropic", "m", redir.URL, "k", "")
	c.Retry.ConnectAttempts = -1
	prov, err := c.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := prov.Complete(context.Background(), req); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect to a remote host must be refused, err = %v", err)
	}

	target = final.URL // local → local is fine
	if _, _, _, err := prov.Complete(context.Background(), req); err != nil || finalHits != 1 {
		t.Fatalf("local redirect: err=%v hits=%d", err, finalHits)
	}
}
