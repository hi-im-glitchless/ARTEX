package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/membrane"
)

// Final review I4: inside a container, with no env keys and no key file,
// ARTEX refuses to generate keys (they would be lost when the container is
// recreated) and says which env vars to set.
func TestMembraneRefusesGeneratedKeysInContainer(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if m.pg == nil {
		t.Skip("no postgres for this run")
	}
	old := inContainer
	inContainer = func() bool { return true }
	t.Cleanup(func() { inContainer = old })
	t.Setenv(membrane.EnvEncKey, "")
	t.Setenv(membrane.EnvHMACKey, "")
	t.Setenv("ARTEX_JWT_KEY_DIR", "")
	keyDir := t.TempDir()
	s := &Server{m: m}
	s.initMembrane(keyDir)
	got := s.membraneStatus()
	if got.Enabled || !strings.Contains(got.Error, membrane.EnvEncKey) || !strings.Contains(got.Error, "container") {
		t.Fatalf("status = %+v, want refused with env var instructions", got)
	}
	if _, err := os.Stat(filepath.Join(keyDir, membrane.KeysFileName)); !os.IsNotExist(err) {
		t.Fatalf("a key file was generated in a container: %v", err)
	}
}

// Port: the shipped compose file mounts ./keys at ARTEX_JWT_KEY_DIR, a
// persistent volume. With that explicit key directory the container rule
// does not refuse (other rules, such as existing entries, still apply).
func TestMembraneContainerWithExplicitKeyDirNotRefused(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if m.pg == nil {
		t.Skip("no postgres for this run")
	}
	old := inContainer
	inContainer = func() bool { return true }
	t.Cleanup(func() { inContainer = old })
	t.Setenv(membrane.EnvEncKey, "")
	t.Setenv(membrane.EnvHMACKey, "")
	keyDir := t.TempDir()
	t.Setenv("ARTEX_JWT_KEY_DIR", keyDir)
	s := &Server{m: m}
	s.initMembrane(keyDir)
	if got := s.membraneStatus(); strings.Contains(got.Error, "container") {
		t.Fatalf("status = %+v, want no container refusal with an explicit key directory", got)
	}
}

// Generated keys are announced loudly: the status carries a warning the UI
// banner shows, naming where the keys are and how to pin them.
func TestMembraneGeneratedKeysWarning(t *testing.T) {
	w := membraneKeysWarning(membrane.KeysGenerated, "/opt/artex")
	for _, want := range []string{"/opt/artex", "back them up", membrane.EnvEncKey, membrane.EnvHMACKey} {
		if !strings.Contains(w, want) {
			t.Fatalf("warning %q lacks %q", w, want)
		}
	}
	for _, src := range []membrane.KeysSource{membrane.KeysEnv, membrane.KeysFile, ""} {
		if w := membraneKeysWarning(src, "/opt/artex"); w != "" {
			t.Fatalf("warning for %q: %q", src, w)
		}
	}
	s := &Server{}
	s.mem.keysWarning = w
	if got := s.membraneStatus(); got.KeysWarning == "" {
		t.Fatal("status does not expose the keys warning")
	}
}
