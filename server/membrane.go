package server

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

// MembraneStatus is the identity membrane's state for the UI (spec §9.4).
// Error carries why a required membrane is not initialised; it never holds
// originals (store and key errors are kind/id-only by construction).
type MembraneStatus struct {
	Enabled    bool   `json:"enabled"`
	Override   bool   `json:"override"`
	Entries    int    `json:"entries"`
	KeysSource string `json:"keys_source"`
	Error      string `json:"error,omitempty"`
	// SeedError is the last startup seed sync failure (non-fatal: each task
	// syncs again before its requests). Step names and ids only.
	SeedError string `json:"seed_error,omitempty"`
	// KeysWarning is set when this boot generated the membrane keys: they
	// exist only in the key file and must be backed up or pinned in env.
	KeysWarning string `json:"keys_warning,omitempty"`
}

// membraneState is built once in New, before any provider, and never changes
// afterwards (except seedErr), so it is read without a lock.
type membraneState struct {
	store      *membrane.Store
	engine     *membrane.Engine
	audit      membrane.Auditor
	override   bool
	keysSource membrane.KeysSource
	// keysWarning: see MembraneStatus.KeysWarning.
	keysWarning string
	err         string
	// seedErr is written by membraneSyncAll after startup, hence atomic.
	seedErr atomic.Pointer[string]
	// seedEpoch changes whenever a seed source changes (company, company
	// scope, task scope, task credentials): it expires the providers'
	// throttled syncs (membrane.SyncEpocher).
	seedEpoch atomic.Uint64
}

// initMembrane opens the membrane store with keys from the environment or
// <keyDir>/membrane.keys (keyDir is where ARTEX keeps jwt.key, outside the
// browsable workspace), and builds the engine and the DB auditor.
//
// With ARTEX_MEMBRANE=off it opens nothing, appends one "override" audit
// event (after the "start" event) and logs a warning; if either event
// cannot be written the override is refused and remote providers fail
// closed. When the store cannot be opened the server still
// starts, but the engine stays nil, so every remote provider construction
// fails closed with agent.ErrMembraneNotInitialised.
func (s *Server) initMembrane(keyDir string) {
	st := &s.mem
	if s.m.pg != nil {
		st.audit = membraneAuditorFor(s.m.pg)
	}
	agent.SetMembraneOverrideRefused(false)
	override := agent.MembraneOverrideRequested()
	// Every boot appends a "start" event saying whether the override is in
	// force for this run (evidence bounds each run by the next start). A
	// membrane that then fails to initialise fails closed, so "override:false"
	// holds for it too. A failed write is only logged for a membraned boot.
	var startErr error
	if st.audit != nil {
		flag := membrane.StartFlagMembraned
		if override {
			flag = membrane.StartFlagOverride
		}
		ev := membrane.Event{Direction: membrane.DirectionStart, Report: membrane.Report{Flags: []string{flag}}}
		if startErr = st.audit.Record(context.Background(), ev); startErr != nil {
			log.Printf("[membrane] start audit event failed: %v", startErr)
		}
	}
	if override {
		// An override that cannot be audited does not take effect: the
		// evidence must be able to show every unmembraned run. The engine
		// stays nil, so remote providers fail closed.
		refuse := func(why string) {
			agent.SetMembraneOverrideRefused(true)
			st.err = agent.MembraneEnv + "=off refused: the override could not be audited (" + why +
				"); the membrane is not initialised and remote LLM providers fail closed"
			log.Printf("[membrane] %s", st.err)
		}
		switch {
		case st.audit == nil:
			refuse("no database")
			return
		case startErr != nil:
			refuse("start event write failed")
			return
		}
		if err := st.audit.Record(context.Background(), membrane.Event{Direction: "override"}); err != nil {
			log.Printf("[membrane] override audit event failed: %v", err)
			refuse("override event write failed")
			return
		}
		st.override = true
		log.Printf("[membrane] WARNING: %s=off — the identity membrane is DISABLED; remote LLM providers receive real data", agent.MembraneEnv)
		return
	}
	if s.m.pg == nil {
		st.err = "no database"
		log.Printf("[membrane] not initialised (no database) — remote LLM providers will fail closed")
		return
	}
	fail := func(reason string) {
		st.err = reason
		log.Printf("[membrane] not initialised — remote LLM providers will fail closed: %s", reason)
	}
	// Generating fresh keys over rows encrypted with other keys would leave
	// the membrane permanently unable to open (for example a Docker container
	// recreated without its key file). Refuse, and say what to restore.
	if !membrane.KeysConfigured(keyDir) && inContainer() && !explicitKeyDir() {
		// A container's install directory is not a volume: a generated key
		// file disappears when the container is recreated, and with it the
		// ability to read the mapping table. Generate only into an explicit
		// key directory (ARTEX_JWT_KEY_DIR, which the shipped compose file
		// mounts as ./keys, next to jwt.key and secret.key).
		fail("running in a container without " + membrane.EnvEncKey + "/" + membrane.EnvHMACKey +
			" or ARTEX_JWT_KEY_DIR: refusing to generate membrane keys that would be lost when the container is recreated — set both in .env " +
			"(each: openssl rand -base64 32), or mount a key directory and set ARTEX_JWT_KEY_DIR, and restart")
		return
	}
	if !membrane.KeysConfigured(keyDir) {
		var has bool
		if err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM membrane_entries)`).Scan(&has); err != nil {
			fail("cannot check the mapping table: " + err.Error())
			return
		}
		if has {
			fail("membrane keys missing but the mapping table has entries encrypted with other keys — restore " +
				membrane.EnvEncKey + "/" + membrane.EnvHMACKey + " or " + filepath.Join(keyDir, membrane.KeysFileName))
			return
		}
	}
	encKey, hmacKey, src, err := membrane.LoadKeysSource(keyDir)
	if err != nil {
		fail("keys: " + err.Error())
		return
	}
	st.keysSource = src
	if st.keysWarning = membraneKeysWarning(src, keyDir); st.keysWarning != "" {
		log.Printf("[membrane] WARNING: %s", st.keysWarning)
	}
	store, err := membrane.OpenStore(s.m.pg, encKey, hmacKey)
	if errors.Is(err, membrane.ErrKeyMismatch) {
		fail("membrane keys do not match the stored mapping — restore the keys the table was written with (" +
			membrane.EnvEncKey + "/" + membrane.EnvHMACKey + " or " + membrane.KeysFileName + "): " + err.Error())
		return
	}
	if err != nil {
		fail("store: " + err.Error())
		return
	}
	st.store = store
	st.engine = membrane.NewEngine(store, nil)
	log.Printf("[membrane] enabled: %d entries, keys from %s", store.Len(), src)
}

// explicitKeyDir reports whether the key directory was set explicitly
// (ARTEX_JWT_KEY_DIR). Inside a container that is the persistent key volume
// the compose file mounts; the install directory is not.
func explicitKeyDir() bool { return strings.TrimSpace(os.Getenv("ARTEX_JWT_KEY_DIR")) != "" }

// inContainer reports whether ARTEX runs in a Docker or Podman container
// (test seam).
var inContainer = func() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// membraneKeysWarning is the operator warning for keys generated by this
// boot, or "".
func membraneKeysWarning(src membrane.KeysSource, keyDir string) string {
	if src != membrane.KeysGenerated {
		return ""
	}
	return "Membrane keys were generated in " + filepath.Join(keyDir, membrane.KeysFileName) +
		" — back them up or set " + membrane.EnvEncKey + "/" + membrane.EnvHMACKey +
		": without them the alias mapping cannot be read and remote LLM calls fail closed"
}

// membraneAuditorFor builds the server's membrane auditor (test seam).
var membraneAuditorFor = func(pg *db.DB) membrane.Auditor { return membrane.NewDBAuditor(pg) }

// attachMembrane gives cfg the server's membrane engine and auditor and the
// profile name recorded in audit events. Every config handed to
// agent.Config.NewProvider goes through here. Without an engine it leaves
// them nil, so a remote provider fails closed.
func (s *Server) attachMembrane(cfg *agent.Config, profile string) {
	cfg.ProfileName = profile
	if s.mem.engine != nil && s.mem.audit != nil {
		cfg.Membrane, cfg.MembraneAudit = s.mem.engine, s.mem.audit
		cfg.MembraneSyncer = s
	}
}

func (s *Server) membraneEngine() *membrane.Engine  { return s.mem.engine }
func (s *Server) membraneStore() *membrane.Store    { return s.mem.store }
func (s *Server) membraneAuditor() membrane.Auditor { return s.mem.audit }

// membraneStatus reports the membrane's state for the UI and logs.
func (s *Server) membraneStatus() MembraneStatus {
	st := MembraneStatus{
		Enabled:     s.mem.engine != nil && s.mem.audit != nil,
		Override:    s.mem.override,
		KeysSource:  string(s.mem.keysSource),
		Error:       s.mem.err,
		KeysWarning: s.mem.keysWarning,
	}
	if s.mem.store != nil {
		st.Entries = s.mem.store.Len()
	}
	if e := s.mem.seedErr.Load(); e != nil {
		st.SeedError = *e
	}
	return st
}
