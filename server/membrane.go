package server

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"sync/atomic"

	"github.com/Autumn-27/artex/agent"
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
}

// membraneState is built once in New, before any provider, and never changes
// afterwards (except seedErr), so it is read without a lock.
type membraneState struct {
	store      *membrane.Store
	engine     *membrane.Engine
	audit      membrane.Auditor
	override   bool
	keysSource membrane.KeysSource
	err        string
	// seedErr is written by membraneSyncAll after startup, hence atomic.
	seedErr atomic.Pointer[string]
}

// initMembrane opens the membrane store with keys from the environment or
// <keyDir>/membrane.keys (keyDir is where ARTEX keeps jwt.key, outside the
// browsable workspace), and builds the engine and the DB auditor.
//
// With ARTEX_MEMBRANE=off it opens nothing, appends one "override" audit
// event and logs a warning. When the store cannot be opened the server still
// starts, but the engine stays nil, so every remote provider construction
// fails closed with agent.ErrMembraneNotInitialised.
func (s *Server) initMembrane(keyDir string) {
	st := &s.mem
	if s.m.pg != nil {
		st.audit = membrane.NewDBAuditor(s.m.pg)
	}
	// Every boot appends a "start" event saying whether the override is in
	// force for this run (evidence bounds each run by the next start). A
	// membrane that then fails to initialise fails closed, so "override:false"
	// holds for it too.
	if st.audit != nil {
		flag := membrane.StartFlagMembraned
		if agent.MembraneOverride() {
			flag = membrane.StartFlagOverride
		}
		ev := membrane.Event{Direction: membrane.DirectionStart, Report: membrane.Report{Flags: []string{flag}}}
		if err := st.audit.Record(context.Background(), ev); err != nil {
			log.Printf("[membrane] start audit event failed: %v", err)
		}
	}
	if agent.MembraneOverride() {
		st.override = true
		log.Printf("[membrane] WARNING: %s=off — the identity membrane is DISABLED; remote LLM providers receive real data", agent.MembraneEnv)
		if st.audit == nil {
			log.Printf("[membrane] override not audited: no database")
			return
		}
		if err := st.audit.Record(context.Background(), membrane.Event{Direction: "override"}); err != nil {
			log.Printf("[membrane] override audit event failed: %v", err)
		}
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
		Enabled:    s.mem.engine != nil && s.mem.audit != nil,
		Override:   s.mem.override,
		KeysSource: string(s.mem.keysSource),
		Error:      s.mem.err,
	}
	if s.mem.store != nil {
		st.Entries = s.mem.store.Len()
	}
	if e := s.mem.seedErr.Load(); e != nil {
		st.SeedError = *e
	}
	return st
}
