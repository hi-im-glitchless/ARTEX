package server

import (
	"context"
	"log"

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
}

// membraneState is built once in New, before any provider, and never changes
// afterwards, so it is read without a lock.
type membraneState struct {
	store      *membrane.Store
	engine     *membrane.Engine
	audit      membrane.Auditor
	override   bool
	keysSource membrane.KeysSource
	err        string
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
	encKey, hmacKey, src, err := membrane.LoadKeysSource(keyDir)
	if err != nil {
		st.err = "keys: " + err.Error()
		log.Printf("[membrane] not initialised — remote LLM providers will fail closed: %s", st.err)
		return
	}
	st.keysSource = src
	store, err := membrane.OpenStore(s.m.pg, encKey, hmacKey)
	if err != nil {
		st.err = "store: " + err.Error()
		log.Printf("[membrane] not initialised — remote LLM providers will fail closed: %s", st.err)
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
	return st
}
