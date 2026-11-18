package server

import (
	"context"
	"log"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/artex/membrane"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// membraneToolCheck returns the identity membrane's tool check for one agent
// (spec §9.2/§9.3), or nil when the membrane is not active (override, or not
// initialised: then no remote provider runs either).
//
// Ruling R19 (amended in Task 10 fix round 1): both rules, unresolved alias
// and web_search originals, apply only when membraned reports the agent's
// provider is membraned; a local model never sees aliases, so every block
// there would be a false positive. membraned is evaluated per tool call (the
// task's profile can change at runtime); nil means always.
//
// A block appends a "tool_block" membrane audit event carrying the rule only
// (no values). An audit failure is logged: the call is blocked anyway.
func (s *Server) membraneToolCheck(taskID, role string, membraned func() bool) guard.MembraneCheck {
	e := s.membraneEngine()
	if e == nil {
		return nil
	}
	audit := s.membraneAuditor()
	return func(tool string, input []byte) (bool, string) {
		v := e.CheckTool(tool, input, membraned == nil || membraned())
		if !v.Block {
			return false, ""
		}
		if audit != nil {
			ev := membrane.Event{TaskID: taskID, Role: role, Direction: "tool_block",
				Blocked: true, BlockReason: v.Rule, Report: membrane.Report{Flags: []string{v.Rule}}}
			if err := audit.Record(context.Background(), ev); err != nil {
				log.Printf("[membrane] tool_block audit event failed (task %q, %s): %v", taskID, v.Rule, err)
			}
		}
		return true, v.Reason
	}
}

// membraneToolHooks wraps membraneToolCheck in a guard of its own (no
// intercept rules) for agents that run tools without the task guard: the
// planner, the main agent and goal decomposition. nil when the membrane is
// not active.
func (s *Server) membraneToolHooks(taskID, role string, membraned func() bool) harness.HookRunner {
	check := s.membraneToolCheck(taskID, role, membraned)
	if check == nil {
		return nil
	}
	g := guard.New()
	g.SetMembraneCheck(check)
	return g.Hooks()
}

// providerMembraned reports whether requests through prov leave through the
// membrane decorator. A failover pool may route to any pooled profile, so it
// counts as membraned (the web_search rule then applies; fail safe).
func providerMembraned(prov llm.Provider, cfg agent.Config) bool {
	if _, ok := prov.(*llmpool.Pool); ok {
		return true
	}
	return agent.MembraneRequired(cfg.BaseURL)
}

// membraned reports whether this task role may currently run on a membraned
// provider, mirroring currentFor's precedence (binding → task chain →
// global). On a chain any membraned profile counts, since per-intent
// rotation may pin any of them. An unresolvable task = true (fail safe).
func (r *taskLLMRuntime) membraned() bool {
	if prov, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return providerMembraned(prov, cfg)
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil || r.s.m == nil || r.s.m.pg == nil {
		return true
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil || pt == nil {
		return true
	}
	if len(pt.LLMProfileIDs) > 0 {
		for _, id := range pt.LLMProfileIDs {
			// A profile that does not build sends nothing: skip it.
			if prov, cfg, ok := r.s.providerForProfile(id); ok && providerMembraned(prov, cfg) {
				return true
			}
		}
		return false
	}
	prov, cfg, ok := r.s.globalProvider()
	if !ok {
		return true
	}
	return providerMembraned(prov, cfg)
}
