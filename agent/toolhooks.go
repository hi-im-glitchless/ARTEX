package agent

import (
	"context"

	"github.com/Autumn-27/norma/harness"
)

// Tool hooks for agents that run tools without the task guard (planner,
// main agent, goal decomposition). The server installs the identity
// membrane's tool check here (spec §9.2/§9.3); nil leaves the session
// without hooks, as before.

type toolHooksKey struct{}

// WithToolHooks attaches hooks to ctx for one-shot runs that have no agent
// struct to configure (DecomposeGoals). A nil h leaves ctx unchanged.
func WithToolHooks(ctx context.Context, h harness.HookRunner) context.Context {
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, toolHooksKey{}, h)
}

func toolHooksFrom(ctx context.Context) harness.HookRunner {
	h, _ := ctx.Value(toolHooksKey{}).(harness.HookRunner)
	return h
}

// SetToolHooks installs PreToolUse/PostToolUse hooks on every planner run.
// nil = none.
func (p *Planner) SetToolHooks(h harness.HookRunner) { p.hooks = h }

// SetToolHooks installs PreToolUse/PostToolUse hooks on every main-agent
// run. nil = none.
func (m *MainAgent) SetToolHooks(h harness.HookRunner) { m.hooks = h }
