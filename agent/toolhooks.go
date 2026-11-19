package agent

import (
	"context"
	"reflect"
	"strings"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// Tool hooks for agents that run tools without the task's worker guard
// (planner, main agent, goal decomposition). The server installs the
// identity membrane's tool check here (spec §9.2/§9.3); the planner and the
// main agent run it before the task's target-only Guard (chainHooks). nil
// leaves the session with the per-call hooks only.

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

// chainHooks runs first's hooks before second's: the membrane tool check
// must see a call before the task's target-only Guard (and its approval
// requests) does. A nil (or typed-nil) runner is skipped; nil when both are.
func chainHooks(first, second harness.HookRunner) harness.HookRunner {
	first, second = concreteHooks(first), concreteHooks(second)
	switch {
	case first == nil:
		return second
	case second == nil:
		return first
	}
	return hookChain{first, second}
}

// concreteHooks maps a typed-nil runner (e.g. a nil *hook.Registry in the
// interface) to a plain nil so the harness never calls through it.
func concreteHooks(h harness.HookRunner) harness.HookRunner {
	if h == nil {
		return nil
	}
	if v := reflect.ValueOf(h); v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	return h
}

// hookChain is two hook runners in order. PreToolUse stops at the first
// block; an input rewrite by an earlier runner is what the later one sees.
type hookChain [2]harness.HookRunner

func (c hookChain) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	var updated []byte
	for _, h := range c {
		block, msg, up := h.PreToolUse(ctx, name, input)
		if block {
			return true, msg, nil
		}
		if len(up) > 0 {
			updated, input = up, up
		}
	}
	return false, "", updated
}

func (c hookChain) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	for _, h := range c {
		h.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (c hookChain) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var (
		prevent bool
		errs    []string
		msgs    []string
	)
	for _, h := range c {
		p, e, m := h.Stop(ctx, messages)
		prevent = prevent || p
		errs = append(errs, e...)
		if m != "" {
			msgs = append(msgs, m)
		}
	}
	return prevent, errs, strings.Join(msgs, "\n")
}
