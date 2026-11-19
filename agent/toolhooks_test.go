package agent

import (
	"context"
	"testing"

	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
)

type recHooks struct {
	name  string
	block bool
	calls *[]string
}

func (r recHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	*r.calls = append(*r.calls, r.name)
	if r.block {
		return true, r.name + " blocked", nil
	}
	return false, "", nil
}
func (r recHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (r recHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

// Port onto upstream main: the planner and the main agent now get the task's
// target-only Guard per call; the membrane tool check must still run first,
// and its block must keep the call from reaching the target gate.
func TestChainHooksMembraneFirst(t *testing.T) {
	var calls []string
	membrane := recHooks{name: "membrane", block: true, calls: &calls}
	target := recHooks{name: "target", calls: &calls}
	block, msg, _ := chainHooks(membrane, target).PreToolUse(context.Background(), "Bash", []byte(`{}`))
	if !block || msg != "membrane blocked" || len(calls) != 1 || calls[0] != "membrane" {
		t.Fatalf("block=%v msg=%q calls=%v, want the membrane to block before the target gate", block, msg, calls)
	}
	calls = nil
	membrane.block = false
	if block, _, _ := chainHooks(membrane, target).PreToolUse(context.Background(), "Bash", []byte(`{}`)); block ||
		len(calls) != 2 || calls[0] != "membrane" || calls[1] != "target" {
		t.Fatalf("calls=%v, want membrane then target", calls)
	}
}

func TestChainHooksNilAndTypedNil(t *testing.T) {
	var calls []string
	only := recHooks{name: "x", calls: &calls}
	var typedNil *hook.Registry
	if h := chainHooks(nil, typedNil); h != nil {
		t.Fatalf("chainHooks(nil, typed nil) = %v, want nil", h)
	}
	if h := chainHooks(typedNil, only); h != only {
		t.Fatalf("typed-nil first runner not skipped")
	}
	if h := chainHooks(only, nil); h != only {
		t.Fatalf("nil second runner not skipped")
	}
}
