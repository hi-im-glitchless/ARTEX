package guard

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGuardRunsMembraneCheckFirst(t *testing.T) {
	g := New()
	var gotTool string
	var gotInput []byte
	g.SetMembraneCheck(func(tool string, input []byte) (bool, string) {
		gotTool, gotInput = tool, input
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(input, &in)
		if in.Command == "nmap 240.9.9.0/16" {
			return true, "unknown alias 240.9.9.0/16 — use only names from your context"
		}
		return false, ""
	})
	input, _ := json.Marshal(map[string]string{"command": "nmap 240.9.9.0/16"})
	block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	if !block || msg != "unknown alias 240.9.9.0/16 — use only names from your context" {
		t.Fatalf("block=%v msg=%q", block, msg)
	}
	if gotTool != "Bash" || string(gotInput) != string(input) {
		t.Fatalf("check saw %q %s", gotTool, gotInput)
	}
	// Evaluated first: the block is the only audit entry for the call (no
	// "allow" recorded before it, intercept rules never reached).
	a := g.Audit()
	if len(a) != 1 || a[0].Action != "block" || a[0].Tool != "Bash" || a[0].Reason != msg || a[0].Command != "nmap 240.9.9.0/16" {
		t.Fatalf("audit %+v", a)
	}

	// Allowed by the check: the normal path runs.
	ok, _ := json.Marshal(map[string]string{"command": "ls"})
	if block, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", ok); block {
		t.Fatal("allowed call blocked")
	}
	if a := g.Audit(); len(a) != 2 || a[1].Action != "allow" {
		t.Fatalf("audit %+v", a)
	}

	// No check: unchanged behaviour.
	g.SetMembraneCheck(nil)
	if block, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input); block {
		t.Fatal("blocked without a membrane check")
	}
}
