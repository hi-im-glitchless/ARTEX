package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/artex/membrane"
)

func toolInput(k, v string) []byte {
	b, _ := json.Marshal(map[string]string{k: v})
	return b
}

// Every tool-running agent gets the membrane tool check; a block is audited
// as a "tool_block" event carrying the rule only; the web_search originals
// rule follows the agent's provider (R19).
func TestMembraneToolGuardWiring(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	kw := "Zorblax" + strconv.FormatInt(time.Now().UnixNano()%1e6, 36)
	if _, err := s.membraneStore().Enroll(membrane.KindOrg, kw, membrane.Provenance{Source: "seed"}); err != nil {
		t.Fatal(err)
	}
	taskID := strconv.FormatInt(time.Now().UnixNano(), 10)
	const alias = "240.9.9.0/16"

	remote := s.membraneToolCheck(taskID, "worker", func() bool { return true })
	block, reason := remote("Bash", toolInput("command", "nmap "+alias))
	if !block || reason != "unknown alias "+alias+" — use only names from your context" {
		t.Fatalf("unresolved alias: %v %q", block, reason)
	}
	evs, _, err := m.pg.ListMembraneEvents(taskID, 1, 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("audit: %v %d", err, len(evs))
	}
	if ev := evs[0]; ev.Direction != "tool_block" || !ev.Blocked || ev.BlockReason != membrane.RuleUnresolvedAlias ||
		ev.Role != "worker" || len(ev.Flags) != 1 || ev.Flags[0] != membrane.RuleUnresolvedAlias {
		t.Fatalf("event %+v", ev)
	}
	if b, _ := json.Marshal(evs[0]); strings.Contains(string(b), "240.9") {
		t.Fatalf("audit event carries the value: %s", b)
	}
	if block, reason := remote("web_search", toolInput("query", kw+" vpn login")); !block ||
		reason != "search for the technology or CVE, not the target" || strings.Contains(reason, kw) {
		t.Fatalf("web_search original: %v %q", block, reason)
	}
	if block, _ := remote("web_search", toolInput("query", "Spring Boot actuator CVE")); block {
		t.Fatal("technology search blocked")
	}
	// A local provider: aliases still block, originals in searches do not.
	local := s.membraneToolCheck(taskID, "planner", func() bool { return false })
	if block, _ := local("web_search", toolInput("query", kw+" vpn login")); block {
		t.Fatal("web_search rule applied to a local provider")
	}
	if block, _ := local("Bash", toolInput("command", "nmap "+alias)); !block {
		t.Fatal("unresolved alias allowed for a local provider")
	}

	// Task worker guards built by the manager carry the check.
	task := taskFromPG(&pgdb.Task{ID: 987654321}, nil, nil, m.membraneCheckFor)
	if block, _, _ := task.Guard.Hooks().PreToolUse(context.Background(), "Bash", toolInput("command", "nmap "+alias)); !block {
		t.Fatal("task guard has no membrane check")
	}
	// Planner / main agent / goals hooks.
	h := s.membraneToolHooks(taskID, "planner", nil)
	if h == nil {
		t.Fatal("no hooks with the membrane enabled")
	}
	if block, _, _ := h.PreToolUse(context.Background(), "web_search", toolInput("query", kw)); !block {
		t.Fatal("planner hooks do not block")
	}
	// Chat guards: provider-dependent web_search rule.
	localCfg := agent.ConfigFrom("openai", "m", "http://127.0.0.1:11434/v1", "k", "")
	if block, _, _ := s.chatGuard(nil, localCfg).Hooks().PreToolUse(context.Background(), "web_search", toolInput("query", kw)); block {
		t.Fatal("chat guard on a local model blocked an original search")
	}
	remoteCfg := agent.ConfigFrom("anthropic", "m", "https://api.kimi.com/coding/v1", "k", "")
	if block, _, _ := s.chatGuard(nil, remoteCfg).Hooks().PreToolUse(context.Background(), "web_search", toolInput("query", kw)); !block {
		t.Fatal("chat guard on a remote model allowed an original search")
	}
	if !providerMembraned(&llmpool.Pool{}, localCfg) {
		t.Fatal("a failover pool must count as membraned")
	}
}

func TestMembraneToolGuardOffWithOverride(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "off")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	if s.membraneToolCheck("1", "worker", nil) != nil || s.membraneToolHooks("1", "planner", nil) != nil {
		t.Fatal("membrane check installed with the override on")
	}
	if m.membraneCheckFor("1") != nil {
		t.Fatal("task guard check with the override on")
	}
	if block, _, _ := s.chatGuard(nil, agent.Config{}).Hooks().PreToolUse(context.Background(), "Bash", toolInput("command", "nmap 240.9.9.9")); block {
		t.Fatal("chat guard blocked with the override on")
	}
}
