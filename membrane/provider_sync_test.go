package membrane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// fakeSyncer counts SyncTask calls per task and answers with companies.
type fakeSyncer struct {
	mu        sync.Mutex
	calls     map[string]int
	companies []int64
	err       error
}

func (f *fakeSyncer) SyncTask(_ context.Context, taskID string) ([]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[taskID]++
	if f.err != nil {
		return nil, f.err
	}
	return slices.Clone(f.companies), nil
}

func (f *fakeSyncer) count(taskID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[taskID]
}

func taskCtx(id string) context.Context {
	return llmrec.WithTaskID(transcript.WithSessionID(context.Background(), "exp3-worker-i1"), id)
}

func TestSyncThrottle(t *testing.T) {
	e, _ := newTestEngine(t)
	sy := &fakeSyncer{companies: []int64{5}}
	a := &memAuditor{}
	w := wrap(&fakeProvider{}, e, a, "p", WithSyncer(sy))
	now := time.Unix(1_000_000, 0)
	w.now = func() time.Time { return now }

	call := func(ctx context.Context) {
		t.Helper()
		if _, _, _, err := w.Complete(ctx, userReq("hello")); err != nil {
			t.Fatal(err)
		}
	}
	call(taskCtx("42"))
	call(taskCtx("42"))
	if n := sy.count("42"); n != 1 {
		t.Fatalf("two requests within 30s synced %d times, want 1", n)
	}
	call(taskCtx("43")) // the throttle is per task
	if n := sy.count("43"); n != 1 {
		t.Fatalf("other task synced %d times, want 1", n)
	}
	now = now.Add(29 * time.Second)
	call(taskCtx("42"))
	if n := sy.count("42"); n != 1 {
		t.Fatalf("29s later synced %d times, want 1", n)
	}
	now = now.Add(2 * time.Second)
	call(taskCtx("42"))
	if n := sy.count("42"); n != 2 {
		t.Fatalf("31s later synced %d times, want 2", n)
	}
	// No task id (chat conversation, connection test): no sync at all.
	chat := transcript.WithSessionID(context.Background(), "conv-9")
	call(chat)
	call(context.Background())
	sy.mu.Lock()
	total := 0
	for _, n := range sy.calls {
		total += n
	}
	sy.mu.Unlock()
	if total != 3 {
		t.Fatalf("requests without a task id must not sync: %d calls total", total)
	}
}

func TestSyncFailureBlocksRequest(t *testing.T) {
	e, _ := newTestEngine(t)
	sy := &fakeSyncer{err: errors.New("db down")}
	a := &memAuditor{}
	f := &fakeProvider{}
	w := wrap(f, e, a, "p", WithSyncer(sy))

	_, _, _, err := w.Complete(taskCtx("42"), userReq("hello acmebank.pt"))
	if err == nil {
		t.Fatal("a failed seed sync must block the request")
	}
	if strings.Contains(strings.ToLower(err.Error()), "acmebank") {
		t.Fatalf("error carries an original: %v", err)
	}
	for ev, err := range w.Stream(taskCtx("42"), userReq("hello")) {
		_ = ev
		if err == nil {
			t.Fatal("stream: a failed seed sync must block the request")
		}
	}
	if f.calls() != 0 {
		t.Fatalf("blocked requests reached the provider: %d", f.calls())
	}
	evs := a.events()
	if len(evs) != 2 {
		t.Fatalf("want 2 audit events, got %d", len(evs))
	}
	for _, ev := range evs {
		if !ev.Blocked || ev.BlockReason != "seed sync failed" || ev.Direction != "request" || ev.TaskID != "42" {
			t.Fatalf("audit event = %+v", ev)
		}
	}
	// Failures are not throttled: the next request retries the sync.
	if n := sy.count("42"); n != 2 {
		t.Fatalf("failed syncs must be retried on every request: %d calls", n)
	}
	sy.mu.Lock()
	sy.err = nil
	sy.mu.Unlock()
	if _, _, _, err := w.Complete(taskCtx("42"), userReq("hello")); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

// R16: values auto-enrolled from a task's request carry the task's company
// ids returned by the syncer, so a company purge can remove them.
func TestSyncCompanyIDsInProvenance(t *testing.T) {
	e, s := newTestEngine(t)
	sy := &fakeSyncer{companies: []int64{11, 12}}
	w := wrap(&fakeProvider{}, e, &memAuditor{}, "p", WithSyncer(sy))
	req := llm.CompletionRequest{Messages: []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{toolResultBlock("t1", "found config: db_password=Qx7vT-r9zzk2")}},
	}, MaxTokens: 10}
	if _, _, _, err := w.Complete(taskCtx("77"), req); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.AliasFor("Qx7vT-r9zzk2"); !ok {
		t.Fatal("the secret in the tool result was not auto-enrolled")
	}
	p := s.p.(*fakePersistence)
	p.mu.Lock()
	defer p.mu.Unlock()
	var found bool
	for _, en := range p.entries {
		if en.Kind != string(KindPassword) || !slices.Contains(en.TaskIDs, 77) {
			continue
		}
		found = true
		if !slices.Equal(en.CompanyIDs, []int64{11, 12}) || en.Source != "auto" {
			t.Fatalf("auto-enrolled entry provenance = companies %v source %q", en.CompanyIDs, en.Source)
		}
	}
	if !found {
		t.Fatal("no auto-enrolled password entry for task 77")
	}
}

// toolResultBlock builds a tool_result block carrying text.
func toolResultBlock(id, text string) llm.ContentBlock { return llm.ToolResultText(id, text, false) }
