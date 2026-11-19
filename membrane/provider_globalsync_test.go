package membrane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/transcript"
)

// globalSyncer is a fakeSyncer that also seeds task-less requests and
// exposes an epoch.
type globalSyncer struct {
	fakeSyncer
	gmu    sync.Mutex
	global int
	gerr   error
	epochV atomic.Uint64
}

func (g *globalSyncer) SyncGlobal(context.Context) error {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	g.global++
	return g.gerr
}

func (g *globalSyncer) SyncEpoch() uint64 { return g.epochV.Load() }

func (g *globalSyncer) globalCount() int {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	return g.global
}

// Final review I3: requests without a task id (chat, custom agents) seed the
// task-independent values (companies) before transforming, throttled; a
// failure blocks the request (fail closed, R17).
func TestGlobalSyncForTasklessRequests(t *testing.T) {
	e, _ := newTestEngine(t)
	sy := &globalSyncer{}
	a := &memAuditor{}
	w := wrap(&fakeProvider{}, e, a, "p", WithSyncer(sy))
	now := time.Unix(1_000_000, 0)
	w.now = func() time.Time { return now }
	chat := transcript.WithSessionID(context.Background(), "conv-7")
	if _, _, _, err := w.Complete(chat, userReq("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := w.Complete(chat, userReq("hello")); err != nil {
		t.Fatal(err)
	}
	if n := sy.globalCount(); n != 1 {
		t.Fatalf("global syncs = %d, want 1 (throttled)", n)
	}
	now = now.Add(syncInterval)
	sy.gerr = errors.New("db down")
	if _, _, _, err := w.Complete(chat, userReq("hello")); err == nil {
		t.Fatal("request sent although the global seed sync failed")
	}
	if ev := a.evs[len(a.evs)-1]; !ev.Blocked || ev.BlockReason != "seed sync failed" {
		t.Fatalf("event = %+v", ev)
	}
}

// A seed-source change (epoch) expires the throttle at once, for tasks and
// task-less requests alike.
func TestSyncEpochExpiresThrottle(t *testing.T) {
	e, _ := newTestEngine(t)
	sy := &globalSyncer{}
	w := wrap(&fakeProvider{}, e, &memAuditor{}, "p", WithSyncer(sy))
	now := time.Unix(1_000_000, 0)
	w.now = func() time.Time { return now }
	ctx := taskCtx("42")
	for range 2 {
		if _, _, _, err := w.Complete(ctx, userReq("hi")); err != nil {
			t.Fatal(err)
		}
	}
	if n := sy.count("42"); n != 1 {
		t.Fatalf("syncs = %d, want 1", n)
	}
	sy.epochV.Add(1)
	if _, _, _, err := w.Complete(ctx, userReq("hi")); err != nil {
		t.Fatal(err)
	}
	if n := sy.count("42"); n != 2 {
		t.Fatalf("syncs after epoch change = %d, want 2", n)
	}
}
