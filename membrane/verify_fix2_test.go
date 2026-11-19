package membrane

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Regression for the coordinator's TestProbeStartEventLost: an override run
// whose "start" event was lost still shows as overridden through its
// "override" event, whatever the boot history.
func TestEvidenceOverrideEventWithoutStart(t *testing.T) {
	t0 := time.Now().Add(-2 * time.Hour)
	base := fakeEvidenceSrc{created: t0.Add(5 * time.Minute),
		evs: []db.MembraneEvent{reqEvent(2, t0.Add(10*time.Minute), hashA)}}

	// Membraned boot before the task, then an override event (its start
	// event lost) inside the period.
	a := base
	a.global = []db.MembraneEvent{boot(1, t0, false), {ID: 4, TS: t0.Add(30 * time.Minute), Direction: "override"}}
	if d := overrideOf(t, a); !d.Override.InForce || !strings.Contains(d.Override.Statement, "OVERRIDDEN") {
		t.Fatalf("lost start, override in period: %+v", d.Override)
	}

	// Override event before the period, its start event lost, no later
	// boot recorded: the task started under it.
	b := base
	b.global = []db.MembraneEvent{boot(1, t0.Add(-time.Hour), false), {ID: 3, TS: t0, Direction: "override"}}
	if d := overrideOf(t, b); !d.Override.InForce {
		t.Fatalf("lost start, override before the period: %+v", d.Override)
	}

	// A membraned boot recorded after that override ends its run.
	c := base
	c.global = []db.MembraneEvent{{ID: 3, TS: t0.Add(-time.Hour), Direction: "override"}, boot(4, t0, false)}
	if d := overrideOf(t, c); d.Override.InForce {
		t.Fatalf("override ended by a later membraned boot: %+v", d.Override)
	}

	// Only a membraned boot: not overridden.
	n := base
	n.global = []db.MembraneEvent{boot(1, t0, false)}
	if d := overrideOf(t, n); d.Override.InForce || !strings.Contains(d.Override.Statement, "not overridden") {
		t.Fatalf("membraned only: %+v", d.Override)
	}
}

// Regression for TestProbeOverrideOnlyVerify: a task that ran entirely
// outside the membrane is inconclusive, never a pass.
func TestVerifyOverrideOnlyInconclusive(t *testing.T) {
	e, _ := newTestEngine(t)
	src := fakeEvidenceSrc{recs: []db.LLMRawRequest{{ID: 1, Raw: `{"m":"portal.acmebank.pt"}`}, {ID: 2, Raw: `{}`}}}
	r, err := VerifyTask(e, src, "7")
	if err != nil {
		t.Fatal(err)
	}
	if r.Result != VerifyInconclusive || r.Unmembraned != 2 || r.Checked != 0 || !strings.Contains(r.Reason, "bypassed") {
		t.Fatalf("override-only: %+v", r)
	}
}

// Records of calls the membrane refused are their own bucket; with nothing
// forwarded the pass is worded as such.
func TestVerifyBlockedBucketAndVacuousPass(t *testing.T) {
	e, _ := newTestEngine(t)
	blockedEv := db.MembraneEvent{ID: 1, TS: time.Now(), TaskID: "7", Direction: "request", Blocked: true, BlockReason: "leak check: domain@3"}
	src := fakeEvidenceSrc{created: time.Now().Add(-time.Hour), evs: []db.MembraneEvent{blockedEv},
		recs: []db.LLMRawRequest{{ID: 1, MembraneRefused: true}}}
	r, _ := VerifyTask(e, src, "7")
	if r.Result != VerifyPass || r.Blocked != 1 || r.Unmembraned != 0 || r.Forwarded != 0 || !strings.Contains(r.Reason, "nothing to re-scan") {
		t.Fatalf("blocked only: %+v", r)
	}
	d := overrideOf(t, src)
	if !strings.Contains(d.Proof.Statement, "No request was forwarded") || strings.Contains(d.Proof.Statement, "every forwarded request") {
		t.Fatalf("vacuous pass statement: %q", d.Proof.Statement)
	}
}
