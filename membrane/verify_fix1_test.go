package membrane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
)

// fakeEvidenceSrc is an in-memory EvidenceSource.
type fakeEvidenceSrc struct {
	evs       []db.MembraneEvent // task events
	recs      []db.LLMRawRequest
	global    []db.MembraneEvent // start / override events
	created   time.Time
	completed *time.Time
	noTask    bool
}

func (f fakeEvidenceSrc) MembraneTaskEvents(string) ([]db.MembraneEvent, error) { return f.evs, nil }
func (f fakeEvidenceSrc) LLMRawRequests(_ string, after int64, limit int) ([]db.LLMRawRequest, error) {
	var out []db.LLMRawRequest
	for _, r := range f.recs {
		if r.ID > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f fakeEvidenceSrc) VerifyMembraneChain() (bool, int64, error) { return true, 0, nil }
func (f fakeEvidenceSrc) MembraneEventsByDirection(dir string, from, to time.Time) ([]db.MembraneEvent, error) {
	var out []db.MembraneEvent
	for _, e := range f.global {
		if e.Direction == dir && !e.TS.Before(from) && !e.TS.After(to) {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f fakeEvidenceSrc) MembraneLastEventAtOrBefore(dir string, t time.Time) (*db.MembraneEvent, error) {
	var last *db.MembraneEvent
	for i, e := range f.global {
		if e.Direction == dir && !e.TS.After(t) {
			last = &f.global[i]
		}
	}
	return last, nil
}
func (f fakeEvidenceSrc) MembraneTaskPeriod(string) (time.Time, *time.Time, bool, error) {
	if f.noTask {
		return time.Time{}, nil, false, nil
	}
	return f.created, f.completed, true, nil
}
func (f fakeEvidenceSrc) MembraneChainHeadNow() (db.MembraneChainHead, error) {
	return db.MembraneChainHead{LastID: 1, Hash: "h", Count: 1}, nil
}

const hashA, hashB = "aaaa", "bbbb"

func reqEvent(id int64, ts time.Time, hash string) db.MembraneEvent {
	return db.MembraneEvent{ID: id, TS: ts, TaskID: "7", Direction: "request", RequestSHA256: hash}
}

// A record is membraned only when it carries the membrane hash, whatever
// its profile name (an empty profile no longer hides it), and a forwarded
// request without a paired record makes the result inconclusive.
func TestVerifyTaskPairsByHash(t *testing.T) {
	e, _ := newTestEngine(t)
	t0 := time.Now().Add(-time.Hour)
	leak := `{"m":"portal.acmebank.pt"}`

	// Empty profile, record carries the hash: scanned and failed.
	src := fakeEvidenceSrc{
		evs:  []db.MembraneEvent{reqEvent(1, t0, hashA)},
		recs: []db.LLMRawRequest{{ID: 5, Raw: leak, MembraneHash: hashA}},
	}
	r, err := VerifyTask(e, src, "7")
	if err != nil {
		t.Fatal(err)
	}
	if r.Result != VerifyFail || r.Checked != 1 || r.Failed != 1 || r.Paired != 1 || r.OK() {
		t.Fatalf("hashed record: %+v", r)
	}

	// No hash on the record: unmembraned, and the forwarded event is
	// unpaired -> inconclusive (never a silent pass).
	src.recs = []db.LLMRawRequest{{ID: 5, Raw: leak}}
	r, _ = VerifyTask(e, src, "7")
	if r.Result != VerifyInconclusive || r.Checked != 0 || r.Unmembraned != 1 || r.Unpaired != 1 || r.OK() {
		t.Fatalf("unhashed record: %+v", r)
	}

	// Recording off: forwarded events, no records -> inconclusive.
	src.recs = nil
	r, _ = VerifyTask(e, src, "7")
	if r.Result != VerifyInconclusive || r.Forwarded != 1 || r.Unpaired != 1 {
		t.Fatalf("no records: %+v", r)
	}

	// Two identical requests (same hash), one record: one unpaired.
	src.evs = []db.MembraneEvent{reqEvent(1, t0, hashA), reqEvent(2, t0, hashA), reqEvent(3, t0, hashB)}
	src.recs = []db.LLMRawRequest{{ID: 5, Raw: `{}`, MembraneHash: hashA}, {ID: 6, Raw: `{}`, MembraneHash: hashB}}
	r, _ = VerifyTask(e, src, "7")
	if r.Result != VerifyInconclusive || r.Paired != 2 || r.Unpaired != 1 {
		t.Fatalf("multiplicity: %+v", r)
	}

	// All paired, clean: pass; the trusted-local record is not scanned.
	src.recs = append(src.recs, db.LLMRawRequest{ID: 7, Raw: `{}`, MembraneHash: hashA},
		db.LLMRawRequest{ID: 8, Raw: leak, Profile: "local"})
	r, _ = VerifyTask(e, src, "7")
	if r.Result != VerifyPass || r.Paired != 3 || r.Unpaired != 0 || r.Unmembraned != 1 || !r.OK() {
		t.Fatalf("all paired: %+v", r)
	}
	if !strings.Contains(r.Note, "as of the check") {
		t.Fatalf("note = %q", r.Note)
	}
}

func overrideOf(t *testing.T, src fakeEvidenceSrc) EvidenceDoc {
	t.Helper()
	e, _ := newTestEngine(t)
	in, err := TaskEvidence(e, src, "7", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, js := BuildEvidence(in)
	var doc EvidenceDoc
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func boot(id int64, ts time.Time, override bool) db.MembraneEvent {
	f := StartFlagMembraned
	if override {
		f = StartFlagOverride
	}
	return db.MembraneEvent{ID: id, TS: ts, Direction: DirectionStart, Flags: []string{f}}
}

// The override window is a server run (start event to next start), bounded
// by the task's period from the task row, not by its membrane events.
func TestEvidenceOverrideWindows(t *testing.T) {
	t0 := time.Now().Add(-10 * time.Hour)
	done := t0.Add(5 * time.Hour)
	base := fakeEvidenceSrc{created: t0, completed: &done,
		evs: []db.MembraneEvent{reqEvent(10, t0.Add(time.Hour), hashA)}}

	// (A) membraned boot before the task, overridden restart after its last
	// membrane event while the task continues.
	a := base
	a.global = []db.MembraneEvent{boot(1, t0.Add(-time.Hour), false), boot(20, t0.Add(2*time.Hour), true),
		{ID: 21, TS: t0.Add(2 * time.Hour), Direction: "override"}}
	if d := overrideOf(t, a); !d.Override.InForce || d.Period.Source != "task" || len(d.Override.Boots) != 2 {
		t.Fatalf("override after last event: %+v period %+v", d.Override, d.Period)
	}

	// (B) task starts under an override run, restart membraned later.
	b := base
	b.global = []db.MembraneEvent{boot(1, t0.Add(-time.Hour), true), boot(20, t0.Add(30*time.Minute), false)}
	if d := overrideOf(t, b); !d.Override.InForce {
		t.Fatalf("override before first event: %+v", d.Override)
	}

	// Membraned throughout; an override run after the task completed does
	// not count.
	c := base
	c.global = []db.MembraneEvent{boot(1, t0.Add(-time.Hour), false), boot(30, done.Add(time.Hour), true)}
	d := overrideOf(t, c)
	if d.Override.InForce || !d.Override.BootHistoryComplete || !strings.Contains(d.Override.Statement, "not overridden") {
		t.Fatalf("membraned throughout: %+v", d.Override)
	}

	// No boot record before the task (older history): stated as unknown.
	h := base
	h.global = nil
	if d := overrideOf(t, h); d.Override.InForce || d.Override.BootHistoryComplete || !strings.Contains(d.Override.Statement, "cannot be shown") {
		t.Fatalf("no boot history: %+v", d.Override)
	}

	// Legacy history: an override event before the task, no boot events.
	l := base
	l.global = []db.MembraneEvent{{ID: 2, TS: t0.Add(-time.Hour), Direction: "override"}}
	if d := overrideOf(t, l); !d.Override.InForce {
		t.Fatalf("legacy override before the task: %+v", d.Override)
	}
}

// The decorator hands the audited canonical request hash to the recorder's
// capture, so the record and its audit event pair exactly.
func TestVerifyDecoratorSetsCaptureHash(t *testing.T) {
	e, _ := newTestEngine(t)
	a := &memAuditor{}
	p := Wrap(&fakeProvider{}, e, a, "kimi")
	ctx, capt := llmrec.NewCapture(testCtx())
	if _, _, _, err := p.Complete(ctx, userReq("scan portal.acmebank.pt")); err != nil {
		t.Fatal(err)
	}
	evs := a.events()
	if len(evs) != 1 || evs[0].RequestSHA256 == "" || capt.MembraneHash() != evs[0].RequestSHA256 {
		t.Fatalf("capture hash %q, events %+v", capt.MembraneHash(), evs)
	}
	// Recording off (no capture on ctx): no panic.
	if _, _, _, err := p.Complete(testCtx(), userReq("again")); err != nil {
		t.Fatal(err)
	}
}
