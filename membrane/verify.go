package membrane

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// VerifyRecord is one recorded request to re-check offline: the wire bytes
// of llm_records.raw_request (the aliased body actually sent), never the
// operator view.
type VerifyRecord struct {
	ID  int64
	Raw string
}

// Verify outcomes (VerifyResult.Result).
const (
	VerifyPass         = "pass"
	VerifyFail         = "fail"
	VerifyInconclusive = "inconclusive"
)

// VerifyNote states what a verification does and does not show; the CLI,
// the API and the evidence repeat it.
const VerifyNote = "Verification re-scans the recorded wire bytes with the membrane dictionary as of the check. " +
	"A failure may be a value the membrane learned after the request was sent: still a disclosure to the model provider, " +
	"but not necessarily a membrane miss at send time. Values purged by a company key destruction are no longer scanned."

// VerifyResult is the outcome of an offline verification (spec §10.2). It
// carries counts, record ids and kinds only, never values.
//
// Records are paired with the task's "request" audit events by the
// membrane's canonical request hash (llm_records.membrane_request_sha256 =
// the event's request_sha256). A record without that hash did not go
// through the membrane (a trusted local model, or a record written before
// pairing existed) and is counted in Unmembraned, not scanned.
//
// Checked counts the membraned records with raw bytes that were scanned,
// Failed those in which LeakCheck found an enrolled original (FailedIDs,
// ascending; FailedKinds sums the hits per kind), NoRaw membraned records
// without raw bytes. Forwarded counts the task's forwarded request events,
// Paired those with a scanned record, Unpaired the rest. Result is "fail"
// when a record failed or the chain is broken, else "inconclusive" when a
// forwarded request has no scanned record (recording off, or records
// missing) or when nothing went through the membrane but unmembraned
// records exist (an override run or a trusted local profile), else "pass".
// Blocked counts records of calls the membrane refused (no hash, a
// membrane error): never forwarded, not scanned. ChainOK and ChainFirstBadID come from the audit
// chain check, which Verify itself does not run (VerifyTask does).
type VerifyResult struct {
	Result          string         `json:"result"`
	Checked         int            `json:"checked"`
	Failed          int            `json:"failed"`
	FailedIDs       []int64        `json:"failed_ids"`
	FailedKinds     map[string]int `json:"failed_kinds"`
	NoRaw           int            `json:"no_raw"`
	Unmembraned     int            `json:"unmembraned"`
	Blocked         int            `json:"blocked"`
	Forwarded       int            `json:"forwarded"`
	Paired          int            `json:"paired"`
	Unpaired        int            `json:"unpaired"`
	ChainOK         bool           `json:"chain_ok"`
	ChainFirstBadID int64          `json:"chain_first_bad_id,omitempty"`
	// Reason explains an inconclusive or failed result (counts only).
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note"`
}

// OK reports whether the verification passed: nothing failed, the chain is
// intact and every forwarded request was checked.
func (r VerifyResult) OK() bool { return r.Result == VerifyPass }

// finish sets Result from the counts.
func (r *VerifyResult) finish() {
	switch {
	case r.Failed > 0 || !r.ChainOK:
		r.Result = VerifyFail
		var why []string
		if r.Failed > 0 {
			why = append(why, fmt.Sprintf("%d recorded request(s) hold an enrolled original", r.Failed))
		}
		if !r.ChainOK {
			why = append(why, "the audit chain is broken")
		}
		r.Reason = strings.Join(why, "; ")
	case r.Unpaired > 0 || (r.Forwarded > 0 && r.Checked == 0):
		r.Result = VerifyInconclusive
		r.Reason = fmt.Sprintf("%d of %d forwarded request(s) have no recorded wire body paired with their audit event (recording off or records missing)",
			r.Unpaired, r.Forwarded)
	case r.Forwarded == 0 && r.Unmembraned > 0:
		r.Result = VerifyInconclusive
		r.Reason = fmt.Sprintf("no request was forwarded through the membrane, but %d recorded request(s) bypassed it (ARTEX_MEMBRANE=off or a trusted local profile)",
			r.Unmembraned)
	default:
		r.Result = VerifyPass
		if r.Forwarded == 0 {
			r.Reason = "no request was forwarded through the membrane for this task: nothing to re-scan"
		}
	}
	r.Note = VerifyNote
}

func newVerifyResult() VerifyResult {
	return VerifyResult{FailedIDs: []int64{}, FailedKinds: map[string]int{}, Note: VerifyNote}
}

// Verify re-runs the pre-send leak check over the recorded raw requests with
// the current dictionary: an original enrolled after a request was sent is
// caught too. Records with no raw bytes are counted in NoRaw. It does not
// pair records with events nor check the chain (Result stays empty).
func Verify(e *Engine, records []VerifyRecord) VerifyResult {
	r := newVerifyResult()
	r.add(e, records)
	return r
}

func (r *VerifyResult) add(e *Engine, records []VerifyRecord) {
	for _, rec := range records {
		if rec.Raw == "" {
			r.NoRaw++
			continue
		}
		r.Checked++
		hits := e.LeakCheck([]byte(rec.Raw))
		if len(hits) == 0 {
			continue
		}
		r.Failed++
		r.FailedIDs = append(r.FailedIDs, rec.ID)
		for _, h := range hits {
			r.FailedKinds[string(h.Kind)]++
		}
	}
	sort.Slice(r.FailedIDs, func(i, j int) bool { return r.FailedIDs[i] < r.FailedIDs[j] })
}

// VerifySource is the part of *db.DB VerifyTask reads.
type VerifySource interface {
	MembraneTaskEvents(taskID string) ([]db.MembraneEvent, error)
	LLMRawRequests(taskID string, afterID int64, limit int) ([]db.LLMRawRequest, error)
	VerifyMembraneChain() (ok bool, firstBadID int64, err error)
}

// verifyPage bounds the raw requests held in memory at once.
const verifyPage = 50

// VerifyTask verifies every recorded membraned request of taskID, pairs
// them with the task's forwarded request events and checks the whole audit
// chain. Errors carry no values.
func VerifyTask(e *Engine, src VerifySource, taskID string) (VerifyResult, error) {
	evs, err := src.MembraneTaskEvents(taskID)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("membrane verify: load events: %w", err)
	}
	return verifyTask(e, src, taskID, evs)
}

func verifyTask(e *Engine, src VerifySource, taskID string, evs []db.MembraneEvent) (VerifyResult, error) {
	res := newVerifyResult()
	// Forwarded request events by hash (identical requests share a hash:
	// pairing is by multiplicity).
	want := map[string]int{}
	for _, ev := range evs {
		if ev.Direction == "request" && !ev.Blocked {
			res.Forwarded++
			want[ev.RequestSHA256]++
		}
	}
	var after int64
	for {
		page, err := src.LLMRawRequests(taskID, after, verifyPage)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("membrane verify: load records: %w", err)
		}
		if len(page) == 0 {
			break
		}
		recs := make([]VerifyRecord, 0, len(page))
		for _, p := range page {
			after = p.ID
			if p.MembraneHash == "" {
				if p.MembraneRefused {
					res.Blocked++
				} else {
					res.Unmembraned++
				}
				continue
			}
			if p.Raw != "" && want[p.MembraneHash] > 0 {
				want[p.MembraneHash]--
				res.Paired++
			}
			recs = append(recs, VerifyRecord{ID: p.ID, Raw: p.Raw})
		}
		res.add(e, recs)
	}
	res.Unpaired = res.Forwarded - res.Paired
	ok, bad, err := src.VerifyMembraneChain()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("membrane verify: audit chain: %w", err)
	}
	res.ChainOK, res.ChainFirstBadID = ok, bad
	res.finish()
	return res, nil
}
