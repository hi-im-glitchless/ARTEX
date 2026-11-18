package membrane

import (
	"fmt"
	"sort"

	"github.com/Autumn-27/artex/db"
)

// VerifyRecord is one recorded request to re-check offline: the wire bytes
// of llm_records.raw_request (the aliased body actually sent), never the
// operator view.
type VerifyRecord struct {
	ID  int64
	Raw string
}

// VerifyResult is the outcome of an offline verification (spec §10.2). It
// carries counts, record ids and kinds only, never values.
//
// Checked counts the records with raw bytes that were scanned, Failed those
// in which LeakCheck found an enrolled original (FailedIDs, ascending;
// FailedKinds sums the hits per kind). NoRaw counts the records without raw
// bytes (recording was off or the call never reached HTTP), Unmembraned the
// task records of profiles that were never membraned (trusted local models,
// which legitimately see originals). ChainOK and ChainFirstBadID come from
// the audit chain check, which Verify itself does not run (VerifyTask does).
type VerifyResult struct {
	Checked         int            `json:"checked"`
	Failed          int            `json:"failed"`
	FailedIDs       []int64        `json:"failed_ids"`
	FailedKinds     map[string]int `json:"failed_kinds"`
	NoRaw           int            `json:"no_raw"`
	Unmembraned     int            `json:"unmembraned"`
	ChainOK         bool           `json:"chain_ok"`
	ChainFirstBadID int64          `json:"chain_first_bad_id,omitempty"`
}

// OK reports whether nothing failed and the chain is intact.
func (r VerifyResult) OK() bool { return r.Failed == 0 && r.ChainOK }

// Verify re-runs the pre-send leak check over the recorded raw requests with
// the current dictionary: an original enrolled after a request was sent is
// caught too. Records with no raw bytes are counted in NoRaw.
func Verify(e *Engine, records []VerifyRecord) VerifyResult {
	r := VerifyResult{FailedIDs: []int64{}, FailedKinds: map[string]int{}}
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

// VerifyTask verifies every recorded request of taskID made through a
// membraned profile (one that appears in the task's "request" audit
// events) and checks the whole audit chain. Errors carry no values.
func VerifyTask(e *Engine, src VerifySource, taskID string) (VerifyResult, error) {
	evs, err := src.MembraneTaskEvents(taskID)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("membrane verify: load events: %w", err)
	}
	return verifyTask(e, src, taskID, evs)
}

func verifyTask(e *Engine, src VerifySource, taskID string, evs []db.MembraneEvent) (VerifyResult, error) {
	membraned := map[string]bool{}
	for _, ev := range evs {
		if ev.Direction == "request" && ev.Profile != "" {
			membraned[ev.Profile] = true
		}
	}
	res := VerifyResult{FailedIDs: []int64{}, FailedKinds: map[string]int{}}
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
			if !membraned[p.Profile] {
				res.Unmembraned++
				continue
			}
			recs = append(recs, VerifyRecord{ID: p.ID, Raw: p.Raw})
		}
		res.add(e, recs)
	}
	ok, bad, err := src.VerifyMembraneChain()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("membrane verify: audit chain: %w", err)
	}
	res.ChainOK, res.ChainFirstBadID = ok, bad
	return res, nil
}
