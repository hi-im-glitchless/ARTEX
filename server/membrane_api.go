package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

// Membrane API (spec §10, §12). Every route sits behind the server's JWT
// auth like the other /api routes. None of them lists or looks up mapping
// entries; verify and evidence carry counts, ids and kinds only. The preview
// returns the operator's own text (and its aliases) to the operator's
// browser and logs nothing of it.

// registerMembraneRoutes adds the membrane routes to mux.
func (s *Server) registerMembraneRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/membrane/status", s.membraneStatusHandler)
	mux.HandleFunc("POST /api/membrane/preview", s.membranePreview)
	mux.HandleFunc("GET /api/tasks/{id}/membrane/events", s.membraneTaskEvents)
	mux.HandleFunc("POST /api/tasks/{id}/membrane/verify", s.membraneTaskVerify)
	mux.HandleFunc("GET /api/tasks/{id}/membrane/evidence", s.membraneTaskEvidence)
	mux.HandleFunc("POST /api/companies/{id}/membrane/destroy", s.membraneDestroyCompany)
}

func (s *Server) membraneStatusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.membraneStatus())
}

// maxPreviewBytes bounds the preview text.
const maxPreviewBytes = 512 << 10

type previewRequest struct {
	Text       string          `json:"text"`
	CompanyIDs []int64         `json:"companyIds"`
	TaskID     json.RawMessage `json:"taskId,omitempty"` // number or numeric string
	// TaskScope holds task-scope rows not yet saved (the create form's
	// pending sensitive terms). Only keyword and icp rows are seeded, as the
	// real run seeds them from the task scope.
	TaskScope []previewScopeRow `json:"taskScope,omitempty"`
}

type previewScopeRow struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// PreviewSpan is a replaced value in the aliased text. Start and End are
// UTF-16 code unit offsets (JavaScript string indices).
type PreviewSpan struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Kind  string `json:"kind"`
	State string `json:"state"`
}

// PreviewSuspicious is an unaliased token that looks like a name or a
// domain (UTF-16 offsets into the aliased text).
type PreviewSuspicious struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

// PreviewResponse is the dry-run view of what the model would see.
type PreviewResponse struct {
	Aliased    string              `json:"aliased"`
	Spans      []PreviewSpan       `json:"spans"`
	Suspicious []PreviewSuspicious `json:"suspicious"`
}

func parseTaskIDJSON(raw json.RawMessage) (int64, error) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" || t == `""` {
		return 0, nil
	}
	t = strings.Trim(t, `"`)
	id, err := strconv.ParseInt(t, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid taskId")
	}
	return id, nil
}

// membranePreview runs the text through a dry-run engine view: the linked
// companies and the task are seeded into an in-memory copy of the store (as
// the real run seeds them) and the transform derives the aliases the real
// run would mint, but nothing is enrolled, persisted or cached in the live
// engine.
func (s *Server) membranePreview(w http.ResponseWriter, r *http.Request) {
	e := s.membraneEngine()
	if e == nil || s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "membrane not enabled")
		return
	}
	var req previewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPreviewBytes+64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Text) > maxPreviewBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "text too large")
		return
	}
	taskID, err := parseTaskIDJSON(req.TaskID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dry := e.WithDryRun()
	sd := &seeder{s: s, st: dry.Store(), e: dry, seen: map[string]bool{}}
	companies := []int64{}
	for _, cid := range req.CompanyIDs {
		if cid <= 0 {
			continue
		}
		if err := sd.company(cid); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("preview: seed company %d failed", cid))
			return
		}
		companies = append(companies, cid)
	}
	prov := membrane.Provenance{CompanyIDs: companies}
	if taskID > 0 {
		tc, err := sd.task(r.Context(), taskID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "preview: seed task failed")
			return
		}
		prov = membrane.Provenance{CompanyIDs: tc, TaskIDs: []int64{taskID}}
	}
	for _, row := range req.TaskScope {
		if row.Kind != "keyword" && row.Kind != "icp" {
			continue
		}
		if err := sd.keyword(row.Value, prov); err != nil {
			writeErr(w, http.StatusInternalServerError, "preview: seed task scope failed")
			return
		}
	}
	out, _, err := dry.ToModel(req.Text, prov)
	if err != nil {
		// Transform errors carry kinds only; still keep them out of logs.
		writeErr(w, http.StatusInternalServerError, "preview: transform failed")
		return
	}
	resp := PreviewResponse{Aliased: out, Spans: []PreviewSpan{}, Suspicious: []PreviewSuspicious{}}
	idx := newUTF16Index(out)
	for _, sp := range dry.AliasSpans(out) {
		resp.Spans = append(resp.Spans, PreviewSpan{Start: idx.at(sp.Start), End: idx.at(sp.End), Kind: string(sp.Kind), State: "replaced"})
	}
	for _, sp := range dry.Suspicious(out) {
		resp.Suspicious = append(resp.Suspicious, PreviewSuspicious{Start: idx.at(sp.Start), End: idx.at(sp.End), Text: sp.Text})
	}
	writeJSON(w, 200, resp)
}

// utf16Index converts byte offsets of a string to UTF-16 code unit offsets.
type utf16Index struct{ off []int }

func newUTF16Index(s string) utf16Index {
	off := make([]int, len(s)+1)
	u := 0
	for i, r := range s {
		n := utf8.RuneLen(r)
		if n < 0 {
			n = 1
		}
		for j := 0; j < n && i+j < len(s); j++ {
			off[i+j] = u
		}
		u += utf16.RuneLen(r)
	}
	off[len(s)] = u
	return utf16Index{off}
}

func (x utf16Index) at(b int) int {
	if b < 0 {
		return 0
	}
	if b >= len(x.off) {
		return x.off[len(x.off)-1]
	}
	return x.off[b]
}

// taskPathID validates the {id} path value (a numeric task id) and returns
// it in the form audit events and llm_records use.
func taskPathID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return "", false
	}
	return strconv.FormatInt(id, 10), true
}

// MembraneEventDTO is one audit event as the API shows it.
type MembraneEventDTO struct {
	ID            int64          `json:"id"`
	TS            time.Time      `json:"ts"`
	TaskID        string         `json:"task_id"`
	Session       string         `json:"session"`
	Role          string         `json:"role"`
	Profile       string         `json:"profile"`
	Direction     string         `json:"direction"`
	Counts        map[string]int `json:"counts"`
	Enrolled      int            `json:"enrolled"`
	Flags         []string       `json:"flags"`
	Blocked       bool           `json:"blocked"`
	BlockReason   string         `json:"block_reason"`
	RequestSHA256 string         `json:"request_sha256"`
	PrevHash      string         `json:"prev_hash"`
	Hash          string         `json:"hash"`
}

func (s *Server) membraneTaskEvents(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	id, ok := taskPathID(w, r)
	if !ok {
		return
	}
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	size := atoiDefault(r.URL.Query().Get("size"), 50)
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	evs, total, err := s.m.pg.ListMembraneEvents(id, page, size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list membrane events failed")
		return
	}
	out := make([]MembraneEventDTO, 0, len(evs))
	for _, ev := range evs {
		out = append(out, MembraneEventDTO{ID: ev.ID, TS: ev.TS, TaskID: ev.TaskID, Session: ev.Session, Role: ev.Role,
			Profile: ev.Profile, Direction: ev.Direction, Counts: ev.Counts, Enrolled: ev.Enrolled, Flags: ev.Flags,
			Blocked: ev.Blocked, BlockReason: ev.BlockReason, RequestSHA256: ev.RequestSHA256, PrevHash: ev.PrevHash, Hash: ev.Hash})
	}
	writeJSON(w, 200, map[string]any{"events": out, "total": total, "page": page, "size": size})
}

// membraneVerifyEngine is the engine verify uses: the live one (its
// dictionary is the full mapping table).
func (s *Server) membraneVerifyEngine(w http.ResponseWriter) (*membrane.Engine, bool) {
	e := s.membraneEngine()
	if e == nil || s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "membrane not enabled")
		return nil, false
	}
	return e, true
}

func (s *Server) membraneTaskVerify(w http.ResponseWriter, r *http.Request) {
	id, ok := taskPathID(w, r)
	if !ok {
		return
	}
	e, ok := s.membraneVerifyEngine(w)
	if !ok {
		return
	}
	res, err := membrane.VerifyTask(e, s.m.pg, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "verify failed")
		log.Printf("[membrane] verify task %s: %v", id, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) membraneTaskEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := taskPathID(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	if format != "md" && format != "json" {
		writeErr(w, http.StatusBadRequest, "format must be md or json")
		return
	}
	e, ok := s.membraneVerifyEngine(w)
	if !ok {
		return
	}
	in, err := membrane.TaskEvidence(e, s.m.pg, id, time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence export failed")
		log.Printf("[membrane] evidence task %s: %v", id, err)
		return
	}
	md, js := membrane.BuildEvidence(in)
	name := "membrane-evidence-task-" + id + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(js)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(md))
}

// membraneDestroyCompany purges the mapping entries referenced only by the
// company (spec §10.5). It is refused (409, with the reference counts) while
// any real data that can still reach a prompt references the company,
// including the company row itself (a re-seed would undo the destroy). The
// reference check, the purge and the "destroy" audit event (company id and
// count only) run in one database transaction; then the live store
// reloads, so the purged originals leave memory too.
func (s *Server) membraneDestroyCompany(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	cid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	ev := &db.MembraneEvent{Direction: "destroy"}
	refs, n, err := s.m.pg.DestroyMembraneCompany(cid, ev, func(purged int) []string {
		return []string{"company:" + strconv.FormatInt(cid, 10), "purged:" + strconv.Itoa(purged)}
	})
	if errors.Is(err, db.ErrMembraneReferenced) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":      "company data still references the membrane mapping; delete the company and its data first",
			"references": refs,
		})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "destroy failed (nothing purged)")
		log.Printf("[membrane] destroy company %d: %v", cid, err)
		return
	}
	if st := s.membraneStore(); st != nil {
		if err := st.Reload(); err != nil {
			log.Printf("[membrane] destroy company %d: reload: %v", cid, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":      "purged " + strconv.Itoa(n) + " entries (audited), but the in-memory store did not reload; restart the server",
				"company_id": cid, "purged": n})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"company_id": cid, "purged": n})
}

var _ membrane.EvidenceSource = (*db.DB)(nil)
