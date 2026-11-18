package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

func membraneAPICall(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	mux := http.NewServeMux()
	s.registerMembraneRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func countMembraneEntries(t *testing.T, m *Manager) int {
	t.Helper()
	var n int
	if err := m.pg.QueryRow(`SELECT count(*) FROM membrane_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStatusEndpoint(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, _ := newMembraneTestServer(t)
	w := membraneAPICall(t, s, "GET", "/api/membrane/status", nil)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var st MembraneStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.KeysSource != "env" || st.Entries != s.membraneStore().Len() {
		t.Fatalf("status = %+v", st)
	}
}

type previewResp struct {
	Aliased string `json:"aliased"`
	Spans   []struct {
		Start, End int
		Kind       string `json:"kind"`
		State      string `json:"state"`
	} `json:"spans"`
	Suspicious []struct {
		Start, End int
		Text       string `json:"text"`
	} `json:"suspicious"`
}

// utf16Slice returns s[start:end] in UTF-16 code units (JS string indices).
func utf16Slice(s string, start, end int) string {
	u := utf16.Encode([]rune(s))
	if start < 0 || end > len(u) || start > end {
		return "<out of range>"
	}
	return string(utf16.Decode(u[start:end]))
}

func TestPreviewDoesNotEnroll(t *testing.T) {
	f := newSeedFixture(t)
	st := f.s.membraneStore()
	// "Préview 😀: log in to " is 22 UTF-16 code units (é is one unit, the
	// emoji a surrogate pair) but 25 bytes.
	text := "Préview 😀: log in to portal.acmebank.pt as joao.silva / hunter2 for Acme Bank, " +
		"host 185.12.40.7, contact Maria Fernandes at maria@acmebank.pt."
	beforeLen, beforeRows := st.Len(), countMembraneEntries(t, f.m)
	var beforeBlocks int
	_ = f.m.pg.QueryRow(`SELECT count(*) FROM membrane_ip_blocks`).Scan(&beforeBlocks)

	w := membraneAPICall(t, f.s, "POST", "/api/membrane/preview",
		map[string]any{"text": text, "companyIds": []int64{f.cid}, "taskId": f.taskID})
	if w.Code != 200 {
		t.Fatalf("preview %d: %s", w.Code, w.Body)
	}
	var got previewResp
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"acmebank", "Acme Bank", "joao.silva", "hunter2", "185.12.40.7"} {
		if strings.Contains(got.Aliased, o) {
			t.Errorf("preview output still holds an original (len %d)", len(o))
		}
	}
	if len(got.Spans) < 5 {
		t.Fatalf("spans = %+v", got.Spans)
	}
	for _, sp := range got.Spans {
		a := utf16Slice(got.Aliased, sp.Start, sp.End)
		if sp.State != "replaced" || a == "" || strings.Contains(a, "acmebank") {
			t.Errorf("span %+v -> %q", sp, a)
		}
	}
	found := false
	for _, sp := range got.Suspicious {
		if utf16Slice(got.Aliased, sp.Start, sp.End) != sp.Text {
			t.Errorf("suspicious span %+v does not index the aliased text", sp)
		}
		if sp.Text == "Maria Fernandes" {
			found = true
		}
	}
	if !found {
		t.Errorf("suspicious = %+v, want the unknown name", got.Suspicious)
	}
	var afterBlocks int
	_ = f.m.pg.QueryRow(`SELECT count(*) FROM membrane_ip_blocks`).Scan(&afterBlocks)
	if st.Len() != beforeLen || countMembraneEntries(t, f.m) != beforeRows || afterBlocks != beforeBlocks {
		t.Fatalf("preview enrolled: store %d->%d rows %d->%d blocks %d->%d", beforeLen, st.Len(),
			beforeRows, countMembraneEntries(t, f.m), beforeBlocks, afterBlocks)
	}

	// The real run (seed sync, then the transform) produces the same text.
	companies, err := f.s.SyncTask(context.Background(), f.id())
	if err != nil {
		t.Fatal(err)
	}
	real, _, err := f.s.membraneEngine().ToModel(text, membrane.Provenance{CompanyIDs: companies, TaskIDs: []int64{f.taskID}})
	if err != nil {
		t.Fatal(err)
	}
	if real != got.Aliased {
		t.Fatalf("preview differs from the real run:\n preview %q\n real    %q", got.Aliased, real)
	}
	// Exact UTF-16 offsets of the host alias.
	host, _, ok := f.s.membraneStore().AliasFor("portal.acmebank.pt")
	if !ok || !strings.HasPrefix(got.Aliased[25:], host) {
		t.Fatalf("host alias not at byte 25 of %q", got.Aliased)
	}
	hostLen := len(utf16.Encode([]rune(host)))
	if got.Spans[0].Start != 22 || got.Spans[0].End != 22+hostLen || got.Spans[0].Kind != "domain" {
		t.Fatalf("first span = %+v, want {22 %d domain}", got.Spans[0], 22+hostLen)
	}
}

func TestDestroyRefusedWhileReferenced(t *testing.T) {
	f := newSeedFixture(t)
	if _, err := f.s.SyncTask(context.Background(), f.id()); err != nil {
		t.Fatal(err)
	}
	before := countMembraneEntries(t, f.m)
	w := membraneAPICall(t, f.s, "POST", fmt.Sprintf("/api/companies/%d/membrane/destroy", f.cid), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("destroy %d: %s", w.Code, w.Body)
	}
	var body struct {
		References map[string]int `json:"references"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.References["tasks"] < 1 || body.References["scope"] < 1 || body.References["company"] != 1 {
		t.Fatalf("references = %v", body.References)
	}
	if countMembraneEntries(t, f.m) != before {
		t.Fatal("a refused destroy purged entries")
	}
	if _, _, ok := f.s.membraneStore().AliasFor("acmebank.pt"); !ok {
		t.Fatal("a refused destroy dropped entries from memory")
	}
}

func TestDestroyPurges(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE", "")
	membraneTestKeys(t)
	s, m := newMembraneTestServer(t)
	cs := m.pg.Companies()
	const name = "Destroy Membrane Co"
	if old, _ := cs.GetCompanyByName(name); old != nil {
		_ = cs.DeleteCompany(old.ID)
	}
	cid, _, err := cs.UpsertCompany(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM membrane_entries WHERE $1::bigint = ANY(company_ids)`, cid)
		_ = cs.DeleteCompany(cid)
	})
	st := s.membraneStore()
	prov := membrane.Provenance{CompanyIDs: []int64{cid}, Source: "seed"}
	if _, err := st.EnrollRoot("destroyco-membrane.com", prov); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enroll(membrane.KindOrg, "DestroyCoKeyword", prov); err != nil {
		t.Fatal(err)
	}
	// The company row itself is a reference (a re-seed would undo the
	// destroy): refused until it is deleted.
	if w := membraneAPICall(t, s, "POST", fmt.Sprintf("/api/companies/%d/membrane/destroy", cid), nil); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), `"company":1`) {
		t.Fatalf("destroy with the company row present: %d %s", w.Code, w.Body)
	}
	if err := cs.DeleteCompany(cid); err != nil {
		t.Fatal(err)
	}
	head0, err := m.pg.MembraneChainHeadNow()
	if err != nil {
		t.Fatal(err)
	}

	w := membraneAPICall(t, s, "POST", fmt.Sprintf("/api/companies/%d/membrane/destroy", cid), nil)
	if w.Code != 200 {
		t.Fatalf("destroy %d: %s", w.Code, w.Body)
	}
	var body struct {
		CompanyID int64 `json:"company_id"`
		Purged    int   `json:"purged"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CompanyID != cid || body.Purged < 2 {
		t.Fatalf("destroy body = %+v", body)
	}
	for _, v := range []string{"destroyco-membrane.com", "DestroyCoKeyword"} {
		if _, _, ok := st.AliasFor(v); ok {
			t.Errorf("purged value still in the live store (len %d)", len(v))
		}
	}
	var left int
	_ = m.pg.QueryRow(`SELECT count(*) FROM membrane_entries WHERE $1::bigint = ANY(company_ids)`, cid).Scan(&left)
	if left != 0 {
		t.Fatalf("%d entries left", left)
	}
	evs, err := m.pg.MembraneEventsByDirection("destroy", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"company:" + strconv.FormatInt(cid, 10), "purged:" + strconv.Itoa(body.Purged)}
	if !slices.ContainsFunc(evs, func(e db.MembraneEvent) bool { return slices.Equal(e.Flags, want) && e.ID > head0.LastID }) {
		t.Fatalf("no destroy audit event with flags %v in %+v", want, evs)
	}
}

func TestMembraneAPIEventsVerifyEvidence(t *testing.T) {
	f := newSeedFixture(t)
	if _, err := f.s.SyncTask(context.Background(), f.id()); err != nil {
		t.Fatal(err)
	}
	e := f.s.membraneEngine()
	clean, _, err := e.ToModel("call portal.acmebank.pt as joao.silva / hunter2", membrane.Provenance{TaskIDs: []int64{f.taskID}})
	if err != nil {
		t.Fatal(err)
	}
	const profile = "t-membrane-api-profile"
	audit := f.s.membraneAuditor()
	for _, ev := range []membrane.Event{
		{TaskID: f.id(), Profile: profile, Direction: "request", RequestSHA256: strings.Repeat("a", 64),
			Report: membrane.Report{Counts: map[membrane.Kind]int{membrane.KindDomain: 1}, Enrolled: 1}},
		{TaskID: f.id(), Profile: profile, Direction: "request", RequestSHA256: strings.Repeat("b", 64)},
		{TaskID: f.id(), Profile: profile, Direction: "request", Blocked: true, BlockReason: "leak check: password@3"},
	} {
		if err := audit.Record(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	raw := func(s string) string { b, _ := json.Marshal(map[string]any{"messages": []string{s}}); return string(b) }
	var ids []int64
	for _, r := range []db.LLMRecord{
		{TaskID: f.id(), ProfileName: profile, Model: "m", RequestBody: "operator view acmebank.pt", RawRequest: raw(clean),
			MembraneRequestSHA256: strings.Repeat("a", 64)},
		{TaskID: f.id(), ProfileName: "", Model: "m", RawRequest: raw("leaked hunter2 here"), MembraneRequestSHA256: strings.Repeat("b", 64)},
		{TaskID: f.id(), ProfileName: "local-trusted", Model: "m", RawRequest: raw("local model sees acmebank.pt")},
	} {
		if err := f.m.pg.InsertLLMRecord(&r); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = f.m.pg.DeleteLLMRecords(f.id()) })
	recs, _ := f.m.pg.LLMRawRequests(f.id(), 0, 10)
	for _, r := range recs {
		ids = append(ids, r.ID)
	}

	w := membraneAPICall(t, f.s, "GET", "/api/tasks/"+f.id()+"/membrane/events?page=1&size=2", nil)
	if w.Code != 200 {
		t.Fatalf("events %d: %s", w.Code, w.Body)
	}
	var evs struct {
		Events []map[string]any `json:"events"`
		Total  int              `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &evs)
	if evs.Total != 3 || len(evs.Events) != 2 || evs.Events[0]["direction"] != "request" {
		t.Fatalf("events = %+v", evs)
	}

	w = membraneAPICall(t, f.s, "POST", "/api/tasks/"+f.id()+"/membrane/verify", nil)
	if w.Code != 200 {
		t.Fatalf("verify %d: %s", w.Code, w.Body)
	}
	var vr membrane.VerifyResult
	_ = json.Unmarshal(w.Body.Bytes(), &vr)
	if vr.Result != membrane.VerifyFail || vr.Checked != 2 || vr.Failed != 1 || !slices.Equal(vr.FailedIDs, []int64{ids[1]}) ||
		vr.Unmembraned != 1 || vr.Forwarded != 2 || vr.Paired != 2 || !vr.ChainOK {
		t.Fatalf("verify = %+v (ids %v)", vr, ids)
	}
	if strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "acmebank") {
		t.Fatal("verify response carries an original")
	}

	for _, format := range []string{"md", "json"} {
		w = membraneAPICall(t, f.s, "GET", "/api/tasks/"+f.id()+"/membrane/evidence?format="+format, nil)
		if w.Code != 200 {
			t.Fatalf("evidence %s %d: %s", format, w.Code, w.Body)
		}
		out := w.Body.String()
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
			t.Fatalf("%s evidence leak hits %v", format, hits)
		}
		for _, o := range []string{"acmebank", "Acme Bank", "joao.silva", "hunter2", "AcmeOnline"} {
			if strings.Contains(out, o) {
				t.Fatalf("%s evidence contains an original (len %d)", format, len(o))
			}
		}
		if !strings.Contains(out, strconv.FormatInt(ids[1], 10)) || !strings.Contains(out, "raw-bytes") {
			t.Fatalf("%s evidence lacks the failed id or proof level:\n%s", format, out)
		}
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("json evidence content type %q", w.Header().Get("Content-Type"))
	}
}

// Every boot appends a "start" event saying whether the override is on.
func TestMembraneAPIStartEventEveryBoot(t *testing.T) {
	membraneTestKeys(t)
	last := func(m *Manager) []string {
		ev, err := m.pg.MembraneLastEventAtOrBefore(membrane.DirectionStart, time.Now().Add(time.Hour))
		if err != nil || ev == nil {
			t.Fatalf("no start event: %v", err)
		}
		return ev.Flags
	}
	t.Setenv("ARTEX_MEMBRANE", "")
	_, m := newMembraneTestServer(t)
	if f := last(m); !slices.Equal(f, []string{membrane.StartFlagMembraned}) {
		t.Fatalf("membraned boot flags = %v", f)
	}
	t.Setenv("ARTEX_MEMBRANE", "off")
	_, m = newMembraneTestServer(t)
	if f := last(m); !slices.Equal(f, []string{membrane.StartFlagOverride}) {
		t.Fatalf("override boot flags = %v", f)
	}
}
