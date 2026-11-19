package db

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

func membraneTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestMembraneEntryUpsertMergesProvenance(t *testing.T) {
	d := membraneTestDB(t)
	hmac := fmt.Sprintf("hmac-upsert-%d", time.Now().UnixNano())
	alias := "alias-" + hmac
	t.Cleanup(func() { d.Exec(`DELETE FROM membrane_entries WHERE original_hmac=$1`, hmac) })

	first, err := d.InsertMembraneEntry(&MembraneEntry{
		Kind: "domain", OriginalHMAC: hmac, OriginalEnc: []byte{1, 2, 3},
		Alias: alias, Source: "seed", CompanyIDs: []int64{1}, TaskIDs: []int64{10},
	})
	if err != nil || first.ID == 0 {
		t.Fatalf("first insert: %+v %v", first, err)
	}
	second, err := d.InsertMembraneEntry(&MembraneEntry{
		Kind: "domain", OriginalHMAC: hmac, OriginalEnc: []byte{9},
		Alias: "other-alias", Source: "auto", CompanyIDs: []int64{1, 2}, TaskIDs: []int64{11},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Alias != alias || !reflect.DeepEqual(second.OriginalEnc, []byte{1, 2, 3}) {
		t.Fatalf("conflict must return the existing row: %+v", second)
	}
	if !reflect.DeepEqual(second.CompanyIDs, []int64{1, 2}) || !reflect.DeepEqual(second.TaskIDs, []int64{10, 11}) {
		t.Fatalf("provenance not merged: %+v", second)
	}
	var found bool
	list, err := d.ListMembraneEntries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.ID == first.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("entry missing from list")
	}
}

func TestMembraneEntryUpdateAliasRetiresOld(t *testing.T) {
	d := membraneTestDB(t)
	hmac := fmt.Sprintf("hmac-remint-%d", time.Now().UnixNano())
	t.Cleanup(func() { d.Exec(`DELETE FROM membrane_entries WHERE original_hmac=$1`, hmac) })
	e, err := d.InsertMembraneEntry(&MembraneEntry{
		Kind: "domain", OriginalHMAC: hmac, OriginalEnc: []byte{1}, Alias: "a1-" + hmac,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.RetiredAliases) != 0 {
		t.Fatalf("new entry has retired aliases %v", e.RetiredAliases)
	}
	if err := d.UpdateMembraneEntryAlias(e.ID, "a2-"+hmac); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateMembraneEntryAlias(e.ID, "a2-"+hmac); err != nil { // no-op
		t.Fatal(err)
	}
	if err := d.UpdateMembraneEntryAlias(e.ID, "a3-"+hmac); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListMembraneEntries()
	if err != nil {
		t.Fatal(err)
	}
	var got *MembraneEntry
	for i := range list {
		if list[i].ID == e.ID {
			got = &list[i]
		}
	}
	if got == nil || got.Alias != "a3-"+hmac ||
		!reflect.DeepEqual(got.RetiredAliases, []string{"a1-" + hmac, "a2-" + hmac}) {
		t.Fatalf("after re-mint: %+v", got)
	}
	if err := d.UpdateMembraneEntryAlias(-1, "x-"+hmac); err == nil {
		t.Fatal("update of a missing entry must fail")
	}
}

func resetMembraneBlocks(d *DB, prefixes ...string) {
	for _, p := range prefixes {
		d.Exec(`DELETE FROM membrane_ip_blocks WHERE real_prefix=$1`, p)
	}
}

func TestAllocateBlockIdempotentAndAligned(t *testing.T) {
	d := membraneTestDB(t)
	ps := []string{"198.51.100.0/24", "198.51.101.0/24", "203.0.112.0/22"}
	resetMembraneBlocks(d, ps...)
	t.Cleanup(func() { resetMembraneBlocks(d, ps...) })

	a1, err := d.AllocateMembraneBlock(ps[0], 24)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := d.AllocateMembraneBlock(ps[0], 24)
	if err != nil || a1 != a2 {
		t.Fatalf("not idempotent: %q %q %v", a1, a2, err)
	}
	b, err := d.AllocateMembraneBlock(ps[1], 24)
	if err != nil || b == a1 {
		t.Fatalf("distinct /24s must differ: %q %q %v", a1, b, err)
	}
	c, err := d.AllocateMembraneBlock(ps[2], 22)
	if err != nil {
		t.Fatal(err)
	}
	var ip [4]int
	var bits int
	if _, err := fmt.Sscanf(c, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits); err != nil {
		t.Fatalf("bad alias %q: %v", c, err)
	}
	if bits != 22 || ip[0] < 240 || ip[2]%4 != 0 || ip[3] != 0 {
		t.Fatalf("/22 alias not aligned in 240/4: %q", c)
	}
	blocks, err := d.ListMembraneBlocks()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, bl := range blocks {
		if bl.RealPrefix == ps[0] && bl.AliasPrefix == a1 && bl.Bits == 24 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("block not listed exactly once: %+v", blocks)
	}
}

func TestEventChain(t *testing.T) {
	d := membraneTestDB(t)
	var ids []int64
	t.Cleanup(func() {
		// Test-only cleanup of rows this test appended; production code has no delete path.
		d.Exec(`DELETE FROM membrane_events WHERE task_id='chain-test'`)
	})
	for i := 0; i < 3; i++ {
		ev := &MembraneEvent{
			TaskID: "chain-test", Session: "s", Role: "worker", Profile: "p",
			Direction: "request", Counts: map[string]int{"domain": i + 1},
			Enrolled: i, Flags: []string{"f"}, RequestSHA256: "abc",
		}
		if err := d.AppendMembraneEvent(ev); err != nil {
			t.Fatal(err)
		}
		if ev.ID == 0 || ev.Hash == "" {
			t.Fatalf("event not filled: %+v", ev)
		}
		ids = append(ids, ev.ID)
	}
	ok, bad, err := d.VerifyMembraneChain()
	if err != nil || !ok || bad != 0 {
		t.Fatalf("clean chain must verify: ok=%v bad=%d err=%v", ok, bad, err)
	}
	evs, total, err := d.ListMembraneEvents("chain-test", 1, 10)
	if err != nil || total != 3 || len(evs) != 3 {
		t.Fatalf("list: %d %d %v", total, len(evs), err)
	}
	if _, err := d.Exec(`UPDATE membrane_events SET enrolled=99 WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	ok, bad, err = d.VerifyMembraneChain()
	if err != nil || ok || bad != ids[1] {
		t.Fatalf("tamper not detected at row 2: ok=%v bad=%d want=%d err=%v", ok, bad, ids[1], err)
	}
}

func TestPurgeRules(t *testing.T) {
	d := membraneTestDB(t)
	cs := d.Companies()
	c1, _, err := cs.UpsertCompany(fmt.Sprintf("mb-purge-a-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := cs.UpsertCompany(fmt.Sprintf("mb-purge-b-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.DeleteCompany(c1); cs.DeleteCompany(c2) })
	tk, err := d.CreateTask("purge test", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(tk.ID) })
	if _, err := d.Exec(`UPDATE tasks SET company_id=$1 WHERE id=$2`, c1, tk.ID); err != nil {
		t.Fatal(err)
	}

	tag := fmt.Sprintf("purge-%d", time.Now().UnixNano())
	t.Cleanup(func() { d.Exec(`DELETE FROM membrane_entries WHERE original_hmac LIKE $1`, tag+"%") })
	ins := func(name string, companies, tasks []int64) MembraneEntry {
		e, err := d.InsertMembraneEntry(&MembraneEntry{Kind: "domain", OriginalHMAC: tag + name,
			OriginalEnc: []byte{1}, Alias: tag + name, Source: "auto", CompanyIDs: companies, TaskIDs: tasks})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	only := ins("only", []int64{c1}, []int64{tk.ID})
	tk2, err := d.CreateTask("purge test other", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(tk2.ID) })
	if _, err := d.Exec(`UPDATE tasks SET company_id=$1 WHERE id=$2`, c2, tk2.ID); err != nil {
		t.Fatal(err)
	}
	foreignTask := ins("ftask", []int64{c1}, []int64{tk2.ID})
	// A task hard-deleted before the purge (guard passed): entry must be purged.
	gone, err := d.CreateTask("purge test gone", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	deleted := ins("deleted", []int64{c1}, []int64{gone.ID})
	if err := d.DeleteTask(gone.ID); err != nil {
		t.Fatal(err)
	}
	shared := ins("shared", []int64{c1, c2}, []int64{tk.ID})

	n, err := d.PurgeMembraneCompany(c1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	byID := map[int64]MembraneEntry{}
	list, _ := d.ListMembraneEntries()
	for _, e := range list {
		byID[e.ID] = e
	}
	if _, ok := byID[only.ID]; ok {
		t.Fatal("exclusive entry must be deleted")
	}
	if _, ok := byID[deleted.ID]; ok {
		t.Fatal("entry whose task was hard-deleted must be purged")
	}
	if e, ok := byID[foreignTask.ID]; !ok || len(e.CompanyIDs) != 0 {
		t.Fatalf("entry with foreign task must survive with company removed: %+v", e)
	}
	s, ok := byID[shared.ID]
	if !ok {
		t.Fatal("shared entry must survive")
	}
	got := append([]int64(nil), s.CompanyIDs...)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if !reflect.DeepEqual(got, []int64{c2}) {
		t.Fatalf("shared provenance not reduced: %+v", s.CompanyIDs)
	}

	refs, err := d.MembraneCompanyReferences(c1)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tasks", "assets", "findings", "lessons", "scope"} {
		if _, ok := refs[k]; !ok {
			t.Fatalf("missing key %q in %v", k, refs)
		}
	}
	if refs["tasks"] != 1 {
		t.Fatalf("tasks = %d, want 1", refs["tasks"])
	}
}

// Tasks are linked to companies through task_scope (kind company): the purge
// keeps entries of a task linked to another company that way, and the guard
// counts tasks linked that way.
func TestPurgeRulesTaskScopeCompany(t *testing.T) {
	d := membraneTestDB(t)
	cs := d.Companies()
	c1, _, err := cs.UpsertCompany(fmt.Sprintf("mb-purge-ts-a-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := cs.UpsertCompany(fmt.Sprintf("mb-purge-ts-b-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.DeleteCompany(c1); cs.DeleteCompany(c2) })
	tk, err := d.CreateTaskWithOptions("purge ts test", "g", TaskCreateOptions{CompanyIDs: []int64{c2}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(tk.ID) })
	tag := fmt.Sprintf("purge-ts-%d", time.Now().UnixNano())
	t.Cleanup(func() { d.Exec(`DELETE FROM membrane_entries WHERE original_hmac LIKE $1`, tag+"%") })
	e, err := d.InsertMembraneEntry(&MembraneEntry{Kind: "domain", OriginalHMAC: tag, OriginalEnc: []byte{1},
		Alias: tag, Source: "auto", CompanyIDs: []int64{c1}, TaskIDs: []int64{tk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PurgeMembraneCompany(c1); err != nil {
		t.Fatal(err)
	}
	list, _ := d.ListMembraneEntries()
	kept := false
	for _, x := range list {
		if x.ID == e.ID {
			kept = len(x.CompanyIDs) == 0
		}
	}
	if !kept {
		t.Fatal("entry of a task linked to another company (task_scope) must survive with the company removed")
	}
	refs, err := d.MembraneCompanyReferences(c2)
	if err != nil {
		t.Fatal(err)
	}
	if refs["tasks"] != 1 {
		t.Fatalf("guard must count a task linked through task_scope: %v", refs)
	}
}
