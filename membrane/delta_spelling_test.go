package membrane

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// Final review N1: every text the forward dictionary matches for an entry
// must be one of that entry's change-log needles, or a cached ToModel or
// LeakCheck result over that text survives the enrolment that should have
// changed it.
func TestEntryChangeNeedlesCoverDictionarySpellings(t *testing.T) {
	e, s := newTestEngine(t)
	_ = e
	puny, err := idna.Punycode.ToASCII("bancoação.pt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollRoot(puny, Provenance{CompanyIDs: []int64{1}, Source: "seed"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		k Kind
		v string
	}{
		{KindPhone, "+351912345678"},
		{KindEmail, "carol@acmebank.pt"},
		{KindPerson, "Carolina Mendes"},
	} {
		if _, err := s.seedEnroll(v.k, v.v, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.RLock()
	pats := s.patternsLocked()
	entries := make([]*entry, 0, len(s.byKey))
	for _, en := range s.byKey {
		entries = append(entries, en)
	}
	s.mu.RUnlock()
	if len(pats) == 0 {
		t.Fatal("no dictionary patterns")
	}
	sawUnicode := false
	for _, p := range pats {
		if p.text == "bancoação.pt" {
			sawUnicode = true
		}
		var owner *entry
		for _, en := range entries {
			if en.alias == p.alias || slices.ContainsFunc(phoneVariants(en), func(v [2]string) bool { return v[1] == p.alias }) {
				owner = en
				break
			}
		}
		if owner == nil {
			t.Fatalf("pattern of kind %s has no owning entry", p.kind)
		}
		needles := entryChange(owner).needles
		if !slices.ContainsFunc(needles, func(n string) bool { return strings.EqualFold(n, p.text) }) {
			t.Errorf("%s entry: dictionary spelling (len %d) is not a change needle", owner.kind, len(p.text))
		}
	}
	if !sawUnicode {
		t.Fatal("IDN root did not produce its Unicode dictionary spelling (test premise)")
	}
}

// Final review N1 counterexample: enrolling an IDN root from its punycode
// form must invalidate cached ToModel and LeakCheck results over text that
// writes the domain in Unicode.
func TestIDNEnrolRootInvalidatesCachedResults(t *testing.T) {
	e, s := newTestEngine(t)
	puny, err := idna.Punycode.ToASCII("bancoação.pt")
	if err != nil {
		t.Fatal(err)
	}
	text := "login page at https://portal.bancoação.pt/entrar and bancoação.pt"
	prov := Provenance{TaskIDs: []int64{3}}
	before, _, err := e.ToModel(text, prov) // cached at the current generation
	if err != nil {
		t.Fatal(err)
	}
	oldBody, _ := json.Marshal(map[string]string{"t": before})
	if hits := e.LeakCheck(oldBody); len(hits) != 0 {
		t.Fatalf("premise: no leak before the domain is declared, got %v", hits)
	}

	if _, err := s.EnrollRoot(puny, Provenance{CompanyIDs: []int64{1}, Source: "seed"}); err != nil {
		t.Fatal(err)
	}
	after, _, err := e.ToModel(text, prov)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _, err := e.toModel(text, prov, false)
	if err != nil {
		t.Fatal(err)
	}
	if after != fresh {
		t.Fatalf("cached ToModel is stale after EnrollRoot: cached != fresh")
	}
	if strings.Contains(after, "bancoação") || strings.Contains(after, puny) {
		t.Fatal("declared IDN domain left in clear by ToModel")
	}
	// The body built before the enrolment, as a cache hit would send it.
	hits, full := e.LeakCheck(oldBody), e.leakCheckFull(string(oldBody))
	if len(full) == 0 {
		t.Fatal("premise: leakCheckFull must flag the Unicode domain")
	}
	if len(hits) != len(full) {
		t.Fatalf("cached LeakCheck is stale: %d hits, full scan %d", len(hits), len(full))
	}
}
