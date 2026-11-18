package membrane

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/publicsuffix"
)

// Every denylisted root is the registrable root of its tenants' hosts, so
// the exact-root check can match it.
func TestSharedTenantRootsAreRegistrable(t *testing.T) {
	for r := range sharedTenantRoots {
		got, err := publicsuffix.EffectiveTLDPlusOne("acme." + r)
		if err != nil || got != r {
			t.Errorf("%s: eTLD+1 of a tenant host is %q (dead entry)", r, got)
		}
	}
}

// Fix I-A: a shared root stored before the denylist (and a host under it)
// is quarantined on load: it is no root, does not alias, does not resolve
// and nothing derives under its old alias.
func TestStoredSharedRootQuarantined(t *testing.T) {
	s, p := newTestStore(t)
	if _, err := s.seedEnroll(KindDomain, "acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	// Simulate rows written by the pre-fix code.
	put := func(norm, alias string) {
		mac := s.indexHMAC(KindDomain, norm)
		enc, err := s.encrypt(KindDomain, mac, norm)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.InsertMembraneEntry(&db.MembraneEntry{Kind: string(KindDomain), OriginalHMAC: mac,
			OriginalEnc: enc, Alias: alias, Source: "seed"}); err != nil {
			t.Fatal(err)
		}
	}
	old := s.deriver.RootDomain("okta.com")
	put("okta.com", old)
	put("login.okta.com", "login."+old)
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(s, NewPipeline(s))
	if s.HasRoot("okta.com") || slices.Contains(s.Roots(), "okta.com") {
		t.Fatal("stored shared root still a root")
	}
	if _, _, ok := s.OriginalFor(old); ok {
		t.Fatal("old shared-root alias still resolves")
	}
	back, unres := e.ToReal("curl https://othercorp." + old + "/ ; subfinder -d " + old + " ; ping login." + old)
	if strings.Contains(back, "okta.com") || len(unres) == 0 {
		t.Fatalf("derived into a shared root: %q (unresolved %v)", back, unres)
	}
	out := toModel(t, e, "IdP https://login.okta.com and https://x.okta.com")
	if !strings.Contains(out, "login.okta.com") || !strings.Contains(out, "x.okta.com") {
		t.Fatalf("hosts under a quarantined root still aliased: %q", out)
	}
	if _, err := s.Enroll(KindDomain, "acme.okta.com", Provenance{Source: "auto"}); !errors.Is(err, ErrNotClientRoot) {
		t.Fatalf("enrol under a quarantined root: %v", err)
	}
	if !s.aliasTaken(old) {
		t.Fatal("quarantined alias may be minted again")
	}
	if !s.HasRoot("acmebank.pt") {
		t.Fatal("client root lost on reload")
	}
}

func TestLabelHasKeyword(t *testing.T) {
	kws := []string{"Acme Bank", "acmebank", "acme", "admin", "ab"}
	for label, want := range map[string]bool{
		"acmebank-online": true, // 5+ runes: substring
		"myacmebankapp":   true,
		"acme-cdn":        true, // short: whole token
		"acmeprod":        false,
		"admin":           false, // stoplisted
		"ab":              false, // too short
		"outlook":         false,
	} {
		if got := LabelHasKeyword(label, kws); got != want {
			t.Errorf("LabelHasKeyword(%q) = %v, want %v", label, got, want)
		}
	}
}
