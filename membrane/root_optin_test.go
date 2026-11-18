package membrane

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Task 9 fix C1: Enroll never makes a client root implicitly, so a
// third-party root (okta.com under acme.okta.com) cannot become alias space
// that derivation maps the model's hosts onto.
func TestEnrollNeverMintsRootImplicitly(t *testing.T) {
	e, s := newTestEngine(t)
	auto := Provenance{TaskIDs: []int64{9}, Source: "auto"}
	for _, h := range []string{"acme.okta.com", "okta.com", "AcmeProd.okta.com."} {
		if _, err := s.Enroll(KindDomain, h, auto); !errors.Is(err, ErrNotClientRoot) {
			t.Fatalf("Enroll(domain) without an enrolled root: err = %v", err)
		}
	}
	// An email on a third-party domain keeps the domain; only the local
	// part is aliased, and no root is created.
	a, err := s.Enroll(KindEmail, "jane.doe@vendor-mail.com", auto)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(a, "@vendor-mail.com") || strings.Contains(a, "jane") {
		t.Fatalf("third-party email alias = %q", a)
	}
	// ... with client literals in its labels still replaced.
	m, err := s.Enroll(KindEmail, "ops@acmebank.okta.com", auto)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(m), "acmebank") || !strings.HasSuffix(m, ".okta.com") {
		t.Fatalf("email on a keyword-bearing third-party host = %q", m)
	}
	// Free text: third-party emails and hosts do not create roots either.
	out := toModel(t, e, "mail support@okta.com, see https://login.okta.com and partner@cloudvendor.io")
	if !strings.Contains(out, "login.okta.com") || !strings.Contains(out, "@okta.com") {
		t.Fatalf("third-party host rewritten: %q", out)
	}
	for _, r := range []string{"okta.com", "vendor-mail.com", "cloudvendor.io"} {
		if s.HasRoot(r) || slices.Contains(s.Roots(), r) {
			t.Fatalf("third-party root %q became a client root", r)
		}
	}
	if !s.HasRoot("acmebank.pt") {
		t.Fatal("declared root missing")
	}
	// No root alias derives into the third party.
	for _, r := range s.Roots() {
		ra, _, _ := s.AliasFor(r)
		back, _ := e.ToReal("run subfinder -d " + ra + " and curl https://othercorp." + ra + "/")
		if strings.Contains(back, "okta.com") {
			t.Fatalf("derivation produced a third-party host: %q", back)
		}
	}
}

func TestEnrollRootOptIn(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.EnrollRoot("portal.acme.pt", seedProv); err == nil {
		t.Fatal("EnrollRoot must refuse a subdomain")
	}
	ra, err := s.EnrollRoot("Acme.PT", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasRoot("acme.pt") || !strings.HasSuffix(ra, ".example") {
		t.Fatalf("root alias %q", ra)
	}
	sub, err := s.Enroll(KindDomain, "portal.acme.pt", Provenance{Source: "auto"})
	if err != nil || sub != "portal."+ra {
		t.Fatalf("subdomain under an opted-in root: %q %v", sub, err)
	}
}
