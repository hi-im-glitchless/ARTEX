package membrane

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// fakePersistence mimics the db upsert and block allocation semantics in memory.
type fakePersistence struct {
	mu      sync.Mutex
	entries []db.MembraneEntry
	blocks  []db.MembraneBlock
	inserts int
}

func (f *fakePersistence) InsertMembraneEntry(e *db.MembraneEntry) (db.MembraneEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inserts++
	for i := range f.entries {
		x := &f.entries[i]
		if x.Kind == e.Kind && x.OriginalHMAC == e.OriginalHMAC {
			x.CompanyIDs = mergeIDs(x.CompanyIDs, e.CompanyIDs)
			x.TaskIDs = mergeIDs(x.TaskIDs, e.TaskIDs)
			return *x, nil
		}
	}
	for _, x := range f.entries {
		if x.Alias == e.Alias {
			return db.MembraneEntry{}, errors.New("duplicate alias")
		}
	}
	n := *e
	n.ID = int64(len(f.entries) + 1)
	if n.Source == "" {
		n.Source = "auto"
	}
	n.OriginalEnc = append([]byte(nil), e.OriginalEnc...)
	f.entries = append(f.entries, n)
	return n, nil
}

func (f *fakePersistence) ListMembraneEntries() ([]db.MembraneEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]db.MembraneEntry(nil), f.entries...), nil
}

func (f *fakePersistence) AllocateMembraneBlock(realPrefix string, bits int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.blocks {
		if b.RealPrefix == realPrefix {
			return b.AliasPrefix, nil
		}
	}
	size := uint64(1) << (32 - uint(bits))
	for start := uint64(0xF0000000); start+size-1 <= 0xFFFFFFFF; start += size {
		clash := false
		for _, b := range f.blocks {
			p := netip.MustParsePrefix(b.AliasPrefix)
			lo := uint64(addrToU32(p.Addr()))
			hi := lo + 1<<(32-uint(p.Bits())) - 1
			if start <= hi && lo <= start+size-1 {
				clash = true
				break
			}
		}
		if !clash {
			a := fmt.Sprintf("%d.%d.%d.%d/%d", start>>24&0xFF, start>>16&0xFF, start>>8&0xFF, start&0xFF, bits)
			f.blocks = append(f.blocks, db.MembraneBlock{RealPrefix: realPrefix, AliasPrefix: a, Bits: bits})
			return a, nil
		}
	}
	return "", errors.New("exhausted")
}

func (f *fakePersistence) ListMembraneBlocks() ([]db.MembraneBlock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]db.MembraneBlock(nil), f.blocks...), nil
}

func mergeIDs(a, b []int64) []int64 {
	seen := map[int64]bool{}
	var out []int64
	for _, x := range append(append([]int64(nil), a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

var (
	testEncKey  = bytes.Repeat([]byte{0x11}, 32)
	testHMACKey = bytes.Repeat([]byte{0x22}, 32)
	seedProv    = Provenance{CompanyIDs: []int64{1}, TaskIDs: []int64{7}, Source: "seed"}
)

func newTestStore(t *testing.T) (*Store, *fakePersistence) {
	t.Helper()
	p := &fakePersistence{}
	s, err := OpenStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestEnrollIdempotent(t *testing.T) {
	s, p := newTestStore(t)
	a1, err := s.Enroll(KindDomain, "acmebank.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{6}\.example$`).MatchString(a1) {
		t.Fatalf("bad root alias %q", a1)
	}
	a2, err := s.Enroll(KindDomain, "AcmeBank.PT.", seedProv)
	if err != nil || a2 != a1 {
		t.Fatalf("not idempotent: %q %q %v", a1, a2, err)
	}
	if len(p.entries) != 1 {
		t.Fatalf("want 1 row, got %d", len(p.entries))
	}
	// Reopening from the same rows yields the same alias without a new insert.
	s2, err := OpenStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if a, k, ok := s2.AliasFor("acmebank.pt"); !ok || a != a1 || k != KindDomain {
		t.Fatalf("reopen AliasFor = %q %q %v", a, k, ok)
	}
	if o, k, ok := s2.OriginalFor(a1); !ok || o != "acmebank.pt" || k != KindDomain {
		t.Fatalf("reopen OriginalFor = %q %q %v", o, k, ok)
	}
	if got := s2.Roots(); len(got) != 1 || got[0] != "acmebank.pt" {
		t.Fatalf("Roots = %v", got)
	}
	// Originals are never stored in clear.
	for _, e := range p.entries {
		if bytes.Contains(e.OriginalEnc, []byte("acmebank")) || strings.Contains(e.OriginalHMAC, "acmebank") {
			t.Fatal("original stored in clear")
		}
	}
}

func TestEnrollSubdomainKeepsLabels(t *testing.T) {
	s, _ := newTestStore(t)
	sub, err := s.Enroll(KindDomain, "portal.acmebank.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	root, _, ok := s.AliasFor("acmebank.pt")
	if !ok {
		t.Fatal("root not enrolled with subdomain")
	}
	if sub != "portal."+root {
		t.Fatalf("sub alias %q, root %q", sub, root)
	}
	// Keyword labels are replaced with the lowercase keyword alias.
	kw, err := s.Enroll(KindOrg, "AcmeBank", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	vpn, err := s.Enroll(KindDomain, "acmebank-vpn.acmebank.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if vpn != strings.ToLower(kw)+"-vpn."+root {
		t.Fatalf("keyword label alias %q (kw %q)", vpn, kw)
	}
}

func TestEnrollEmail(t *testing.T) {
	s, _ := newTestStore(t)
	a, err := s.Enroll(KindEmail, "Joao.Silva@AcmeBank.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	root, _, _ := s.AliasFor("acmebank.pt")
	if !regexp.MustCompile(`^user-[0-9a-f]{4}@` + regexp.QuoteMeta(root) + `$`).MatchString(a) {
		t.Fatalf("email alias %q", a)
	}
	g, err := s.Enroll(KindEmail, "someone@gmail.com", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^u-[0-9a-f]{4}@gmail\.com$`).MatchString(g) {
		t.Fatalf("free-mail alias %q", g)
	}
}

func TestEnrollConcurrent(t *testing.T) {
	s, p := newTestStore(t)
	const n = 50
	var wg sync.WaitGroup
	aliases := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			aliases[i], errs[i] = s.Enroll(KindDomain, "portal.acmebank.pt", seedProv)
			_ = s.Dictionary().FindAll("portal.acmebank.pt")
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if aliases[i] != aliases[0] {
			t.Fatalf("divergent aliases %q vs %q", aliases[i], aliases[0])
		}
	}
	if len(p.entries) != 2 { // subdomain + root
		t.Fatalf("want 2 rows, got %d", len(p.entries))
	}
}

func TestKeywordCollisionRehash(t *testing.T) {
	s, _ := newTestStore(t)
	s.keywordAlias = func(kind Kind, term string, attempt int) string {
		if attempt == 0 {
			return strings.ToUpper(string(kind)) + "-0000"
		}
		return fmt.Sprintf("%s-%04x", strings.ToUpper(string(kind)), attempt)
	}
	a, err := s.Enroll(KindOrg, "Acme", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Enroll(KindOrg, "Globex", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if a != "ORG-0000" || b == a {
		t.Fatalf("collision not resolved: %q %q", a, b)
	}
	if o, _, _ := s.OriginalFor(b); o != "Globex" {
		t.Fatalf("OriginalFor(%q) = %q", b, o)
	}
	if o, _, _ := s.OriginalFor("org-0000"); o != "Acme" {
		t.Fatalf("case-insensitive keyword reverse = %q", o)
	}
}

func TestKeywordCollisionRehashDeterministic(t *testing.T) {
	// With the real deriver, a second store over the same rows re-derives
	// identically and returns the persisted aliases.
	s, p := newTestStore(t)
	want := map[string]string{}
	for i := 0; i < 300; i++ {
		term := fmt.Sprintf("brand%d", i)
		a, err := s.Enroll(KindProduct, term, seedProv)
		if err != nil {
			t.Fatal(err)
		}
		want[term] = a
	}
	seen := map[string]bool{}
	for _, a := range want {
		if seen[a] {
			t.Fatalf("duplicate alias %q", a)
		}
		seen[a] = true
	}
	s2, err := OpenStore(p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	for term, a := range want {
		if got, _, _ := s2.AliasFor(term); got != a {
			t.Fatalf("%s: %q != %q", term, got, a)
		}
	}
}

func TestIPv4BlockPreservesLastOctet(t *testing.T) {
	s, _ := newTestStore(t)
	ip := netip.MustParseAddr("185.12.40.17")
	a, err := s.IPv4Alias(ip, seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("240.0.0.0/4").Contains(a) || a.As4()[3] != 17 {
		t.Fatalf("alias %v", a)
	}
	b, _ := s.IPv4Alias(netip.MustParseAddr("185.12.40.99"), seedProv)
	if b.As4()[0] != a.As4()[0] || b.As4()[1] != a.As4()[1] || b.As4()[2] != a.As4()[2] || b.As4()[3] != 99 {
		t.Fatalf("same /24 not same block: %v %v", a, b)
	}
	if r, ok := s.IPv4Real(a); !ok || r != ip {
		t.Fatalf("IPv4Real(%v) = %v %v", a, r, ok)
	}
	// Any host inside an allocated block reverses, enrolled or not.
	h := netip.AddrFrom4([4]byte{a.As4()[0], a.As4()[1], a.As4()[2], 55})
	if r, ok := s.IPv4Real(h); !ok || r != netip.MustParseAddr("185.12.40.55") {
		t.Fatalf("IPv4Real(%v) = %v %v", h, r, ok)
	}
	if _, ok := s.IPv4Real(netip.MustParseAddr("250.1.2.3")); ok {
		t.Fatal("unallocated block reversed")
	}
	// Non-public addresses are not aliased.
	for _, x := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.1.1", "192.168.1.1", "240.0.0.9"} {
		ad := netip.MustParseAddr(x)
		got, err := s.IPv4Alias(ad, seedProv)
		if err != nil || got != ad {
			t.Fatalf("%s aliased to %v (%v)", x, got, err)
		}
	}
	// Enroll(KindIPv4) is the same path.
	e, err := s.Enroll(KindIPv4, "185.12.40.17", seedProv)
	if err != nil || e != a.String() {
		t.Fatalf("Enroll ipv4 = %q %v", e, err)
	}
	if r, ok := s.CIDRReal(netip.PrefixFrom(a, 24).Masked()); !ok || r != netip.MustParsePrefix("185.12.40.0/24") {
		t.Fatalf("CIDRReal /24 = %v %v", r, ok)
	}
	if r, ok := s.CIDRReal(netip.PrefixFrom(a, 28).Masked()); !ok || r != netip.MustParsePrefix("185.12.40.16/28") {
		t.Fatalf("CIDRReal /28 = %v %v", r, ok)
	}
	if _, ok := s.CIDRReal(netip.PrefixFrom(a, 16).Masked()); ok {
		t.Fatal("CIDRReal wider than block reversed")
	}
}

func TestSeedCIDRAfterIPKeepsOldAlias(t *testing.T) {
	s, _ := newTestStore(t)
	old, err := s.IPv4Alias(netip.MustParseAddr("185.12.40.17"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SeedCIDR(netip.MustParsePrefix("185.12.40.0/22"), seedProv); err != nil {
		t.Fatal(err)
	}
	again, _ := s.IPv4Alias(netip.MustParseAddr("185.12.40.17"), seedProv)
	if again != old {
		t.Fatalf("old alias changed %v -> %v", old, again)
	}
	other, _ := s.IPv4Alias(netip.MustParseAddr("185.12.40.200"), seedProv)
	if other.As4()[2] != old.As4()[2] || other.As4()[3] != 200 {
		t.Fatalf("pre-existing /24 block not kept: %v vs %v", other, old)
	}
	n, err := s.IPv4Alias(netip.MustParseAddr("185.12.41.5"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	var wide netip.Prefix
	for _, b := range s.blocksSnapshot() {
		if b.real == netip.MustParsePrefix("185.12.40.0/22") {
			wide = b.alias
		}
	}
	if !wide.IsValid() || wide.Bits() != 22 || wide.Masked() != wide {
		t.Fatalf("wide block %v", wide)
	}
	want := netip.AddrFrom4([4]byte{wide.Addr().As4()[0], wide.Addr().As4()[1], wide.Addr().As4()[2] + 1, 5})
	if n != want {
		t.Fatalf("185.12.41.5 -> %v, want %v (block %v)", n, want, wide)
	}
	if r, ok := s.IPv4Real(n); !ok || r != netip.MustParseAddr("185.12.41.5") {
		t.Fatalf("IPv4Real(%v) = %v", n, r)
	}
	if r, ok := s.CIDRReal(wide); !ok || r != netip.MustParsePrefix("185.12.40.0/22") {
		t.Fatalf("CIDRReal(wide) = %v %v", r, ok)
	}
	if _, ok := s.CIDRReal(netip.PrefixFrom(wide.Addr(), 23)); ok {
		t.Fatal("CIDRReal of a /23 inside the wide block must not reverse")
	}
	// Reopen: block state survives.
	s2, err := OpenStore(s.p, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := s2.IPv4Alias(netip.MustParseAddr("185.12.42.9"), seedProv); !wide.Contains(x) {
		t.Fatalf("after reopen %v not in %v", x, wide)
	}
}

func TestOpenStoreFailsOnWrongKey(t *testing.T) {
	s, p := newTestStore(t)
	if _, err := s.Enroll(KindPassword, "hunter2!", seedProv); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(p, bytes.Repeat([]byte{0x33}, 32), testHMACKey); err == nil {
		t.Fatal("wrong enc key accepted")
	}
	if _, err := OpenStore(p, testEncKey, bytes.Repeat([]byte{0x44}, 32)); err == nil {
		t.Fatal("wrong hmac key accepted")
	}
	if _, err := OpenStore(p, []byte("short"), testHMACKey); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestAutomatonCaseInsensitiveDomainsExactSecrets(t *testing.T) {
	s, _ := newTestStore(t)
	mustEnroll := func(k Kind, v string) string {
		a, err := s.Enroll(k, v, seedProv)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	dom := mustEnroll(KindDomain, "acmebank.pt")
	pw := mustEnroll(KindPassword, "S3cretPass")
	mustEnroll(KindOrg, "Acme Bank")
	mustEnroll(KindUsername, "admin") // stoplisted: not in the automaton
	mustEnroll(KindOrg, "XY")         // too short: not in the automaton

	text := "Visit ACMEBANK.PT now; login admin / S3cretPass, not s3cretpass. acme bank says xy."
	ms := s.Dictionary().FindAll(text)
	got := map[string]Match{}
	for _, m := range ms {
		got[text[m.Start:m.End]] = m
	}
	if m, ok := got["ACMEBANK.PT"]; !ok || m.Kind != KindDomain || m.Original != "acmebank.pt" || m.Alias != dom {
		t.Fatalf("domain match missing/wrong: %+v (all %+v)", m, ms)
	}
	if m, ok := got["S3cretPass"]; !ok || m.Kind != KindPassword || m.Alias != pw {
		t.Fatalf("secret exact match missing: %+v", ms)
	}
	if _, ok := got["s3cretpass"]; ok {
		t.Fatal("secret matched case-insensitively")
	}
	if m, ok := got["acme bank"]; !ok || m.Original != "Acme Bank" {
		t.Fatalf("keyword case-insensitive match missing: %+v", ms)
	}
	if _, ok := got["admin"]; ok {
		t.Fatal("stoplisted word in automaton")
	}
	if _, ok := got["xy"]; ok {
		t.Fatal("short term in automaton")
	}
	// Stoplisted/short entries stay in the store for exact lookup.
	if _, _, ok := s.AliasFor("admin"); !ok {
		t.Fatal("stoplisted entry not in store")
	}
	// Snapshot isolation: an older snapshot is unaffected by later enrolment.
	old := s.Dictionary()
	mustEnroll(KindProduct, "AcmeOnline")
	if len(old.FindAll("AcmeOnline")) != 0 || len(s.Dictionary().FindAll("acmeonline")) != 1 {
		t.Fatal("snapshot not copy-on-write")
	}
}

func TestAutomatonLongestMatch(t *testing.T) {
	s, _ := newTestStore(t)
	for _, v := range []string{"acme", "acmebank", "portal.acmebank.pt"} {
		k := KindOrg
		if strings.Contains(v, ".") {
			k = KindDomain
		}
		if _, err := s.Enroll(k, v, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	text := "go to https://portal.acmebank.pt/ and ask acmebank"
	ms := s.Dictionary().FindAll(text)
	var spans []string
	for _, m := range ms {
		spans = append(spans, text[m.Start:m.End])
	}
	if strings.Join(spans, "|") != "portal.acmebank.pt|acmebank" {
		t.Fatalf("spans = %v", spans)
	}
}

func TestModelKnown(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Enroll(KindDomain, "acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	s.MarkModelKnown("Example-Vendor.com.")
	if !s.IsModelKnown("example-vendor.com") {
		t.Fatal("not model-known")
	}
	s.MarkModelKnown("evil.acmebank.pt")
	if s.IsModelKnown("evil.acmebank.pt") {
		t.Fatal("protected root subdomain reported model-known")
	}
}

func TestLoadKeys(t *testing.T) {
	t.Setenv("ARTEX_MEMBRANE_KEY", "")
	t.Setenv("ARTEX_MEMBRANE_HMAC_KEY", "")
	dir := t.TempDir()
	enc, mac, src, err := LoadKeysSource(dir)
	if err != nil || src != KeysGenerated || len(enc) != 32 || len(mac) != 32 || bytes.Equal(enc, mac) {
		t.Fatalf("generate: %v %v", src, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "membrane.keys"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v %v", fi, err)
	}
	enc2, mac2, src, err := LoadKeysSource(dir)
	if err != nil || src != KeysFile || !bytes.Equal(enc, enc2) || !bytes.Equal(mac, mac2) {
		t.Fatalf("reload: %v %v", src, err)
	}
	if e3, m3, err := LoadKeys(dir); err != nil || !bytes.Equal(e3, enc) || !bytes.Equal(m3, mac) {
		t.Fatalf("LoadKeys: %v", err)
	}

	k1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	t.Setenv("ARTEX_MEMBRANE_KEY", k1)
	t.Setenv("ARTEX_MEMBRANE_HMAC_KEY", k2)
	enc, mac, src, err = LoadKeysSource(dir)
	if err != nil || src != KeysEnv || enc[0] != 1 || mac[0] != 2 {
		t.Fatalf("env: %v %v", src, err)
	}
	t.Setenv("ARTEX_MEMBRANE_HMAC_KEY", "")
	if _, _, _, err := LoadKeysSource(dir); err == nil {
		t.Fatal("only one env var set must be an error")
	}
	t.Setenv("ARTEX_MEMBRANE_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, _, _, err := LoadKeysSource(dir); err == nil {
		t.Fatal("short env key accepted")
	}

	t.Setenv("ARTEX_MEMBRANE_KEY", "")
	t.Setenv("ARTEX_MEMBRANE_HMAC_KEY", "")
	if err := os.Chmod(filepath.Join(dir, "membrane.keys"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadKeysSource(dir); err == nil {
		t.Fatal("world-readable key file accepted")
	}
}
