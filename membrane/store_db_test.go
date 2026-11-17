package membrane

import (
	"net/netip"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestOpenStoreRealDBRoundTrip(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no PostgreSQL DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	// The membrane test database is private to this package.
	if _, err := d.Exec(`DELETE FROM membrane_entries; DELETE FROM membrane_ip_blocks`); err != nil {
		t.Fatal(err)
	}
	var _ Persistence = d

	s, err := OpenStore(d, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.Enroll(KindDomain, "portal.acmebank.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := s.IPv4Alias(netip.MustParseAddr("185.12.40.17"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SeedCIDR(netip.MustParsePrefix("185.12.40.0/22"), seedProv); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(d, testEncKey, testHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if o, k, ok := s2.OriginalFor(sub); !ok || o != "portal.acmebank.pt" || k != KindDomain {
		t.Fatalf("OriginalFor = %q %q %v", o, k, ok)
	}
	if r, ok := s2.IPv4Real(ip); !ok || r != netip.MustParseAddr("185.12.40.17") {
		t.Fatalf("IPv4Real = %v %v", r, ok)
	}
	if again, _ := s2.IPv4Alias(netip.MustParseAddr("185.12.40.17"), seedProv); again != ip {
		t.Fatalf("alias changed after reopen: %v -> %v", ip, again)
	}
	if _, err := OpenStore(d, testHMACKey, testHMACKey); err == nil {
		t.Fatal("wrong key accepted against real rows")
	}
}
