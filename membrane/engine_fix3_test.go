package membrane

import (
	"net/netip"
	"strings"
	"testing"
)

// Fix round 3 regressions, built from the reviewer's probe7 inputs.

func TestAliasNotReversedIntoThirdPartyHost(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	for _, in := range []string{
		"evil." + ra + ".attacker.com", ra + ".evil.com", ra + ".com", ra + ".xyz", ra + ".com.br",
		"dev." + ra + ".co.uk", ra + ".attacker.co.uk", ra + ".github.io", ra + ".s3.amazonaws.com",
		ra + ".sh", ra + ".zip", ra + ".bak.zip", // real TLDs: accepted trade-off, no round trip
	} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("reversed into a third-party host: %q -> %q", in, back)
		}
	}
	for _, in := range []string{"cat acmebank.pt.conf", "ls acmebank.pt.nmap acmebank.pt.gnmap acmebank.pt.xml", "dig acmebank.pt.in-addr"} {
		out := toModel(t, e, in)
		if back, _ := e.ToReal(out); back != in {
			t.Fatalf("file name round trip %q -> %q -> %q", in, out, back)
		}
	}
}

func TestNewRootRemintsHostsCarryingIt(t *testing.T) {
	e, s := newTestEngine(t)
	old := toModel(t, e, "host k.pt.acmebank.pt up") // minted before k.pt is a root
	in := "host k.pt.acmebank.pt up, mail 0@k.pt"
	out := toModel(t, e, in)
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 || strings.Contains(out, "k.pt") {
		t.Fatalf("new root left in a host alias: %q (hits %+v)", out, hits)
	}
	if back, _ := e.ToReal(out); back != in {
		t.Fatalf("round trip %q", back)
	}
	if back, _ := e.ToReal(old); back != "host k.pt.acmebank.pt up" {
		t.Fatalf("retired alias must still resolve: %q", back)
	}
	_ = s
}

func TestKeptSpansNotRewritten(t *testing.T) {
	e, s := newTestEngine(t)
	ipA, err := s.IPv4Alias(netip.MustParseAddr("185.12.41.7"), seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(KindPassword, "240", seedProv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(KindPassword, "1234", seedProv); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"model said ping " + ipA.String(), "ping 10.240.1.1", "see 2400", "version v1.2.1234", "pi 1234.5",
		"see " + mustAlias(t, s, "Acme Bank"),
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("kept span rewritten: %q -> %q", in, out)
		}
	}
	// A standalone short secret is still aliased.
	if out := toModel(t, e, "pin 240 ok"); strings.Contains(out, " 240 ") {
		t.Fatalf("standalone secret kept: %q", out)
	}
}

func TestGluedFlagScope(t *testing.T) {
	e, s := newTestEngine(t)
	for _, in := range []string{
		"find /var/lib/mysql -path '*.ibd' -print", "find /var/lib/mysql -user mysql -prune",
		"docker run -d -p3306:3306 mysql:8", "ssh -p2222 host", "psql -p5432 -Upostgres",
		"mkdir -pv /etc/mysql", "cp -pr /etc/mysql /bak", "mysql\n-pNotOnSameLine",
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("not a credential, but rewritten: %q -> %q", in, out)
		}
	}
	for _, in := range []string{"mysqldump -uroot -p$DB_PASS app", "mysql -uroot -p${MYSQL_PWD}"} {
		if out := toModel(t, e, in); !strings.Contains(out, " -p$") {
			t.Fatalf("variable reference rewritten: %q -> %q", in, out)
		}
	}
	for _, w := range []string{"${MYSQL_PWD}", "NotOnSameLine"} {
		if _, _, ok := s.AliasFor(w); ok {
			t.Fatalf("%q enrolled", w)
		}
	}
	for _, w := range []string{"ath", "rint", "ser", "pv", "2222", "3306:3306", "$DB_PASS"} {
		if _, _, ok := s.AliasFor(w); ok {
			t.Fatalf("%q enrolled", w)
		}
	}
	for _, c := range []struct{ in, secret string }{
		{"ssh -p2222 host 'mysql -uroot -pS3cr3t!'", "S3cr3t!"},
		{`mysql -uroot -p"S3cr3t!x"`, "S3cr3t!x"},
		{"echo hi | sudo mysql -uadmin2 -pQw3rty9 db", "Qw3rty9"},
		{"sshpass -pHunter99 ssh bob@h", "Hunter99"},
		{"cat x; /usr/bin/mysql -ujdoe -pZx8v app", "Zx8v"},
	} {
		out := toModel(t, e, c.in)
		if strings.Contains(out, c.secret) {
			t.Fatalf("glued password kept in %q: %q", c.in, out)
		}
		if strings.Contains(c.in, "2222") && !strings.Contains(out, "-p2222") {
			t.Fatalf("ssh port rewritten: %q", out)
		}
		if back, _ := e.ToReal(out); back != c.in {
			t.Fatalf("round trip %q -> %q -> %q", c.in, out, back)
		}
	}
}
