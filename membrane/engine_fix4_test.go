package membrane

import (
	"strings"
	"testing"
)

// Fix round 4 regressions, built from the reviewer's probe8 inputs.

// assertAliased checks that secret is absent from the transform's output,
// that LeakCheck then flags the input, that the output is leak-free, and
// that the output round-trips.
func assertAliased(t *testing.T, e *Engine, in, secret string) {
	t.Helper()
	out := toModel(t, e, in)
	if strings.Contains(out, secret) {
		t.Fatalf("%q kept in %q -> %q", secret, in, out)
	}
	// Stoplisted originals (root) stay out of the dictionary (ruling R3).
	if hits := e.LeakCheck([]byte(in)); len(hits) == 0 && !literalStoplist[secret] {
		t.Fatalf("LeakCheck misses %q in %q", secret, in)
	}
	if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
		t.Fatalf("leak in output %q: %+v", out, hits)
	}
	if back, _ := e.ToReal(out); back != in {
		t.Fatalf("round trip %q -> %q -> %q", in, out, back)
	}
}

func TestGluedFlagCommandPosition(t *testing.T) {
	for _, in := range []string{
		"docker exec -it db mysql -uroot -pKx81mq",
		"kubectl exec pod -- mysql -uroot -pKx81mq",
		"ssh host mysql -uroot -pKx81mq",
		"MYSQL_HOST=db mysql -uroot -pKx81mq",
		"env mysql -uroot -pKx81mq",
		"watch mysql -uroot -pKx81mq",
		"nice mysql -uroot -pKx81mq",
		"xargs mysql -uroot -pKx81mq",
		"$ mysql -uroot -pKx81mq",
		"> mysql -uroot -pKx81mq",
		"root@h:~# mysql -uroot -pKx81mq",
		"sudo -u mysql mysql -uroot -pKx81mq",
		"timeout 10 mysql -uroot -pKx81mq",
		"nice -n 10 mysql -uroot -pKx81mq",
		"docker compose exec -u app db mysql -uroot -pKx81mq",
		"kubectl -n prod exec -it pod -c c1 -- mysql -uroot -pKx81mq",
		"ssh -p 2222 -i key.pem user@host mysqldump -uroot -pKx81mq app",
		"(venv) user@h:~/app$ mysql -uroot -pKx81mq",
		"  mysql -uroot -pKx81mq",
		"(mysql -uroot -pKx81mq)",
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, in, "Kx81mq")
	}
	// The round-3 false positives stay untouched.
	e, s := newTestEngine(t)
	for _, in := range []string{
		"find /var/lib/mysql -path '*.ibd' -print", "find /var/lib/mysql -user mysql -prune",
		"docker run -d -p3306:3306 mysql:8", "ssh -p2222 host", "ssh -p2222 host uptime", "ssh -p 2222 host mysql",
		"$ find /var/lib/mysql -user mysql -prune", "env -u mysql find /x -prune",
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("not a credential, but rewritten: %q -> %q", in, out)
		}
	}
	if out := toModel(t, e, "mysqldump -p$DB_PASS app"); out != "mysqldump -p$DB_PASS app" {
		t.Fatalf("variable reference rewritten: %q", out)
	}
	out := toModel(t, e, "ssh -p2222 host 'mysql -uroot -pKx95mq'")
	if !strings.Contains(out, "-p2222") || strings.Contains(out, "Kx95mq") {
		t.Fatalf("ssh port or quoted password: %q", out)
	}
	for _, w := range []string{"ath", "rint", "rune", "2222", "3306:3306", "$DB_PASS"} {
		if _, _, ok := s.AliasFor(w); ok {
			t.Fatalf("%q enrolled", w)
		}
	}
}

func TestHostSuffixEncodedDot(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	for _, in := range []string{
		"https://" + ra + "%2Ecom/x", "https://" + ra + "%2ecom/x", "https://" + ra + "&#46;com/x",
		"https://" + ra + "&#x2e;com/x", ra + `\.com`, ra + "．com", ra + "。com",
		"https://" + ra + "%2Eattacker%2Eco%2Euk/x", "https://" + ra + "%252Ecom/x",
	} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("reversed into a third-party host: %q -> %q", in, back)
		}
	}
	// A non-suffix continuation still resolves.
	if back, _ := e.ToReal("cat " + ra + "%2Econf"); back != "cat acmebank.pt%2Econf" {
		t.Fatalf("file name: %q", back)
	}
}

func TestDashedCredentialOptions(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{"psql --password=Zz11yy", "Zz11yy"},
		{"mysql --password=Kx93mqLonger1", "Kx93mqLonger1"},
		{"run --password=Zz11yy", "Zz11yy"},
		{"--password=Zz11yy", "Zz11yy"},
		{"x --pass=Zz11yy", "Zz11yy"},
		{"x -password=Zz11yy", "Zz11yy"},
		{"mysql --user=root", "root"},
		{"mysql --user=jdoe7 --password Zz11yy", "jdoe7"},
		{"mysql --password Zz11yy", "Zz11yy"},
		{`mysql --password="Zz 11yy"`, "Zz 11yy"},
		{"mysql --password='Zz11yy'", "Zz11yy"},
		{"cli --api-key Zq7rT2vX9k", "Zq7rT2vX9k"},
		{"mysql --user root --password=Zz11yy db", "Zz11yy"},
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
	}
	e, s := newTestEngine(t)
	for _, in := range []string{
		"mysql --password=$DB_PASS", "mysql --password=${DB_PASS}", "mysql --password=<password>",
		"mysql --password $MYSQL_PWD db", "psql --password -h db", "docker run --user=1000:1000 img",
		"docker run --user 1000 img", "curl --user-agent=Mozilla/5.0 x", "ssh --key-file=/etc/k.pem",
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("not a literal credential, but rewritten: %q -> %q", in, out)
		}
	}
	for _, w := range []string{"$DB_PASS", "$MYSQL_PWD", "1000", "1000:1000", "-h", "Mozilla/5.0", "/etc/k.pem"} {
		if _, _, ok := s.AliasFor(w); ok {
			t.Fatalf("%q enrolled", w)
		}
	}
}
