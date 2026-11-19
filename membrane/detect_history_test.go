package membrane

import "testing"

// A shell history listing numbers each command; a glued MySQL password in
// it must be aliased like one at a prompt (found by the contract suite).
func TestGluedFlagHistoryListing(t *testing.T) {
	for _, in := range []string{
		"  101  mysql -uroot -pKx81mq -h 10.0.0.5 core",
		"101  mysql -uroot -pKx81mq",
		"  57* mysqldump -uroot -pKx81mq app",
		"$ history | tail -2\n  101  mysql -uroot -pKx81mq\n  102  exit\n",
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, in, "Kx81mq")
	}
	e, _ := newTestEngine(t)
	for _, in := range []string{"  12  find /var/lib/mysql -user mysql -prune", "3 mysql servers -p", "  12  grep -pfoo mysql.log"} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("not a credential, but rewritten: %q -> %q", in, out)
		}
	}
}
