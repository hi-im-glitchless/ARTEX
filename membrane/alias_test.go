package membrane

import (
	"net/netip"
	"regexp"
	"testing"
	"unicode"
)

func testDeriver() *Deriver { return NewDeriver([]byte("test-key-0123456789")) }

func TestRootDomainDeterministic(t *testing.T) {
	d := testDeriver()
	a := d.RootDomain("acmebank.pt")
	if a != d.RootDomain("acmebank.pt") {
		t.Fatal("not deterministic")
	}
	if !regexp.MustCompile(`^[0-9a-f]{6}\.example$`).MatchString(a) {
		t.Fatalf("bad shape %q", a)
	}
	if d.RootDomain("AcmeBank.PT") != a {
		t.Fatal("not case-insensitive")
	}
}

func TestKeywordShape(t *testing.T) {
	d := testDeriver()
	k := d.Keyword(KindOrg, "Acme")
	if !regexp.MustCompile(`^ORG-[0-9a-f]{4}$`).MatchString(k) {
		t.Fatalf("bad shape %q", k)
	}
	if k != d.Keyword(KindOrg, "Acme") {
		t.Fatal("not deterministic")
	}
	if !regexp.MustCompile(`^user-[0-9a-f]{4}$`).MatchString(d.EmailLocal("john")) {
		t.Fatal("bad email local shape")
	}
}

func TestFormatPreserving(t *testing.T) {
	d := testDeriver()
	got := d.FormatPreserving(KindPassword, "hunter2")
	if len([]rune(got)) != 7 || got == "hunter2" {
		t.Fatalf("bad %q", got)
	}
	for i, r := range got {
		if i < 6 && !unicode.IsLower(r) || i == 6 && !unicode.IsDigit(r) {
			t.Fatalf("class mismatch at %d in %q", i, got)
		}
	}
	p := d.FormatPreserving(KindPassword, "Pa$$w0rd!")
	if p == "Pa$$w0rd!" || p[2] != '$' || p[3] != '$' || p[8] != '!' ||
		!unicode.IsUpper(rune(p[0])) || !unicode.IsDigit(rune(p[5])) {
		t.Fatalf("bad %q", p)
	}
	if p != d.FormatPreserving(KindPassword, "Pa$$w0rd!") {
		t.Fatal("not deterministic")
	}
	other := NewDeriver([]byte("another-key"))
	if other.FormatPreserving(KindPassword, "hunter2") == got {
		t.Fatal("different key gave same result")
	}
}

func luhnValid(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		v := int(s[i] - '0')
		if alt {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		alt = !alt
	}
	return sum%10 == 0
}

func TestFormatPreservingCardLuhn(t *testing.T) {
	d := testDeriver()
	for _, in := range []string{"4111111111111111", "5500005555555559", "378282246310005"} {
		if !luhnValid(in) {
			t.Fatalf("fixture invalid %s", in)
		}
		out := d.FormatPreserving(KindCard, in)
		if len(out) != len(in) || out == in || !luhnValid(out) {
			t.Fatalf("%q -> %q", in, out)
		}
	}
}

func TestFormatPreservingDiffersFromInput(t *testing.T) {
	d := testDeriver()
	for _, in := range []string{"a", "7", "Z", "ab", "x1"} {
		for _, k := range []Kind{KindPassword, KindToken, KindUsername} {
			if d.FormatPreserving(k, in) == in {
				t.Fatalf("equal for %q", in)
			}
		}
	}
}

func TestIPv6InDocPrefix(t *testing.T) {
	d := testDeriver()
	ip := netip.MustParseAddr("2a00:1450:4001:81b::200e")
	out := d.IPv6(ip)
	if !netip.MustParsePrefix("2001:db8::/32").Contains(out) {
		t.Fatalf("%s outside prefix", out)
	}
	if out != d.IPv6(ip) {
		t.Fatal("not deterministic")
	}
}
