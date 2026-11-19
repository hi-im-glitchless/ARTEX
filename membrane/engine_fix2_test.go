package membrane

import (
	"strings"
	"testing"
)

// Fix round 2 regressions, built from the reviewer's probe6 inputs.

func TestShortCredentialsGluedToFlags(t *testing.T) {
	e, s := newTestEngine(t)
	for _, v := range []struct {
		k Kind
		v string
	}{{KindPassword, "abc123x"}, {KindPassword, "1234"}, {KindUsername, "bob"}} {
		if _, err := s.seedEnroll(v.k, v.v, seedProv); err != nil {
			t.Fatal(err)
		}
	}
	for _, in := range []string{
		"mysql -ubob -p1234 db", "mysql -uroot -pabc123x", "sshpass -p1234 ssh bob@h",
		"pw_abc123x_", "x=abc123x1", "PGPASSWORD=abc123x_ psql",
	} {
		if len(e.LeakCheck([]byte(in))) == 0 {
			t.Fatalf("LeakCheck missed a credential in %q", in)
		}
		out := toModel(t, e, in)
		for _, real := range []string{"bob", "1234", "abc123x"} {
			if strings.Contains(in, real) && strings.Contains(out, real) {
				t.Fatalf("%q kept %q: %q", in, real, out)
			}
		}
		if hits := e.LeakCheck([]byte(out)); len(hits) != 0 {
			t.Fatalf("leak %+v in %q", hits, out)
		}
		if back, _ := e.ToReal(out); back != in {
			t.Fatalf("round trip %q -> %q -> %q", in, out, back)
		}
	}
	// Single-class values still do not match inside a run of their class.
	if out := toModel(t, e, "bobby 12345"); out != "bobby 12345" {
		t.Fatalf("matched inside a word: %q", out)
	}
}

func TestReplacementExposingShortCredential(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "0000000000ACmeBAnkjsilva" // jsilva glued to letters; after aliasing it follows a digit
	out := toModel(t, e, in)
	if strings.Contains(out, "jsilva") || len(e.LeakCheck([]byte(out))) != 0 {
		t.Fatalf("exposed original kept: %q", out)
	}
}

func TestWrappedRealSecretsNotPlaceholders(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, c := range []struct{ in, secret string }{
		{`{"password":"{Xk9#mq2}"}`, "{Xk9#mq2}"},
		{`{"password":"[S3cret!]"}`, "[S3cret!]"},
		{`{"password":"<Secr3t>"}`, "<Secr3t>"},
		{`pass=%Pa55w0rd%`, "%Pa55w0rd%"},
	} {
		if out := toModel(t, e, c.in); strings.Contains(out, c.secret) {
			t.Fatalf("real secret %q treated as placeholder: %q", c.secret, out)
		}
	}
	for _, in := range []string{`{"password":"<password>"}`, `{"token":"{{ api_token }}"}`, `{"secret":"${DB_PASS}"}`,
		`pass=%DB_PASSWORD%`, `{"password":"[REDACTED_VALUE]"}`, `{"key":"{token}"}`} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("placeholder aliased: %q -> %q", in, out)
		}
	}
}

func TestDomainFileNamesRoundTrip(t *testing.T) {
	e, s := newTestEngine(t)
	for _, in := range []string{
		"openssl x509 -in /etc/ssl/acmebank.pt.crt",
		"cat /etc/nginx/sites-enabled/acmebank.pt.conf",
		"nmap -oA acmebank.pt then read acmebank.pt.nmap acmebank.pt.xml acmebank.pt.gnmap",
		"host acmebank.pt.", "mail joao.silva@acmebank.pt.",
	} {
		out := toModel(t, e, in)
		if strings.Contains(out, "acmebank") {
			t.Fatalf("not aliased: %q", out)
		}
		if back, u := e.ToReal(out); back != in || len(u) != 0 {
			t.Fatalf("round trip %q -> %q -> %q (unresolved %v)", in, out, back, u)
		}
	}
	ra := mustAlias(t, s, "acmebank.pt")
	for _, in := range []string{"evil." + ra + ".attacker.com", ra + ".evil.com", "x@" + ra + ".evil.com"} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("rewritten under a third-party host: %q -> %q", in, back)
		}
	}
}

func TestPhoneVariants(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.seedEnroll(KindPhone, "+351912345678", seedProv); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		`{"phone":351912345678}`, "call 00351912345678 now", "call +351912345678 now", "tel:351912345678",
	} {
		if len(e.LeakCheck([]byte(in))) == 0 {
			t.Fatalf("LeakCheck missed the phone in %q", in)
		}
		out := toModel(t, e, in)
		if strings.Contains(out, "912345678") || len(e.LeakCheck([]byte(out))) != 0 {
			t.Fatalf("phone kept: %q", out)
		}
		if back, _ := e.ToReal(out); back != in {
			t.Fatalf("round trip %q -> %q -> %q", in, out, back)
		}
	}
	// Not inside longer digit runs.
	if out := toModel(t, e, "id 13519123456789"); out != "id 13519123456789" {
		t.Fatalf("matched inside a longer number: %q", out)
	}
}
