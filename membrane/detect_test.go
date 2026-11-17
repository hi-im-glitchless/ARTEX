package membrane

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// detectAll runs the pipeline and checks the span invariants every caller
// relies on: in bounds, ordered, non-overlapping.
func detectAll(t *testing.T, p *Pipeline, text string) []Span {
	t.Helper()
	spans := p.Detect(text)
	prev := 0
	for _, sp := range spans {
		if sp.Start < prev || sp.End <= sp.Start || sp.End > len(text) {
			t.Fatalf("bad span order/bounds %+v in %q (all %+v)", sp, text, spans)
		}
		prev = sp.End
	}
	return spans
}

// findSpan returns the span whose raw text is raw.
func findSpan(text string, spans []Span, raw string) (Span, bool) {
	for _, sp := range spans {
		if text[sp.Start:sp.End] == raw {
			return sp, true
		}
	}
	return Span{}, false
}

func describe(text string, spans []Span) string {
	var b []string
	for _, sp := range spans {
		b = append(b, fmt.Sprintf("%s[%q v=%q enc=%d]", sp.Kind, text[sp.Start:sp.End], sp.Value, sp.Encoding))
	}
	return strings.Join(b, " ")
}

func wantSpan(t *testing.T, text string, spans []Span, raw string, kind Kind, value string, enc Encoding) {
	t.Helper()
	sp, ok := findSpan(text, spans, raw)
	if !ok {
		t.Fatalf("no span on %q; got %s", raw, describe(text, spans))
	}
	if sp.Kind != kind || sp.Value != value || sp.Encoding != enc {
		t.Fatalf("span on %q = kind %s value %q enc %d; want %s %q %d", raw, sp.Kind, sp.Value, sp.Encoding, kind, value, enc)
	}
}

func noSpan(t *testing.T, text string, spans []Span, raw string) {
	t.Helper()
	for _, sp := range spans {
		if strings.Contains(text[sp.Start:sp.End], raw) {
			t.Fatalf("unexpected span covering %q: %s", raw, describe(text, spans))
		}
	}
}

func newTestPipeline(t *testing.T, enrol ...[2]string) (*Pipeline, *Store) {
	t.Helper()
	s, _ := newTestStore(t)
	for _, e := range enrol {
		if _, err := s.Enroll(Kind(e[0]), e[1], seedProv); err != nil {
			t.Fatal(err)
		}
	}
	return NewPipeline(s), s
}

func TestDetectSubdomainUnderRoot(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"domain", "acmebank.pt"})
	text := "scan dev.acmebank.pt, api.cdn.ACMEBANK.pt. and ACMEBANK.PT;"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "dev.acmebank.pt", KindDomain, "dev.acmebank.pt", EncRaw)
	wantSpan(t, text, spans, "api.cdn.ACMEBANK.pt", KindDomain, "api.cdn.ACMEBANK.pt", EncRaw)
	// The root itself is a dictionary hit (Value is the enrolled original).
	wantSpan(t, text, spans, "ACMEBANK.PT", KindDomain, "acmebank.pt", EncRaw)
}

func TestDetectThirdPartyIgnored(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"domain", "acmebank.pt"}, [2]string{"org", "acmebank"})
	text := "cdn.cloudflare.net then acmebank.okta.com"
	spans := detectAll(t, p, text)
	if len(spans) != 1 {
		t.Fatalf("want only the keyword span, got %s", describe(text, spans))
	}
	wantSpan(t, text, spans, "acmebank", KindOrg, "acmebank", EncRaw)
	if spans[0].Start != strings.Index(text, "acmebank.okta") {
		t.Fatalf("keyword span at wrong offset: %+v", spans[0])
	}
}

func TestDetectPrivateIPIgnored(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "10.0.0.5 192.168.1.1 172.16.3.4 127.0.0.1 169.254.169.254 100.64.1.1 0.0.0.0 fd00::1 ::1 fe80::1 240.1.2.3"
	if spans := detectAll(t, p, text); len(spans) != 0 {
		t.Fatalf("non-public IPs detected: %s", describe(text, spans))
	}
}

func TestDetectPublicIP(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "host 185.12.40.17, v6 2a00:1450:4003:80e::200e. not 1.2.3.4.5 nor 999.1.1.1 nor v1.2.3 nor 12:30:45"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "185.12.40.17", KindIPv4, "185.12.40.17", EncRaw)
	wantSpan(t, text, spans, "2a00:1450:4003:80e::200e", KindIPv6, "2a00:1450:4003:80e::200e", EncRaw)
	if len(spans) != 2 {
		t.Fatalf("extra spans: %s", describe(text, spans))
	}
}

func TestDetectEmail(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"domain", "acmebank.pt"})
	text := "mail Joao.Silva@acmebank.pt or x.y+z@gmail.com; alias user-1a2b@abc123.example stays"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "Joao.Silva@acmebank.pt", KindEmail, "Joao.Silva@acmebank.pt", EncRaw)
	wantSpan(t, text, spans, "x.y+z@gmail.com", KindEmail, "x.y+z@gmail.com", EncRaw)
	noSpan(t, text, spans, "abc123.example")
}

func TestDetectPhonePT(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "call +351 912 345 678 or 912 345 678 or 00351 213 456 789; ts 1700000000000"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "+351 912 345 678", KindPhone, "+351 912 345 678", EncRaw)
	wantSpan(t, text, spans, "912 345 678", KindPhone, "912 345 678", EncRaw)
	wantSpan(t, text, spans, "00351 213 456 789", KindPhone, "00351 213 456 789", EncRaw)
	noSpan(t, text, spans, "1700000000000")
}

func TestDetectIBAN(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "pay PT50 0002 0123 1234 5678 9015 4 or PT50000201231234567890154, not PT51000201231234567890154"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "PT50 0002 0123 1234 5678 9015 4", KindIBAN, "PT50 0002 0123 1234 5678 9015 4", EncRaw)
	wantSpan(t, text, spans, "PT50000201231234567890154", KindIBAN, "PT50000201231234567890154", EncRaw)
	noSpan(t, text, spans, "PT51")
}

func TestDetectNIFChecksum(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "NIF 123456789 vs bad 123456780"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "123456789", KindNIF, "123456789", EncRaw)
	noSpan(t, text, spans, "123456780")
}

func TestDetectCardLuhnOnly(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "card 4111 1111 1111 1111 and 5500-0000-0000-0004 but not 4111111111111112"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "4111 1111 1111 1111", KindCard, "4111 1111 1111 1111", EncRaw)
	wantSpan(t, text, spans, "5500-0000-0000-0004", KindCard, "5500-0000-0000-0004", EncRaw)
	noSpan(t, text, spans, "4111111111111112")
}

func TestDetectSecretByHeaderLine(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := "GET / HTTP/1.1\r\nHost: example.org\r\nCookie: sessionid=abc123def; theme=dark\r\n" +
		"Authorization: Bearer tok_9f8e7d6c5b4a\r\nX-Api-Key: k3y-AbCdEf12345\r\n\r\n" +
		"HTTP/1.1 200 OK\nSet-Cookie: SID=zzzyyyxxx; Path=/; HttpOnly\n" +
		`curl -H "X-Auth-Token: qwerty12345" https://example.org` + "\n" +
		`{"raw":"GET / HTTP/1.1\r\nCookie: jsess=lmnop9876\r\n"}`
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "abc123def", KindToken, "abc123def", EncRaw)
	wantSpan(t, text, spans, "dark", KindToken, "dark", EncRaw)
	wantSpan(t, text, spans, "tok_9f8e7d6c5b4a", KindToken, "tok_9f8e7d6c5b4a", EncRaw)
	wantSpan(t, text, spans, "k3y-AbCdEf12345", KindToken, "k3y-AbCdEf12345", EncRaw)
	wantSpan(t, text, spans, "zzzyyyxxx", KindToken, "zzzyyyxxx", EncRaw)
	wantSpan(t, text, spans, "qwerty12345", KindToken, "qwerty12345", EncRaw)
	wantSpan(t, text, spans, "lmnop9876", KindToken, "lmnop9876", EncRaw)
	for _, bad := range []string{"Bearer", "Path", "HttpOnly", "sessionid", "SID"} {
		if _, ok := findSpan(text, spans, bad); ok {
			t.Fatalf("header syntax %q detected as secret: %s", bad, describe(text, spans))
		}
	}
}

func TestDetectSecretByJSONKey(t *testing.T) {
	p, _ := newTestPipeline(t)
	text := `{"author":"xavier","session_token":"abc123xyz","password":"hunter2","username":"jdoe","last_login_ip":"185.12.40.17","authToken":"a\u0062c-def"}`
	spans := detectAll(t, p, text)
	noSpan(t, text, spans, "xavier")
	wantSpan(t, text, spans, "abc123xyz", KindToken, "abc123xyz", EncRaw)
	wantSpan(t, text, spans, "hunter2", KindPassword, "hunter2", EncRaw)
	wantSpan(t, text, spans, "jdoe", KindUsername, "jdoe", EncRaw)
	// Value shape wins over key name: an IP is an IP.
	wantSpan(t, text, spans, "185.12.40.17", KindIPv4, "185.12.40.17", EncRaw)
	wantSpan(t, text, spans, `a\u0062c-def`, KindToken, "abc-def", EncJSONEscape)

	// Query/form key=value pairs use the same key rules.
	q := "GET /login?user=jdoe&pwd=p%40ss99&lang=en&api_key=AKx99zz"
	qs := detectAll(t, p, q)
	wantSpan(t, q, qs, "jdoe", KindUsername, "jdoe", EncRaw)
	wantSpan(t, q, qs, "p%40ss99", KindPassword, "p@ss99", EncURL)
	wantSpan(t, q, qs, "AKx99zz", KindToken, "AKx99zz", EncRaw)
	noSpan(t, q, qs, "en")
}

func TestSecretKeyAuthNotAuthor(t *testing.T) {
	cases := map[string]bool{
		"author": false, "authors": false, "Author_Name": false, "co_author": false,
		"auth": true, "authorization": false, "x-auth-token": true, "oauth": true,
		"authorauth": true, "session_id": true, "sid": true, "side": false, "title": false,
	}
	for k, want := range cases {
		if got := secretKey(k); got != want {
			t.Errorf("secretKey(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestDetectBasicAuthDecoded(t *testing.T) {
	p, _ := newTestPipeline(t)
	b64 := base64.StdEncoding.EncodeToString([]byte("jdoe:S3cret!"))
	text := "Authorization: Basic " + b64 + "\r\nAccept: */*"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, b64, KindPassword, "jdoe:S3cret!", EncBasicAuth)

	u := "fetch https://jdoe:S3cret99@portal.example.org/x"
	us := detectAll(t, p, u)
	wantSpan(t, u, us, "jdoe", KindUsername, "jdoe", EncRaw)
	wantSpan(t, u, us, "S3cret99", KindPassword, "S3cret99", EncRaw)
}

func TestDetectURLAndJSONEscapedForms(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"domain", "acmebank.pt"}, [2]string{"org", "Acme Bank"})
	text := "a joao.silva@acmebank.pt b /s?to=joao.silva%40acmebank.pt&q=Acme%20Bank c " +
		`{"to":"joao.silva\u0040acmebank.pt"} d joao.silva&#64;acmebank.pt e Acme&amp;Bank Acme&#32;Bank`
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, "joao.silva@acmebank.pt", KindEmail, "joao.silva@acmebank.pt", EncRaw)
	wantSpan(t, text, spans, "joao.silva%40acmebank.pt", KindEmail, "joao.silva@acmebank.pt", EncURL)
	wantSpan(t, text, spans, `joao.silva\u0040acmebank.pt`, KindEmail, "joao.silva@acmebank.pt", EncJSONEscape)
	wantSpan(t, text, spans, "joao.silva&#64;acmebank.pt", KindEmail, "joao.silva@acmebank.pt", EncHTMLEntity)
	wantSpan(t, text, spans, "Acme%20Bank", KindOrg, "Acme Bank", EncURL)
	wantSpan(t, text, spans, "Acme&#32;Bank", KindOrg, "Acme Bank", EncHTMLEntity)
	noSpan(t, text, spans, "Acme&amp;Bank")
}

func TestStoplistNotLiteralScanned(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"username", "admin"})
	text := "open /admin panel as admin"
	if spans := detectAll(t, p, text); len(spans) != 0 {
		t.Fatalf("stoplisted username scanned: %s", describe(text, spans))
	}
}

func TestMinLen3(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"password", "ab"}, [2]string{"org", "XY"}, [2]string{"password", "abc"})
	text := "ab XY xy ab abc"
	spans := detectAll(t, p, text)
	if len(spans) != 1 {
		t.Fatalf("want only the 3-char hit, got %s", describe(text, spans))
	}
	wantSpan(t, text, spans, "abc", KindPassword, "abc", EncRaw)
	// Short structural secrets are not reported either.
	q := "Cookie: a=1; lang=pt"
	if qs := detectAll(t, p, q); len(qs) != 0 {
		t.Fatalf("short cookie values detected: %s", describe(q, qs))
	}
}

func TestDetectJWTFormat(t *testing.T) {
	p, _ := newTestPipeline(t)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	text := "token=" + jwt + " and plain " + jwt + "."
	spans := detectAll(t, p, text)
	n := 0
	for _, sp := range spans {
		if text[sp.Start:sp.End] == jwt && sp.Kind == KindToken && sp.Value == jwt {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("JWT not detected twice: %s", describe(text, spans))
	}
}

func TestDetectPEMBlock(t *testing.T) {
	p, _ := newTestPipeline(t)
	block := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n-----END RSA PRIVATE KEY-----"
	text := "key:\n" + block + "\nend"
	spans := detectAll(t, p, text)
	wantSpan(t, text, spans, block, KindPrivateKey, block, EncRaw)
	if len(spans) != 1 {
		t.Fatalf("PEM block split: %s", describe(text, spans))
	}
	// Other known formats.
	f := "aws AKIAIOSFODNN7EXAMPLE dp CfDJ8Abcdefghijklmnopqrstu gh ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	fs := detectAll(t, p, f)
	wantSpan(t, f, fs, "AKIAIOSFODNN7EXAMPLE", KindToken, "AKIAIOSFODNN7EXAMPLE", EncRaw)
	wantSpan(t, f, fs, "CfDJ8Abcdefghijklmnopqrstu", KindToken, "CfDJ8Abcdefghijklmnopqrstu", EncRaw)
	wantSpan(t, f, fs, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", KindToken, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", EncRaw)
}

type fixedDetector []Span

func (f fixedDetector) Detect(string) []Span { return f }

func TestPipelineOverlapOrder(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Enroll(KindDomain, "acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	text := "x acmebank.pt y"
	i := strings.Index(text, "acmebank.pt")
	// Equal length: dictionary beats extra.
	p := NewPipeline(s, fixedDetector{{Start: i, End: i + 11, Kind: KindPerson, Value: "z"}})
	spans := detectAll(t, p, text)
	if len(spans) != 1 || spans[0].Kind != KindDomain {
		t.Fatalf("equal-length tie not won by dictionary: %s", describe(text, spans))
	}
	// Longer extra wins; out-of-range extra spans are dropped.
	p = NewPipeline(s, fixedDetector{{Start: 0, End: i + 11, Kind: KindPerson, Value: "z"}, {Start: 5, End: 99}})
	spans = detectAll(t, p, text)
	if len(spans) != 1 || spans[0].Kind != KindPerson {
		t.Fatalf("longer extra did not win: %s", describe(text, spans))
	}
}

func TestDetectNoPanicOnOddInput(t *testing.T) {
	p, _ := newTestPipeline(t, [2]string{"domain", "acmebank.pt"}, [2]string{"org", "acmebank"})
	for _, text := range []string{"", "%", "%4", "%zz", `\u12`, `\ud83d`, `\ud83d\ude00acmebank`, `\ude00x`, "&#;", "&#xFFFFFFFF;",
		"\xff\xfeacmebank\xff", "Authorization: Basic ", "Authorization: Basic !!!", "Cookie:", "-----BEGIN PRIVATE KEY-----",
		"a=", "=b", `{"password":"\"}`, "::", "1.2.3.", "+", "\\", "acme&#97;bank"} {
		_ = detectAll(t, p, text)
	}
	if NewPipeline(nil).Detect("185.12.40.17") == nil {
		t.Fatal("nil-store pipeline should still run structural detectors")
	}
}

// Ruling R10: keywords of 3-4 characters match only at token boundaries;
// longer keywords match inside compounds. The same rule applies to the label
// substitution used for subdomain aliases.
func TestKeywordShortTermsNeedBoundary(t *testing.T) {
	p, s := newTestPipeline(t, [2]string{"org", "ING"}, [2]string{"org", "acmebank"}, [2]string{"product", "Zeta"})
	text := "billing via ING, acmebankonline, ing-portal, ZETA_app, zetas and Ingress"
	spans := detectAll(t, p, text)
	if got := describe(text, spans); strings.Count(got, "org[") != 3 || strings.Count(got, "product[") != 1 {
		t.Fatalf("spans = %s", got)
	}
	wantSpan(t, text, spans, "ING", KindOrg, "ING", EncRaw)
	wantSpan(t, text, spans, "ing", KindOrg, "ING", EncRaw)
	wantSpan(t, text, spans, "acmebank", KindOrg, "acmebank", EncRaw)
	wantSpan(t, text, spans, "ZETA", KindProduct, "Zeta", EncRaw)
	noSpan(t, text, spans, "billing")
	noSpan(t, text, spans, "zetas")
	noSpan(t, text, spans, "Ingress")

	ing, _, _ := s.AliasFor("ing")
	a, err := s.Enroll(KindDomain, "billing.ing-vpn.acme.pt", seedProv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, "billing."+strings.ToLower(ing)+"-vpn.") {
		t.Fatalf("label substitution ignores R10: %q (kw %q)", a, ing)
	}
}

func FuzzPipelineDetect(f *testing.F) {
	for _, s := range []string{"joao.silva%40acmebank.pt", "Authorization: Basic am9lOng=", `{"password":"a@b"}`,
		"dev.acmebank.pt 185.12.40.17 2a00::1", "acme&#64;bank", "+351 912 345 678", "Cookie: a=bcd; e=fgh"} {
		f.Add(s)
	}
	s, err := OpenStore(&fakePersistence{}, testEncKey, testHMACKey)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range [][2]string{{"domain", "acmebank.pt"}, {"org", "acme"}, {"org", "acmebank"}, {"password", "S3cret"}} {
		if _, err := s.Enroll(Kind(e[0]), e[1], seedProv); err != nil {
			f.Fatal(err)
		}
	}
	p := NewPipeline(s)
	f.Fuzz(func(t *testing.T, text string) {
		_ = detectAll(t, p, text)
	})
}

func BenchmarkPipelineDetect(b *testing.B) {
	s, err := OpenStore(&fakePersistence{}, testEncKey, testHMACKey)
	if err != nil {
		b.Fatal(err)
	}
	for _, e := range [][2]string{{"domain", "acmebank.pt"}, {"org", "acme"}, {"org", "acmebank"}, {"password", "S3cret"}} {
		if _, err := s.Enroll(Kind(e[0]), e[1], seedProv); err != nil {
			b.Fatal(err)
		}
	}
	p := NewPipeline(s)
	line := "GET /a?to=joao%40acmebank.pt&pwd=S3cret HTTP/1.1\r\nHost: dev.acmebank.pt\r\nCookie: sid=abc123def\r\n" +
		`{"ip":"185.12.40.17","mail":"x@acme.pt","note":"acme @ billing"} +351 912 345 678 4111 1111 1111 1111` + "\n"
	cases := map[string]string{
		"log1MB":   strings.Repeat(line, 1<<20/len(line)),
		"blob256K": strings.Repeat("a@b.cc", 1<<18/6),
		"prose1MB": strings.Repeat("The scan of dev.acmebank.pt found port 443 open on 185.12.40.17; ask Acme about billing.\n", 1<<20/89),
	}
	for name, text := range cases {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				p.Detect(text)
			}
		})
	}
}
