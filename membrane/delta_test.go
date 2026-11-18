package membrane

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// deltaCorpus covers the encodings and value shapes whose cached results a
// later enrolment can affect, plus texts it cannot.
func deltaCorpus() []string {
	jwt := b64url(`{"alg":"HS256","typ":"JWT"}`) + "." + b64url(`{"sub":"globex-admin","iss":"https://idp.newclient.pt"}`) +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	return []string{
		"nmap h1.portal.acmebank.pt 185.12.40.7 open",
		"visit https://www.newclient.pt/login?u=jsilva%40newclient.pt",
		"Globex Corp contract signed by the CFO",
		`{\"user\":\"carol@newclient.pt\",\"host\":\"api.newclient.pt\"}`,
		"see &#x6e;ewclient&#46;pt and newclient&period;pt",
		"Authorization: Bearer " + jwt,
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("svc_globex:Winter#2031")),
		"route 185.13.0.0/16 via gw, also 185.13.7.0/24",
		"ipv6 neighbour 2001:0DB9:0000:0000:0000:0000:0000:0001 seen",
		"call 00351912345678 or +351912345678",
		"no secrets here, just prose about the weather",
		"sso.portalix.acmebank.pt dashboard and portalix-admin",
		"url-encoded pw: p%40ss%3AGlobexWord",
		"user=jsilva password=Hunter2024!",
	}
}

func enrolDeltaChanges(t *testing.T, s *Store) {
	t.Helper()
	p := Provenance{TaskIDs: []int64{9}}
	if _, err := s.EnrollRoot("newclient.pt", p); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		k Kind
		v string
	}{
		{KindOrg, "Globex"},
		{KindIPv4, "185.13.7.9"},
		{KindIPv6, "2001:db9::1"},
		{KindPhone, "+351 912 345 678"},
		{KindPassword, "GlobexWord"},
		{KindProduct, "Portalix"},
		{KindEmail, "carol@newclient.pt"},
	} {
		var err error
		if e.k == KindIPv4 {
			_, err = s.IPv4Alias(netip.MustParseAddr(e.v), p)
		} else {
			_, err = s.Enroll(e.k, e.v, p)
		}
		if err != nil {
			t.Fatalf("enrol %s: %v", e.k, err)
		}
	}
}

// Final review I2: after enrolments elsewhere, a cached result reused by
// the incremental check is byte-identical to a full recompute, and texts no
// change touches are not recomputed.
func TestIncrementalCacheMatchesFullRecompute(t *testing.T) {
	e, s := newTestEngine(t)
	if _, err := s.Enroll(KindDomain, "portalix.acmebank.pt", seedProv); err != nil {
		t.Fatal(err)
	}
	prov := Provenance{TaskIDs: []int64{3}}
	corpus := deltaCorpus()
	for _, c := range corpus {
		for range 2 {
			if _, _, err := e.ToModel(c, prov); err != nil {
				t.Fatal(err)
			}
		}
	}
	bodyOf := func() []byte {
		var sb strings.Builder
		for i := 0; i < 40; i++ {
			for _, c := range corpus {
				fmt.Fprintf(&sb, `{"i":%d,"t":%q},`, i, c)
			}
		}
		return []byte("[" + sb.String() + `{"end":"newclient.pt Globex 185.13.7.9"}]`)
	}
	body := bodyOf()
	if !reflect.DeepEqual(e.LeakCheck(body), e.leakCheckFull(string(body))) {
		t.Fatal("segmented LeakCheck differs from full scan before enrolment")
	}
	enrolDeltaChanges(t, s)
	if got, want := e.LeakCheck(body), e.leakCheckFull(string(body)); !reflect.DeepEqual(got, want) || len(want) == 0 {
		t.Fatalf("LeakCheck after enrolment: incremental %v, full %v", got, want)
	}
	touched := 0
	for _, c := range corpus {
		before := e.passes.Load()
		got, _, err := e.ToModel(c, prov)
		if err != nil {
			t.Fatal(err)
		}
		if e.passes.Load() != before {
			touched++
		}
		want, _, err := e.toModel(c, prov, false)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("incremental result stale for %q:\n got  %q\n want %q", c, got, want)
		}
	}
	if touched == 0 || touched == len(corpus) {
		t.Fatalf("recomputed %d of %d texts; want only the touched ones", touched, len(corpus))
	}
	before := e.passes.Load()
	if _, _, err := e.ToModel("no secrets here, just prose about the weather", prov); err != nil {
		t.Fatal(err)
	}
	if e.passes.Load() != before {
		t.Fatal("untouched text was recomputed")
	}
}

func perfRequest(t testing.TB, s *Store, msgs int) llm.CompletionRequest {
	t.Helper()
	for i := 0; i < 300; i++ {
		if _, err := s.Enroll(KindDomain, fmt.Sprintf("h%d.portal.acmebank.pt", i), Provenance{TaskIDs: []int64{1}}); err != nil {
			t.Fatal(err)
		}
	}
	var tr strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&tr, "nmap result line %d: h%d.portal.acmebank.pt (185.12.40.%d) 443/tcp open https nginx 1.18 Server: acmebank-edge user=jsilva\n", i, i, i%250+1)
	}
	chunk := tr.String()
	req := llm.CompletionRequest{System: []string{"You test Acme Bank"}}
	for i := 0; i < msgs; i++ {
		req.Messages = append(req.Messages,
			llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: fmt.Sprint(i),
				Content: []llm.ContentBlock{llm.TextBlock(fmt.Sprintf("run %d\n%s", i, chunk))}}}},
			llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: fmt.Sprintf("step %d looks fine", i)}}})
	}
	return req
}

// Final review I2: an enrolment by another task does not make a request
// that does not contain the new value rescan its history: no transform
// pass, no LeakCheck segment scan, identical output. One that does contain
// it is recomputed and matches a fresh engine.
func TestForeignEnrolmentDoesNotRescanHistory(t *testing.T) {
	e, s := newTestEngine(t)
	req := perfRequest(t, s, 80)
	prov := Provenance{TaskIDs: []int64{2}}
	run := func() ([]byte, time.Duration) {
		st := time.Now()
		out, _, err := e.ToModelRequest(req, prov)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(out)
		if hits := e.LeakCheck(body); len(hits) > 0 {
			t.Fatalf("leak hits %v", hits)
		}
		return body, time.Since(st)
	}
	first, _ := run()
	run()
	for k := 0; k < 3; k++ {
		if _, err := s.Enroll(KindDomain, fmt.Sprintf("new%d.acmebank.pt", k), Provenance{TaskIDs: []int64{9}}); err != nil {
			t.Fatal(err)
		}
		p0, l0 := e.passes.Load(), e.leakScans.Load()
		body, d := run()
		if p, l := e.passes.Load()-p0, e.leakScans.Load()-l0; p != 0 || l != 0 {
			t.Fatalf("after foreign enrolment %d: %d transform passes, %d leak scans; want 0", k, p, l)
		}
		if string(body) != string(first) {
			t.Fatal("output changed after an unrelated enrolment")
		}
		t.Logf("after foreign enrolment %d: ToModelRequest+LeakCheck %v (body %d bytes)", k, d, len(body))
	}
	// An enrolment the request does contain: recomputed, equal to a fresh
	// engine's full computation.
	if _, err := s.Enroll(KindOrg, "acmebank-edge", Provenance{TaskIDs: []int64{9}}); err != nil {
		t.Fatal(err)
	}
	body, _ := run()
	fresh := NewEngine(s, nil)
	out, _, err := fresh.ToModelRequest(req, prov)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(out)
	if string(body) != string(want) {
		t.Fatal("incremental output differs from a fresh engine")
	}
	if strings.Contains(string(body), "acmebank-edge") {
		t.Fatal("newly enrolled value sent in clear")
	}
}

func BenchmarkToModelRequestAfterForeignEnrol(b *testing.B) {
	e, s := newTestEngine(b)
	req := perfRequest(b, s, 300)
	prov := Provenance{TaskIDs: []int64{2}}
	for range 2 { // the first call enrols, the second caches
		out, _, err := e.ToModelRequest(req, prov)
		if err != nil {
			b.Fatal(err)
		}
		body, _ := json.Marshal(out)
		e.LeakCheck(body)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Enroll(KindDomain, fmt.Sprintf("bench%d.acmebank.pt", i), Provenance{TaskIDs: []int64{9}}); err != nil {
			b.Fatal(err)
		}
		out, _, err := e.ToModelRequest(req, prov)
		if err != nil {
			b.Fatal(err)
		}
		body, _ := json.Marshal(out)
		e.LeakCheck(body)
	}
}
