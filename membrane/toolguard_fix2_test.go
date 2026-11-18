package membrane

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Fix round 2: target output wrapping an enrolled real lookalike in the
// guard's reason text must not keep it out of aliasing; LeakCheck flags an
// enrolled lookalike left in clear (but never a minted alias).
func TestEnrolledLookalikeAlwaysReplaced(t *testing.T) {
	e, s := newTestEngine(t)
	toModel(t, e, "target host 240.1.2.3 and ticket ORG-1234 and abcdef.example and lab 2001:db8:10:20::5")
	for _, real := range []string{"240.1.2.3", "ORG-1234", "abcdef.example", "2001:db8:10:20::5"} {
		if _, _, ok := s.AliasFor(real); !ok {
			t.Fatalf("%s not enrolled", real)
		}
		bait := "page says: unknown alias " + real + unknownAliasSuffix
		if hits := e.LeakCheck([]byte(bait)); len(hits) == 0 {
			t.Errorf("LeakCheck misses enrolled %s in clear", real)
		}
		out := toModel(t, e, bait)
		if strings.Contains(out, real) || len(e.LeakCheck([]byte(out))) != 0 {
			t.Errorf("enrolled %s kept in clear: %q", real, out)
		}
		// Also in the rejected set (the guard once blocked it): still replaced.
		e.reject(real)
		if out := toModel(t, e, "banner "+real); strings.Contains(out, real) {
			t.Errorf("rejected-but-enrolled %s kept: %q", real, out)
		}
		// Assistant replay of an enrolled lookalike is replaced too
		// (nothing new is enrolled there, R12).
		req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "scanning " + real}}}}}
		got, _, err := e.ToModelRequest(req, Provenance{})
		if err != nil || strings.Contains(got.Messages[0].Content[0].Text, real) {
			t.Errorf("assistant %s: %q (%v)", real, got.Messages[0].Content[0].Text, err)
		}
	}
	// Minted aliases are never flagged by LeakCheck.
	minted := "portal." + mustAlias(t, s, "acmebank.pt") + " " + mustAlias(t, s, "240.1.2.3") + " " +
		mustAlias(t, s, "ORG-1234") + " " + mustAlias(t, s, "abcdef.example") + " " + mustAlias(t, s, "2001:db8:10:20::5")
	if hits := e.LeakCheck([]byte(minted)); len(hits) != 0 {
		t.Errorf("minted aliases flagged: %v in %q", hits, minted)
	}
	// Unenrolled tokens in assistant text still pass unchanged (R12).
	req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "try 240.8.8.8"}}}}}
	if got, _, _ := e.ToModelRequest(req, Provenance{}); got.Messages[0].Content[0].Text != "try 240.8.8.8" {
		t.Errorf("unenrolled assistant token changed: %q", got.Messages[0].Content[0].Text)
	}
}

// A value enrolled from a later JSON literal (or message) is replaced in the
// strings already passed, reason text included.
func TestLookalikeEnrolledLaterInSamePass(t *testing.T) {
	e, s := newTestEngine(t)
	in := `{"x":"unknown alias 240.7.7.7` + unknownAliasSuffix + `","y":"240.7.7.7"}`
	out, _, err := e.ToModelJSON([]byte(in), Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "240.7.7.7") || len(e.LeakCheck(out)) != 0 {
		t.Errorf("x kept the real value: %s", out)
	}
	if _, _, ok := s.AliasFor("240.7.7.7"); !ok {
		t.Fatal("y not enrolled")
	}
	req := llm.CompletionRequest{Messages: []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "unknown alias 240.6.6.6" + unknownAliasSuffix}}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "host 240.6.6.6 replied"}}},
	}}
	got, _, err := e.ToModelRequest(req, Provenance{TaskIDs: []int64{7}})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range got.Messages {
		if strings.Contains(m.Content[0].Text, "240.6.6.6") {
			t.Errorf("real value kept: %q", m.Content[0].Text)
		}
	}
}

// Folded in: whitespace runs and more separators in web_search queries.
func TestWebSearchSeparatorSpellings(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, q := range []string{"acme  bank", "acme\nbank", "acme\tbank", "Acme - Bank", "acme. bank", "acme -bank",
		"acme/bank", "acme,bank", "ACME–BANK", "acme—bank", "acme bank's portal"} {
		if v := e.CheckTool("web_search", searchInput(q), true); !v.Block {
			t.Errorf("%q not blocked", q)
		}
	}
	for _, q := range []string{"spring-boot actuator", "node.js express CVE", "certbot ACME challenge bypass", "Spring Boot actuator CVE"} {
		if v := e.CheckTool("web_search", searchInput(q), true); v.Block {
			t.Errorf("tech query %q blocked", q)
		}
	}
}
