package membrane

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
)

// Tool guard rules (spec §9.2, §9.3). They run on a tool call's input after
// the decorator mapped it back to real values, before the tool executes.
const (
	// RuleUnresolvedAlias: the input still holds an alias-shaped value that
	// is not an enrolled original (the model invented or garbled a name).
	RuleUnresolvedAlias = "unresolved_alias"
	// RuleWebSearchOriginal: a web_search query holds a client original;
	// the query would leave for an external search engine.
	RuleWebSearchOriginal = "web_search_original"
)

// WebSearchTool is the name of the web search tool the originals rule
// applies to.
const WebSearchTool = "web_search"

const webSearchReason = "search for the technology or CVE, not the target"

// Unresolved-alias block reason: reasonPrefix + token + reasonSuffix. The
// exact form is load-bearing: lookalikes recognises it when the reason comes
// back in a tool_result and never enrols the echoed token (see reject).
const (
	reasonPrefix = "unknown alias "
	reasonSuffix = " — use only names from your context"
)

// reasonSuffixJSON is reasonSuffix with the dash JSON-escaped.
var reasonSuffixJSON = strings.Replace(reasonSuffix, "—", "\\u2014", 1)

// maxRejected bounds the engine's set of guard-rejected tokens.
const maxRejected = 65536

// localWriteTools only write local files (reports, notes, todos): their
// content may legitimately quote documentation placeholders (user-1234,
// ORG-0001, .example hosts), so the unresolved-alias rule skips them. They
// send nothing anywhere; a later Bash/WebFetch use of the value is still
// checked.
var localWriteTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "TodoWrite": true,
}

// ToolVerdict is the outcome of CheckTool. Reason is model-facing; it never
// contains an original (an unresolved alias is echoed, which by definition
// is not one). Rule is one of the Rule* constants when Block is set.
type ToolVerdict struct {
	Block  bool
	Reason string
	Rule   string
}

// ToolCheck applies both tool guard rules for an agent on a membraned
// provider: it blocks an input that still holds an unresolved alias-shaped
// value, and a web_search input that holds any client original.
func (e *Engine) ToolCheck(tool string, input []byte) (block bool, reason string) {
	v := e.CheckTool(tool, input, true)
	return v.Block, v.Reason
}

// CheckTool applies the tool guard rules when membraned is set, i.e. the
// agent's provider is membraned (ruling R19, amended: an agent on a local
// model never sees aliases, so neither rule applies to it):
//   - unresolved alias, for every tool except local file writes
//     (localWriteTools);
//   - client originals, for web_search.
//
// Every string in the input is scanned: the raw bytes, each decoded JSON
// string (object keys included) and their URL/JSON/HTML-decoded views. An
// alias-shaped value is allowed only when it is an enrolled original (a real
// 240.x address or <hex6>.example host seen in target output, R11); values
// under a quarantined shared root are not enrolled, so they block. A
// rejected token is remembered so that ToModel never enrols it when the
// block reason comes back (see lookalikes).
func (e *Engine) CheckTool(tool string, input []byte, membraned bool) ToolVerdict {
	if !membraned {
		return ToolVerdict{}
	}
	texts := toolTexts(input)
	if !localWriteTools[tool] {
		for _, t := range texts {
			if a, ok := e.unknownAlias(t); ok {
				e.reject(a)
				return ToolVerdict{Block: true, Rule: RuleUnresolvedAlias, Reason: reasonPrefix + a + reasonSuffix}
			}
		}
	}
	if tool == WebSearchTool {
		for _, t := range texts {
			for _, v := range separatorViews(t) {
				if len(e.LeakCheck([]byte(v))) > 0 {
					return ToolVerdict{Block: true, Rule: RuleWebSearchOriginal, Reason: webSearchReason}
				}
			}
		}
	}
	return ToolVerdict{}
}

// isSeparator reports the word separators a brand may be written with.
func isSeparator(r rune) bool { return r == '-' || r == '_' || r == '+' || r == '.' }

// separatorViews returns t, t with the word separators - _ + . turned into
// spaces, and t with them removed, so a brand written acme-bank, acme_bank
// or acme.bank is caught by the "Acme Bank" / "acmebank" keywords.
func separatorViews(t string) []string {
	if !strings.ContainsFunc(t, isSeparator) {
		return []string{t}
	}
	spaced := strings.Map(func(r rune) rune {
		if isSeparator(r) {
			return ' '
		}
		return r
	}, t)
	joined := strings.Map(func(r rune) rune {
		if isSeparator(r) {
			return -1
		}
		return r
	}, t)
	return []string{t, spaced, joined}
}

// reject records a token the guard blocked (and, for a CIDR, its address),
// lowercase. The set is cleared when full; the reason-text rule in
// lookalikes still covers tokens forgotten that way, and after a restart.
func (e *Engine) reject(tok string) {
	e.rejMu.Lock()
	defer e.rejMu.Unlock()
	if e.rejected == nil || len(e.rejected) >= maxRejected {
		e.rejected = map[string]struct{}{}
	}
	tok = strings.ToLower(tok)
	e.rejected[tok] = struct{}{}
	if i := strings.IndexByte(tok, '/'); i > 0 {
		e.rejected[tok[:i]] = struct{}{}
	}
}

// isRejected reports whether the guard rejected tok in this process.
func (e *Engine) isRejected(tok string) bool {
	e.rejMu.Lock()
	defer e.rejMu.Unlock()
	_, ok := e.rejected[strings.ToLower(tok)]
	return ok
}

// inGuardReason reports whether text[s:end] is the token of an
// unresolved-alias block reason ("unknown alias <tok> — use only names from
// your context"), with the dash written raw or JSON-escaped.
func inGuardReason(text string, s, end int) bool {
	if s < len(reasonPrefix) || text[s-len(reasonPrefix):s] != reasonPrefix {
		return false
	}
	rest := text[end:]
	return strings.HasPrefix(rest, reasonSuffix) || strings.HasPrefix(rest, reasonSuffixJSON)
}

// toolTexts returns the raw input followed by every string token (keys and
// values) of the input when it is JSON.
func toolTexts(input []byte) []string {
	texts := []string{string(input)}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err != nil {
			break // end of input, or not JSON: the raw text is scanned
		}
		if s, ok := tok.(string); ok && s != "" {
			texts = append(texts, s)
		}
	}
	return texts
}

// unknownAlias returns the first alias-shaped token in t, or in one of its
// decoded views, that is not an enrolled original.
func (e *Engine) unknownAlias(t string) (string, bool) {
	check := func(s string) (string, bool) {
		for _, sh := range scanShapes(s) {
			if !guardShape(sh) || e.knownOriginal(sh) {
				continue
			}
			return sh.text, true
		}
		return "", false
	}
	if a, ok := check(t); ok {
		return a, true
	}
	for _, v := range decodedViews(t) {
		if a, ok := check(v.text); ok {
			return a, true
		}
	}
	return "", false
}

// guardShape narrows scanShapes for the guard: a 2001:db8::/32 token counts
// only when at most one of its six trailing 16-bit groups is zero. Minted
// IPv6 aliases carry 96 HMAC bits; documentation addresses (2001:db8::1,
// 2001:db8:85a3::8a2e:370:7334, 2001:DB8::) do not.
func guardShape(sh shape) bool {
	if sh.kind != shapeIPv6 {
		return true
	}
	a, err := netip.ParseAddr(sh.text)
	if err != nil {
		return true
	}
	b := a.As16()
	zeros := 0
	for i := 4; i < 16; i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			zeros++
		}
	}
	return zeros <= 1
}

// knownOriginal reports whether an alias-shaped token is a real value the
// store has enrolled. A host also counts when its <hex6>.example root is an
// enrolled original (a subdomain of a real lookalike domain); a CIDR when
// its address is.
func (e *Engine) knownOriginal(sh shape) bool {
	if _, _, ok := e.s.AliasFor(sh.text); ok {
		return true
	}
	switch sh.kind {
	case shapeHost:
		labels := strings.Split(strings.TrimSuffix(sh.text, "."), ".")
		if len(labels) > 2 {
			root := strings.Join(labels[len(labels)-2:], ".")
			if _, _, ok := e.s.AliasFor(root); ok {
				return true
			}
		}
	case shapeCIDR:
		if i := strings.IndexByte(sh.text, '/'); i > 0 {
			if _, _, ok := e.s.AliasFor(sh.text[:i]); ok {
				return true
			}
		}
	}
	return false
}
