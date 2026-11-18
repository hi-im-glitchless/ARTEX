package membrane

import (
	"bytes"
	"encoding/json"
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

// maxReasonAlias caps the alias echoed in a block reason.
const maxReasonAlias = 256

// ToolVerdict is the outcome of CheckTool. Reason is model-facing; it never
// contains an original (an unresolved alias is echoed, which by definition
// is not one). Rule is one of the Rule* constants when Block is set.
type ToolVerdict struct {
	Block  bool
	Reason string
	Rule   string
}

// ToolCheck applies both tool guard rules: it blocks an input that still
// holds an unresolved alias-shaped value, and a web_search input that holds
// any client original. It is the check for agents on a membraned provider.
func (e *Engine) ToolCheck(tool string, input []byte) (block bool, reason string) {
	v := e.CheckTool(tool, input, true)
	return v.Block, v.Reason
}

// CheckTool applies the unresolved-alias rule to every tool, and, when
// webSearchRule is set and tool is web_search, the originals rule (ruling
// R19: only for agents whose provider is membraned).
//
// Every string in the input is scanned: the raw bytes, each decoded JSON
// string (object keys included) and their URL/JSON/HTML-decoded views. An
// alias-shaped value is allowed only when it is an enrolled original (a real
// 240.x address or <hex6>.example host seen in target output, R11); values
// under a quarantined shared root are not enrolled, so they block.
func (e *Engine) CheckTool(tool string, input []byte, webSearchRule bool) ToolVerdict {
	texts := toolTexts(input)
	for _, t := range texts {
		if a, ok := e.unknownAlias(t); ok {
			if len(a) > maxReasonAlias {
				a = a[:maxReasonAlias]
			}
			return ToolVerdict{Block: true, Rule: RuleUnresolvedAlias,
				Reason: "unknown alias " + a + " — use only names from your context"}
		}
	}
	if webSearchRule && tool == WebSearchTool {
		for _, t := range texts {
			if len(e.LeakCheck([]byte(t))) > 0 {
				return ToolVerdict{Block: true, Rule: RuleWebSearchOriginal, Reason: webSearchReason}
			}
		}
	}
	return ToolVerdict{}
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
			if !e.knownOriginal(sh) {
				return sh.text, true
			}
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
