package membrane

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

// ScrubRequest is the last repair before a leak block. The transform
// decides per context what to replace (role rules, alias-shaped tokens,
// replacement edges), while LeakCheck scans every byte for an enrolled
// original; when the two disagree on plain text, blocking would stop the
// task on every retry of the same history. ScrubRequest replaces, in a copy
// of req, each enrolled original that LeakCheck reports in plain text (the
// same matches it reports: outside minted aliases and request settings)
// with its alias: System segments, message text, unsigned thinking,
// tool_use input and tool_result content. Tool definitions and signed
// thinking are left as they are. It returns the copy and the number of
// values replaced; LeakCheck must run again on the result, and anything
// still found (an encoded form, a signed block) blocks as before.
func (e *Engine) ScrubRequest(req llm.CompletionRequest) (llm.CompletionRequest, int) {
	n := 0
	out := req
	if req.System != nil {
		out.System = make([]string, len(req.System))
		for i, s := range req.System {
			var k int
			out.System[i], k = e.scrubText(s)
			n += k
		}
	}
	if req.Messages != nil {
		out.Messages = make([]llm.Message, len(req.Messages))
		for i, m := range req.Messages {
			c, k := e.scrubBlocks(m.Content)
			out.Messages[i] = llm.Message{Role: m.Role, Content: c}
			n += k
		}
	}
	return out, n
}

func (e *Engine) scrubBlocks(bs []llm.ContentBlock) ([]llm.ContentBlock, int) {
	if bs == nil {
		return nil, 0
	}
	n := 0
	out := make([]llm.ContentBlock, len(bs))
	for i, b := range bs {
		nb := b
		var k int
		nb.Text, k = e.scrubText(b.Text)
		n += k
		if b.Signature == "" {
			nb.Thinking, k = e.scrubText(b.Thinking)
			n += k
		}
		if len(b.Input) > 0 {
			if s, k := e.scrubText(string(b.Input)); k > 0 && json.Valid([]byte(s)) {
				nb.Input = json.RawMessage(s)
				n += k
			}
		}
		nb.Content, k = e.scrubBlocks(b.Content)
		n += k
		out[i] = nb
	}
	return out, n
}

// scrubText replaces the enrolled originals LeakCheck would report in t
// (plain view) with their aliases.
func (e *Engine) scrubText(t string) (string, int) {
	if t == "" {
		return t, 0
	}
	ms := e.s.Dictionary().FindAll(t)
	if len(ms) == 0 {
		return t, 0
	}
	aliases := e.aliasOccurrences(t)
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Start != ms[j].Start {
			return ms[i].Start < ms[j].Start
		}
		return ms[i].End > ms[j].End
	})
	var b strings.Builder
	last, n := 0, 0
next:
	for _, m := range ms {
		if m.Start < last {
			continue // overlaps a match already replaced
		}
		for _, a := range aliases {
			if a[0] <= m.Start && m.End <= a[1] {
				continue next
			}
		}
		if envelopeNumber(t, m.Start, m.End) || e.mintedEmailLocal(t, m.Start, m.End) {
			continue
		}
		alias, _, ok := e.s.AliasFor(m.Original)
		if !ok {
			continue
		}
		if isKeywordKind(m.Kind) && inHostToken(t, m.Start, m.End) {
			alias = strings.ToLower(alias)
		}
		b.WriteString(t[last:m.Start])
		b.WriteString(alias)
		last = m.End
		n++
	}
	if n == 0 {
		return t, 0
	}
	b.WriteString(t[last:])
	return b.String(), n
}
