package membrane

import (
	"sort"
	"unicode"
	"unicode/utf8"
)

// Match is one dictionary hit in a scanned text: text[Start:End] (byte
// offsets) is an occurrence of the enrolled Original, or of a variant of it
// such as the Unicode form of an IDN domain, and maps to Alias.
type Match struct {
	Start, End int
	Kind       Kind
	Original   string
	Alias      string
}

// Automaton is an immutable Aho-Corasick matcher over enrolled originals.
// Patterns are matched on ASCII-lowered bytes; case-sensitive patterns are
// then verified against the exact text. It is safe for concurrent use.
type Automaton struct {
	nodes []acNode
	pats  []acPattern
}

type acPattern struct {
	text          string // matched text (exactly when caseSensitive)
	original      string // enrolled original reported in Match
	kind          Kind
	alias         string
	caseSensitive bool
	// boundary requires a token boundary (text edge or a non-alphanumeric
	// rune) on both sides of the match (ruling R10: short keywords).
	boundary bool
}

// isAlnumRune reports whether r is a letter or digit (any script).
func isAlnumRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// atTokenBoundary reports whether text[start:end] has no letter or digit
// directly before or after it.
func atTokenBoundary(text string, start, end int) bool {
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isAlnumRune(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isAlnumRune(r) {
			return false
		}
	}
	return true
}

type acNode struct {
	next map[byte]int32
	fail int32
	out  []int32 // pattern ids ending here, including via fail links
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func buildAutomaton(pats []acPattern) *Automaton {
	a := &Automaton{nodes: []acNode{{}}, pats: pats}
	for id, p := range pats {
		cur := int32(0)
		for _, c := range []byte(lowerASCII(p.text)) {
			nx, ok := a.nodes[cur].next[c]
			if !ok {
				a.nodes = append(a.nodes, acNode{})
				nx = int32(len(a.nodes) - 1)
				if a.nodes[cur].next == nil {
					a.nodes[cur].next = map[byte]int32{}
				}
				a.nodes[cur].next[c] = nx
			}
			cur = nx
		}
		a.nodes[cur].out = append(a.nodes[cur].out, int32(id))
	}
	// Breadth-first fail links.
	queue := make([]int32, 0, len(a.nodes))
	for _, child := range a.nodes[0].next {
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for c, child := range a.nodes[n].next {
			f := a.nodes[n].fail
			for {
				if nx, ok := a.nodes[f].next[c]; ok && nx != child {
					a.nodes[child].fail = nx
					break
				}
				if f == 0 {
					break
				}
				f = a.nodes[f].fail
			}
			fo := a.nodes[a.nodes[child].fail].out
			if len(fo) > 0 {
				a.nodes[child].out = append(append([]int32(nil), a.nodes[child].out...), fo...)
			}
			queue = append(queue, child)
		}
	}
	return a
}

// Len returns the number of patterns in the automaton.
func (a *Automaton) Len() int {
	if a == nil {
		return 0
	}
	return len(a.pats)
}

// FindAll returns the leftmost-longest, non-overlapping dictionary matches in
// text, ordered by Start. Domains and keywords match case-insensitively
// (ASCII); secrets and credentials match exactly. Keywords of 3-4 runes match
// only at token boundaries, longer ones also inside compounds (ruling R10).
// A nil Automaton matches nothing.
func (a *Automaton) FindAll(text string) []Match { return a.findAll(text, nil) }

// findAll is FindAll restricted to patterns whose kind accept allows.
func (a *Automaton) findAll(text string, accept func(Kind) bool) []Match {
	if a == nil || len(a.pats) == 0 {
		return nil
	}
	low := lowerASCII(text)
	type span struct{ s, e int }
	best := map[span]int32{} // per span: chosen pattern id
	cur := int32(0)
	for i := 0; i < len(low); i++ {
		c := low[i]
		for {
			if nx, ok := a.nodes[cur].next[c]; ok {
				cur = nx
				break
			}
			if cur == 0 {
				break
			}
			cur = a.nodes[cur].fail
		}
		for _, id := range a.nodes[cur].out {
			p := &a.pats[id]
			if accept != nil && !accept(p.kind) {
				continue
			}
			sp := span{i + 1 - len(p.text), i + 1}
			if p.caseSensitive && text[sp.s:sp.e] != p.text {
				continue
			}
			if p.boundary && !atTokenBoundary(text, sp.s, sp.e) {
				continue
			}
			// Prefer an exact (case-sensitive) pattern over a folded one.
			if prev, ok := best[sp]; !ok || (p.caseSensitive && !a.pats[prev].caseSensitive) {
				best[sp] = id
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	cands := make([]Match, 0, len(best))
	for sp, id := range best {
		p := &a.pats[id]
		cands = append(cands, Match{Start: sp.s, End: sp.e, Kind: p.kind, Original: p.original, Alias: p.alias})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Start != cands[j].Start {
			return cands[i].Start < cands[j].Start
		}
		return cands[i].End > cands[j].End
	})
	out := cands[:0]
	end := -1
	for _, m := range cands {
		if m.Start >= end {
			out = append(out, m)
			end = m.End
		}
	}
	return out
}
