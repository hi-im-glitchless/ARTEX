package membrane

import (
	"sort"
	"strings"
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
	// seam: some pattern contains leakSeam, so a match can straddle a
	// LeakCheck segment cut.
	seam bool
}

type acPattern struct {
	text          string // matched text (exactly when caseSensitive)
	original      string // enrolled original reported in Match
	kind          Kind
	alias         string
	caseSensitive bool
	bound         boundMode
}

// boundMode says which neighbours a match must not have.
type boundMode uint8

const (
	boundNone boundMode = iota
	// boundToken: no letter or digit on either side (ruling R10: keywords
	// of 3-4 runes).
	boundToken
	// boundHost: no letter, digit or '-' on either side, so a domain does
	// not match inside another host label (notacme.pt, acme.ptx.com). A '.'
	// is a boundary: portal.acme.pt still contains acme.pt.
	boundHost
	// boundEmail: like boundHost on the right; on the left no byte that can
	// belong to a local part (xjo@acme.pt is not jo@acme.pt).
	boundEmail
	// boundDigits: no digit on either side (an all-digit value: 1234 is not
	// inside 12345, but is in -p1234 or pw1234).
	boundDigits
	// boundLetters: no letter on either side (an all-letter value: bob is
	// not inside bobby, but is in bob123).
	boundLetters
	// boundKeywordLeft: a long keyword (org, product, person) does not
	// continue a word on its left (fusion is not in confusion), except at a
	// camelCase start (getFusion); glued on the right it matches
	// (fusionbank, robinhoodapp).
	boundKeywordLeft
)

// isAlnumRune reports whether r is a letter or digit (any script).
func isAlnumRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func isHostRune(r rune) bool { return isAlnumRune(r) || r == '-' }

func isLocalPartRune(r rune) bool { return isAlnumRune(r) || strings.ContainsRune("._%+-", r) }

// atBoundary reports whether text[start:end] is free of the neighbours mode
// forbids. The text edge is always a boundary.
func atBoundary(text string, start, end int, mode boundMode) bool {
	left, right := isAlnumRune, isAlnumRune
	switch mode {
	case boundNone:
		return true
	case boundHost:
		left, right = isHostRune, isHostRune
	case boundEmail:
		left, right = isLocalPartRune, isHostRune
	case boundDigits:
		left, right = unicode.IsDigit, unicode.IsDigit
	case boundLetters:
		left, right = unicode.IsLetter, unicode.IsLetter
	}
	if mode == boundKeywordLeft {
		if start == 0 {
			return true
		}
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if !unicode.IsLetter(r) {
			return true
		}
		f, _ := utf8.DecodeRuneInString(text[start:])
		return unicode.IsLower(r) && unicode.IsUpper(f)
	}
	if mode == boundDigits && inDottedNumber(text, start, end) {
		return false
	}
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); left(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); right(r) {
			return false
		}
	}
	return true
}

// inDottedNumber reports whether text[start:end] is one group of a dotted
// number (240 in 240.0.1.7 or 10.240.1.1, 1234 in v1.2.1234 or 1234.5): an
// all-digit credential there is an address or version part, not a secret.
func inDottedNumber(text string, start, end int) bool {
	if start >= 2 && text[start-1] == '.' && text[start-2] >= '0' && text[start-2] <= '9' {
		return true
	}
	return end+1 < len(text) && text[end] == '.' && text[end+1] >= '0' && text[end+1] <= '9'
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
		a.seam = a.seam || strings.Contains(p.text, leakSeam)
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

// any reports whether some pattern matches in text.
func (a *Automaton) any(text string) bool { return len(a.findAll(text, nil)) > 0 }

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
			if !atBoundary(text, sp.s, sp.e, p.bound) {
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
