package membrane

import (
	"net/netip"
	"strings"
)

// Incremental cache validation (final review I2).
//
// Every store change that can alter a transform's output bumps the
// generation and appends a storeChange describing what changed: the texts
// it added (originals and their variants, aliases, retired aliases) and the
// addresses or blocks it added. A ToModel or LeakCheck result cached at
// generation g stays valid at a later generation when none of the changes
// after g touches its input: no added text occurs in the input or in any of
// its decoded views (URL, JSON escape, HTML entity, nested up to
// maxDeltaDepth, plus JWT header/payload and Basic credentials), no added
// address is written in it, and no dotted quad in it shares a first octet
// with an added block. A change that cannot be described this way (a reload,
// a log that no longer reaches back to g) invalidates everything.
//
// Why this is sound: every store-dependent decision in a transform is about
// a value written in the text (a dictionary match, an alias-shaped token, a
// host under a root, an address inside a block). A new entry can only change
// a decision about a value that contains the entry's original or alias as a
// substring (case-insensitively; hosts contain their root, compounds their
// keyword, phone variants their digits), or about an address the entry or
// block covers. Values the transform detected structurally were enrolled
// when the result was computed, so later enrolments of the same value
// change nothing.

// maxStoreChanges bounds the change log; a cached result older than the
// oldest kept change is recomputed.
const maxStoreChanges = 1 << 14

// maxDeltaDepth bounds the nesting of decoded views checked for added texts.
const maxDeltaDepth = 3

// fewNeedles is the needle count up to which deltaMatcher searches
// substrings instead of building an automaton.
const fewNeedles = 32

// storeChange is one generation step.
type storeChange struct {
	gen      uint64
	full     bool
	needles  []string
	addrs    []netip.Addr
	prefixes []netip.Prefix
}

// bump records c as the next generation. Callers may hold s.mu.
func (s *Store) bump(c storeChange) {
	s.chMu.Lock()
	c.gen = s.gen.Add(1)
	s.changes = append(s.changes, c)
	if len(s.changes) > maxStoreChanges {
		s.changes = append([]storeChange(nil), s.changes[len(s.changes)/2:]...)
	}
	s.chMu.Unlock()
}

// entryChange describes the indexing of e.
// Its needles are every dictionary spelling of e (forwardSpellings, shared
// with patternsLocked), plus norm, alias and retired aliases.
func entryChange(e *entry) storeChange {
	c := storeChange{needles: []string{e.norm, e.alias}}
	c.needles = append(c.needles, e.retired...)
	for _, sp := range forwardSpellings(e) {
		c.needles = append(c.needles, sp.text)
		if sp.alias != "" {
			c.needles = append(c.needles, sp.alias)
		}
	}
	if e.kind == KindIPv4 || e.kind == KindIPv6 {
		for _, v := range append([]string{e.original, e.alias}, e.retired...) {
			if a, err := netip.ParseAddr(v); err == nil {
				c.addrs = append(c.addrs, a.Unmap())
			}
		}
	}
	return c
}

// changesSince merges the changes after generation g. cur is the generation
// they bring the store to; ok is false when the log cannot describe them
// (a full change, or a log that no longer reaches back to g).
func (s *Store) changesSince(g uint64) (merged storeChange, cur uint64, ok bool) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	cur = s.gen.Load()
	if g == cur {
		return storeChange{}, cur, true
	}
	if g > cur || len(s.changes) == 0 || s.changes[0].gen > g+1 {
		return storeChange{}, cur, false
	}
	// changes are ordered by gen; find the first after g.
	lo, hi := 0, len(s.changes)
	for lo < hi {
		m := (lo + hi) / 2
		if s.changes[m].gen <= g {
			lo = m + 1
		} else {
			hi = m
		}
	}
	for _, c := range s.changes[lo:] {
		if c.full {
			return storeChange{}, cur, false
		}
		merged.needles = append(merged.needles, c.needles...)
		merged.addrs = append(merged.addrs, c.addrs...)
		merged.prefixes = append(merged.prefixes, c.prefixes...)
	}
	return merged, cur, true
}

// deltaMatcher tests whether an input is touched by a set of changes.
type deltaMatcher struct {
	// few holds the lowercased needles when there are at most fewNeedles
	// (substring search on the lowercased text beats the automaton);
	// otherwise ac matches them.
	few     []string
	ac      *Automaton
	addrs   map[netip.Addr]bool
	v6      bool
	octets  [256]bool
	anyOcts bool
}

func newDeltaMatcher(c storeChange) (*deltaMatcher, bool) {
	d := &deltaMatcher{addrs: map[netip.Addr]bool{}}
	seen := map[string]bool{}
	var pats []acPattern
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || seen[lowerASCII(n)] {
			return
		}
		seen[lowerASCII(n)] = true
		pats = append(pats, acPattern{text: n, original: n, bound: boundNone})
	}
	for _, n := range c.needles {
		add(n)
	}
	for _, a := range c.addrs {
		d.addrs[a] = true
		add(a.String())
		if a.Is6() {
			d.v6 = true
		}
	}
	for _, p := range c.prefixes {
		if !p.Addr().Is4() || p.Bits() < 8 {
			return nil, false
		}
		d.octets[p.Addr().As4()[0]] = true
		d.anyOcts = true
	}
	switch {
	case len(pats) > fewNeedles:
		d.ac = buildAutomaton(pats)
	default:
		for _, p := range pats {
			d.few = append(d.few, lowerASCII(p.text))
		}
	}
	return d, true
}

// touches reports whether the changes may alter a result computed for t.
func (d *deltaMatcher) touches(t string) bool { return d.touchesAt(t, 0) }

func (d *deltaMatcher) touchesAt(t string, depth int) bool {
	if t == "" {
		return false
	}
	if d.ac != nil && d.ac.any(t) {
		return true
	}
	if len(d.few) > 0 {
		lt := lowerASCII(t)
		for _, n := range d.few {
			if strings.Contains(lt, n) {
				return true
			}
		}
	}
	if d.anyOcts && d.quadWithOctet(t) {
		return true
	}
	if d.v6 && d.ipv6Touch(t) {
		return true
	}
	for _, jt := range jwtTokens(t) {
		if d.touchesAt(string(jt.header), depth+1) || d.touchesAt(string(jt.payload), depth+1) {
			return true
		}
	}
	for _, bt := range basicTokens(t) {
		if d.touchesAt(bt.plain, depth+1) {
			return true
		}
	}
	if depth < maxDeltaDepth {
		for _, v := range decodedViews(t) {
			if d.touchesAt(v.text, depth+1) {
				return true
			}
		}
	}
	return false
}

// quadWithOctet reports whether t holds a number followed by ".<digit>"
// whose value is the first octet of an added block (a superset of every
// dotted quad and CIDR the block can affect).
func (d *deltaMatcher) quadWithOctet(t string) bool {
	for i := 0; i < len(t); i++ {
		if !isDigitByte(t[i]) || i > 0 && isDigitByte(t[i-1]) {
			continue
		}
		n, j := 0, i
		for j < len(t) && j-i < 4 && isDigitByte(t[j]) {
			n = n*10 + int(t[j]-'0')
			j++
		}
		if j-i <= 3 && n < 256 && j+1 < len(t) && t[j] == '.' && isDigitByte(t[j+1]) && d.octets[n] {
			return true
		}
		i = j - 1
	}
	return false
}

// ipv6Touch reports whether t writes an added IPv6 address in any notation.
func (d *deltaMatcher) ipv6Touch(t string) bool {
	hit := false
	forRuns(t, func(c byte) bool { return isHexByte(c) || c == ':' || c == '.' }, func(s, e int) {
		if hit || strings.Count(t[s:e], ":") < 2 {
			return
		}
		for ; e > s; e-- {
			if a, err := netip.ParseAddr(t[s:e]); err == nil {
				hit = d.addrs[a.Unmap()]
				return
			}
			if t[e-1] != '.' && t[e-1] != ':' {
				return
			}
		}
	})
	return hit
}

// delta returns the matcher for the changes after generation from and the
// generation it validates to; nil when everything must be recomputed.
func (e *Engine) delta(from uint64) (*deltaMatcher, uint64) {
	c, cur, ok := e.s.changesSince(from)
	if !ok {
		return nil, cur
	}
	key := [2]uint64{from, cur}
	e.deltaMu.Lock()
	if d, ok := e.deltas[key]; ok {
		e.deltaMu.Unlock()
		return d, cur
	}
	e.deltaMu.Unlock()
	d, ok := newDeltaMatcher(c)
	if !ok {
		return nil, cur
	}
	e.deltaMu.Lock()
	if e.deltas == nil || len(e.deltas) >= 64 {
		e.deltas = map[[2]uint64]*deltaMatcher{}
	}
	e.deltas[key] = d
	e.deltaMu.Unlock()
	return d, cur
}

// stillValid reports whether a result computed for in at generation from
// holds now, and the generation it holds at.
func (e *Engine) stillValid(in string, from uint64) (uint64, bool) {
	d, cur := e.delta(from)
	if d == nil {
		return cur, false
	}
	return cur, !d.touches(in)
}
