package membrane

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

// shapeKind classifies a token shaped like an alias.
type shapeKind uint8

const (
	shapeHost    shapeKind = iota // <labels.>hex6.example
	shapeIPv4                     // address in 240.0.0.0/4 (255/8 excluded)
	shapeCIDR                     // the same with a /bits suffix
	shapeIPv6                     // address in 2001:db8::/32
	shapeKeyword                  // ORG-, PRODUCT-, PERSON-, user- + 4 hex
)

// shape is one alias-shaped token text[Start:End].
type shape struct {
	Start, End int
	kind       shapeKind
	text       string
}

var (
	shapeHostRE    = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[0-9a-f]{6}\.example`)
	shapeIPv4RE    = regexp.MustCompile(`(?:24[0-9]|25[0-4])(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?`)
	shapeIPv6RE    = regexp.MustCompile(`(?i)2001:0{0,3}db8:[0-9a-f:]*`)
	shapeKeywordRE = regexp.MustCompile(`(?i)(?:ORG|PRODUCT|PERSON|user)-[0-9a-f]{4}`)
)

// scanShapes returns every alias-shaped token in text that is not contained
// in a longer one, ordered by Start. 255.0.0.0/8 is left out: netmasks
// (255.255.255.0) are not aliases and the allocator never reaches it.
func scanShapes(text string) []shape {
	var out []shape
	add := func(s, e int, k shapeKind) {
		out = append(out, shape{Start: s, End: e, kind: k, text: text[s:e]})
	}
	if containsFoldASCII(text, ".example") {
		for _, m := range shapeHostRE.FindAllStringIndex(text, -1) {
			s, e := m[0], m[1]
			before, after := byteBefore(text, s), byteAfter(text, e)
			if isHostByte(before) || before == '.' || isHostByte(after) ||
				(after == '.' && isASCIIAlnum(byteAfter(text, e+1))) {
				continue
			}
			add(s, e, shapeHost)
		}
	}
	var ipv4 [][]int
	if strings.Contains(text, "24") || strings.Contains(text, "25") {
		ipv4 = shapeIPv4RE.FindAllStringIndex(text, -1)
	}
	for _, m := range ipv4 {
		s, e := m[0], m[1]
		if b := byteBefore(text, s); isDigitByte(b) || b == '.' {
			continue
		}
		addrEnd := e
		if i := strings.IndexByte(text[s:e], '/'); i >= 0 {
			addrEnd = s + i
		}
		if _, err := netip.ParseAddr(text[s:addrEnd]); err != nil {
			continue
		}
		if addrEnd < e {
			if p, err := netip.ParsePrefix(text[s:e]); err != nil || p.Bits() > 32 || isDigitByte(byteAfter(text, e)) {
				e = addrEnd // not a valid prefix: just the address
			}
		}
		if a := byteAfter(text, e); isDigitByte(a) || (a == '.' && isDigitByte(byteAfter(text, e+1))) {
			continue
		}
		if e > addrEnd {
			add(s, e, shapeCIDR)
		} else {
			add(s, e, shapeIPv4)
		}
	}
	for _, m := range shapeIPv6RE.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if b := byteBefore(text, s); isWordByte(b) || b == ':' {
			continue
		}
		_, err := netip.ParseAddr(text[s:e])
		for err != nil && e > s && text[e-1] == ':' {
			e--
			_, err = netip.ParseAddr(text[s:e])
		}
		if err != nil || isWordByte(byteAfter(text, e)) {
			continue
		}
		add(s, e, shapeIPv6)
	}
	for _, m := range shapeKeywordRE.FindAllStringIndex(text, -1) {
		if atBoundary(text, m[0], m[1], boundToken) {
			add(m[0], m[1], shapeKeyword)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End > out[j].End
	})
	kept := out[:0]
	end := -1
	for _, sh := range out {
		if sh.Start >= end {
			kept = append(kept, sh)
			end = sh.End
		} else if sh.End > end {
			// Partial overlap (e.g. a keyword shape running into a host):
			// keep the earlier, longer-reaching token only.
			continue
		}
	}
	return kept
}

// containsFoldASCII reports whether text contains sub (lowercase ASCII) in
// any ASCII case, without allocating.
func containsFoldASCII(text, sub string) bool {
	for i := 0; i+len(sub) <= len(text); i++ {
		j := 0
		for j < len(sub) {
			c := text[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				break
			}
			j++
		}
		if j == len(sub) {
			return true
		}
	}
	return false
}

// AliasShaped returns the distinct alias-shaped tokens in text, in order of
// first appearance: hosts ending in <6 hex>.example, IPv4 addresses (and
// CIDRs) in 240.0.0.0/4, IPv6 addresses in 2001:db8::/32 and
// ORG-/PRODUCT-/PERSON-/user- followed by 4 hex digits. Whether the store
// minted them is not checked.
func (e *Engine) AliasShaped(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sh := range scanShapes(text) {
		if !seen[sh.text] {
			seen[sh.text] = true
			out = append(out, sh.text)
		}
	}
	return out
}

// Suspicion is an unknown-but-suspicious token: text[Start:End] == Text.
type Suspicion struct {
	Start, End int
	Text       string
}

var nameRunRE = regexp.MustCompile(`\p{Lu}\p{Ll}+(?:[ \t]+\p{Lu}\p{Ll}+){1,3}`)

// Suspicious returns capitalised multi-word runs (2-4 words; a sentence's
// first word does not count, so "The Bank" at a sentence start is one word)
// and domain-shaped tokens outside the enrolled roots that are neither
// model-known nor in the alias space. Used for preview and audit flags; it
// never blocks.
func (e *Engine) Suspicious(text string) []Suspicion {
	var out []Suspicion
	for _, m := range nameRunRE.FindAllStringIndex(text, -1) {
		s, end := m[0], m[1]
		if r, _ := utf8.DecodeLastRuneInString(text[:s]); s > 0 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			continue
		}
		if r, _ := utf8.DecodeRuneInString(text[end:]); end < len(text) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			continue
		}
		if sentenceStart(text, s) {
			// Drop the sentence-initial word; keep the rest if it is still a run.
			sp := strings.IndexAny(text[s:end], " \t")
			s += sp
			for s < end && (text[s] == ' ' || text[s] == '\t') {
				s++
			}
			if !strings.ContainsAny(text[s:end], " \t") {
				continue
			}
		}
		out = append(out, Suspicion{Start: s, End: end, Text: text[s:end]})
	}
	roots := map[string]bool{}
	if e.s != nil {
		for _, r := range e.s.Roots() {
			roots[r] = true
		}
	}
	forDomainTokens(text, func(s, end int) {
		host := strings.ToLower(text[s:end])
		if host == "example" || strings.HasSuffix(host, ".example") {
			return
		}
		if suf, icann := publicsuffix.PublicSuffix(host); !icann || suf == host {
			return
		}
		if root, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && roots[root] {
			return
		}
		if e.s != nil && e.s.IsModelKnown(host) {
			return
		}
		out = append(out, Suspicion{Start: s, End: end, Text: text[s:end]})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// sentenceStart reports whether position s begins a sentence: only spaces
// separate it from the text start or from '.', '!', '?' or a newline.
func sentenceStart(text string, s int) bool {
	i := s
	for i > 0 && (text[i-1] == ' ' || text[i-1] == '\t') {
		i--
	}
	return i == 0 || strings.IndexByte(".!?\n\r", text[i-1]) >= 0
}

// forDomainTokens calls fn for every domain-shaped token text[s:e] (two or
// more labels, alphabetic last label) that is not part of a longer host.
func forDomainTokens(text string, fn func(s, e int)) {
	inHost := func(c byte) bool { return isHostByte(c) || c == '.' }
	forRuns(text, inHost, func(rs, re int) {
		if strings.IndexByte(text[rs:re], '.') < 0 {
			return
		}
		for _, m := range findIn(domainTokenRE, text, rs, re) {
			if isHostByte(byteBefore(text, m[0])) || isHostByte(byteAfter(text, m[1])) {
				continue
			}
			fn(m[0], m[1])
		}
	})
}
