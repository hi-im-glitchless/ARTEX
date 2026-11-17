package membrane

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

// rCand is a ToReal replacement candidate over text[Start:End]. A blocked
// candidate is an alias-shaped token that does not resolve: it is left in
// place, reported as unresolved, and keeps shorter candidates out of it.
type rCand struct {
	Start, End int
	repl       string
	blocked    bool
	prio       int
	unresolved []string // from inside a decoded token (JWT claims, Basic)
}

func (c rCand) bounds() (int, int, int) { return c.Start, c.End, c.prio }

// Candidate priorities on equal length: exact alias in raw text, then in a
// decoded view, then encoded tokens, then shape derivation.
const (
	prioExact  = 0
	prioView   = 1  // + Encoding
	prioToken  = 8  // JWT, Basic
	prioDerive = 10 // shape rules
)

// ToReal maps model text back to real values:
//  1. exact alias lookup (current and retired aliases, any kind) through the
//     reverse automaton, in raw text and in its URL/JSON/HTML decoded views
//     (re-encoded the same way);
//  2. derivation (spec §6): <labels>.<root alias> -> real labels + real
//     root, an address inside an allocated block -> real address, a CIDR of
//     /24 or narrower inside a block (or exactly a seeded block) -> real
//     CIDR; derived hosts and addresses are enrolled (ruling R4);
//  3. any alias-shaped token left is returned as unresolved, unchanged.
//
// Domains the model introduced (not aliases, not under a client root) are
// marked model-known.
func (e *Engine) ToReal(text string) (string, []string) {
	return e.toReal(text, 0)
}

func (e *Engine) toReal(text string, depth int) (string, []string) {
	if text == "" {
		return "", nil
	}
	rd := e.s.ReverseDictionary()
	var cands []rCand
	for _, m := range rd.FindAll(text) {
		if !hostSuffixOK(text, m) {
			continue
		}
		cands = append(cands, rCand{Start: m.Start, End: m.End, repl: reverseText(text[m.Start:m.End], m), prio: prioExact})
	}
	for _, v := range decodedViews(text) {
		for _, m := range rd.FindAll(v.text) {
			if !hostSuffixOK(v.text, m) {
				continue
			}
			sp, ok := v.toRaw(text, Span{Start: m.Start, End: m.End})
			if !ok || sp.Encoding == EncRaw {
				continue
			}
			orig := reverseText(v.text[m.Start:m.End], m)
			cands = append(cands, rCand{Start: sp.Start, End: sp.End,
				repl: encodeLike(text[sp.Start:sp.End], v.enc, orig), prio: prioView + int(v.enc)})
		}
	}
	for _, sh := range scanShapes(text) {
		cands = append(cands, e.deriveShape(sh))
	}
	cands = append(cands, e.jwtCandidates(text)...)
	if depth == 0 {
		cands = append(cands, e.basicCandidates(text, depth)...)
	}
	kept := pickLongest(cands, len(text))

	var b strings.Builder
	var unresolved []string
	seen := map[string]bool{}
	note := func(u string) {
		if !seen[u] {
			seen[u] = true
			unresolved = append(unresolved, u)
		}
	}
	last := 0
	for _, c := range kept {
		b.WriteString(text[last:c.Start])
		if c.blocked {
			b.WriteString(text[c.Start:c.End])
			note(text[c.Start:c.End])
		} else {
			b.WriteString(c.repl)
		}
		for _, u := range c.unresolved {
			note(u)
		}
		last = c.End
	}
	b.WriteString(text[last:])

	e.markModelDomains(text, kept)
	return b.String(), unresolved
}

// hostSuffixOK rejects a domain or email alias match that does not end its
// host: in evil.ffcc79.example.attacker.com or ffcc79.example.evil.com the
// alias is a label sequence of someone else's host, not client space.
func hostSuffixOK(t string, m Match) bool {
	if m.Kind != KindDomain && m.Kind != KindEmail {
		return true
	}
	return !(byteAfter(t, m.End) == '.' && isHostByte(byteAfter(t, m.End+1)))
}

// reverseText is the original for alias match m written as matched. A
// keyword alias written in lowercase (the DNS form inside hostnames) gives
// the lowercase original.
func reverseText(matched string, m Match) string {
	if isKeywordKind(m.Kind) && matched == strings.ToLower(matched) {
		return strings.ToLower(m.Original)
	}
	return m.Original
}

// deriveShape resolves one alias-shaped token by exact lookup or derivation.
func (e *Engine) deriveShape(sh shape) rCand {
	c := rCand{Start: sh.Start, End: sh.End, prio: prioDerive, blocked: true}
	switch sh.kind {
	case shapeHost:
		if real, ok := e.resolveHost(sh.text, true); ok {
			c.repl, c.blocked = real, false
		}
	case shapeIPv4:
		if real, ok := e.s.IPv4Real(netip.MustParseAddr(sh.text)); ok {
			e.enrolDerivedIP(real)
			c.repl, c.blocked = real.String(), false
		}
	case shapeCIDR:
		if real, ok := e.s.CIDRReal(netip.MustParsePrefix(sh.text)); ok {
			c.repl, c.blocked = real.String(), false
		}
	case shapeIPv6:
		if orig, _, ok := e.s.OriginalFor(netip.MustParseAddr(sh.text).String()); ok {
			c.repl, c.blocked = orig, false
		}
	case shapeKeyword:
		if orig, kind, ok := e.s.OriginalFor(sh.text); ok {
			c.repl, c.blocked = reverseText(sh.text, Match{Kind: kind, Original: orig}), false
		}
	}
	return c
}

// resolveHost maps an alias host to its real host: exactly, or by the
// longest enrolled alias suffix with the labels before it de-aliased (the
// inverse of the store's replaceLiterals). With enrol, a derived host is
// enrolled with its parent's provenance, Source "auto" (ruling R4). An
// enrolment failure does not undo the derivation: the host is in client
// space by construction and ToModel enrols it on sight.
func (e *Engine) resolveHost(host string, enrol bool) (string, bool) {
	if orig, kind, ok := e.s.OriginalFor(host); ok {
		return orig, kind == KindDomain
	}
	labels := strings.Split(host, ".")
	for i := 1; i+2 <= len(labels); i++ {
		parent, kind, ok := e.s.OriginalFor(strings.Join(labels[i:], "."))
		if !ok || kind != KindDomain {
			continue
		}
		prefix, ok := e.reversePrefix(strings.Join(labels[:i], "."))
		if !ok {
			return "", false
		}
		real := prefix + "." + parent
		if enrol {
			_, _ = e.s.Enroll(KindDomain, real, e.s.provenanceOf(KindDomain, parent))
		}
		return real, true
	}
	return "", false
}

// reversePrefix de-aliases the labels in front of an alias root: every
// alias written there is replaced by its original (keyword aliases by the
// lowercase original). It fails on an unknown keyword alias, or when the
// result is not host-shaped (an original that cannot sit in a label).
func (e *Engine) reversePrefix(prefix string) (string, bool) {
	ms := e.s.ReverseDictionary().FindAll(prefix)
	var b strings.Builder
	last := 0
	gap := func(s, end int) bool {
		for _, k := range shapeKeywordRE.FindAllStringIndex(prefix[s:end], -1) {
			if atBoundary(prefix, s+k[0], s+k[1], boundToken) {
				return false // unknown keyword alias
			}
		}
		b.WriteString(prefix[s:end])
		return true
	}
	for _, m := range ms {
		if !gap(last, m.Start) {
			return "", false
		}
		if isKeywordKind(m.Kind) {
			b.WriteString(strings.ToLower(m.Original))
		} else {
			b.WriteString(m.Original)
		}
		last = m.End
	}
	if !gap(last, len(prefix)) {
		return "", false
	}
	out := b.String()
	for i := 0; i < len(out); i++ {
		if !isHostByte(out[i]) && out[i] != '.' {
			return "", false
		}
	}
	return out, true
}

// enrolDerivedIP enrols a real address reached through its block (R4).
func (e *Engine) enrolDerivedIP(real netip.Addr) {
	if _, _, ok := e.s.AliasFor(real.String()); ok {
		return
	}
	_, _ = e.s.IPv4Alias(real, e.s.ipProvenance(real))
}

var basicRE = regexp.MustCompile(`(?i)\bbasic[ \t]+([A-Za-z0-9+/]{4,}={0,2})`)

// basicToken is a "Basic <base64(user:pass)>" credential anywhere in text
// (an Authorization header, WWW-Authenticate, prose): text[Start:End] is the
// base64, plain the decoded credential.
type basicToken struct {
	Start, End int
	plain      string
}

// basicTokens finds Basic credentials whose base64 decodes (strictly) to
// printable text containing ':'.
func basicTokens(text string) []basicToken {
	if !containsFoldASCII(text, "basic") {
		return nil
	}
	var out []basicToken
	for _, m := range basicRE.FindAllStringSubmatchIndex(text, -1) {
		s, end := m[2], m[3]
		if a := byteAfter(text, end); isASCIIAlnum(a) || a == '+' || a == '/' || a == '=' {
			continue
		}
		dec, err := base64Like(text[s:end]).Strict().DecodeString(text[s:end])
		if err != nil || !utf8.Valid(dec) || !strings.Contains(string(dec), ":") {
			continue
		}
		printable := true
		for _, r := range string(dec) {
			if !unicode.IsPrint(r) {
				printable = false
				break
			}
		}
		if printable {
			out = append(out, basicToken{Start: s, End: end, plain: string(dec)})
		}
	}
	return out
}

// basicToModelCandidates makes every Basic credential a ToModel candidate,
// so one outside an Authorization header (WWW-Authenticate, logs, prose) is
// aliased too.
func basicToModelCandidates(text string) []tmCand {
	var out []tmCand
	for _, bt := range basicTokens(text) {
		out = append(out, tmCand{Span: Span{Start: bt.Start, End: bt.End, Kind: KindPassword,
			Value: bt.plain, Encoding: EncBasicAuth}, added: true, prio: 2})
	}
	return out
}

// basicCandidates de-aliases "Basic <base64(user:pass)>" credentials.
func (e *Engine) basicCandidates(text string, depth int) []rCand {
	var out []rCand
	for _, bt := range basicTokens(text) {
		inner, unresolved := e.toReal(bt.plain, depth+1)
		if inner == bt.plain && len(unresolved) == 0 {
			continue
		}
		out = append(out, rCand{Start: bt.Start, End: bt.End,
			repl: base64Like(text[bt.Start:bt.End]).EncodeToString([]byte(inner)),
			prio: prioToken, unresolved: unresolved})
	}
	return out
}

// markModelDomains marks domain-shaped tokens of model text as model-known
// when no replacement touched them, they are not alias space and their root
// is not a client root (spec §7: model-introduced domains are not aliased).
func (e *Engine) markModelDomains(text string, kept []rCand) {
	var roots map[string]bool
	forDomainTokens(text, func(s, end int) {
		for _, c := range kept {
			if c.Start < end && s < c.End {
				return
			}
		}
		host := strings.ToLower(text[s:end])
		if strings.HasSuffix(host, ".example") {
			return
		}
		if suf, icann := publicsuffix.PublicSuffix(host); !icann || suf == host {
			return
		}
		if roots == nil {
			roots = map[string]bool{}
			for _, r := range e.s.Roots() {
				roots[r] = true
			}
		}
		if root, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil || roots[root] {
			return
		}
		e.s.MarkModelKnown(host)
	})
}
