package membrane

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Engine rewrites text between the real universe and the alias universe:
// ToModel (detect, enrol, replace) before a request leaves, ToReal (exact
// lookup plus derivation) on what the model sends back, and LeakCheck on
// the serialised request. It is safe for concurrent use.
type Engine struct {
	s     *Store
	p     *Pipeline
	cache *toModelCache
	// rejected holds the alias-shaped tokens the tool guard blocked
	// (lowercase, bounded by maxRejected): invented values that lookalikes
	// must never enrol as real when the block reason comes back.
	rejMu    sync.Mutex
	rejected map[string]struct{}

	// leaks caches LeakCheck results per body segment (see LeakCheck).
	leaks *leakCache
	// deltas memoises change matchers by (from, to) generation.
	deltaMu sync.Mutex
	deltas  map[[2]uint64]*deltaMatcher
	// passes counts full transform passes (tests).
	passes atomic.Int64
	// leakScans counts uncached LeakCheck segment scans (tests).
	leakScans atomic.Int64
}

// NewEngine returns an engine over s (required). p may be nil
// (NewPipeline(s)).
func NewEngine(s *Store, p *Pipeline) *Engine {
	if p == nil {
		p = NewPipeline(s)
	}
	return &Engine{s: s, p: p, cache: newToModelCache(), leaks: newLeakCache()}
}

// Report summarises one ToModel call. Counts is per kind of replaced value,
// Enrolled the number of values newly enrolled by the call, Flags the
// sorted, distinct audit flags ("suspicious_name", "suspicious_domain").
// It never contains originals.
type Report struct {
	Counts   map[Kind]int
	Enrolled int
	Flags    []string
}

func newReport() Report { return Report{Counts: map[Kind]int{}} }

func (r Report) clone() Report {
	c := Report{Counts: make(map[Kind]int, len(r.Counts)), Enrolled: r.Enrolled}
	for k, v := range r.Counts {
		c.Counts[k] = v
	}
	if r.Flags != nil {
		c.Flags = append([]string(nil), r.Flags...)
	}
	return c
}

func (r *Report) merge(o Report) {
	if r.Counts == nil {
		r.Counts = map[Kind]int{}
	}
	for k, v := range o.Counts {
		r.Counts[k] += v
	}
	r.Enrolled += o.Enrolled
	r.Flags = unionSorted(r.Flags, o.Flags)
}

func unionSorted(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LeakHit locates an enrolled original found by LeakCheck: its kind and the
// byte offset in the scanned bytes. The value itself is never included.
type LeakHit struct {
	Kind   Kind
	Offset int
}

// generation changes whenever a cached ToModel result may be stale.
func (e *Engine) generation() uint64 { return e.s.generation() }

// ToModel rewrites text into the alias universe. text is treated as
// non-assistant content (system, user, tool output). Every detected value
// with no alias yet is enrolled with prov (and prov is merged into values
// already enrolled); real values shaped like aliases are enrolled too
// (ruling R11); aliases the store minted pass through. Results are cached
// per (text, role, provenance, store generation), so replayed history is not
// rescanned. Errors never contain originals; on error nothing must be sent.
func (e *Engine) ToModel(text string, prov Provenance) (string, Report, error) {
	return e.toModelRole(text, prov, false)
}

// cacheKey hashes everything a ToModel result depends on besides the store
// generation.
func cacheKey(text string, prov Provenance, assistant bool) [32]byte {
	h := sha256.New()
	if assistant {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	fmt.Fprintf(h, "%v|%v|%s|", prov.CompanyIDs, prov.TaskIDs, prov.Source)
	h.Write([]byte(text))
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

// toModelRole is ToModel with the message role: in assistant text and
// thinking (assistant true), alias-shaped tokens the store did not mint are
// the model's own words and pass through, never enrolled (ruling R12).
func (e *Engine) toModelRole(text string, prov Provenance, assistant bool) (string, Report, error) {
	if text == "" {
		return "", newReport(), nil
	}
	key := cacheKey(text, prov, assistant)
	g := e.generation()
	if ce, ok := e.cache.get(key); ok {
		if ce.gen == g {
			return ce.out, ce.rep, nil
		}
		// Generation moved: reuse the result unless a change since it
		// was computed touches this text (delta.go).
		if cur, ok := e.stillValid(text, ce.gen); ok {
			e.cache.revalidate(key, ce.gen, cur)
			return ce.out, ce.rep, nil
		}
	}
	out, rep, err := e.toModel(text, prov, assistant)
	if err != nil {
		return "", Report{}, err
	}
	// A result is cached at the generation read before computing it: any
	// change made meanwhile (by another goroutine) is after that generation
	// and is checked against the text on the next lookup. A call that
	// enrolled something is not cached: the next identical call recomputes
	// once (with Enrolled 0) and caches that.
	if rep.Enrolled == 0 {
		e.cache.put(key, g, text, out, rep)
	}
	return out, rep, nil
}

// tmCand is a ToModel replacement candidate: a pipeline span, or one the
// engine adds (added): a real value shaped like an alias (look), or a Basic
// credential outside an Authorization header.
type tmCand struct {
	Span
	look  bool
	added bool
	prio  int
}

func (c tmCand) bounds() (int, int, int) { return c.Start, c.End, c.prio }

// maxPasses bounds the ToModel fixpoint (see toModel).
const maxPasses = 4

// toModel runs transform passes until one leaves the table unchanged. An
// enrolment can make an earlier, already-passed occurrence an original (an
// email enrols its domain as a client root; a keyword re-mints hosts), so a
// pass that enrolled anything is redone on the original text with the
// grown dictionary. Enrolled sums all passes.
func (e *Engine) toModel(text string, prov Provenance, assistant bool) (string, Report, error) {
	enrolled := 0
	for pass := 1; ; pass++ {
		g := e.generation()
		out, rep, err := e.transformPass(text, prov, assistant)
		if err != nil {
			return "", Report{}, err
		}
		enrolled += rep.Enrolled
		if e.generation() == g || pass == maxPasses {
			rep.Enrolled = enrolled
			return out, rep, nil
		}
	}
}

func (e *Engine) transformPass(text string, prov Provenance, assistant bool) (string, Report, error) {
	e.passes.Add(1)
	rep := newReport()
	var b strings.Builder
	last := 0
	extra := basicToModelCandidates(text)
	extra = append(extra, e.lookalikes(text, assistant)...)
	// Minted aliases already in the text are protected: no detection inside
	// one is replaced (a short secret "240" inside the IP alias 240.0.1.7).
	prot := e.mintedOccurrences(text)
	var spans []Span
	for _, sp := range e.p.Detect(text) {
		if !insideAny(prot, sp.Start, sp.End) {
			spans = append(spans, sp)
		}
	}
	// ranges: output ranges that exposedOriginals must not touch; written
	// marks a replacement, the others are kept detections and minted aliases.
	var ranges []outRange
	copyRaw := func(from, to int) {
		for _, p := range prot {
			if p[0] >= from && p[1] <= to {
				o := b.Len() + p[0] - from
				ranges = append(ranges, outRange{o, o + p[1] - p[0], false})
			}
		}
		b.WriteString(text[from:to])
	}
	for _, c := range mergeAdded(spans, extra) {
		raw := text[c.Start:c.End]
		repl, err := e.replacement(text, c, prov, &rep)
		if err != nil {
			return "", Report{}, err
		}
		copyRaw(last, c.Start)
		if repl != raw {
			rep.Counts[c.Kind]++
		}
		ranges = append(ranges, outRange{b.Len(), b.Len() + len(repl), repl != raw})
		b.WriteString(repl)
		last = c.End
	}
	copyRaw(last, len(text))
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].s < ranges[j].s })
	out, err := e.exposedOriginals(b.String(), ranges, prov, &rep)
	if err != nil {
		return "", Report{}, err
	}
	for _, sp := range e.Suspicious(out) {
		if strings.ContainsAny(sp.Text, " \t") {
			rep.Flags = unionSorted(rep.Flags, []string{"suspicious_name"})
		} else {
			rep.Flags = unionSorted(rep.Flags, []string{"suspicious_domain"})
		}
	}
	return out, rep, nil
}

// outRange is a range of the ToModel output: a replacement (written) or a
// span kept as written (a detection that is already an alias, a minted
// alias).
type outRange struct {
	s, e    int
	written bool
}

func insideAny(rs [][2]int, s, e int) bool {
	for _, r := range rs {
		if r[0] <= s && e <= r[1] {
			return true
		}
	}
	return false
}

// mintedOccurrences returns the ranges of minted aliases in t: exact aliases
// (reverse automaton, not as the left part of a third-party host) and
// alias-shaped tokens that resolve (hosts under a minted domain alias,
// addresses inside allocated blocks, known keyword and IPv6 aliases).
func (e *Engine) mintedOccurrences(t string) [][2]int {
	var out [][2]int
	for _, m := range e.s.ReverseDictionary().FindAll(t) {
		if e.hostSuffixOK(t, m) {
			out = append(out, [2]int{m.Start, m.End})
		}
	}
	for _, sh := range scanShapes(t) {
		ok := false
		switch sh.kind {
		case shapeHost:
			ok = e.underMintedDomain(sh.text)
		case shapeIPv4:
			_, ok = e.s.IPv4Real(netip.MustParseAddr(sh.text))
		case shapeCIDR:
			_, ok = e.s.CIDRReal(netip.MustParsePrefix(sh.text))
			if !ok {
				_, ok = e.s.IPv4Real(netip.MustParseAddr(sh.text[:strings.IndexByte(sh.text, '/')]))
			}
		case shapeIPv6:
			_, _, ok = e.s.OriginalFor(netip.MustParseAddr(sh.text).String())
		case shapeKeyword:
			_, _, ok = e.s.OriginalFor(sh.text)
		}
		if ok {
			out = append(out, [2]int{sh.Start, sh.End})
		}
	}
	return out
}

// maxExposedRounds bounds exposedOriginals.
const maxExposedRounds = 3

// exposedOriginals aliases originals that a replacement exposed: the
// boundary of a short single-class credential depends on its neighbours, so
// "ACmeBAnkjsilva" (jsilva glued to letters, not matched) becomes
// "ORG-3be1jsilva" (jsilva after a digit, matched). Only a dictionary match
// that touches the edge of a replacement and overlaps no range (replaced,
// kept, or minted alias) is aliased: everything else was decided by the
// pass itself. A match straddling a replacement is a juxtaposition of an
// alias with real text and is left to LeakCheck (fail closed).
func (e *Engine) exposedOriginals(out string, ranges []outRange, prov Provenance, rep *Report) (string, error) {
	for round := 0; round < maxExposedRounds; round++ {
		var fixes []Match
	next:
		for _, m := range e.s.Dictionary().FindAll(out) {
			adjacent := false
			for _, r := range ranges {
				if r.s < m.End && m.Start < r.e {
					continue next
				}
				if r.written && (r.e == m.Start || r.s == m.End) {
					adjacent = true
				}
			}
			if adjacent {
				fixes = append(fixes, m)
			}
		}
		if len(fixes) == 0 {
			return out, nil
		}
		var b strings.Builder
		var moved []outRange
		last, delta, ri := 0, 0, 0
		for _, m := range fixes {
			a, keep, err := e.aliasValue(m.Kind, m.Original, prov, rep)
			if err != nil {
				return "", err
			}
			if keep {
				a = out[m.Start:m.End]
			}
			if isKeywordKind(m.Kind) && inHostToken(out, m.Start, m.End) {
				a = strings.ToLower(a)
			}
			for ; ri < len(ranges) && ranges[ri].e <= m.Start; ri++ {
				moved = append(moved, outRange{ranges[ri].s + delta, ranges[ri].e + delta, ranges[ri].written})
			}
			b.WriteString(out[last:m.Start])
			moved = append(moved, outRange{b.Len(), b.Len() + len(a), true})
			b.WriteString(a)
			delta += len(a) - (m.End - m.Start)
			last = m.End
			rep.Counts[m.Kind]++
		}
		for ; ri < len(ranges); ri++ {
			moved = append(moved, outRange{ranges[ri].s + delta, ranges[ri].e + delta, ranges[ri].written})
		}
		b.WriteString(out[last:])
		out, ranges = b.String(), moved
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].s < ranges[j].s })
	}
	return out, nil
}

// replacement returns the text written over candidate c.
func (e *Engine) replacement(text string, c tmCand, prov Provenance, rep *Report) (string, error) {
	raw := text[c.Start:c.End]
	switch {
	case c.look:
		return e.enrolLookalike(c.Kind, c.Value, prov, rep)
	case c.Encoding == EncBasicAuth:
		return e.basicToModel(raw, c.Value, prov, rep)
	case c.Kind == KindToken:
		j, ok, err := e.jwtToModel(c.Value, prov, rep)
		if err != nil {
			return "", err
		}
		if ok {
			return encodeLike(raw, c.Encoding, j), nil
		}
	}
	a, keep, err := e.aliasValue(c.Kind, c.Value, prov, rep)
	if err != nil {
		return "", err
	}
	if keep {
		return raw, nil
	}
	if isKeywordKind(c.Kind) && inHostToken(text, c.Start, c.End) {
		a = strings.ToLower(a) // DNS-safe form inside hostnames
	}
	return encodeLike(raw, c.Encoding, a), nil
}

// aliasValue returns the alias of a detected value, enrolling it when it
// has none and merging prov into it when it has. keep is true when v must
// stay as written: it is already an alias the store minted.
func (e *Engine) aliasValue(kind Kind, v string, prov Provenance, rep *Report) (alias string, keep bool, err error) {
	if a, _, ok := e.s.AliasFor(v); ok {
		if err := e.s.noteUse(v, prov); err != nil {
			return "", false, fmt.Errorf("membrane to_model: %w", err)
		}
		return a, false, nil
	}
	if _, _, ok := e.s.OriginalFor(v); ok {
		return "", true, nil
	}
	if kind == KindIPv4 {
		ip, perr := netip.ParseAddr(strings.TrimSpace(v))
		if perr != nil {
			return "", false, fmt.Errorf("membrane to_model: invalid %s value", kind)
		}
		var ap netip.Addr
		if ap, err = e.s.IPv4Alias(ip, prov); err == nil {
			alias = ap.String()
		}
	} else {
		alias, err = e.s.Enroll(kind, v, prov)
	}
	if err != nil {
		return "", false, fmt.Errorf("membrane to_model: enrol %s: %w", kind, err)
	}
	if alias == v {
		return "", true, nil // not aliased by policy (e.g. a private address)
	}
	rep.Enrolled++
	return alias, false, nil
}

// enrolLookalike aliases a real value shaped like an alias (ruling R11).
func (e *Engine) enrolLookalike(kind Kind, v string, prov Provenance, rep *Report) (string, error) {
	if a, _, ok := e.s.AliasFor(v); ok {
		if err := e.s.noteUse(v, prov); err != nil {
			return "", fmt.Errorf("membrane to_model: %w", err)
		}
		return a, nil
	}
	a, err := e.s.enrollLookalike(kind, v, prov)
	if err != nil {
		return "", fmt.Errorf("membrane to_model: enrol alias-shaped %s: %w", kind, err)
	}
	rep.Enrolled++
	return a, nil
}

// basicToModel aliases the user and password of a Basic credential and
// re-encodes it in the same base64 flavour.
func (e *Engine) basicToModel(raw, val string, prov Provenance, rep *Report) (string, error) {
	part := func(kind Kind, v string) (string, error) {
		if v == "" {
			return v, nil
		}
		a, keep, err := e.aliasValue(kind, v, prov, rep)
		if keep {
			return v, err
		}
		return a, err
	}
	var plain string
	if user, pass, ok := strings.Cut(val, ":"); ok {
		ua, err := part(KindUsername, user)
		if err != nil {
			return "", err
		}
		pa, err := part(KindPassword, pass)
		if err != nil {
			return "", err
		}
		plain = ua + ":" + pa
	} else {
		pa, err := part(KindPassword, val)
		if err != nil {
			return "", err
		}
		plain = pa
	}
	if plain == val {
		return raw, nil
	}
	return base64Like(raw).EncodeToString([]byte(plain)), nil
}

// base64Like returns the standard base64 flavour src was written in.
func base64Like(src string) *base64.Encoding {
	if strings.HasSuffix(src, "=") || len(src)%4 == 0 {
		return base64.StdEncoding
	}
	return base64.RawStdEncoding
}

// inHostToken reports whether text[s:e] sits inside a dotted host name
// (acmebank.okta.com, acmebank-sso.okta.com), not in prose.
func inHostToken(text string, s, e int) bool {
	for s > 0 && (isHostByte(text[s-1]) || text[s-1] == '.') {
		s--
	}
	for e < len(text) && (isHostByte(text[e]) || text[e] == '.') {
		e++
	}
	tok := strings.Trim(text[s:e], ".")
	i := strings.IndexByte(tok, '.')
	return i > 0 && i < len(tok)-1
}

// lookalikes returns ToModel candidates for alias-shaped tokens in
// non-assistant content that the store did not mint: real values (ruling
// R11). A minted alias, or a value derivable from one (an address inside an
// allocated block), passes through (ruling R5). A host whose suffix is a
// minted domain alias is alias space whatever its labels (ruling R12):
// never enrolled, never an error.
//
// An enrolled real lookalike is replaced wherever it appears, assistant
// text and guard block reasons included: the detectors skip the reserved
// ranges, so this is its only replacement path. In assistant content
// (assistant true) nothing new is enrolled (ruling R12): only enrolled
// lookalikes become candidates.
func (e *Engine) lookalikes(text string, assistant bool) []tmCand {
	var out []tmCand
	add := func(s, end int, k Kind) {
		out = append(out, tmCand{Span: Span{Start: s, End: end, Kind: k, Value: text[s:end]}, look: true, added: true, prio: 1})
	}
	for _, sh := range scanShapes(text) {
		if s, end, k, ok := e.enrolledLookalike(text, sh); ok {
			add(s, end, k)
			continue
		}
		// Not enrolled. In assistant content it is the model's own token; a
		// token the tool guard rejected is an invented value. Both pass
		// through unchanged (rejected: in this process via the set, after a
		// restart via the block reason around it).
		if assistant || e.isRejected(sh.text) || inGuardReason(text, sh.Start, sh.End) {
			continue
		}
		switch sh.kind {
		case shapeHost:
			if e.underMintedDomain(sh.text) {
				continue
			}
			if ls := emailLocalStart(text, sh.Start); ls >= 0 {
				email := text[ls:sh.End]
				if _, _, ok := e.s.OriginalFor(email); ok {
					continue
				}
				add(ls, sh.End, KindEmail)
				continue
			}
			add(sh.Start, sh.End, KindDomain)
		case shapeIPv4:
			if _, ok := e.s.IPv4Real(netip.MustParseAddr(sh.text)); !ok {
				add(sh.Start, sh.End, KindIPv4)
			}
		case shapeCIDR:
			if _, ok := e.s.CIDRReal(netip.MustParsePrefix(sh.text)); ok {
				continue
			}
			ae := sh.Start + strings.IndexByte(sh.text, '/')
			if _, ok := e.s.IPv4Real(netip.MustParseAddr(text[sh.Start:ae])); !ok {
				add(sh.Start, ae, KindIPv4)
			}
		case shapeIPv6:
			a := netip.MustParseAddr(sh.text)
			if _, _, ok := e.s.OriginalFor(a.String()); !ok {
				add(sh.Start, sh.End, KindIPv6)
			}
		case shapeKeyword:
			if _, _, ok := e.s.OriginalFor(sh.text); ok || e.inMintedEmail(text, sh) {
				continue
			}
			add(sh.Start, sh.End, keywordShapeKind(sh.text))
		}
	}
	return out
}

// enrolledLookalike reports whether the alias-shaped token sh in text is an
// enrolled real value (R11), and the span to replace: the whole email when
// a host is the domain of an enrolled email, the address of a CIDR. Minted
// aliases and values derivable from them are not (a real address equal to
// a minted one is alias space, R5).
func (e *Engine) enrolledLookalike(text string, sh shape) (start, end int, kind Kind, ok bool) {
	v := sh.text
	switch sh.kind {
	case shapeHost:
		if e.underMintedDomain(v) {
			return 0, 0, "", false
		}
		if ls := emailLocalStart(text, sh.Start); ls >= 0 {
			if _, k, ok := e.s.AliasFor(text[ls:sh.End]); ok {
				return ls, sh.End, k, true
			}
		}
	case shapeIPv4:
		if _, ok := e.s.IPv4Real(netip.MustParseAddr(v)); ok {
			return 0, 0, "", false
		}
	case shapeCIDR:
		ae := sh.Start + strings.IndexByte(v, '/')
		addr := text[sh.Start:ae]
		if _, ok := e.s.IPv4Real(netip.MustParseAddr(addr)); ok {
			return 0, 0, "", false
		}
		if _, k, ok := e.s.AliasFor(addr); ok {
			return sh.Start, ae, k, true
		}
		return 0, 0, "", false
	case shapeIPv6:
		if _, _, ok := e.s.OriginalFor(netip.MustParseAddr(v).String()); ok {
			return 0, 0, "", false
		}
	case shapeKeyword:
		if _, _, ok := e.s.OriginalFor(v); ok {
			return 0, 0, "", false
		}
	}
	if _, _, ok := e.s.OriginalFor(v); ok {
		return 0, 0, "", false
	}
	if _, k, ok := e.s.AliasFor(v); ok {
		return sh.Start, sh.End, k, true
	}
	return 0, 0, "", false
}

// underMintedDomain reports whether host, or a suffix of it, is a minted
// domain alias (current or retired).
func (e *Engine) underMintedDomain(host string) bool {
	labels := strings.Split(host, ".")
	for i := 0; i+2 <= len(labels); i++ {
		if _, k, ok := e.s.OriginalFor(strings.Join(labels[i:], ".")); ok && k == KindDomain {
			return true
		}
	}
	return false
}

// mergeAdded combines the pipeline's (non-overlapping) spans with the
// candidates the engine adds. An added candidate replaces the pipeline spans
// it fully contains (its replacement aliases everything inside it); one
// that only partly overlaps a pipeline span is dropped, because the
// pipeline has already discarded the shorter alternatives around that span
// and dropping it would let them through in clear. Longer added candidates
// win among themselves. The result is ordered by Start.
func mergeAdded(spans []Span, looks []tmCand) []tmCand {
	sort.SliceStable(looks, func(i, j int) bool {
		return looks[i].End-looks[i].Start > looks[j].End-looks[j].Start
	})
	out := make([]tmCand, 0, len(spans)+len(looks))
	for _, sp := range spans {
		out = append(out, tmCand{Span: sp})
	}
next:
	for _, l := range looks {
		var inside []int
		for i, c := range out {
			if c.Start >= l.End || l.Start >= c.End {
				continue
			}
			if c.added || c.Start < l.Start || c.End > l.End {
				continue next
			}
			inside = append(inside, i)
		}
		for k := len(inside) - 1; k >= 0; k-- {
			out = append(out[:inside[k]], out[inside[k]+1:]...)
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func keywordShapeKind(tok string) Kind {
	switch strings.ToLower(tok[:strings.IndexByte(tok, '-')]) {
	case "org":
		return KindOrg
	case "product":
		return KindProduct
	case "person":
		return KindPerson
	}
	return KindUsername
}

// emailLocalStart returns where the email local part ending in "@" right
// before host position h starts, or -1.
func emailLocalStart(text string, h int) int {
	if byteBefore(text, h) != '@' {
		return -1
	}
	i := h - 1
	for i > 0 && (isASCIIAlnum(text[i-1]) || strings.IndexByte("._%+-", text[i-1]) >= 0) {
		i--
	}
	if i == h-1 {
		return -1
	}
	return i
}

// inMintedEmail reports whether keyword shape sh (user-xxxx) is the local
// part of a minted email alias written right after it ("@" or "%40").
func (e *Engine) inMintedEmail(text string, sh shape) bool {
	rest := text[sh.End:]
	var hs int
	switch {
	case strings.HasPrefix(rest, "@"):
		hs = sh.End + 1
	case len(rest) >= 3 && strings.EqualFold(rest[:3], "%40"):
		hs = sh.End + 3
	default:
		return false
	}
	he := hs
	for he < len(text) && (isHostByte(text[he]) || text[he] == '.') {
		he++
	}
	host := strings.TrimRight(text[hs:he], ".")
	if host == "" {
		return false
	}
	_, _, ok := e.s.OriginalFor(sh.text + "@" + host)
	return ok
}

// LeakCheck scans serialised (raw, and its URL, JSON-escape and HTML-entity
// decoded views) for any enrolled original: the dictionary of originals,
// plus enrolled public IP addresses (which the dictionary leaves to the
// address detectors). Hits are ordered by offset and carry no value.
//
// The body is scanned in segments cut between "}" and ",{" (message and
// block boundaries of a serialised request, or any other place those bytes
// occur), at least leakSegMin bytes long, and each segment's hits are cached
// like ToModel results (revalidated against the store changes since). This
// is exact: every detector and view decodes locally, the text edge is a
// boundary like "}" and ",", and no escape covers either byte, so a hit
// straddling a cut would have to contain "}," itself; when an enrolled
// original or alias does, the body is scanned whole.
func (e *Engine) LeakCheck(serialised []byte) []LeakHit {
	text := string(serialised)
	cuts := leakCuts(text)
	if len(cuts) == 0 || e.s.Dictionary().seam || e.s.ReverseDictionary().seam {
		return e.leakSegment(text)
	}
	var hits []LeakHit
	prev := 0
	for _, c := range append(cuts, len(text)) {
		for _, h := range e.leakSegment(text[prev:c]) {
			h.Offset += prev
			hits = append(hits, h)
		}
		prev = c
	}
	sortHits(hits)
	return hits
}

// leakSeam is the byte pair LeakCheck segments are cut between.
const leakSeam = "},"

// leakSegMin is the minimum LeakCheck segment length.
const leakSegMin = 16 << 10

// leakCuts returns the segment cut positions of text: the "," of a "},{"
// at least leakSegMin bytes after the previous cut.
func leakCuts(text string) []int {
	var cuts []int
	prev := 0
	for i := prev + leakSegMin; i < len(text); {
		j := strings.Index(text[i:], "},{")
		if j < 0 {
			break
		}
		c := i + j + 1
		cuts = append(cuts, c)
		prev = c
		i = prev + leakSegMin
	}
	return cuts
}

// leakSegment returns the (cached) hits of one segment.
func (e *Engine) leakSegment(seg string) []LeakHit {
	key := sha256.Sum256([]byte(seg))
	g := e.generation()
	if gen, hits, ok := e.leaks.get(key); ok {
		if gen == g {
			return slices.Clone(hits)
		}
		if cur, ok := e.stillValid(seg, gen); ok {
			e.leaks.revalidate(key, gen, cur)
			return slices.Clone(hits)
		}
	}
	hits := e.leakCheckFull(seg)
	e.leaks.put(key, g, seg, slices.Clone(hits))
	return hits
}

func sortHits(hits []LeakHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Offset != hits[j].Offset {
			return hits[i].Offset < hits[j].Offset
		}
		return hits[i].Kind < hits[j].Kind
	})
}

// leakCheckFull is LeakCheck without segments or cache.
func (e *Engine) leakCheckFull(text string) []LeakHit {
	e.leakScans.Add(1)
	dict := e.s.Dictionary()
	seen := map[LeakHit]bool{}
	var hits []LeakHit
	add := func(k Kind, off int) {
		h := LeakHit{Kind: k, Offset: off}
		if !seen[h] {
			seen[h] = true
			hits = append(hits, h)
		}
	}
	scan := func(t string, toRaw func(int) int) {
		ms := dict.FindAll(t)
		var aliases [][2]int
		if len(ms) > 0 {
			aliases = e.aliasOccurrences(t)
		}
	hits:
		for _, m := range ms {
			for _, a := range aliases {
				if a[0] <= m.Start && m.End <= a[1] {
					continue hits // inside an alias: HMAC-derived, not a leak
				}
			}
			if envelopeNumber(t, m.Start, m.End) {
				continue // a request setting (max_tokens), not content
			}
			add(m.Kind, toRaw(m.Start))
		}
		for _, sp := range ipv6s(t, ipv4s(t, nil)) {
			if _, k, ok := e.s.AliasFor(sp.Value); ok && (k == KindIPv4 || k == KindIPv6) {
				add(k, toRaw(sp.Start))
			}
		}
		// Enrolled real values inside the alias ranges (240/4,
		// 2001:db8::/32, <hex6>.example, keyword shapes): the address
		// detectors skip those ranges. Minted aliases are not flagged.
		for _, sh := range scanShapes(t) {
			if s, _, k, ok := e.enrolledLookalike(t, sh); ok {
				add(k, toRaw(s))
			}
		}
	}
	// tokens scans the base64 views: JWT header and payload, Basic
	// credentials (spec §7.2/§9.1). A hit is reported at the token's start.
	tokens := func(t string, toRaw func(int) int) {
		for _, jt := range jwtTokens(t) {
			at := toRaw(jt.Start)
			scan(string(jt.header), func(int) int { return at })
			scan(string(jt.payload), func(int) int { return at })
		}
		for _, bt := range basicTokens(t) {
			at := toRaw(bt.Start)
			scan(bt.plain, func(int) int { return at })
		}
	}
	scan(text, func(i int) int { return i })
	tokens(text, func(i int) int { return i })
	for _, v := range decodedViews(text) {
		scan(v.text, func(i int) int { return v.rs[i] })
		tokens(v.text, func(i int) int { return v.rs[i] })
	}
	sortHits(hits)
	return hits
}

// envelopeKeys are request settings, in the canonical (Go field) and wire
// spellings, lowercased. Their numeric values carry no client data and the
// rewriter never touches them, so an enrolled number equal to one (a PIN
// 4096 and max_tokens 4096) would otherwise block every request.
var envelopeKeys = map[string]bool{
	"maxtokens": true, "max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true,
	"maxoutputtokens": true, "dynamicboundary": true, "temperature": true, "top_p": true, "top_k": true,
	"n": true, "seed": true, "budget_tokens": true, "frequency_penalty": true, "presence_penalty": true,
}

// envelopeNumber reports that t[s:e] is a whole JSON number value of an
// envelopeKeys member ("max_tokens":4096).
func envelopeNumber(t string, s, e int) bool {
	for i := s; i < e; i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	if e < len(t) && (t[e] == '.' || (t[e] >= '0' && t[e] <= '9')) {
		return false
	}
	i := s - 1
	for i >= 0 && (t[i] == ' ' || t[i] == '\t') {
		i--
	}
	if i < 0 || t[i] != ':' {
		return false
	}
	i--
	for i >= 0 && (t[i] == ' ' || t[i] == '\t') {
		i--
	}
	if i < 0 || t[i] != '"' {
		return false
	}
	j := strings.LastIndexByte(t[:i], '"')
	if j < 0 {
		return false
	}
	return envelopeKeys[lowerASCII(t[j+1:i])]
}

// rootAliasRE matches the HMAC-derived part of a domain alias.
var rootAliasRE = regexp.MustCompile(`(?i)[0-9a-f]{6}\.example`)

// aliasOccurrences returns the [start, end) ranges of the HMAC-derived parts
// of minted aliases in t. A short original (a 3-digit username) can occur by
// chance inside a random alias (010e13.example); that is not a leak. Only
// derived parts are exempt: whole keyword and format-preserving aliases, a
// root alias <hex6>.example, an email alias's local part, and addresses
// inside allocated blocks. Preserved host labels are not exempt, so an
// original left in a label is still caught.
func (e *Engine) aliasOccurrences(t string) [][2]int {
	var out [][2]int
	for _, m := range e.s.ReverseDictionary().FindAll(t) {
		switch m.Kind {
		case KindDomain:
			// root part handled below
		case KindEmail:
			if at := strings.IndexByte(t[m.Start:m.End], '@'); at > 0 {
				out = append(out, [2]int{m.Start, m.Start + at})
			}
		default:
			out = append(out, [2]int{m.Start, m.End})
		}
	}
	if containsFoldASCII(t, ".example") {
		for _, r := range rootAliasRE.FindAllStringIndex(t, -1) {
			if _, k, ok := e.s.OriginalFor(t[r[0]:r[1]]); ok && k == KindDomain {
				out = append(out, [2]int{r[0], r[1]})
			}
		}
	}
	for _, sh := range scanShapes(t) {
		ok := false
		switch sh.kind {
		case shapeHost:
			continue
		case shapeIPv4:
			_, ok = e.s.IPv4Real(netip.MustParseAddr(sh.text))
		case shapeCIDR:
			_, ok = e.s.CIDRReal(netip.MustParsePrefix(sh.text))
		default:
			_, _, ok = e.s.OriginalFor(sh.text)
		}
		if ok {
			out = append(out, [2]int{sh.Start, sh.End})
		}
	}
	return out
}

// ranged is a replacement candidate: [start, end) and a tie-break priority.
type ranged interface{ bounds() (start, end, prio int) }

// pickLongest keeps non-overlapping candidates, longest first, then lower
// priority, then leftmost; the result is ordered by start.
func pickLongest[T ranged](cs []T, n int) []T {
	if len(cs) == 0 {
		return nil
	}
	sort.SliceStable(cs, func(i, j int) bool {
		si, ei, pi := cs[i].bounds()
		sj, ej, pj := cs[j].bounds()
		if ei-si != ej-sj {
			return ei-si > ej-sj
		}
		if pi != pj {
			return pi < pj
		}
		return si < sj
	})
	taken := make([]bool, n)
	var kept []T
next:
	for _, c := range cs {
		s, end, _ := c.bounds()
		if s < 0 || end > n || s >= end {
			continue
		}
		for i := s; i < end; i++ {
			if taken[i] {
				continue next
			}
		}
		for i := s; i < end; i++ {
			taken[i] = true
		}
		kept = append(kept, c)
	}
	sort.Slice(kept, func(i, j int) bool {
		si, _, _ := kept[i].bounds()
		sj, _, _ := kept[j].bounds()
		return si < sj
	})
	return kept
}
