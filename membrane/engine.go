package membrane

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Engine rewrites text between the real universe and the alias universe:
// ToModel (detect, enrol, replace) before a request leaves, ToReal (exact
// lookup plus derivation) on what the model sends back, and LeakCheck on
// the serialised request. It is safe for concurrent use.
type Engine struct {
	s     *Store
	p     *Pipeline
	cache *toModelCache
}

// NewEngine returns an engine over s (required). p may be nil
// (NewPipeline(s)).
func NewEngine(s *Store, p *Pipeline) *Engine {
	if p == nil {
		p = NewPipeline(s)
	}
	return &Engine{s: s, p: p, cache: newToModelCache()}
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
	if out, rep, ok := e.cache.get(key, g); ok {
		return out, rep, nil
	}
	out, rep, err := e.toModel(text, prov, assistant)
	if err != nil {
		return "", Report{}, err
	}
	// Cache only results computed against a stable table: when this call
	// (or another goroutine) enrolled something, the next identical call
	// recomputes once (with Enrolled 0) and caches that.
	if e.generation() == g {
		e.cache.put(key, g, out, rep)
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
	rep := newReport()
	var b strings.Builder
	last := 0
	extra := basicToModelCandidates(text)
	if !assistant {
		extra = append(extra, e.lookalikes(text)...)
	}
	for _, c := range mergeAdded(e.p.Detect(text), extra) {
		raw := text[c.Start:c.End]
		repl, err := e.replacement(text, c, prov, &rep)
		if err != nil {
			return "", Report{}, err
		}
		if repl != raw {
			rep.Counts[c.Kind]++
		}
		b.WriteString(text[last:c.Start])
		b.WriteString(repl)
		last = c.End
	}
	b.WriteString(text[last:])
	out := b.String()
	for _, sp := range e.Suspicious(out) {
		if strings.ContainsAny(sp.Text, " \t") {
			rep.Flags = unionSorted(rep.Flags, []string{"suspicious_name"})
		} else {
			rep.Flags = unionSorted(rep.Flags, []string{"suspicious_domain"})
		}
	}
	return out, rep, nil
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
func (e *Engine) lookalikes(text string) []tmCand {
	var out []tmCand
	add := func(s, end int, k Kind) {
		out = append(out, tmCand{Span: Span{Start: s, End: end, Kind: k, Value: text[s:end]}, look: true, added: true, prio: 1})
	}
	for _, sh := range scanShapes(text) {
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
func (e *Engine) LeakCheck(serialised []byte) []LeakHit {
	text := string(serialised)
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
			add(m.Kind, toRaw(m.Start))
		}
		for _, sp := range ipv6s(t, ipv4s(t, nil)) {
			if _, k, ok := e.s.AliasFor(sp.Value); ok && (k == KindIPv4 || k == KindIPv6) {
				add(k, toRaw(sp.Start))
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
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Offset != hits[j].Offset {
			return hits[i].Offset < hits[j].Offset
		}
		return hits[i].Kind < hits[j].Kind
	})
	return hits
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
