package membrane

import (
	"cmp"
	"slices"
	"sort"
)

// Encoding says how a span's value is written in the raw text. A replacement
// must be written back in the same encoding.
type Encoding int

const (
	// EncRaw: text[Start:End] is the value itself.
	EncRaw Encoding = iota
	// EncURL: percent-encoding (%40, and + for space).
	EncURL
	// EncJSONEscape: JSON string escapes (@, \/, \" ...).
	EncJSONEscape
	// EncHTMLEntity: HTML character references (&#64;, &commat;, &amp; ...).
	EncHTMLEntity
	// EncBasicAuth: text[Start:End] is the base64 credential of an
	// "Authorization: Basic" header; Value is the decoded "user:pass". The
	// span's Kind is KindPassword; the replacer must split Value at the first
	// ':' and alias the user part as KindUsername and the rest as
	// KindPassword, then re-encode.
	EncBasicAuth
)

// Span is one detected sensitive value. Start and End are byte offsets into
// the scanned (raw) text and cover the whole encoded form. Value is the
// decoded value: for dictionary hits the enrolled original, otherwise the
// text as found (after decoding Encoding). Detectors never enrol; the caller
// decides what to do with Value.
type Span struct {
	Start, End int
	Kind       Kind
	Value      string
	Encoding   Encoding
}

// Detector finds sensitive spans in text. Implementations must be safe for
// concurrent use and must not panic on any input.
type Detector interface {
	Detect(text string) []Span
}

// Pipeline runs the dictionary, structural and extra detectors over the raw
// text and over its decoded views (URL, JSON escape, HTML entity), and
// resolves overlaps.
type Pipeline struct {
	store *Store
	dets  []Detector // structural, then extra
}

// NewPipeline returns the detection pipeline over s. s may be nil (no
// dictionary, no known roots). extra detectors run after the built-in ones
// and lose equal-length ties to them.
func NewPipeline(s *Store, extra ...Detector) *Pipeline {
	dets := []Detector{structDetector{s}, secretDetector{}}
	dets = append(dets, extra...)
	return &Pipeline{store: s, dets: dets}
}

// dictDetector adapts one automaton snapshot to Detector.
type dictDetector struct{ a *Automaton }

func (d dictDetector) Detect(text string) []Span {
	ms := d.a.FindAll(text)
	out := make([]Span, 0, len(ms))
	for _, m := range ms {
		out = append(out, Span{Start: m.Start, End: m.End, Kind: m.Kind, Value: m.Original})
	}
	return out
}

type candidate struct {
	Span
	prio int // lower wins an equal-length tie
	seq  int // emission order, the last tie-break
}

// Detect returns non-overlapping spans ordered by Start. On overlap the
// longest span (in raw bytes) wins; at equal length the earlier detector
// (dictionary, structural, extra) wins, and a raw-text hit beats a hit in a
// decoded view.
func (p *Pipeline) Detect(text string) []Span {
	var dict *Automaton
	if p.store != nil {
		dict = p.store.Dictionary()
	}
	dets := append([]Detector{dictDetector{dict}}, p.dets...)

	var cands []candidate
	for prio, d := range dets {
		for _, sp := range d.Detect(text) {
			if sp.Start >= 0 && sp.Start < sp.End && sp.End <= len(text) {
				cands = append(cands, candidate{Span: sp, prio: prio})
			}
		}
	}
	for _, v := range decodedViews(text) {
		for di, d := range dets {
			for _, sp := range d.Detect(v.text) {
				c, ok := v.toRaw(text, sp)
				if !ok {
					continue
				}
				// Views rank after raw text, in Encoding order.
				cands = append(cands, candidate{Span: c, prio: int(v.enc)*len(dets) + di})
			}
		}
	}
	return resolveOverlaps(cands, len(text))
}

// resolveOverlaps keeps the longest candidates greedily, ties broken by
// priority and then position. Cost is linear in the total candidate length.
func resolveOverlaps(cands []candidate, textLen int) []Span {
	for i := range cands {
		cands[i].seq = i
	}
	slices.SortFunc(cands, func(a, b candidate) int {
		if c := cmp.Compare(b.End-b.Start, a.End-a.Start); c != 0 {
			return c
		}
		if c := cmp.Compare(a.prio, b.prio); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Start, b.Start); c != 0 {
			return c
		}
		return cmp.Compare(a.seq, b.seq) // deterministic: detector output order
	})
	if len(cands) == 0 {
		return nil
	}
	taken := make([]bool, textLen)
	var kept []Span
next:
	for _, c := range cands {
		for i := c.Start; i < c.End; i++ {
			if taken[i] {
				continue next
			}
		}
		for i := c.Start; i < c.End; i++ {
			taken[i] = true
		}
		kept = append(kept, c.Span)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}
