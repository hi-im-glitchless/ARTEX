package membrane

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
)

// Stream hold-back bounds (ruling R14).
const (
	// maxAliasLen is the minimum number of trailing bytes held back: an
	// alias that has only partly arrived is never cut.
	maxAliasLen = 64
	// maxHoldBytes caps a held run with no boundary; past it the run is
	// flushed (de-aliased) anyway.
	maxHoldBytes = 1024
)

// streamDelims end a token: no alias shape (host, URL, email, IP, CIDR,
// keyword) contains one. Format-preserving aliases can; those are protected
// by the exact-alias span check in cut.
const streamDelims = "\"'<>()[]{},;`"

func isStreamDelim(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(streamDelims, r) }

// lastBoundary returns the largest i in (0, limit] such that s[:i] ends with
// a delimiter, or 0.
func lastBoundary(s string, limit int) int {
	for i := limit; i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		if isStreamDelim(r) {
			return i
		}
		i -= size
	}
	return 0
}

// streamAliasSpans returns the [start, end) ranges of exact minted aliases
// in text; the stream never cuts inside one.
func (e *Engine) streamAliasSpans(text string) [][2]int {
	ms := e.s.ReverseDictionary().FindAll(text)
	out := make([][2]int, len(ms))
	for i, m := range ms {
		out[i] = [2]int{m.Start, m.End}
	}
	return out
}

// streamDealiaser de-aliases a normalised event stream.
//
// Contract: event types and their order are preserved, except that a run of
// consecutive deltas of one type (text_delta, thinking_delta,
// tool_input_delta) may be re-chunked into fewer, larger deltas of that
// type: the sequence of event types, after merging consecutive same-type
// deltas, equals the inner sequence after the same merge. A non-empty run
// always yields at least one delta. Concatenating a run's output equals
// ToReal applied chunk-wise to the run's input, where every chunk ends at a
// token boundary.
//
//   - text/thinking: the buffer emits its longest prefix that ends at a
//     delimiter (whitespace or streamDelims), keeps at least maxAliasLen
//     trailing bytes, and does not cut inside an exact alias. So no alias
//     (however long, e.g. a.b.c.<hex6>.example/path) is split between
//     chunks. A boundary-less run over maxHoldBytes is flushed anyway.
//   - tool_input_delta: buffered for the tool in flight (the stream carries
//     no index on input deltas; they belong to the last tool_use_start) and
//     emitted as one ToRealJSON-de-aliased delta.
//   - Any other event first flushes all buffers, so block boundaries
//     (thinking↔text switch, tool_use_start, tool_use_signature,
//     thinking_signature, message_delta, message_stop) and the end of the
//     stream (flush) emit everything held.
type streamDealiaser struct {
	e    engineAPI
	sigs *sigCache

	mode    llm.StreamEventType // text_delta, thinking_delta or "" (no run)
	buf     string              // held alias-space text of the run
	emitted bool                // the run produced at least one delta

	tool *strings.Builder // pending tool input (alias space), nil if none

	// thinkRaw is the alias-space text of the thinking block the caller's
	// llm.Accumulator is building; a thinking_signature caches it.
	thinkRaw strings.Builder

	unresolved []string
}

func newStreamDealiaser(e engineAPI, sigs *sigCache) *streamDealiaser {
	return &streamDealiaser{e: e, sigs: sigs}
}

// push consumes one inner event and returns the events to emit now.
func (d *streamDealiaser) push(ev llm.StreamEvent) []llm.StreamEvent {
	switch ev.Type {
	case llm.SETextDelta, llm.SEThinkingDelta:
		var out []llm.StreamEvent
		if d.mode != ev.Type {
			out = d.flush()
			d.mode = ev.Type
		}
		if ev.Type == llm.SEThinkingDelta {
			d.thinkRaw.WriteString(ev.Text)
		} else {
			d.thinkRaw.Reset()
		}
		d.buf += ev.Text
		if c := d.cut(d.buf); c > 0 {
			out = append(out, d.real(d.buf[:c]))
			d.buf = d.buf[c:]
		}
		return out
	case llm.SEToolInputJSON:
		out := d.flushText()
		if d.tool == nil {
			d.tool = &strings.Builder{}
		}
		d.tool.WriteString(ev.Text)
		return out
	}
	out := d.flush()
	switch ev.Type {
	case llm.SEThinkingSignature:
		if d.thinkRaw.Len() > 0 && ev.Text != "" {
			d.sigs.put(ev.Text, d.thinkRaw.String())
		}
	case llm.SEToolUseStart, llm.SEMessageStop:
		d.thinkRaw.Reset()
	}
	return append(out, ev)
}

// cut returns how many bytes of s may be emitted now (0: hold everything).
func (d *streamDealiaser) cut(s string) int {
	c := 0
	if limit := len(s) - maxAliasLen; limit > 0 {
		c = lastBoundary(s, limit)
		var spans [][2]int
		if c > 0 {
			spans = d.e.streamAliasSpans(s)
		}
		for moved := true; c > 0 && moved; {
			moved = false
			for _, sp := range spans {
				if sp[0] < c && c < sp[1] {
					c, moved = lastBoundary(s, sp[0]), true
					break
				}
			}
		}
	}
	if c == 0 && len(s) > maxHoldBytes {
		if c = lastBoundary(s, len(s)); c == 0 {
			c = len(s)
		}
	}
	return c
}

// real de-aliases one chunk of the current run into a delta event.
func (d *streamDealiaser) real(chunk string) llm.StreamEvent {
	t, u := d.e.ToReal(chunk)
	d.unresolved = appendNew(d.unresolved, u...)
	d.emitted = true
	return llm.StreamEvent{Type: d.mode, Text: t}
}

// flushText emits the rest of the current text/thinking run.
func (d *streamDealiaser) flushText() []llm.StreamEvent {
	if d.mode == "" {
		return nil
	}
	var out []llm.StreamEvent
	if d.buf != "" || !d.emitted {
		out = append(out, d.real(d.buf))
	}
	d.mode, d.buf, d.emitted = "", "", false
	return out
}

// flush emits everything held: the text/thinking run and the pending tool
// input (as one de-aliased delta).
func (d *streamDealiaser) flush() []llm.StreamEvent {
	out := d.flushText()
	if d.tool != nil {
		raw, u := d.e.ToRealJSON([]byte(d.tool.String()))
		d.unresolved = appendNew(d.unresolved, u...)
		out = append(out, llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(raw)})
		d.tool = nil
	}
	return out
}
