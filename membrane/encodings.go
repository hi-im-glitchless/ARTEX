package membrane

import (
	"html"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// view is a decoded rendering of a raw text. Byte i of text came from
// raw[rs[i]:re[i]]; all bytes decoded from one escape share that range.
type view struct {
	enc    Encoding
	text   string
	rs, re []int
}

type viewBuilder struct {
	b      strings.Builder
	rs, re []int
}

// put appends decoded bytes produced by raw[s:e].
func (vb *viewBuilder) put(decoded string, s, e int) {
	vb.b.WriteString(decoded)
	for range len(decoded) {
		vb.rs = append(vb.rs, s)
		vb.re = append(vb.re, e)
	}
}

// copyRaw appends raw[s:e] unchanged, byte by byte.
func (vb *viewBuilder) copyRaw(raw string, s, e int) {
	vb.b.WriteString(raw[s:e])
	for i := s; i < e; i++ {
		vb.rs = append(vb.rs, i)
		vb.re = append(vb.re, i+1)
	}
}

func (vb *viewBuilder) view(enc Encoding) view {
	return view{enc: enc, text: vb.b.String(), rs: vb.rs, re: vb.re}
}

// decoders lists the views in priority order with the bytes that can start
// an escape in each.
var decoders = []struct {
	marks  string
	decode func(string) (view, bool)
}{
	{"%+", urlView},
	{`\`, jsonView},
	{"&", htmlView},
}

// decodedViews returns the URL, JSON-escape and HTML-entity views of raw.
// One layer of encoding is decoded per view, and only over groups of
// consecutive lines that contain an escape mark (no encoded value spans a
// raw newline), so text without escapes costs nothing extra.
func decodedViews(raw string) []view {
	var out []view
	for _, d := range decoders {
		segStart := -1
		flush := func(end int) {
			if segStart < 0 {
				return
			}
			if v, ok := d.decode(raw[segStart:end]); ok {
				for i := range v.rs {
					v.rs[i] += segStart
					v.re[i] += segStart
				}
				out = append(out, v)
			}
			segStart = -1
		}
		for s := 0; s < len(raw); {
			e := strings.IndexByte(raw[s:], '\n')
			if e < 0 {
				e = len(raw)
			} else {
				e += s
			}
			if strings.ContainsAny(raw[s:e], d.marks) {
				if segStart < 0 {
					segStart = s
				}
			} else {
				flush(s)
			}
			s = e + 1
		}
		flush(len(raw))
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// urlView decodes %XX and '+' (as space).
func urlView(raw string) (view, bool) {
	if !strings.ContainsAny(raw, "%+") {
		return view{}, false
	}
	var vb viewBuilder
	changed := false
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '%':
			if i+2 < len(raw) {
				h, ok1 := unhex(raw[i+1])
				l, ok2 := unhex(raw[i+2])
				if ok1 && ok2 {
					vb.put(string([]byte{h<<4 | l}), i, i+3)
					i += 3
					changed = true
					continue
				}
			}
		case '+':
			vb.put(" ", i, i+1)
			i++
			changed = true
			continue
		}
		vb.copyRaw(raw, i, i+1)
		i++
	}
	return vb.view(EncURL), changed
}

var jsonSimpleEscapes = map[byte]string{
	'"': `"`, '\\': `\`, '/': "/", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t",
}

func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var r rune
	for i := range 4 {
		v, ok := unhex(s[i])
		if !ok {
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

// jsonView decodes JSON string escapes. Malformed escapes and unpaired
// surrogates are kept raw.
func jsonView(raw string) (view, bool) {
	if !strings.Contains(raw, `\`) {
		return view{}, false
	}
	var vb viewBuilder
	changed := false
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+1 < len(raw) {
			c := raw[i+1]
			if d, ok := jsonSimpleEscapes[c]; ok {
				vb.put(d, i, i+2)
				i += 2
				changed = true
				continue
			}
			if c == 'u' {
				if r, ok := hex4(raw[i+2:]); ok {
					n := 6
					if utf16.IsSurrogate(r) {
						r2, ok2 := rune(0), false
						if i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
							r2, ok2 = hex4(raw[i+8:])
						}
						r = utf16.DecodeRune(r, r2)
						if !ok2 || r == utf8.RuneError {
							vb.copyRaw(raw, i, i+1)
							i++
							continue
						}
						n = 12
					}
					vb.put(string(r), i, i+n)
					i += n
					changed = true
					continue
				}
			}
		}
		vb.copyRaw(raw, i, i+1)
		i++
	}
	return vb.view(EncJSONEscape), changed
}

var htmlEntityRE = regexp.MustCompile(`&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});`)

// htmlView decodes HTML character references.
func htmlView(raw string) (view, bool) {
	if !strings.Contains(raw, "&") {
		return view{}, false
	}
	var vb viewBuilder
	changed := false
	last := 0
	for _, m := range htmlEntityRE.FindAllStringIndex(raw, -1) {
		ent := raw[m[0]:m[1]]
		d := html.UnescapeString(ent)
		if d == ent {
			continue
		}
		vb.copyRaw(raw, last, m[0])
		vb.put(d, m[0], m[1])
		last = m[1]
		changed = true
	}
	vb.copyRaw(raw, last, len(raw))
	return vb.view(EncHTMLEntity), changed
}

// toRaw maps a span found in the view back onto raw. A span that cuts
// through one escape is dropped. A span whose raw bytes equal its view bytes
// is reported as found (no encoding involved); otherwise it carries the
// view's encoding. A span that was itself decoded by its detector (nested
// encodings) keeps the view's encoding and its singly-decoded view text as
// Value.
func (v view) toRaw(raw string, sp Span) (Span, bool) {
	if sp.Start < 0 || sp.Start >= sp.End || sp.End > len(v.text) {
		return Span{}, false
	}
	if sp.Start > 0 && v.rs[sp.Start] == v.rs[sp.Start-1] {
		return Span{}, false
	}
	if sp.End < len(v.text) && v.rs[sp.End] == v.rs[sp.End-1] {
		return Span{}, false
	}
	s, e := v.rs[sp.Start], v.re[sp.End-1]
	vt := v.text[sp.Start:sp.End]
	out := sp
	out.Start, out.End = s, e
	if raw[s:e] == vt {
		return out, true
	}
	if sp.Encoding != EncRaw {
		out.Value = vt
	}
	out.Encoding = v.enc
	return out, true
}
