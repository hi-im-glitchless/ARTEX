package membrane

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Autumn-27/norma/llm"
)

// walkJSONStrings calls fn with the raw (still escaped) content of every
// string value of the valid JSON raw; object keys are left alone. Only
// literals whose content fn changes are rewritten, so layout, key order and
// the escaping of untouched bytes are preserved. raw itself is returned
// when nothing changed.
func walkJSONStrings(raw []byte, fn func(lit string) (string, error)) ([]byte, bool, error) {
	var out []byte
	var stack []bool // true = object
	keyNext := false
	last := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '{':
			stack = append(stack, true)
			keyNext = true
		case '[':
			stack = append(stack, false)
			keyNext = false
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			keyNext = false
		case ',':
			keyNext = len(stack) > 0 && stack[len(stack)-1]
		case ':':
			keyNext = false
		case '"':
			j := i + 1
			for j < len(raw) && raw[j] != '"' {
				if raw[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(raw) {
				return nil, false, errors.New("membrane: unterminated JSON string")
			}
			if !(keyNext && len(stack) > 0 && stack[len(stack)-1]) {
				lit := string(raw[i+1 : j])
				n, err := fn(lit)
				if err != nil {
					return nil, false, err
				}
				if n != lit {
					if out == nil {
						out = make([]byte, 0, len(raw)+64)
					}
					out = append(out, raw[last:i+1]...)
					out = append(out, n...)
					last = j
				}
			}
			i = j
		}
	}
	if out == nil {
		return raw, false, nil
	}
	return append(out, raw[last:]...), true, nil
}

// litTransform applies t to a JSON string literal's raw content. When the
// result is no longer a valid literal (a value containing a quote or a
// backslash was swapped raw), it decodes the literal, applies t to the
// plain text and encodes the result instead.
func litTransform(lit string, t func(string) (string, error)) (string, error) {
	n, err := t(lit)
	if err != nil || n == lit {
		return n, err
	}
	if json.Valid([]byte(`"` + n + `"`)) {
		return n, nil
	}
	var dec string
	if err := json.Unmarshal([]byte(`"`+lit+`"`), &dec); err != nil {
		return "", errors.New("membrane: invalid JSON string literal")
	}
	n, err = t(dec)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(n); err != nil {
		return "", err
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return string(b[1 : len(b)-1]), nil
}

// ToModelJSON transforms the string values of a JSON document (keys and
// non-string values are kept) and rewrites only the literals that changed.
// Invalid JSON is transformed as plain text (fail safe).
func (e *Engine) ToModelJSON(raw json.RawMessage, prov Provenance) (json.RawMessage, Report, error) {
	rep := newReport()
	if len(raw) == 0 {
		return raw, rep, nil
	}
	if !json.Valid(raw) {
		out, r, err := e.ToModel(string(raw), prov)
		if err != nil {
			return nil, Report{}, err
		}
		return json.RawMessage(out), r, nil
	}
	out, _, err := walkJSONStrings(raw, func(lit string) (string, error) {
		var used Report
		n, err := litTransform(lit, func(s string) (string, error) {
			o, r, err := e.ToModel(s, prov)
			used = r
			return o, err
		})
		if err == nil {
			rep.merge(used)
		}
		return n, err
	})
	if err != nil {
		return nil, Report{}, err
	}
	return json.RawMessage(out), rep, nil
}

// ToRealJSON de-aliases the string values of a JSON document like ToReal
// and returns the unresolved alias-shaped values.
func (e *Engine) ToRealJSON(raw json.RawMessage) (json.RawMessage, []string) {
	if len(raw) == 0 {
		return raw, nil
	}
	if !json.Valid(raw) {
		out, u := e.ToReal(string(raw))
		return json.RawMessage(out), u
	}
	var unresolved []string
	out, _, err := walkJSONStrings(raw, func(lit string) (string, error) {
		var used []string
		n, err := litTransform(lit, func(s string) (string, error) {
			o, u := e.ToReal(s)
			used = u
			return o, nil
		})
		unresolved = appendNew(unresolved, used...)
		return n, err
	})
	if err != nil {
		out, u := e.ToReal(string(raw))
		return json.RawMessage(out), u
	}
	return json.RawMessage(out), unresolved
}

func appendNew(dst []string, src ...string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

// ToModelRequest transforms a request: System segments and every message
// block's text, thinking, tool_use input and (recursively) tool_result
// content. Tool definitions, ids, names and signatures are kept. The result
// shares no slice with req. Signed thinking is transformed like any text;
// replaying it byte-exact is the provider decorator's job (spec §8).
func (e *Engine) ToModelRequest(req llm.CompletionRequest, prov Provenance) (llm.CompletionRequest, Report, error) {
	rep := newReport()
	out := req
	out.System = nil
	if req.System != nil {
		out.System = make([]string, len(req.System))
		for i, s := range req.System {
			t, r, err := e.ToModel(s, prov)
			if err != nil {
				return llm.CompletionRequest{}, Report{}, err
			}
			out.System[i] = t
			rep.merge(r)
		}
	}
	out.Messages = nil
	if req.Messages != nil {
		out.Messages = make([]llm.Message, len(req.Messages))
		for i, m := range req.Messages {
			c, err := e.blocksToModel(m.Content, prov, m.Role == llm.RoleAssistant, &rep)
			if err != nil {
				return llm.CompletionRequest{}, Report{}, err
			}
			out.Messages[i] = llm.Message{Role: m.Role, Content: c}
		}
	}
	out.Tools = slices.Clone(req.Tools)
	out.Stop = slices.Clone(req.Stop)
	if req.Temperature != nil {
		t := *req.Temperature
		out.Temperature = &t
	}
	return out, rep, nil
}

// blocksToModel transforms blocks; assistant marks the text and thinking of
// an assistant message (ruling R12). tool_use input and tool_result content
// are never assistant prose.
func (e *Engine) blocksToModel(bs []llm.ContentBlock, prov Provenance, assistant bool, rep *Report) ([]llm.ContentBlock, error) {
	if bs == nil {
		return nil, nil
	}
	text := func(s string) (string, error) {
		if s == "" {
			return s, nil
		}
		t, r, err := e.toModelRole(s, prov, assistant)
		rep.merge(r)
		return t, err
	}
	out := make([]llm.ContentBlock, len(bs))
	for i, b := range bs {
		nb := b
		var err error
		if nb.Text, err = text(b.Text); err != nil {
			return nil, err
		}
		if nb.Thinking, err = text(b.Thinking); err != nil {
			return nil, err
		}
		if b.Input != nil {
			in, r, err := e.ToModelJSON(b.Input, prov)
			if err != nil {
				return nil, err
			}
			rep.merge(r)
			nb.Input = slices.Clone(in)
		}
		if nb.Content, err = e.blocksToModel(b.Content, prov, false, rep); err != nil {
			return nil, err
		}
		out[i] = nb
	}
	return out, nil
}

// ToRealMessage de-aliases a model message (text, thinking, tool_use input,
// tool_result content) into a copy and returns the unresolved alias-shaped
// values.
func (e *Engine) ToRealMessage(m llm.Message) (llm.Message, []string) {
	var unresolved []string
	return llm.Message{Role: m.Role, Content: e.blocksToReal(m.Content, &unresolved)}, unresolved
}

func (e *Engine) blocksToReal(bs []llm.ContentBlock, unresolved *[]string) []llm.ContentBlock {
	if bs == nil {
		return nil
	}
	text := func(s string) string {
		if s == "" {
			return s
		}
		t, u := e.ToReal(s)
		*unresolved = appendNew(*unresolved, u...)
		return t
	}
	out := make([]llm.ContentBlock, len(bs))
	for i, b := range bs {
		nb := b
		nb.Text = text(b.Text)
		nb.Thinking = text(b.Thinking)
		if b.Input != nil {
			in, u := e.ToRealJSON(b.Input)
			*unresolved = appendNew(*unresolved, u...)
			nb.Input = slices.Clone(in)
		}
		nb.Content = e.blocksToReal(b.Content, unresolved)
		out[i] = nb
	}
	return out
}
