package membrane

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// JWTs keep their structure (spec §7.2): the decoded header and payload go
// through the engine as text (keys, string and number claims alike), and
// the signature segment gets a format-preserving fake that maps back. A
// token whose transformed segments are not JSON any more, or still carry
// something the detectors or the dictionary find, falls back to an opaque
// token alias.

var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)

var jwtSegment = base64.RawURLEncoding.Strict()

func isB64URLByte(c byte) bool { return isASCIIAlnum(c) || c == '-' || c == '_' }

// parseJWT splits tok into its decoded JSON header and payload and its
// signature segment. Only canonical unpadded base64url with JSON segments is
// accepted, so re-encoding unchanged segments reproduces them exactly.
func parseJWT(tok string) (header, payload []byte, sig string, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, "", false
	}
	h, err1 := jwtSegment.DecodeString(parts[0])
	p, err2 := jwtSegment.DecodeString(parts[1])
	if err1 != nil || err2 != nil || !json.Valid(h) || !json.Valid(p) {
		return nil, nil, "", false
	}
	return h, p, parts[2], true
}

// jwtToken is a JWT found in text[Start:End].
type jwtToken struct {
	Start, End      int
	header, payload []byte
	sig             string
}

// jwtTokens finds well-formed JWTs (see parseJWT) standing alone in text.
func jwtTokens(text string) []jwtToken {
	if !strings.Contains(text, "eyJ") {
		return nil
	}
	var out []jwtToken
	for _, m := range jwtRE.FindAllStringIndex(text, -1) {
		s, end := m[0], m[1]
		if isB64URLByte(byteBefore(text, s)) || isB64URLByte(byteAfter(text, end)) {
			continue
		}
		if h, p, sig, ok := parseJWT(text[s:end]); ok {
			out = append(out, jwtToken{Start: s, End: end, header: h, payload: p, sig: sig})
		}
	}
	return out
}

// jwtToModel aliases a JWT's segments and signature. ok is false when tok is
// not a JWT or its structure cannot be kept safely (the caller then aliases
// it as an opaque token).
func (e *Engine) jwtToModel(tok string, prov Provenance, rep *Report) (string, bool, error) {
	h, p, sig, ok := parseJWT(tok)
	if !ok {
		return "", false, nil
	}
	var segRep Report
	seg := func(b []byte) ([]byte, bool, error) {
		out, r, err := e.toModelRole(string(b), prov, false)
		if err != nil {
			return nil, false, err
		}
		if !json.Valid([]byte(out)) || e.residual(out) {
			return nil, false, nil
		}
		segRep.merge(r)
		return []byte(out), true, nil
	}
	nh, ok, err := seg(h)
	if err != nil || !ok {
		return "", false, err
	}
	np, ok, err := seg(p)
	if err != nil || !ok {
		return "", false, err
	}
	rep.merge(segRep)
	ns := sig
	if sig != "" {
		a, keep, err := e.aliasValue(KindToken, sig, prov, rep)
		if err != nil {
			return "", false, err
		}
		if !keep {
			ns = a
		}
	}
	return jwtSegment.EncodeToString(nh) + "." + jwtSegment.EncodeToString(np) + "." + ns, true, nil
}

// residual reports whether transformed text still holds something sensitive:
// a leak-check hit, or a detection that is not a minted alias.
func (e *Engine) residual(out string) bool {
	if len(e.LeakCheck([]byte(out))) > 0 {
		return true
	}
	for _, sp := range e.p.Detect(out) {
		if _, _, ok := e.s.OriginalFor(sp.Value); !ok {
			return true
		}
	}
	return false
}

// jwtCandidates de-aliases JWTs: segments through ToReal (kept when the
// result is not JSON), the signature through an exact lookup (kept as
// written when unknown, e.g. after the model edited the token).
func (e *Engine) jwtCandidates(text string) []rCand {
	var out []rCand
	for _, jt := range jwtTokens(text) {
		seg := func(b []byte) ([]byte, []string) {
			r, u := e.ToReal(string(b))
			if !json.Valid([]byte(r)) {
				return b, u
			}
			return []byte(r), u
		}
		nh, u1 := seg(jt.header)
		np, u2 := seg(jt.payload)
		ns := jt.sig
		if orig, _, ok := e.s.OriginalFor(jt.sig); ok && jt.sig != "" {
			ns = orig
		}
		repl := jwtSegment.EncodeToString(nh) + "." + jwtSegment.EncodeToString(np) + "." + ns
		if repl == text[jt.Start:jt.End] && len(u1)+len(u2) == 0 {
			continue
		}
		out = append(out, rCand{Start: jt.Start, End: jt.End, repl: repl, prio: prioToken, unresolved: append(u1, u2...)})
	}
	return out
}
