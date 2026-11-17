package membrane

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// JWTs keep their structure (spec §7.2): header and payload string claims
// go through the engine (in place, so unchanged bytes stay byte-exact), and
// the signature segment gets a format-preserving fake that maps back.

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

// jwtToModel aliases a JWT's claims and signature. ok is false when tok is
// not a JWT (the caller then aliases it as an opaque token).
func (e *Engine) jwtToModel(tok string, prov Provenance, rep *Report) (string, bool, error) {
	h, p, sig, ok := parseJWT(tok)
	if !ok {
		return "", false, nil
	}
	nh, hr, err := e.ToModelJSON(h, prov)
	if err != nil {
		return "", false, err
	}
	np, pr, err := e.ToModelJSON(p, prov)
	if err != nil {
		return "", false, err
	}
	rep.merge(hr)
	rep.merge(pr)
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

// jwtCandidates de-aliases JWTs: claims through ToRealJSON, the signature
// through an exact lookup (kept as written when unknown, e.g. after the
// model edited the token).
func (e *Engine) jwtCandidates(text string) []rCand {
	if !strings.Contains(text, "eyJ") {
		return nil
	}
	var out []rCand
	for _, m := range jwtRE.FindAllStringIndex(text, -1) {
		s, end := m[0], m[1]
		if isB64URLByte(byteBefore(text, s)) || isB64URLByte(byteAfter(text, end)) {
			continue
		}
		tok := text[s:end]
		h, p, sig, ok := parseJWT(tok)
		if !ok {
			continue
		}
		nh, u1 := e.ToRealJSON(h)
		np, u2 := e.ToRealJSON(p)
		ns := sig
		if orig, _, ok := e.s.OriginalFor(sig); ok && sig != "" {
			ns = orig
		}
		repl := jwtSegment.EncodeToString(nh) + "." + jwtSegment.EncodeToString(np) + "." + ns
		if repl == tok && len(u1)+len(u2) == 0 {
			continue
		}
		out = append(out, rCand{Start: s, End: end, repl: repl, prio: prioToken, unresolved: append(u1, u2...)})
	}
	return out
}
