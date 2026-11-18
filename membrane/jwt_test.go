package membrane

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const jwtTestSig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func jwtParts(t *testing.T) (header, payload, tok string) {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	header = enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload = enc([]byte(`{"sub":"joao.silva@acmebank.pt","iss":"https://sso.acmebank.pt"}`))
	return header, payload, header + "." + payload + "." + jwtTestSig
}

func TestJWTClaimsAliased(t *testing.T) {
	e, _ := newTestEngine(t)
	header, payload, tok := jwtParts(t)
	out := toModel(t, e, tok)
	parts := strings.Split(out, ".")
	if len(parts) != 3 || parts[0] != header {
		t.Fatalf("structure lost: %q", out)
	}
	if parts[1] == payload {
		t.Fatal("payload not aliased")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !json.Valid(claims) {
		t.Fatalf("claims not valid JSON: %q %v", claims, err)
	}
	if strings.Contains(string(claims), "acmebank") || strings.Contains(string(claims), "joao.silva") {
		t.Fatalf("claims leak: %s", claims)
	}
	if parts[2] == jwtTestSig || len(parts[2]) != len(jwtTestSig) {
		t.Fatalf("signature %q", parts[2])
	}
}

func TestJWTExactRoundTrip(t *testing.T) {
	e, _ := newTestEngine(t)
	_, _, tok := jwtParts(t)
	out := toModel(t, e, tok)
	back, unresolved := e.ToReal(out)
	if back != tok || len(unresolved) != 0 {
		t.Fatalf("round trip %q (unresolved %v)", back, unresolved)
	}
}

func TestJWTEditedByModel(t *testing.T) {
	e, _ := newTestEngine(t)
	_, _, tok := jwtParts(t)
	parts := strings.Split(toModel(t, e, tok), ".")
	enc := base64.RawURLEncoding.EncodeToString
	edited := enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."
	back, _ := e.ToReal(edited)
	bp := strings.Split(back, ".")
	if len(bp) != 3 || bp[2] != "" {
		t.Fatalf("got %q", back)
	}
	h, err := base64.RawURLEncoding.DecodeString(bp[0])
	if err != nil || !strings.Contains(string(h), `"alg":"none"`) {
		t.Fatalf("header %q %v", h, err)
	}
	c, err := base64.RawURLEncoding.DecodeString(bp[1])
	if err != nil || !strings.Contains(string(c), "joao.silva@acmebank.pt") || !strings.Contains(string(c), "https://sso.acmebank.pt") {
		t.Fatalf("claims %q %v", c, err)
	}
}
