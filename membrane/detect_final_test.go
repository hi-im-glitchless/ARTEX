package membrane

import (
	"strings"
	"testing"
)

// assertNoClear runs text through ToModel and fails if any of secrets is
// still written in the output.
func assertNoClear(t *testing.T, e *Engine, text string, secrets ...string) string {
	t.Helper()
	out, _, err := e.ToModel(text, Provenance{TaskIDs: []int64{5}})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%q still in clear in %q", s, out)
		}
	}
	return out
}

// Final review I5: common credential shapes that passed in clear.
func TestHTMLInputCredentials(t *testing.T) {
	e, _ := newTestEngine(t)
	assertNoClear(t, e, `<input type="text" name="smtp_password" value="Mail#Relay77">`, "Mail#Relay77")
	assertNoClear(t, e, `<input type="password" name="pwd" value="Xq9!vLm2">`, "Xq9!vLm2")
	assertNoClear(t, e, `<INPUT value='Zk2#pQ9w' class=x TYPE=password>`, "Zk2#pQ9w")
	assertNoClear(t, e, `<input id="api-token" value=tok_Q8vX2mLp9R>`, "tok_Q8vX2mLp9R")
	assertNoClear(t, e, `<input name="otp_pin" value="482913">`, "482913")
	// Not secrets: ordinary fields keep their values.
	for _, in := range []string{
		`<input type="text" name="q" value="search terms">`,
		`<input type="hidden" name="page" value="3">`,
		`<input name="password" value="">`,
	} {
		if out, _, _ := e.ToModel(in, Provenance{}); out != in {
			t.Errorf("non-secret input rewritten: %q -> %q", in, out)
		}
	}
}

func TestNumericJSONSecrets(t *testing.T) {
	e, _ := newTestEngine(t)
	assertNoClear(t, e, `{"username":"mferreira","password":83920174}`, "83920174")
	assertNoClear(t, e, `{"pin":482913,"otp_secret":"JBSWY3DPEHPK3PXP"}`, "482913", "JBSWY3DPEHPK3PXP")
	assertNoClear(t, e, `{"pin_code": 7391, "id": 12}`, "7391")
	// Numeric non-secret fields and user ids stay.
	for _, in := range []string{`{"user_id":1042,"port":8443}`, `{"pinned":123456}`, `{"shipping":123456}`} {
		if out, _, _ := e.ToModel(in, Provenance{}); out != in {
			t.Errorf("numeric non-secret rewritten: %q -> %q", in, out)
		}
	}
}

func TestPassphraseWholeLine(t *testing.T) {
	e, _ := newTestEngine(t)
	out := assertNoClear(t, e, "passphrase: correct horse battery staple\nnext: line", "correct", "horse", "battery", "staple")
	if !strings.HasSuffix(out, "\nnext: line") {
		t.Errorf("following line changed: %q", out)
	}
	assertNoClear(t, e, "  ssh_key_passphrase: tall green tree  ", "tall green tree", "green tree")
	// A password keeps the first-word rule ("password: hunter2 (old)").
	out = assertNoClear(t, e, "password: hunter22 (old)", "hunter22")
	if !strings.HasSuffix(out, " (old)") {
		t.Errorf("free-form password note rewritten: %q", out)
	}
}

// Final review I6: command substitutions and variable references after a
// secret-named variable, option or header are references, not secrets.
func TestShellReferencesAreNotSecrets(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, in := range []string{
		"TOKEN=$(curl -s -X POST https://example.org/login -d @creds.json | jq -r .token)",
		"export JWT=$(cat /tmp/jwt.txt)",
		"KEY=$(id -u)",
		"PASSWORD=$PASS",
		"PASSWORD=${DB_PASS:-x}",
		"API_KEY=`cat key.txt`",
		"secret: $(whoami)",
		"password: $DB_PASSWORD",
		`{"password":"$(cat /run/secrets/pw)"}`,
		"curl --token $API_TOKEN https://example.org",
		"app --password=$(pass show db) status",
		"mysql -h db -p$(cat /root/pw) -e 'select 1'",
		"mysql -h db -p$MYSQL_PWD",
		"Authorization: Bearer $TOKEN",
		"password = \"$(vault read -field=pw x)\"",
	} {
		out, _, err := e.ToModel(in, Provenance{TaskIDs: []int64{4}})
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("reference rewritten:\n in  %q\n out %q", in, out)
		}
	}
	// A real secret that merely starts with '$' (mixed case) is still one.
	assertNoClear(t, e, "PASSWORD=$uperS3cret", "$uperS3cret")
	// The host inside a substitution is still aliased by its own detector.
	assertNoClear(t, e, "TOKEN=$(curl -s https://portal.acmebank.pt/login)", "portal.acmebank.pt")
}
