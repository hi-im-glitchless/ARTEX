package membrane

import (
	"strings"
	"testing"
)

// Final review N2: a password that starts with '$' is a secret wherever
// nothing expands '$' (JSON, HTML, URL/query values, Authorization) and,
// in key: value lines, unless it is an UPPER_CASE interpolation; on a
// command line only a plausible environment variable is a reference.
func TestDollarPasswordsAliasedOutsideShellReferences(t *testing.T) {
	e, _ := newTestEngine(t)
	prov := Provenance{TaskIDs: []int64{6}}
	for _, c := range []struct{ in, secret string }{
		{`{"username":"svc","password":"$ummer2024"}`, "$ummer2024"},
		{`{"password":"$ECRET99"}`, "$ECRET99"},
		{`<input type="password" name="pw" value="$ummer2024">`, "$ummer2024"},
		{`https://portal.acmebank.pt/login?user=svc&password=%24ummer2024`, "%24ummer2024"},
		{`https://portal.acmebank.pt/login?user=svc&password=$ummer2024`, "$ummer2024"},
		{`password: $ummer2024`, "$ummer2024"},
		{`password: $uMMer2024`, "$uMMer2024"},
		{`DB_PASSWORD=$ummer2024`, "$ummer2024"},
		{`mysql -u svc -p$ummer2024 db`, "$ummer2024"},
		{`Authorization: Bearer $abc123def456`, "$abc123def456"},
		{`curl -H "Authorization: Bearer $abc123def456" https://x.acmebank.pt/`, "$abc123def456"},
		{`curl -H 'Authorization: Bearer $abc123def456' https://x.acmebank.pt/`, "$abc123def456"},
		{`app --password=$uperS3cret`, "$uperS3cret"},
		{`{"password":"$ummer2024x"}`, "mmer2024x"}, // JSON-escaped
	} {
		out, _, err := e.ToModel(c.in, prov)
		if err != nil {
			t.Fatalf("ToModel(%q): %v", c.in, err)
		}
		if strings.Contains(out, c.secret) {
			t.Errorf("secret left in clear:\n  in  %q\n  out %q", c.in, out)
		}
	}
}

// References to secrets held elsewhere stay as written on a command line
// and in interpolated key: value lines.
func TestShellReferencesKeptVerbatim(t *testing.T) {
	e, _ := newTestEngine(t)
	prov := Provenance{TaskIDs: []int64{6}}
	for _, in := range []string{
		`PASSWORD=$PASS ./deploy.sh`,
		`TOKEN=$(curl -s http://169.254.169.254/latest/token)`,
		`export JWT=$(cat /run/secrets/jwt)`,
		`KEY=$(id -u)`,
		`DB_PASSWORD=${DB_PASSWORD:-x} psql`,
		`PASSWORD=$db_pass make`,
		`mysql -u root -p$MYSQL_PWD db`,
		`app --password=$APP_PASSWORD --token=$(vault read -field=t x)`,
		`password: ${DB_PASSWORD}`,
		`password: $DB_PASSWORD`,
		`curl -H "Authorization: Bearer $TOKEN" https://example.org/`,
		`curl -H "Authorization: Bearer $api_token" https://example.org/`,
	} {
		out, _, err := e.ToModel(in, prov)
		if err != nil {
			t.Fatalf("ToModel(%q): %v", in, err)
		}
		if out != in {
			t.Errorf("reference mangled:\n  in  %q\n  out %q", in, out)
		}
	}
}

func TestReferenceValueContexts(t *testing.T) {
	for _, c := range []struct {
		v    string
		ctx  refContext
		want bool
	}{
		{"$PASS", refShell, true},
		{"$db_pass", refShell, true},
		{"$(cat f)", refShell, true},
		{"`cat f`", refShell, true},
		{"${X:-y}", refShell, true},
		{"$ummer2024", refShell, false},
		{"$uperS3cret", refShell, false},
		{"$PASS", refKeyValue, true},
		{"${PASS}", refKeyValue, true},
		{"$db_pass", refKeyValue, false},
		{"$ummer2024", refKeyValue, false},
		{"$PASS", refNever, false},
		{"$(cat f)", refNever, false},
		{"$_", refShell, false},
	} {
		if got := referenceValue(c.v, c.ctx); got != c.want {
			t.Errorf("referenceValue(%q, %d) = %v, want %v", c.v, c.ctx, got, c.want)
		}
	}
}
