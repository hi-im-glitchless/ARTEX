package membrane

import (
	"strings"
	"testing"
)

// Fix round 5 regressions, built from the reviewer's probe9 inputs.

func TestConfigFlagsNotCredentials(t *testing.T) {
	e, s := newTestEngine(t)
	for _, in := range []string{
		"--auth-type=basic", "--auth-type=digest", "--token-type=bearer", "--authorization-mode=Node,RBAC",
		"--user-namespace=host", "--token-audience=api", "--auth-provider=oidc", "--password-policy=strong",
		"--token-ttl=3600", "--username-attribute=uid", "--secret-name=prod-db", "--secret-ref=mysecret",
		"--secret-id=arn:aws:x", "--user-pool-id=eu_X1", "--api-key-header=X-Api-Key", "--token-endpoint=https://x/y",
		"--user=www-data", "--auth-method=password", "--password-store=basic", "--user-data-dir=/tmp/x",
		"--token-file=/var/run/token", "--passwd-file=/etc/p", "--token-auth-file=/x", "--secretsmanager-arn=x",
		"curl --user-agent=Mozilla/5.0 x", "--passive=yes", // git user.name is a person name, detected since task 6 review
		"kube-apiserver --authorization-mode=Node,RBAC --user-namespace=host --token-audience=api --auth-type=basic --token-type=bearer",
		"auth_type=basic", `{"token_type":"bearer","expires_in":3600}`, "auth: basic",
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("config flag rewritten: %q -> %q", in, out)
		}
	}
	for _, w := range []string{"basic", "digest", "bearer", "host", "api", "oidc", "strong", "3600", "uid",
		"prod-db", "mysecret", "www-data", "Node,RBAC", "https://x/y", "eu_X1", "X-Api-Key"} {
		if _, _, ok := s.AliasFor(w); ok {
			t.Fatalf("%q enrolled", w)
		}
	}
	// No collateral after the kube-apiserver line.
	for _, in := range []string{
		"ssh host uptime; the host is down", "GET /api/v1/users HTTP/1.1", "Node and RBAC authorizers",
	} {
		if out := toModel(t, e, in); out != in {
			t.Fatalf("collateral rewrite: %q -> %q", in, out)
		}
	}
}

func TestCredentialKeysStillDetected(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{`{"session_token":"abc123xyz"}`, "abc123xyz"},
		{"client_secret=Qq99wwZ", "Qq99wwZ"},
		{`{"access_token":"Tk55rr99x"}`, "Tk55rr99x"},
		{`{"apiKey":"Ak44pp88x"}`, "Ak44pp88x"},
		{"DB_PASSWORD=Pw33qq77x", "Pw33qq77x"},
		{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI9K7MDENG", "wJalrXUtnFEMI9K7MDENG"},
		{"X-Api-Key: k3y-AbCdEf12345", "k3y-AbCdEf12345"},
		{"session_id=Sx11yy22zz", "Sx11yy22zz"},
		{"--client-secret=Qq99ww", "Qq99ww"},
		{"aws configure set --secret-key Qq88ww", "Qq88ww"},
		{"--db-password=Qq77ww", "Qq77ww"},
		{"--auth=Qq66ww", "Qq66ww"},
		{"curl --oauth2-bearer Qq55ww", "Qq55ww"},
		{"--passphrase=Qq44ww", "Qq44ww"},
		{"kubeadm join --token abcdef.0123456789abcdef", "abcdef.0123456789abcdef"},
		{"db_password_prod=Pp22oo11x", "Pp22oo11x"},
		{"mysql --user=jdoe7", "jdoe7"},
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
	}
}

func TestGluedFlagShellKeywords(t *testing.T) {
	for _, in := range []string{
		"for h in a b; do mysql -h $h -uroot -pKy18mq; done",
		"if true; then mysql -uroot -pKy18mq; fi",
		"strace mysql -uroot -pKy18mq",
		"ltrace -o x.log mysql -uroot -pKy18mq",
		"if x; then :; else mysql -uroot -pKy18mq; fi",
		"! mysql -uroot -pKy18mq",
		"{ mysql -uroot -pKy18mq; }",
		"ssh mysql-host -p2222 mysql -uroot -pKy18mq",
		"mysql> select 1; -- mysql -uroot -pKy18mq",
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, in, "Ky18mq")
	}
}

func TestHostSuffixEncodedMultibyteDot(t *testing.T) {
	e, s := newTestEngine(t)
	ra := mustAlias(t, s, "acmebank.pt")
	for _, in := range []string{
		"https://" + ra + "%E3%80%82com/x", "https://" + ra + "%EF%BC%8Ecom/x", "https://" + ra + "%ef%bd%a1com/x",
		"https://" + ra + "&period;com/x",
	} {
		if back, _ := e.ToReal(in); back != in {
			t.Fatalf("reversed into a third-party host: %q -> %q", in, back)
		}
	}
	if out := strings.TrimSpace(toModel(t, e, "cat acmebank.pt.conf")); strings.Contains(out, "acmebank") {
		t.Fatalf("%q", out)
	}
}
