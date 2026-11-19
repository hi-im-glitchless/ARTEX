package membrane

import (
	"strings"
	"testing"
)

// Task 6 carried fix: user/login/account name keys and remaining credential
// key spellings.
func TestNameKeysAndRemainingSpellings(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{`{"userName":"mferreira"}`, "mferreira"},
		{`{"UserName":"mferreira"}`, "mferreira"},
		{"user_name=mferreira", "mferreira"},
		{"login_name=mferreira", "mferreira"},
		{"DB_USER_NAME=mferreira", "mferreira"},
		{"account_name=mferreira", "mferreira"},
		{"--user-name=mferreira", "mferreira"},
		{"aws iam create-login-profile --user-name mferreira", "mferreira"},
		{"--login-name mferreira", "mferreira"},
		{"secret_data=Zz81kkQq", "Zz81kkQq"},
		{"token_data=Zz81kkQq", "Zz81kkQq"},
		{"password_server=Zz81kkQq", "Zz81kkQq"},
		{"password_backend=Zz81kkQq", "Zz81kkQq"},
		{"mysql --db-pass Zz81kkQq", "Zz81kkQq"},
		{"mysql --root-password Zz81kkQq", "Zz81kkQq"},
		{"password_hash=Zz81kkQq", "Zz81kkQq"},
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
	}
	for _, in := range []string{
		"password_policy=strong", "password_min_length=12", "--password-policy=strong",
		"--secret-name=prod-db", "--user-namespace=host",
	} {
		e, _ := newTestEngine(t)
		if out := toModel(t, e, in); out != in {
			t.Fatalf("rewritten: %q -> %q", in, out)
		}
	}
}

// Review round 1: numeric ids are not enrolled; git user.name is a person.
func TestNumericIDValuesNotEnrolled(t *testing.T) {
	for _, in := range []string{
		"user_id=1042", "login_id=998877", "account_id=123456789012", `{"user_id":"1042"}`, `{"userId":"1042"}`,
		"--user-id=1042", "user_id=1000:1000",
	} {
		e, s := newTestEngine(t)
		if out := toModel(t, e, in); out != in {
			t.Fatalf("rewritten: %q -> %q", in, out)
		}
		follow := "order 1042 shipped, port 1042"
		if out := toModel(t, e, follow); out != follow {
			t.Fatalf("collateral: %q", out)
		}
		if _, _, ok := s.AliasFor("1042"); ok {
			t.Fatal("1042 enrolled")
		}
	}
	for _, c := range []struct{ in, secret string }{
		{"user_id=550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"user_id=jsilva01", "jsilva01"},
		{`{"account_id":"acct-77x"}`, "acct-77x"},
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
	}
}

func TestGitConfigCRLFAndComments(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{"[user]\r\n\tname = João Silva\r\n\temail = x@example.org\r\n", "João Silva"},
		{"[user]\n\tname = João Silva # work\n", "João Silva"},
		{"[user]\n\tname = \"Maria Costa\" ; old\n", "Maria Costa"},
		{"[user]\r\n\tname = joao\r\n", "joao"},
	} {
		e, _ := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
	}
	e, _ := newTestEngine(t)
	out := toModel(t, e, "[user]\n\tname = João Silva # work\n")
	if !strings.HasSuffix(out, " # work\n") {
		t.Fatalf("comment swallowed: %q", out)
	}
}

func TestGitUserNameIsPerson(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{`git config user.name "João Silva"`, "João Silva"},
		{"git config --global user.name joao", "joao"},
		{"git config --global user.name 'Maria Costa'", "Maria Costa"},
		{"[user]\n\tname = João Silva\n\temail = x@example.org\n", "João Silva"},
		{"[core]\n\teditor = vim\n[user]\n\tname = \"Maria Costa\"\n", "Maria Costa"},
		{"user.name=Jose", "Jose"},
		{"git config --user.name=Jose", "Jose"},
	} {
		e, s := newTestEngine(t)
		assertAliased(t, e, c.in, c.secret)
		a, kind, ok := s.AliasFor(c.secret)
		if !ok || kind != KindPerson {
			t.Fatalf("%q: kind %v ok %v alias %q", c.in, kind, ok, a)
		}
	}
	for _, in := range []string{
		"cluster.name=prodcluster", "--app.name=billing", "git config core.name foo", "[core]\n\tname = hello\n",
		"[remote \"origin\"]\n\turl = x\n", "user.namespace=host",
	} {
		e, _ := newTestEngine(t)
		if out := toModel(t, e, in); out != in {
			t.Fatalf("rewritten: %q -> %q", in, out)
		}
	}
}
