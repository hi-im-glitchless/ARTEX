package membrane

import "testing"

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
		"git config --user.name=Jose", "--secret-name=prod-db", "--user-namespace=host",
	} {
		e, _ := newTestEngine(t)
		if out := toModel(t, e, in); out != in {
			t.Fatalf("rewritten: %q -> %q", in, out)
		}
	}
}
