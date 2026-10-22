package cmdsem

import (
	"strings"
	"testing"
)

func TestRedact_MasksSQLServerPasswordShapes(t *testing.T) {
	cases := []struct{ in, secret string }{
		{"CREATE LOGIN bob WITH PASSWORD='Sup3rSecret!', CHECK_POLICY=OFF", "Sup3rSecret!"},
		{"ALTER LOGIN sa WITH PASSWORD = N'Another#1' UNLOCK", "Another#1"},
		{"CREATE USER u WITH PASSWORD = 'abc123xyz'", "abc123xyz"},
		{"ALTER LOGIN sa WITH PASSWORD = 'new1' OLD_PASSWORD = 'old1'", "old1"},
		{"EXEC sp_addlinkedsrvlogin @rmtsrvname='x', @rmtpassword='Hunter2pw'", "Hunter2pw"},
		{"Server=tcp:db01;User Id=app;Password=P@ssw0rdX;Encrypt=true", "P@ssw0rdX"},
		{"Data Source=db01;Initial Catalog=x;Pwd=Zz9secret;Integrated Security=False", "Zz9secret"},
		{`sqlcmd -S db01 -U sa -P Pa55w0rdQ -Q "select 1"`, "Pa55w0rdQ"},
		{`osql -E -S db01 -U sa -P "Pa55 w0rdQ"`, "Pa55 w0rdQ"},
		{"EXEC sp_password @old='oldpw1', @new='newpw2', @loginame='x'", "newpw2"},
	}
	for _, c := range cases {
		got := Redact(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("secret %q survived: %q", c.secret, got)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("no redaction marker in %q", got)
		}
	}
}

func TestRedact_LeavesOrdinarySQLAlone(t *testing.T) {
	for _, s := range []string{
		"SELECT name FROM sys.databases WHERE name = 'master'",
		"ALTER SERVER ROLE sysadmin ADD MEMBER backdoor01",
		"EXEC sp_configure 'xp_cmdshell', 1",
		"Login failed for user 'alice'. Reason: Password did not match that for the login provided.",
		"CREATE LOGIN bob FROM WINDOWS",
		"sqlcmd -S db01 -E -Q \"select 1\"",
	} {
		if got := Redact(s); got != s {
			t.Errorf("changed an ordinary statement:\n in: %s\nout: %s", s, got)
		}
	}
}
