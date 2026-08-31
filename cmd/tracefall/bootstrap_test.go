package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"tracefall/internal/api"
	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// openService opens a real database at path, so a "restart" in these
// tests is what a restart actually is: a second process opening the same
// file. Nothing about the bootstrap decision is carried in memory.
func openService(t *testing.T, path string) (*api.Service, func()) {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	files := casefiles.NewStore(t.TempDir())
	return api.NewService(db, files), func() { db.Close() }
}

// passwordFrom pulls the credential out of the first-run banner the way
// an operator reads it off their terminal.
var passwordLine = regexp.MustCompile(`(?m)^Password: (.+)$`)

func passwordFrom(t *testing.T, out string) string {
	t.Helper()
	m := passwordLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no password line in the first-run output:\n%s", out)
	}
	return strings.TrimSpace(m[1])
}

// (1)(2)(5) A first run on an empty database creates exactly one admin
// named "tracefall" and prints its credential once.
func TestBootstrap_FirstRunCreatesAndPrintsOnce(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	svc, closeDB := openService(t, dbPath)
	defer closeDB()

	var out bytes.Buffer
	if err := bootstrapAdmin(svc, "", &out); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	banner := out.String()
	for _, want := range []string{
		"Tracefall First-Run Setup",
		"Administrator account created.",
		"Username: tracefall",
		"This password is displayed only once.",
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("first-run output is missing %q:\n%s", want, banner)
		}
	}

	users, err := svc.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want exactly 1", len(users))
	}
	if users[0].Username != "tracefall" {
		t.Errorf("username = %q, want %q", users[0].Username, "tracefall")
	}
	if users[0].Role != model.RoleAdmin {
		t.Errorf("role = %q, want admin", users[0].Role)
	}
	if !users[0].MustChangePassword {
		t.Error("the bootstrap account is not gated behind a password change")
	}

	// (3) The printed password is high-entropy, not a default.
	pw := passwordFrom(t, banner)
	if len(pw) < 24 {
		t.Errorf("generated password is only %d characters: %q", len(pw), pw)
	}
	for _, bad := range []string{"admin", "password", "tracefall", "changeme"} {
		if strings.EqualFold(pw, bad) {
			t.Errorf("generated password is a predictable value: %q", pw)
		}
	}
}

// (3) Two fresh installations must not receive the same password.
func TestBootstrap_PasswordDiffersBetweenInstallations(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		svc, closeDB := openService(t, filepath.Join(t.TempDir(), "fresh.db"))
		var out bytes.Buffer
		if err := bootstrapAdmin(svc, "", &out); err != nil {
			t.Fatal(err)
		}
		closeDB()
		pw := passwordFrom(t, out.String())
		if seen[pw] {
			t.Fatalf("two installations generated the same password: %q", pw)
		}
		seen[pw] = true
	}
}

// (6)(7) Restarting against the SAME database must not generate,
// reprint or overwrite anything. This is the `make run` x3 requirement.
func TestBootstrap_RestartsNeverRegenerateOrReprint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "persistent.db")

	svc, closeDB := openService(t, dbPath)
	var first bytes.Buffer
	if err := bootstrapAdmin(svc, "", &first); err != nil {
		t.Fatal(err)
	}
	originalPW := passwordFrom(t, first.String())
	users, _ := svc.ListUsers()
	originalID := users[0].ID
	closeDB()

	// Two more "starts" against the same file.
	for i := 2; i <= 3; i++ {
		svc, closeDB := openService(t, dbPath)
		var out bytes.Buffer
		if err := bootstrapAdmin(svc, "", &out); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if out.Len() != 0 {
			t.Errorf("start %d printed a bootstrap banner again:\n%s", i, out.String())
		}
		if strings.Contains(out.String(), "Password:") {
			t.Errorf("start %d reprinted a credential", i)
		}
		users, err := svc.ListUsers()
		if err != nil {
			t.Fatal(err)
		}
		if len(users) != 1 {
			t.Errorf("start %d: %d users, want 1 -- bootstrap created another account", i, len(users))
		}
		if users[0].ID != originalID {
			t.Errorf("start %d: the account was recreated (id changed)", i)
		}
		closeDB()
	}

	// (7) The original password still authenticates -- it was not
	// overwritten by any of the restarts.
	svc, closeDB = openService(t, dbPath)
	defer closeDB()
	if _, _, err := svc.Login("tracefall", originalPW, 0); err != nil {
		t.Errorf("the original bootstrap password no longer works after restarts: %v", err)
	}
}

// (19) A genuinely new database bootstraps again, with a different
// password -- resetting the database is a legitimate fresh install.
func TestBootstrap_NewDatabaseBootstrapsAgain(t *testing.T) {
	svcA, closeA := openService(t, filepath.Join(t.TempDir(), "a.db"))
	var outA bytes.Buffer
	if err := bootstrapAdmin(svcA, "", &outA); err != nil {
		t.Fatal(err)
	}
	closeA()

	svcB, closeB := openService(t, filepath.Join(t.TempDir(), "b.db"))
	defer closeB()
	var outB bytes.Buffer
	if err := bootstrapAdmin(svcB, "", &outB); err != nil {
		t.Fatal(err)
	}

	if outB.Len() == 0 {
		t.Fatal("a genuinely new database did not bootstrap")
	}
	if passwordFrom(t, outA.String()) == passwordFrom(t, outB.String()) {
		t.Error("two separate databases received the same bootstrap password")
	}
}

// (20) A database that already has users is never touched -- no new
// account, no reprint, and existing credentials keep working.
func TestBootstrap_ExistingDatabaseWithUsersIsUntouched(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "existing.db")
	svc, closeDB := openService(t, dbPath)

	// An operator-provisioned deployment: accounts already exist and none
	// of them is called "tracefall".
	actor := api.Principal{Username: "setup", Role: model.RoleAdmin}
	if _, err := svc.CreateUser(actor, "carol", "carols-password-12", model.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(actor, "dave", "daves-password-123", model.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	closeDB()

	svc, closeDB = openService(t, dbPath)
	defer closeDB()
	var out bytes.Buffer
	if err := bootstrapAdmin(svc, "", &out); err != nil {
		t.Fatal(err)
	}

	if out.Len() != 0 {
		t.Errorf("bootstrap printed a banner for a database that already has users:\n%s", out.String())
	}
	users, _ := svc.ListUsers()
	if len(users) != 2 {
		t.Fatalf("got %d users, want the 2 that already existed", len(users))
	}
	for _, u := range users {
		if u.Username == "tracefall" {
			t.Error("bootstrap created a 'tracefall' account on a populated database")
		}
		if u.MustChangePassword {
			t.Errorf("bootstrap gated the pre-existing account %q", u.Username)
		}
	}
	if _, _, err := svc.Login("carol", "carols-password-12", 0); err != nil {
		t.Errorf("an existing account's password was disturbed by bootstrap: %v", err)
	}
}

// An operator-supplied password is used as given, is NOT echoed, and is
// not gated -- they chose it, and it was never displayed.
func TestBootstrap_OperatorSuppliedPasswordIsNotEchoedOrGated(t *testing.T) {
	const supplied = "operator-chosen-password"
	svc, closeDB := openService(t, filepath.Join(t.TempDir(), "env.db"))
	defer closeDB()

	var out bytes.Buffer
	if err := bootstrapAdmin(svc, supplied, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), supplied) {
		t.Errorf("an operator-supplied password was echoed to stdout:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "TRACEFALL_ADMIN_PASSWORD") {
		t.Errorf("the banner does not say where the password came from:\n%s", out.String())
	}
	if _, _, err := svc.Login("tracefall", supplied, 0); err != nil {
		t.Errorf("the supplied password does not authenticate: %v", err)
	}
	users, _ := svc.ListUsers()
	if users[0].MustChangePassword {
		t.Error("an operator-supplied password was gated behind a change it does not need")
	}
}
