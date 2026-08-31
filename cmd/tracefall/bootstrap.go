package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"tracefall/internal/api"
	"tracefall/internal/model"
)

// BootstrapUsername is the account created on a first run.
//
// Fixed and documented so an operator who has just installed Tracefall
// knows what to type without reading the source. It is only half a
// credential: the password is generated per-installation, so a known
// username reveals nothing.
const BootstrapUsername = "tracefall"

// bootstrapAdmin creates the initial administrator when authentication
// is enabled and the database contains no users.
//
// # Why a generated password rather than a default
//
// A well-known default credential on a forensic tool is worse than no
// authentication, because it looks secure. The password comes from
// crypto/rand, is printed once to stdout, and is never written to the
// structured logger (which may ship to a collector), the audit trail,
// any API response, or the database in plaintext.
//
// # Why "printed once" is decided by the database
//
// The condition is "the users table is empty", which is persisted
// state. An in-memory flag would reprint on every restart, and a marker
// file could be deleted independently of the accounts it describes. A
// second run therefore cannot generate, reprint, or overwrite anything:
// there is a user, so this function returns immediately.
//
// TRACEFALL_ADMIN_PASSWORD lets an operator supply their own password
// for unattended provisioning. Read from the environment rather than a
// flag so it never appears in the process table.
func bootstrapAdmin(svc *api.Service, envPassword string, out io.Writer) error {
	existing, err := svc.UserCount()
	if err != nil {
		return err
	}
	if existing > 0 {
		// Not a first run. Nothing is created, printed or modified.
		return nil
	}

	password := strings.TrimSpace(envPassword)
	generated := password == ""
	if generated {
		password, err = generatePassword()
		if err != nil {
			return err
		}
	}

	// The account acts as itself in the security log, so the very first
	// entry names the account being created rather than inventing an
	// operator who was not there.
	actor := api.Principal{Username: "bootstrap", Role: model.RoleAdmin}

	// A GENERATED password is gated behind a mandatory change: it has
	// been displayed in plaintext on a terminal, where it can survive in
	// scrollback, a screenshot or a CI log.
	//
	// An operator-SUPPLIED password is not gated. They already chose it,
	// it was never displayed by Tracefall, and forcing a change would
	// break the unattended provisioning the variable exists for.
	if _, err := svc.CreateBootstrapUser(actor, BootstrapUsername, password, generated); err != nil {
		return err
	}

	if !generated {
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "==================================================")
		fmt.Fprintln(out, " Tracefall First-Run Setup")
		fmt.Fprintln(out, "==================================================")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Administrator account created.")
		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "Username: %s\n", BootstrapUsername)
		fmt.Fprintln(out, "Password: (from TRACEFALL_ADMIN_PASSWORD)")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "==================================================")
		fmt.Fprintln(out, "")
		return nil
	}

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintln(out, " Tracefall First-Run Setup")
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Administrator account created.")
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "Username: %s\n", BootstrapUsername)
	fmt.Fprintf(out, "Password: %s\n", password)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "IMPORTANT:")
	fmt.Fprintln(out, "This password is displayed only once.")
	fmt.Fprintln(out, "Sign in and change the password immediately.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintln(out, "")
	return nil
}

// generatePassword returns a high-entropy password.
//
// 24 bytes from crypto/rand, base64url-encoded: 192 bits of entropy,
// far beyond anything a composition rule would produce, and safe to
// print in a terminal and paste into a password manager.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating initial password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
