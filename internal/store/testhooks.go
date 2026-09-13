package store

import "database/sql"

// DB exposes the store's own connection.
//
// It exists for the DELETION AUDIT (internal/store/deletion_audit_test.go),
// which has to ask the live database questions the typed API deliberately
// cannot answer: which tables carry a case_id, whether foreign keys are
// actually enforced on THIS connection, and whether a failed deletion
// rolled back. Asking a second connection would prove nothing about the
// one the application uses.
//
// It is read-mostly by intention. Nothing in the application calls it,
// and nothing should: every production write goes through a typed method
// so the schema and the code cannot drift apart.
func (s *Store) DB() *sql.DB { return s.db }
