package store

import "context"

// ChangeToken identifies a database revision for process-local derived views.
// Compare tokens only for equality; they are not persistent revision numbers.
type ChangeToken struct {
	owner            *Store
	connection       uint64
	changes, version int64
}

// ChangeToken uses the single checked-out SQLite connection for all readings.
// total_changes detects local writes (including conservative invalidation on
// rollback); data_version detects other connections' committed writes. Neither
// counter alone suffices. A new physical connection may reset BOTH counters,
// so a store-local connection generation and store identity are also required.
// This deliberately invalidates on unrelated-case/operational writes too.
func (s *Store) ChangeToken(ctx context.Context) (ChangeToken, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return ChangeToken{}, err
	}
	defer conn.Close()
	token := ChangeToken{owner: s}
	// modernc's concrete connection is a pointer. Keep one identity alive so
	// address reuse cannot alias a replacement. Compare it only inside Raw;
	// never invoke driver methods or expose the driver object outside Raw.
	if err = conn.Raw(func(raw any) error {
		s.changeTokenMu.Lock()
		defer s.changeTokenMu.Unlock()
		if s.changeTokenConnection != raw {
			s.changeTokenConnection = raw
			s.changeTokenGeneration++
		}
		token.connection = s.changeTokenGeneration
		return nil
	}); err != nil {
		return ChangeToken{}, err
	}
	err = conn.QueryRowContext(ctx, `SELECT total_changes(), data_version FROM pragma_data_version`).Scan(&token.changes, &token.version)
	return token, err
}
