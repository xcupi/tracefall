package mssqlxe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/parsers"
)

func TestBinary_UnconfiguredReaderIsAClassifiedError(t *testing.T) {
	t.Setenv("TRACEFALL_MSSQL_READER", "")
	t.Setenv("TRACEFALL_MSSQL_DOTNET_ROOT", "")
	f := filepath.Join(t.TempDir(), "session.xel")
	if err := os.WriteFile(f, []byte("XELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New().ParseWithContext(f, parsers.ParseContext{})
	if !errors.Is(err, ErrReaderUnavailable) {
		t.Fatalf("err = %v, want ErrReaderUnavailable", err)
	}
	_, err = NewAudit().ParseWithContext(f+"audit.sqlaudit", parsers.ParseContext{})
	_ = err
	t.Setenv("TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL", "")
	a := filepath.Join(t.TempDir(), "x.sqlaudit")
	if werr := os.WriteFile(a, []byte("AUDT"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, err = NewAudit().ParseWithContext(a, parsers.ParseContext{}); !errors.Is(err, ErrReaderUnavailable) {
		t.Fatalf("gated audit err = %v, want ErrReaderUnavailable", err)
	}
}
