package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/ese"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/srum"
)

func TestSRUMFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{srum.ErrLimitExceeded, ParseFailureLimit}, {ese.ErrCorrupt, ParseFailureCorrupt}} {
		got, _ := ClassifyParseError(fmt.Errorf("srum: %w", tc.err))
		if got != tc.want {
			t.Fatalf("%v got %s want %s", tc.err, got, tc.want)
		}
	}
	path := filepath.Join(t.TempDir(), "SRUDB.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((8 << 30) + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cov, err := srum.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	category, _ := ClassifyParseError(err)
	if category != ParseFailureLimit || cov == nil || !cov.LimitReached {
		t.Fatalf("file limit %s %v %+v", category, err, cov)
	}
}

func TestSRUMSpoolUsesBoundedNativeCompression(t *testing.T) {
	p, err := newParsedSpool(&stagingBudget{limit: 1 << 20}, model.ArtifactSRUM)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if !p.compressed {
		t.Fatal("SRUM staging still expands whole-source disk budget")
	}
}
