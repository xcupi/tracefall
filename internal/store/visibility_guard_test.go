package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The segmented-import contract hides the rows of a source whose
// import_status is 'importing' from every reader through ONE shared SQL
// fragment (srcVisible / srcVisibleOrOwn). This guard statically scans every
// non-test Go file under internal/ for SQL that reads events,
// event_observations or raw_evidence and fails when a reader does not carry
// the fragment, so a reader added later cannot leak pending rows.
//
// A statement is the maximal "+" concatenation that contains the table
// reference, so a fragment assembled from several literals is judged whole.
// Statements that start with INSERT/UPDATE/DELETE/CREATE/DROP are writers or
// maintenance (inventory: 01-inventory.md) and are not readers.

var (
	guardTableRef = regexp.MustCompile(`(?i)\b(?:from|join)\s+(?:events|event_observations|raw_evidence)\b`)
	guardNotRead  = regexp.MustCompile(`(?i)^\s*(?:insert|update|delete|create|drop|alter|pragma)\b`)
)

// guardAllowlist names the only SELECT statements over the three tables that
// intentionally do not carry the fragment. Key: "<dir>/<file>:<func>".
var guardAllowlist = map[string]string{
	"store/migrate.go:backfillLegacyCollectionForCase":  "startup migration counting legacy rows with collection_id=''; importing sources cannot exist before migration and the rows it rewrites are maintenance, not evidence reads",
	"store/segmented_import.go:FinalizeSegmentedImport": "verification must read the importing source's own pending rows and every other row to prove no dedup hash is shared; it only counts, never returns evidence, and runs before the source is published",
	"store/migrate.go:backfillDedupHashes":              "startup migration over legacy rows (dedup_hash=''); importing sources never exist before migration and rows it rewrites are maintenance, not evidence reads",
}

func guardPredicateNames() map[string]bool {
	return map[string]bool{"srcVisible": true, "srcVisibleOrOwn": true}
}

type guardStatement struct {
	where  string // dir/file:func
	line   int
	text   string
	tables int
	preds  int
}

func scanSQLStatements(t *testing.T, root string) []guardStatement {
	t.Helper()
	var out []guardStatement
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == ".hermes" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		seen := map[ast.Node]bool{}
		for _, decl := range f.Decls {
			fn := "(package)"
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			var stack []ast.Node
			ast.Inspect(decl, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				root := ast.Node(lit)
				for i := len(stack) - 2; i >= 0; i-- {
					if be, ok := stack[i].(*ast.BinaryExpr); ok && be.Op == token.ADD {
						root = be
						continue
					}
					break
				}
				if seen[root] {
					return true
				}
				seen[root] = true
				var text strings.Builder
				preds := 0
				ast.Inspect(root, func(m ast.Node) bool {
					switch v := m.(type) {
					case *ast.BasicLit:
						if v.Kind == token.STRING {
							if s, err := strconv.Unquote(v.Value); err == nil {
								text.WriteString(s)
							}
						}
					case *ast.CallExpr:
						if id, ok := v.Fun.(*ast.Ident); ok && guardPredicateNames()[id.Name] {
							preds++
						}
					}
					return true
				})
				s := strings.Join(strings.Fields(text.String()), " ")
				n2 := len(guardTableRef.FindAllString(s, -1))
				if n2 == 0 {
					return true
				}
				out = append(out, guardStatement{
					where: rel + ":" + fn, line: fset.Position(lit.Pos()).Line,
					text: s, tables: n2, preds: preds,
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].where+strconv.Itoa(out[i].line) < out[j].where+strconv.Itoa(out[j].line)
	})
	return out
}

func TestEveryEvidenceReaderCarriesTheImportingSourceVisibilityPredicate(t *testing.T) {
	stmts := scanSQLStatements(t, "..")
	if len(stmts) < 20 {
		t.Fatalf("scan found only %d statements over events/event_observations/raw_evidence; the scanner is broken", len(stmts))
	}
	used := map[string]bool{}
	readers := 0
	for _, st := range stmts {
		if guardNotRead.MatchString(st.text) {
			continue
		}
		readers++
		// where is "<dir>/<file>.go:<func>"; allowlist keys drop the leading
		// "internal/" because the scan root is internal/ itself.
		if _, ok := guardAllowlist[st.where]; ok {
			used[st.where] = true
			continue
		}
		if st.preds < st.tables {
			t.Errorf("%s (line %d): reader of events/event_observations/raw_evidence has %d table reference(s) but %d visibility predicate call(s); every reader must hide importing sources via srcVisible/srcVisibleOrOwn (or be allowlisted with a reason)\n    %.200s",
				st.where, st.line, st.tables, st.preds, st.text)
		}
	}
	if readers == 0 {
		t.Fatal("no reader statements found")
	}
	for k := range guardAllowlist {
		if !used[k] {
			t.Errorf("stale guard allowlist entry %q: no such reader statement", k)
		}
	}
}
