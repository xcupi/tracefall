package api

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"tracefall/internal/store"
)

// Server-path ingest reads a directory or file that already lives on the
// server's disk. Without a policy that means any readable path on the host:
// /etc, another user's home, a mounted volume. The policy below decides which
// paths the server may read.
//
//   - TRACEFALL_EVIDENCE_ROOTS set: a path is accepted only when, after
//     symbolic links are resolved, it lies inside one of the roots.
//   - not set, and the server is in local no-auth mode on a loopback host:
//     any path, because the operator already has a shell on the machine. The
//     startup log says so.
//   - not set, otherwise: server-path ingest is refused. Upload still works.

// ErrServerPathRefused means the server's policy does not allow reading the
// path. It maps to 403.
var ErrServerPathRefused = errors.New("server path is not allowed for ingest")

// ErrEvidenceTreeEscapes means an evidence folder contains a symbolic link
// whose target lies outside the folder. Following it would read files the
// evidence package does not contain. It maps to 422.
var ErrEvidenceTreeEscapes = errors.New("evidence folder contains symbolic links that point outside it")

// evidencePathPolicy is set once at startup (SetEvidencePathPolicy).
type evidencePathPolicy struct {
	roots         []string // absolute, symlink-resolved
	allowUnrooted bool
}

// SetEvidencePathPolicy configures which server paths ingest may read. Roots
// are resolved once here, so a root given through a symlink compares equal to
// the path it names. A root that does not exist is an error: a misspelled root
// would otherwise refuse every path with no clear reason.
func (s *Service) SetEvidencePathPolicy(roots []string, allowUnrooted bool) error {
	rootsOut := make([]string, 0, len(roots))
	for _, r := range roots {
		if strings.TrimSpace(r) == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			return fmt.Errorf("evidence root %q: %w", r, err)
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return fmt.Errorf("evidence root %q: %w", r, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("evidence root %q: %w", r, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("evidence root %q is not a directory", r)
		}
		rootsOut = append(rootsOut, resolved)
	}
	s.pathPolicy = evidencePathPolicy{roots: rootsOut, allowUnrooted: allowUnrooted}
	return nil
}

// pathWithin reports whether path is root or lies beneath it. Both must be
// absolute and already symlink-resolved.
func pathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveServerPath returns the absolute, symlink-resolved form of path. An
// unresolvable path is reported as not found, which is what the user sees for
// a typo.
func resolveServerPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrEvidencePathNotFound, path)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrEvidencePathNotFound, path)
	}
	return resolved, nil
}

// checkServerPath applies the policy to a path before anything reads it.
func (s *Service) checkServerPath(path string) (string, error) {
	p := s.pathPolicy
	if len(p.roots) == 0 {
		if p.allowUnrooted {
			return path, nil
		}
		return "", fmt.Errorf("%w: server-path ingest is disabled; set TRACEFALL_EVIDENCE_ROOTS to the folders Tracefall may read from", ErrServerPathRefused)
	}
	resolved, err := resolveServerPath(path)
	if err != nil {
		return "", err
	}
	for _, root := range p.roots {
		if pathWithin(resolved, root) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w: %s is outside the configured evidence roots", ErrServerPathRefused, path)
}

// checkEvidenceTree refuses a folder that holds a symbolic link pointing
// outside it. A link that stays inside the folder is harmless and is left
// alone. The check runs before hashing or cataloguing, so a refused folder
// leaves nothing behind.
func checkEvidenceTree(root string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	var escapes []string
	walkErr := filepath.WalkDir(resolvedRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(target, resolvedRoot) {
			rel, relErr := filepath.Rel(resolvedRoot, path)
			if relErr != nil {
				rel = path
			}
			escapes = append(escapes, filepath.ToSlash(rel))
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	if len(escapes) == 0 {
		return nil
	}
	shown := escapes
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return fmt.Errorf("%w: %d link(s), for example %s", ErrEvidenceTreeEscapes, len(escapes), strings.Join(shown, ", "))
}

// VerifyAudit checks the audit hash chain of one case and reports the result.
// It returns the status even when the chain is broken: a broken chain is the
// answer, not an error.
func (s *Service) VerifyAudit(caseID string) (store.AuditChainStatus, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return store.AuditChainStatus{}, err
	}
	return s.store.VerifyAuditChain(caseID)
}

// auditChainSummaryForDeletion describes a case's audit chain as it stands,
// before the case's rows are removed. The summary is written into the case's
// existing security_log entry for the deletion, which survives the case. A
// failure to read the chain is recorded as such, not dropped.
func (s *Service) auditChainSummaryForDeletion(caseID string) string {
	st, err := s.store.VerifyAuditChain(caseID)
	if err != nil {
		return fmt.Sprintf("audit chain could not be read before deletion: %v", err)
	}
	return fmt.Sprintf("audit chain held %d row(s): %d chained, %d unchained, head %q, chain valid=%t",
		st.Rows, st.Chained, st.Unchained, st.Head, st.Valid)
}
