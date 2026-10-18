package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Resumable uploads (roadmap item 2).
//
// A multi-gigabyte image cannot reasonably travel in one HTTP request: a
// dropped connection throws away everything sent. Here the client opens a
// SESSION, sends the file in chunks at explicit offsets, and after any
// failure -- its own, the network's, or a server restart -- asks the
// server how many bytes it durably holds and continues from there.
//
// # Invariants
//
//   - Received is a CONTIGUOUS prefix. A chunk is accepted only at
//     exactly offset == Received, so there are never holes and no chunk
//     can overwrite bytes already counted.
//   - Bytes are fsynced BEFORE Received advances, so the counter can lag
//     the file but never lead it. A crash between the two leaves extra
//     bytes after Received, which the next chunk truncates away.
//   - Received only moves through a compare-and-swap in the store, so two
//     concurrent chunks aimed at the same offset cannot both succeed.
//   - The bytes land in a file named from the server-generated session id
//     alone; nothing a client sends becomes part of a path.
//
// Verification is deliberately NOT done at completion. Hashing a 50 GB
// file inside an HTTP request would outlast any sane timeout, and the
// ingest pipeline has to hash the file anyway. Completion therefore
// checks that every declared byte arrived; the pipeline compares the
// digest the client declared (if any) against the digest it computes,
// in the single pass it already makes.

const (
	// maxUploadChunkBytes bounds one PUT. Clients are expected to send
	// much less; the bound exists so one request cannot be made to hold a
	// connection open indefinitely.
	maxUploadChunkBytes = 64 << 20
	maxUploadNameLen    = 255
	// staleUploadAge is how long an open session may sit untouched
	// before its bytes are reclaimed.
	staleUploadAge = 7 * 24 * time.Hour
)

var (
	// ErrUploadInvalid means an upload request was malformed.
	ErrUploadInvalid = errors.New("invalid upload request")
	// ErrUploadIncomplete means completion was requested before every
	// declared byte had arrived.
	ErrUploadIncomplete = errors.New("the upload is not complete: not every declared byte has been received")
	// ErrUploadNotReady means a pipeline was requested for an upload that
	// was never completed, or that has already been used or discarded.
	ErrUploadNotReady = errors.New("the upload is not available for ingestion")
	// ErrUploadHashMismatch means the digest the client declared is not
	// the digest of the bytes that arrived: the file was corrupted or
	// altered in transit.
	ErrUploadHashMismatch = errors.New("the uploaded bytes do not match the SHA-256 the client declared; the file was corrupted or altered in transit")
)

// UploadOffsetError reports a chunk sent at the wrong offset, carrying
// the offset the server actually holds so the client can resume from it.
type UploadOffsetError struct{ Received int64 }

func (e *UploadOffsetError) Error() string {
	return fmt.Sprintf("the upload offset does not match: the server holds %d byte(s)", e.Received)
}

// uploadLocks serializes writers on one session. The compare-and-swap in
// the store keeps the counter correct on its own; the lock additionally
// keeps two writers from interleaving into the same FILE.
type uploadLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (u *uploadLocks) get(id string) *sync.Mutex {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]*sync.Mutex{}
	}
	l, ok := u.m[id]
	if !ok {
		l = &sync.Mutex{}
		u.m[id] = l
	}
	return l
}

func (u *uploadLocks) forget(id string) {
	u.mu.Lock()
	delete(u.m, id)
	u.mu.Unlock()
}

// loadUpload returns a session that belongs to caseID. A session of any
// other case is reported as not found, never as forbidden: its existence
// is not the caller's to learn.
func (s *Service) loadUpload(caseID, uploadID string) (model.UploadSession, error) {
	u, err := s.store.GetUploadSession(uploadID)
	if err != nil {
		return model.UploadSession{}, err
	}
	if u.CaseID != caseID {
		return model.UploadSession{}, store.ErrUploadNotFound
	}
	return u, nil
}

// CreateUpload opens a resumable upload. maxBytes is the server's upload
// limit; a declared size above it is refused before a byte is sent.
func (s *Service) CreateUpload(caseID string, in UploadInit, maxBytes int64) (model.UploadSession, error) {
	if _, err := s.requireEvidenceMutable(caseID); err != nil {
		return model.UploadSession{}, err
	}
	name := filepath.Base(strings.ReplaceAll(strings.TrimSpace(in.Filename), `\`, "/"))
	switch {
	case in.Filename == "" || name == "." || name == "/" || name == "":
		return model.UploadSession{}, fmt.Errorf("%w: filename is required", ErrUploadInvalid)
	case len(name) > maxUploadNameLen:
		return model.UploadSession{}, fmt.Errorf("%w: filename is too long", ErrUploadInvalid)
	case in.Size <= 0:
		return model.UploadSession{}, fmt.Errorf("%w: size must be greater than zero", ErrUploadInvalid)
	}
	declared := strings.ToLower(strings.TrimSpace(in.SHA256))
	if declared != "" {
		if b, err := hex.DecodeString(declared); err != nil || len(b) != sha256.Size {
			return model.UploadSession{}, fmt.Errorf("%w: sha256 must be 64 hexadecimal characters", ErrUploadInvalid)
		}
	}
	if maxBytes > 0 && in.Size > maxBytes {
		return model.UploadSession{}, fmt.Errorf("%w (limit is %d MB)", ErrUploadTooLarge, maxBytes/(1<<20))
	}

	id := uuid.NewString()
	if err := os.MkdirAll(s.files.UploadsDir(caseID), 0o755); err != nil {
		return model.UploadSession{}, fmt.Errorf("preparing upload storage: %w", err)
	}
	f, err := os.OpenFile(s.files.UploadSessionPath(caseID, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return model.UploadSession{}, fmt.Errorf("creating upload file: %w", err)
	}
	f.Close()

	now := time.Now().UTC()
	u := model.UploadSession{
		ID: id, CaseID: caseID, Filename: name, Size: in.Size, Status: model.UploadOpen,
		ClientSHA256: declared, CreatedBy: s.auditActor(), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateUploadSession(u); err != nil {
		_ = os.Remove(s.files.UploadSessionPath(caseID, id))
		return model.UploadSession{}, err
	}
	return u, nil
}

// UploadStatus reports how many contiguous bytes the server holds.
func (s *Service) UploadStatus(caseID, uploadID string) (model.UploadSession, error) {
	return s.loadUpload(caseID, uploadID)
}

// AppendUploadChunk writes one chunk at offset, which must equal the
// bytes already received. On a bad offset it returns *UploadOffsetError.
func (s *Service) AppendUploadChunk(caseID, uploadID string, offset int64, body io.Reader) (model.UploadSession, error) {
	if _, err := s.loadUpload(caseID, uploadID); err != nil {
		return model.UploadSession{}, err
	}
	lock := s.pipe.uploads.get(uploadID)
	lock.Lock()
	defer lock.Unlock()

	// Re-read under the lock: the first read may predate another chunk.
	u, err := s.loadUpload(caseID, uploadID)
	if err != nil {
		return model.UploadSession{}, err
	}
	if u.Status != model.UploadOpen {
		return u, store.ErrUploadClosed
	}
	if offset != u.Received {
		return u, &UploadOffsetError{Received: u.Received}
	}

	remaining := u.Size - u.Received
	path := s.files.UploadSessionPath(caseID, uploadID)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return u, fmt.Errorf("opening upload file: %w", err)
	}
	defer f.Close()
	// Drop anything past the committed offset: bytes a crashed chunk
	// wrote but never counted.
	if err := f.Truncate(u.Received); err != nil {
		return u, fmt.Errorf("preparing upload file: %w", err)
	}
	if _, err := f.Seek(u.Received, io.SeekStart); err != nil {
		return u, err
	}

	// One byte more than allowed, so an overrun is detected rather than
	// silently cut short.
	n, copyErr := io.Copy(f, io.LimitReader(body, remaining+1))
	if n > remaining {
		_ = f.Truncate(u.Received)
		return u, fmt.Errorf("%w: the chunk runs past the declared size", ErrUploadTooLarge)
	}
	if n == 0 {
		if copyErr != nil {
			return u, copyErr
		}
		return u, fmt.Errorf("%w: empty chunk", ErrUploadInvalid)
	}
	if err := f.Sync(); err != nil {
		return u, fmt.Errorf("syncing upload file: %w", err)
	}
	// Whatever arrived before an interruption is kept: it is a valid
	// contiguous prefix, and the client resumes after it.
	if err := s.store.AdvanceUpload(uploadID, u.Received, u.Received+n, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrUploadOffsetConflict) {
			return u, &UploadOffsetError{Received: u.Received}
		}
		return u, err
	}
	u.Received += n
	if copyErr != nil {
		return u, fmt.Errorf("the chunk was interrupted after %d byte(s): %w", n, copyErr)
	}
	return u, nil
}

// CompleteUpload confirms every declared byte arrived and the file on
// disk is exactly that long. It does not hash the file; see the package
// comment above.
func (s *Service) CompleteUpload(caseID, uploadID string) (model.UploadSession, error) {
	lock := s.pipe.uploads.get(uploadID)
	lock.Lock()
	defer lock.Unlock()

	u, err := s.loadUpload(caseID, uploadID)
	if err != nil {
		return model.UploadSession{}, err
	}
	if u.Status == model.UploadComplete {
		return u, nil // completing twice is harmless
	}
	if u.Status != model.UploadOpen {
		return u, store.ErrUploadClosed
	}
	if u.Received != u.Size {
		return u, ErrUploadIncomplete
	}
	st, err := os.Stat(s.files.UploadSessionPath(caseID, uploadID))
	if err != nil || st.Size() != u.Size {
		return u, ErrUploadIncomplete
	}
	if err := s.store.SetUploadStatus(uploadID, model.UploadComplete, time.Now().UTC()); err != nil {
		return u, err
	}
	u.Status = model.UploadComplete
	return u, nil
}

// AbortUpload discards a session and its bytes. A session already handed
// to a pipeline job is not the caller's to abort; cancel the job.
func (s *Service) AbortUpload(caseID, uploadID string) error {
	lock := s.pipe.uploads.get(uploadID)
	lock.Lock()
	defer lock.Unlock()

	u, err := s.loadUpload(caseID, uploadID)
	if err != nil {
		return err
	}
	if u.Status == model.UploadConsumed {
		return store.ErrUploadClosed
	}
	if err := s.store.SetUploadStatus(uploadID, model.UploadAborted, time.Now().UTC()); err != nil {
		return err
	}
	_ = os.Remove(s.files.UploadSessionPath(caseID, uploadID))
	return nil
}

// PurgeStaleUploads reclaims the bytes of open sessions that have not
// been written to for maxAge, and returns how many it discarded. An
// abandoned multi-gigabyte upload would otherwise hold its disk space
// forever.
func (s *Service) PurgeStaleUploads(maxAge time.Duration) (int, error) {
	stale, err := s.store.ListStaleOpenUploads(time.Now().UTC().Add(-maxAge))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range stale {
		lock := s.pipe.uploads.get(u.ID)
		lock.Lock()
		err := s.store.SetUploadStatus(u.ID, model.UploadAborted, time.Now().UTC())
		if err == nil {
			_ = os.Remove(s.files.UploadSessionPath(u.CaseID, u.ID))
			n++
		}
		lock.Unlock()
		s.pipe.uploads.forget(u.ID)
	}
	return n, nil
}
