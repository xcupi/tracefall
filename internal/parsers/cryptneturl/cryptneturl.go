// Package cryptneturl reads the CryptoAPI URL cache metadata
// (CryptnetUrlCache\\MetaData\\<hash>).
//
// Windows keeps one entry for every URL it retrieves while validating a
// certificate (revocation lists, OCSP, trust lists), and certutil -urlcache -f
// keeps one for every file it downloads. An entry therefore proves that a URL
// was retrieved and when. It does not name the program that asked, and in
// ordinary use nearly every entry is Windows validating a certificate; the value
// of the artifact is the entry that is not.
//
// The layout is the one published by Abdulrhman Alfaifi (the CryptnetURLCache
// parser, and the Velociraptor Windows.Forensics.CertUtil artifact, which agree):
// urlSize at 12, the last download FILETIME at 16, the response's Last-Modified
// FILETIME at 88, the ETag size at 100, the downloaded file's size at 112, then
// the URL and the ETag in UTF-16LE. The rest of the header is not interpreted.
// Every offset and size is bounds-checked; an entry whose parts do not account
// for the whole file is reported as not verified instead of being trusted.
package cryptneturl

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "cryptneturl@1"

const (
	headerLen       = 116
	maxEntryBytes   = 1 << 20
	maxURLBytes     = 16 << 10
	maxETagBytes    = 4 << 10
	maxHashContent  = 64 << 20
	maxRawBytes     = 8 << 10
	filetimeEpochNs = 116444736000000000
)

var nameRe = regexp.MustCompile(`(?i)^[0-9a-f]{32}(?:_[0-9a-f]{32})?$`)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactCryptnetURLCache }

// Detect claims the metadata files by their folder and name. The Content folder
// holds the cached objects themselves and is not an artifact record.
func (Parser) Detect(relPath string) bool {
	p := strings.ToLower(strings.ReplaceAll(relPath, `\`, "/"))
	return strings.Contains(p, "/cryptneturlcache/metadata/") && nameRe.MatchString(filepath.Base(p))
}

// DetectContent claims nothing: the header has no signature of its own.
func (Parser) DetectContent([]byte) bool { return false }

// ConfirmContent checks what a name-claimed file must look like: the 0x70 at the
// start and a URL (UTF-16) with a scheme where the layout says it begins.
func (Parser) ConfirmContent(header []byte) bool {
	if len(header) < headerLen+8 || binary.LittleEndian.Uint32(header[0:4]) != 0x70 {
		return false
	}
	n := binary.LittleEndian.Uint32(header[12:16])
	if n < 4 || n%2 != 0 || n > maxURLBytes {
		return false
	}
	scheme := make([]byte, 0, 12)
	for i := headerLen; i+1 < len(header) && i < headerLen+24; i += 2 {
		if header[i+1] != 0 {
			return false
		}
		scheme = append(scheme, header[i])
	}
	return regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{1,9}://`).Match(scheme)
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

func (Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEntryBytes+1))
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if len(b) > maxEntryBytes {
		return parsers.ParseResult{}, fmt.Errorf("cryptneturl: entry larger than %d bytes", maxEntryBytes)
	}
	if len(b) < headerLen || binary.LittleEndian.Uint32(b[0:4]) != 0x70 {
		return parsers.ParseResult{}, fmt.Errorf("cryptneturl: not a CryptoAPI URL cache entry")
	}
	urlSize := binary.LittleEndian.Uint32(b[12:16])
	hashSize := binary.LittleEndian.Uint32(b[100:104])
	if urlSize < 2 || urlSize%2 != 0 || urlSize > maxURLBytes || hashSize%2 != 0 || hashSize > maxETagBytes ||
		uint64(headerLen)+uint64(urlSize)+uint64(hashSize) > uint64(len(b)) {
		return parsers.ParseResult{}, fmt.Errorf("cryptneturl: the URL and ETag sizes do not fit the file")
	}
	urlBytes := b[headerLen : headerLen+int(urlSize)]
	etagBytes := b[headerLen+int(urlSize) : headerLen+int(urlSize)+int(hashSize)]
	url, urlTerminated := utf16String(urlBytes)
	etag, etagTerminated := utf16String(etagBytes)
	verified := headerLen+int(urlSize)+int(hashSize) == len(b) && urlTerminated && (hashSize == 0 || etagTerminated)

	name := filepath.Base(absPath)
	extra := map[string]string{
		"url":             url,
		"url_host":        hostOf(url),
		"file_size":       strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[112:116])), 10),
		"entry_id":        name,
		"layout_verified": strconv.FormatBool(verified),
		"records_cause":   "false: an entry shows that Windows' CryptoAPI retrieved this URL (certificate validation, or certutil -urlcache); it does not name the program that asked",
	}
	if e := strings.Trim(etag, `"`); e != "" {
		extra["etag"] = e
	}
	if !verified {
		extra["layout_note"] = fmt.Sprintf("the parts account for %d of %d bytes or the URL or ETag is not terminated; nothing beyond the URL and ETag was interpreted", headerLen+int(urlSize)+int(hashSize), len(b))
	}
	if t, ok := fileTime(binary.LittleEndian.Uint64(b[88:96])); ok {
		extra["last_modified_header"] = t.Format("2006-01-02T15:04:05Z")
	}
	if p := strings.ToLower(strings.ReplaceAll(ctx.EvidencePath, `\`, "/")); strings.Contains(p, "systemprofile") {
		extra["cache_profile"] = "systemprofile"
	} else if u := userFromPath(ctx.EvidencePath); u != "" {
		extra["cache_profile"] = u
	}
	content(absPath, name, binary.LittleEndian.Uint32(b[112:116]), extra)

	ts, known := fileTime(binary.LittleEndian.Uint64(b[16:24]))
	if !known {
		extra["timestamp_known"] = "false"
	}
	ref := "entry:" + name
	ev := model.Event{
		Timestamp: ts, EventType: model.EventCryptoURLRetrieval, ArtifactType: model.ArtifactCryptnetURLCache,
		Parser: parserName, FilePath: name, SourceReference: ref, Confidence: 0.9, Extra: extra,
	}
	raw := b
	if len(raw) > maxRawBytes {
		raw = raw[:maxRawBytes]
	}
	return parsers.ParseResult{Events: []model.Event{ev}, Raw: []model.RawEvidence{{SourceReference: ref, Raw: hex.EncodeToString(raw)}}}, nil
}

// content records what the cached object is, from the sibling Content folder.
func content(metaPath, name string, recorded uint32, extra map[string]string) {
	dir := findFold(filepath.Dir(filepath.Dir(metaPath)), "Content")
	if dir == "" {
		extra["content_present"] = "false"
		return
	}
	cp := filepath.Join(dir, name)
	st, err := os.Lstat(cp)
	if err != nil || !st.Mode().IsRegular() {
		extra["content_present"] = "false"
		return
	}
	extra["content_present"] = "true"
	extra["content_size"] = strconv.FormatInt(st.Size(), 10)
	extra["content_size_matches"] = strconv.FormatBool(st.Size() == int64(recorded))
	if st.Size() == 0 {
		return
	}
	f, err := os.Open(cp)
	if err != nil {
		return
	}
	defer f.Close()
	head := make([]byte, 64)
	n, _ := io.ReadFull(f, head)
	extra["content_magic"] = magic(head[:n])
	if st.Size() <= maxHashContent {
		h := sha256.New()
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			if _, err := io.Copy(h, f); err == nil {
				extra["content_sha256"] = hex.EncodeToString(h.Sum(nil))
			}
		}
	}
}

// magic names the kind of a cached object from its first bytes.
func magic(h []byte) string {
	has := func(p string) bool { return len(h) >= len(p) && string(h[:len(p)]) == p }
	switch {
	case has("MZ"):
		return "pe"
	case has("PK\x03\x04"), has("PK\x05\x06"):
		return "zip"
	case has("7z\xbc\xaf\x27\x1c"):
		return "7z"
	case has("Rar!"):
		return "rar"
	case has("MSCF"):
		return "cab"
	case has("\x7fELF"):
		return "elf"
	case has("%PDF"):
		return "pdf"
	case len(h) >= 2 && h[0] == 0x30 && (h[1] == 0x82 || h[1] == 0x81 || h[1] == 0x83 || h[1] < 0x80):
		return "der"
	}
	for _, c := range h {
		if c != '\r' && c != '\n' && c != '\t' && (c < 0x20 || c > 0x7e) {
			return "unknown"
		}
	}
	return "text"
}

func utf16String(b []byte) (string, bool) {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	terminated := len(u) > 0 && u[len(u)-1] == 0
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u)), terminated
}

// fileTime converts a FILETIME, treating zero and implausible years as absent.
func fileTime(v uint64) (time.Time, bool) {
	if v == 0 || v < filetimeEpochNs {
		return time.Time{}, false
	}
	t := time.Unix(0, (int64(v)-filetimeEpochNs)*100).UTC()
	if t.Year() < 1995 || t.Year() > 2100 {
		return time.Time{}, false
	}
	return t, true
}

func hostOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	h := u[i+3:]
	if j := strings.IndexAny(h, "/?#"); j >= 0 {
		h = h[:j]
	}
	if k := strings.LastIndexByte(h, '@'); k >= 0 {
		h = h[k+1:]
	}
	return h
}

func userFromPath(p string) string {
	parts := strings.Split(strings.ReplaceAll(p, `\`, "/"), "/")
	for i, s := range parts {
		if strings.EqualFold(s, "Users") && i+1 < len(parts) {
			n := parts[i+1]
			if !strings.EqualFold(n, "Public") && !strings.EqualFold(n, "Default") {
				return n
			}
		}
	}
	return ""
}

// findFold returns the entry of dir named like want without regard to case.
func findFold(dir, want string) string {
	es, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range es {
		if e.IsDir() && strings.EqualFold(e.Name(), want) {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}
