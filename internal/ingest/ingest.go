// Package ingest walks a KAPE-like evidence directory, detects which
// parser (if any) handles each file, and assembles the parsed output into
// case-scoped SourceFile/Event/RawEvidence records ready for storage.
// This is the only place parser output gets IDs and a CaseID stamped onto
// it -- parsers themselves stay case-agnostic and storage-agnostic.
//
// Discovery and parsing are deliberately separate operations (see
// Discover and ParseFile below): internal/api.Service catalogs every file
// in a newly-added evidence package as soon as it's discovered, before
// parsing anything, so an investigator can select exactly which files
// become evidence -- see docs/data-model.md's "Evidence selection
// workflow" section for why.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"tracefall/internal/browsercache"
	"tracefall/internal/browserdb"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/activitiescache"
	"tracefall/internal/parsers/authlog"
	"tracefall/internal/parsers/bashhistory"
	browsercacheparser "tracefall/internal/parsers/browsercache"
	browsercacheindexparser "tracefall/internal/parsers/browsercacheindex"
	"tracefall/internal/parsers/browserhistory"
	evtxnative "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
	filezillaparser "tracefall/internal/parsers/filezilla"
	imageparser "tracefall/internal/parsers/image"
	"tracefall/internal/parsers/journal"
	jumplistparser "tracefall/internal/parsers/jumplist"
	lnkparser "tracefall/internal/parsers/lnk"
	"tracefall/internal/parsers/logfile"
	"tracefall/internal/parsers/mft"
	"tracefall/internal/parsers/netcapture"
	"tracefall/internal/parsers/packagelog"
	"tracefall/internal/parsers/pecmd"
	"tracefall/internal/parsers/prefetchraw"
	"tracefall/internal/parsers/pshistory"
	"tracefall/internal/parsers/recmd"
	recyclebinparser "tracefall/internal/parsers/recyclebin"
	recyclebincontentparser "tracefall/internal/parsers/recyclebincontent"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/parsers/scheduledtasks"
	"tracefall/internal/parsers/syslog"
	"tracefall/internal/parsers/usnjrnl"
	"tracefall/internal/parsers/volatility"
	"tracefall/internal/parsers/webaccess"
	"tracefall/internal/parsers/wtmp"
	"tracefall/internal/regf"
)

// Registry is the ordered list of known artifact parsers. Adding support
// for a new KAPE artifact means writing a parsers.ArtifactParser
// implementation and appending it here; ingestion, detection, and storage
// all work unmodified.
func Registry() []parsers.ArtifactParser {
	return []parsers.ArtifactParser{
		evtxcsv.New(),
		pecmd.New(),
		recmd.New(),
		scheduledtasks.New(),
		// Phase 9: native Windows artifacts. Ordered after the EZ Tools
		// CSV parsers so a KAPE collection containing both an EvtxECmd
		// export and the .evtx it came from classifies each by its own
		// most specific match. Both of these also implement
		// parsers.ContentDetector, so they still find a hive or an event
		// log that arrives under an unrecognized name.
		evtxnative.New(),
		registry.New(),
		// Phase 10A. Ordered after the EZ Tools CSV parsers for the same
		// reason: a collection holding both PECmd output and the .pf it
		// came from classifies each by its own most specific match.
		prefetchraw.New(),
		pshistory.New(),
		// Linux shell and login records. Both are recognised by file name
		// only; neither format has a signature that is safe to sniff.
		bashhistory.New(),
		wtmp.New(),
		authlog.New(),
		syslog.New(),
		journal.New(),
		// Package and web server logs. dpkg.log is name-only. The access
		// log is claimed by name, and also by the layout of its first
		// line, so a renamed log is still found while no other text file
		// is mistaken for one.
		packagelog.New(),
		webaccess.New(),
		// Packet captures: claimed by extension and confirmed by their magic
		// number, and also found by magic number under any name.
		netcapture.New(),
		// Roadmap item 4: the combined Volatility output for a memory
		// image. Detected by its fixed name and confirmed by its schema
		// marker, so nothing else can be claimed as one.
		volatility.New(),
		browserhistory.New(),
		// Phase 16: Windows Timeline. Registered AFTER the browser
		// parsers: its content detector can only see the SQLite
		// signature on a 512-byte header, so it must never pre-empt a
		// parser whose database it would otherwise claim. The real check
		// is the schema, which Parse performs -- a SQLite file that is
		// not a Timeline database is reported as not-this-artifact.
		activitiescache.New(),
		// Phase 15: NTFS $MFT. Ordered last among the native parsers
		// because its content detector is the broadest -- it must not
		// pre-empt a more specific match on a file that merely happens
		// to begin with a plausible record header.
		mft.New(),
		// Phase 16: the other two NTFS metadata structures. Each has a
		// reserved name and a structural sniff of its own, so none of
		// the three can claim another's file.
		usnjrnl.New(),
		logfile.New(),
		// Phase 14: browser HTTP cache. Registered LAST because these
		// two detect almost entirely by content -- they must never
		// pre-empt a parser whose filename match is more specific.
		//
		// The container parser comes FIRST of the two: a blockfile index
		// and a cache1 map describe a cache rather than holding an
		// entry, and only it accepts them. The entry parser rejects both
		// by name in its own error, so the order is belt and braces
		// rather than a dependency.
		browsercacheindexparser.New(),
		browsercacheparser.New(),
		// Phase 17: shortcuts and Recycle Bin metadata. Both detect
		// purely by content -- neither claims a filename -- so their
		// position here only guarantees they never pre-empt a parser
		// whose match is more specific.
		lnkparser.New(),
		recyclebinparser.New(),
		// The $R half of a Recycle Bin pair. Registered AFTER the $I
		// parser: $I is content-detected and $R is claimed by name, so
		// the more specific check runs first and a mislabelled file
		// cannot be taken for the wrong half of the pair.
		recyclebincontentparser.New(),
		// Phase 21: Jump Lists. Registered after the shortcut parser so
		// a standalone .lnk is never mistaken for a container, and it
		// detects by container structure as well as by extension, which
		// is what finds a renamed Jump List.
		jumplistparser.NewAutomatic(),
		jumplistparser.NewCustom(),
		// Phase 20: FileZilla connection files. Name-detected with a
		// content confirmation, and content-detected as well, so a
		// recentservers.xml found under any name is still claimed while
		// an unrelated file merely NAMED recentservers.xml is not.
		filezillaparser.New(),
		// Phase 20: image metadata. Registered LAST of every parser
		// because its content detector is the broadest of all -- a JPEG
		// signature says only "this is a picture", and any file whose
		// bytes a more specific parser can identify must be claimed by
		// that parser first.
		imageparser.New(),
	}
}

// DiscoveredFile is one file found while cataloging an evidence root --
// classified and hashed, but not yet parsed. See Discover.
type DiscoveredFile struct {
	Path         string // relative to the evidence root, forward-slash
	OriginalName string // basename
	ArtifactType string // "" if no parser recognizes this file
	Parser       string // "" if no parser recognizes this file
	Supported    bool
	SizeBytes    int64
	SHA256       string
}

// Discover walks every regular file under root and classifies each one
// against the parser registry (first match wins), without parsing any of
// them. This is the first phase of adding evidence: it produces the
// catalog an investigator selects from (see internal/api.Service's
// discovery methods) -- Parse/import happens later, only for the files
// actually selected, via ParseFile.
func Discover(root string, registry []parsers.ArtifactParser) ([]DiscoveredFile, error) {
	var out []DiscoveredFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)

		// The header is read once and reused: a name match that needs
		// confirming and content-based detection both want it, and
		// discovery runs over every file in a triage collection.
		header := readHeader(path, parsers.SniffLength)

		var matched parsers.ArtifactParser
		for _, p := range registry {
			if !p.Detect(relPath) {
				continue
			}
			// A parser may require its name match to be backed by the
			// bytes. See parsers.ContentConfirmer: this is what stops a
			// text file called SAM being claimed as a registry hive and
			// then reported as a broken one.
			if cc, ok := p.(parsers.ContentConfirmer); ok && len(header) > 0 && !cc.ConfirmContent(header) {
				continue
			}
			matched = p
			break
		}
		// Nothing recognized the name. Native Windows artifacts are
		// identified by content instead -- a hive copied out of a triage
		// image may be called anything, and a .evtx extension proves
		// nothing about what is inside. See parsers.ContentDetector.
		var recognized string
		if matched == nil {
			if len(header) > 0 {
				for _, p := range registry {
					if !contentDetectionApplies(p, relPath) {
						continue
					}
					if cd, ok := p.(parsers.ContentDetector); ok && cd.DetectContent(header) {
						matched = p
						break
					}
				}
				// Still unclaimed. Before giving up, ask what the bytes
				// ARE. A cache directory is full of rankings, payload
				// blocks, journals and bodies that no parser will ever
				// claim and that are not broken evidence -- recognizing
				// each one lets triage explain it instead of reporting
				// them all identically. See browsercache.RecognizeUnparsed.
				if matched == nil {
					recognized = recognizeUnparsed(relPath, header)
				}
			}
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		df := DiscoveredFile{
			Path:         relPath,
			OriginalName: filepath.Base(relPath),
			SizeBytes:    info.Size(),
			SHA256:       sha256File(path),
		}
		if matched != nil {
			df.ArtifactType = matched.ArtifactType()
			df.Parser = matched.Name()
			df.Supported = true
		} else if recognized != "" {
			// Recognized, deliberately NOT supported: knowing what a file
			// is does not mean it can be parsed into forensic records,
			// and the supported count must keep meaning exactly that.
			df.ArtifactType = recognized
		}
		out = append(out, df)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ingest: discovering %s: %w", root, err)
	}
	return out, nil
}

// recognizeUnparsed maps a structural recognition onto the model's
// recognition-only artifact types.
//
// It runs only for files no parser claimed, and only ever produces types
// that are never Supported. Nothing here changes what is parsed; it
// changes what an analyst is told about what is not.
// RecognizeUnparsed names a file no parser claimed, so triage can
// explain it instead of listing it as an anonymous unsupported blob.
//
// Exported for the same reason MatchParser is: there is more than one
// way into Tracefall, and a file that is "a registry transaction log"
// from a folder must not be "unrecognized" from an AD1 image.
//
// Recognizing is NOT parsing. Everything named here is catalogued as
// present and explicitly unsupported; no event, timestamp or value is
// produced from any of it.
func RecognizeUnparsed(relPath string, header []byte) string {
	return recognizeUnparsed(relPath, header)
}

func recognizeUnparsed(relPath string, header []byte) string {
	// A registry TRANSACTION LOG is a REGF file with the hive signature
	// and a different base-block file type. Recognized here so it is
	// catalogued as what it is instead of being claimed as a hive and
	// then failed at import. See regf.SniffTransactionLog.
	if regf.SniffTransactionLog(header) {
		return model.ArtifactRegistryTransactionLog
	}

	// A browser-related SQLite database that is not history. Recognized
	// rather than claimed, so it stops being reported as broken browser
	// history. See internal/browserdb.
	if k := browserdb.Recognize(relPath, browserhistory.IsSQLite(header)); k != browserdb.KindNone {
		return model.ArtifactUnsupportedBrowserDB
	}

	lower := strings.ToLower(relPath)
	if !browsercache.InCacheDirectory("/" + lower) {
		return ""
	}
	base := path.Base(lower)

	switch r := browsercache.RecognizeUnparsed(base, header); r {
	case browsercache.RecognizedBlockfileRankings:
		return model.ArtifactBrowserCacheRankings
	case browsercache.RecognizedBlockfilePayload:
		return model.ArtifactBrowserCachePayload
	case browsercache.RecognizedNone:
		// fall through to the name-defined classes below
	default:
		if r.IsVariant() {
			return model.ArtifactBrowserCacheVariant
		}
		return model.ArtifactBrowserCacheAuxiliary
	}

	// The bytes settled nothing. Two classes of cache file carry no
	// signature at all and are identified by the exact filenames their
	// formats define -- a cached response body, and a cache's own
	// bookkeeping. Both are checked only INSIDE a cache directory, and
	// both use exact names rather than patterns, so a file that merely
	// resembles one elsewhere is never claimed.
	if isCachedBodyName(base) {
		return model.ArtifactBrowserCacheBody
	}
	if isCacheStateName(base) {
		return model.ArtifactBrowserCacheState
	}
	// Nothing settled it here. Deliberately NOT reporting "unknown":
	// the capability registry still has path rules for the cache files
	// that carry no signature at all, and returning a recognition now
	// would pre-empt them. Its generic fallback is the last word.
	return ""
}

// isCachedBodyName matches a Chromium blockfile external body file:
// f_ followed by exactly six hexadecimal digits, and nothing else.
func isCachedBodyName(base string) bool {
	if len(base) != 8 || !strings.HasPrefix(base, "f_") {
		return false
	}
	for i := 2; i < 8; i++ {
		c := base[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isCacheStateName matches the bookkeeping files browsers write beside
// their caches. Exact names only.
func isCacheStateName(base string) bool {
	switch base {
	case "lock", ".lock", "parent.lock", "journal", "index.log", "index.tmp",
		"temp-index", "index-dir", "context.tmp", "cache_dir_lock":
		return true
	}
	return false
}

// ParsedFile is the result of parsing exactly one already-discovered
// file -- the events/raw records it produced, ready for deduplication
// and storage.
type ParsedFile struct {
	Events []model.Event
	Raw    []model.RawEvidence
}

// MatchParser decides which parser, if any, owns a file. It is the
// SINGLE place that decision is made, because there is more than one way
// into Tracefall -- a directory or ZIP walked by Discover, and an AD1
// image catalogued entry by entry (internal/api's catalogAD1) -- and the
// two answering differently is a bug an analyst experiences as "the same
// hive is evidence from a folder and unsupported from an image".
//
// The order is: name match, confirmed against the bytes where the parser
// asks for that, then content match.
//
//   - A name match alone is right for the EZ Tools CSVs, whose filenames
//     are produced by the tool itself.
//   - A name match that must be CONFIRMED is right for the native hives:
//     "SAM", "SYSTEM" and "NTUSER.DAT" are ordinary words, and a text
//     file carrying one is not a hive. See parsers.ContentConfirmer.
//   - A content match catches everything renamed -- a hive copied out of
//     a triage image may be called anything, and a .evtx extension
//     proves nothing about what is inside. See parsers.ContentDetector.
//
// header may be empty (nothing could be read), in which case only
// unconfirmed name matches can apply.
func MatchParser(relPath string, header []byte, registry []parsers.ArtifactParser) parsers.ArtifactParser {
	for _, p := range registry {
		if !p.Detect(relPath) {
			continue
		}
		if cc, ok := p.(parsers.ContentConfirmer); ok && len(header) > 0 && !cc.ConfirmContent(header) {
			continue
		}
		return p
	}
	if len(header) == 0 {
		return nil
	}
	for _, p := range registry {
		if !contentDetectionApplies(p, relPath) {
			continue
		}
		if cd, ok := p.(parsers.ContentDetector); ok && cd.DetectContent(header) {
			return p
		}
	}
	return nil
}

// contentDetectionApplies asks a parser whether its CONTENT detector
// should be consulted for this path at all. See
// parsers.PathScopedDetector: a signature can identify a format
// correctly and still be the wrong answer about the artifact, and a
// parser whose detector is that broad scopes itself here rather than
// having ingestion carry a list of exceptions.
//
// A parser that does not implement the interface is always consulted,
// which is every parser that existed before this was added.
func contentDetectionApplies(p parsers.ArtifactParser, relPath string) bool {
	ps, ok := p.(parsers.PathScopedDetector)
	return !ok || ps.DetectPath(relPath)
}

// ParseFile parses one file at root/relPath with p, stamping every
// resulting Event/RawEvidence with caseID/collectionID/sourceFileID.
//
// It deliberately does NOT fill in a missing Host. Some artifact formats
// (Prefetch, registry hives) never record a hostname at all, so their
// events arrive here blank -- but this function only ever sees ONE file,
// which is not enough context to resolve that correctly: the host is
// usually only knowable from a sibling file in the same collection (an
// EvtxECmd CSV, say). Deciding it here would make the result depend on
// which file happened to be parsed first. Host resolution is therefore
// the ingestion/service layer's job, done once per import batch over the
// complete picture -- see internal/api.Service.enrichBatchHosts.
func ParseFile(caseID, collectionID, sourceFileID, root, relPath string, p parsers.ArtifactParser) (ParsedFile, error) {
	return ParseFileWithContext(caseID, collectionID, sourceFileID, root, relPath, p, parsers.ParseContext{})
}

// ParseFileWithContext is ParseFile plus collection-scoped context (see
// parsers.ParseContext). A parser that does not implement
// parsers.ContextualParser is called exactly as ParseFile calls it, so
// passing context is free for every parser that has no use for it.
func ParseFileWithContext(caseID, collectionID, sourceFileID, root, relPath string, p parsers.ArtifactParser, ctx parsers.ParseContext) (ParsedFile, error) {
	abs := filepath.Join(root, filepath.FromSlash(relPath))
	// Keep evidence-relative identity separate from the absolute server
	// path used to open the artifact.
	ctx.EvidencePath = filepath.ToSlash(relPath)

	// In-process by default; the server runs each parse in a child process.
	parsed, err := runner.Run(p, root, abs, ctx)
	if err != nil {
		return ParsedFile{}, err
	}

	events := make([]model.Event, len(parsed.Events))
	raw := make([]model.RawEvidence, 0, len(parsed.Raw))
	for i := range parsed.Events {
		ev := parsed.Events[i]
		ev.ID = uuid.NewString()
		ev.CaseID = caseID
		ev.CollectionID = collectionID
		ev.SourceFileID = sourceFileID

		if i < len(parsed.Raw) {
			r := parsed.Raw[i]
			r.ID = uuid.NewString()
			r.CaseID = caseID
			r.SourceFileID = sourceFileID
			ev.RawEvidenceID = r.ID
			raw = append(raw, r)
		}
		events[i] = ev
	}

	// Raw evidence a parser produced BEYOND its events is carried through
	// rather than discarded.
	//
	// The loop above pairs raw[i] to events[i] positionally, which is the
	// contract Service.deduplicate also relies on. Anything past that
	// index used to be dropped silently -- which meant a parser's own
	// analysis report was lost, and a parser that legitimately produces
	// NO events (internal/parsers/logfile validates the NTFS transaction
	// log and deliberately emits no timeline entries) had all of its
	// output discarded.
	//
	// These records carry no RawEvidenceID on any event; they belong to
	// the SOURCE FILE, which is what raw_evidence.source_file_id has
	// always recorded. Appending them AFTER the paired ones keeps every
	// index below len(events) exactly where it was, so the positional
	// contract is untouched.
	for i := len(events); i < len(parsed.Raw); i++ {
		r := parsed.Raw[i]
		r.ID = uuid.NewString()
		r.CaseID = caseID
		r.SourceFileID = sourceFileID
		raw = append(raw, r)
	}
	return ParsedFile{Events: events, Raw: raw}, nil
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readHeader reads up to n leading bytes of a file for content sniffing.
// A file that cannot be opened simply yields no header and stays
// unclassified, which is the same outcome as not matching -- discovery
// must not fail a whole collection over one unreadable file.
func readHeader(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if read == 0 && err != nil {
		return nil
	}
	return buf[:read]
}
