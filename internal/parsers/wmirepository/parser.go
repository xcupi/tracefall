// Package wmirepository normalizes selected native WMI snapshot objects.
package wmirepository

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/wmirepo"
)

type Parser struct{}

func New() *Parser                  { return &Parser{} }
func (Parser) Name() string         { return "wmirepository@1" }
func (Parser) ArtifactType() string { return model.ArtifactWMIRepository }
func (Parser) Detect(p string) bool {
	return strings.EqualFold(path.Base(strings.ReplaceAll(p, `\`, "/")), "OBJECTS.DATA")
}
func (Parser) Parse(string) (parsers.ParseResult, error) {
	return parsers.ParseResult{}, wmirepo.ErrMissingBundle
}
func (Parser) ParseWithContext(abs string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	result := parsers.ParseResult{}
	if !filepath.IsAbs(ctx.EvidenceRoot) || len(ctx.BundleFiles) < 3 || len(ctx.BundleFiles) > 5 {
		return result, wmirepo.ErrMissingBundle
	}
	files := map[string]wmirepo.File{}
	members := map[string]parsers.BundleFile{}
	paths := map[string]bool{}
	for _, member := range ctx.BundleFiles {
		if !wmirepo.BundleRole(member.Role) || member.SourceFileID == "" || paths[member.Path] {
			return result, wmirepo.ErrMissingBundle
		}
		if _, ok := members[member.Role]; ok {
			return result, wmirepo.ErrMissingBundle
		}
		if member.Role == "OBJECTS.DATA" && (member.Path != ctx.EvidencePath || filepath.Clean(abs) != filepath.Join(ctx.EvidenceRoot, filepath.FromSlash(member.Path))) {
			return result, wmirepo.ErrMissingBundle
		}
		f, err := openMember(ctx.EvidenceRoot, member.Path)
		if err != nil {
			return result, err
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			return result, wmirepo.ErrMissingBundle
		}
		files[member.Role] = wmirepo.File{Reader: f, Size: stat.Size()}
		members[member.Role] = member
		paths[member.Path] = true
	}
	decoded, err := wmirepo.ReadBundle(files)
	if err != nil {
		return result, err
	}
	h := sha256.New()
	for _, f := range decoded.Files {
		member := members[f.Name]
		if member.SHA256 != "" && member.SHA256 != f.SHA256 {
			return result, fmt.Errorf("%w: admitted bundle digest mismatch", wmirepo.ErrCorrupt)
		}
		fmt.Fprintf(h, "%s\x00%s\x00", f.Name, f.SHA256)
	}
	repositoryID := fmt.Sprintf("%x", h.Sum(nil))
	scope := wmirepo.Scope{CaseID: "bundle-local", CollectionID: "bundle-local", RepositoryID: repositoryID}
	objects := []wmirepo.ScopedObject{}
	for _, o := range decoded.Snapshot.Objects {
		ns := strings.SplitN(o.NativeKey, "/", 2)[0]
		objects = append(objects, wmirepo.ScopedObject{Scope: scope, NamespaceID: ns, NativeKey: o.NativeKey, Class: o.Class, Keys: o.KeyProperties})
	}
	for _, o := range decoded.Snapshot.Objects {
		ns := strings.SplitN(o.NativeKey, "/", 2)[0]
		extra := map[string]string{"wmi_class": o.Class, "wmi_namespace_id": ns, "wmi_native_key": o.NativeKey, "wmi_repository_sha256": repositoryID, "wmi_record_sha256": o.Record.SHA256, "wmi_property_count": strconv.Itoa(len(o.Properties)), "timestamp_basis": "undated configuration snapshot; repository FILETIMEs retained only as metadata in raw evidence", "wmi_semantics": "configuration only; no firing, execution, actor, maliciousness or authorization established"}
		if o.Class == "__FilterToConsumerBinding" {
			for _, role := range []string{"Filter", "Consumer"} {
				v, ok := o.Properties[role]
				literal, isString := v.Value.(string)
				resolved := wmirepo.ReferenceResolution{Status: "unresolved", Reason: "reference_unavailable"}
				if ok && isString && v.Presence != "uninitialized" {
					resolved = wmirepo.ResolveReference(literal, ns, scope, objects)
				}
				prefix := strings.ToLower(role)
				extra[prefix+"_reference_status"] = resolved.Status
				extra[prefix+"_reference_reason"] = resolved.Reason
				if resolved.TargetNativeKey != "" {
					extra[prefix+"_native_key"] = resolved.TargetNativeKey
				}
			}
		}
		ref := o.NativeKey
		raw, err := json.Marshal(struct {
			Object            wmirepo.Instance
			Members           []parsers.BundleFile
			Files             []wmirepo.FileDigest
			MappingName       string
			MappingGeneration uint32
		}{o, ctx.BundleFiles, decoded.Files, decoded.MappingName, decoded.MappingGeneration})
		if err != nil {
			return parsers.ParseResult{}, err
		}
		result.Events = append(result.Events, model.Event{EventType: model.EventWMISnapshot, ArtifactType: model.ArtifactWMIRepository, Parser: "wmirepository@1", SourceReference: ref, Extra: extra})
		result.Raw = append(result.Raw, model.RawEvidence{SourceReference: ref, Raw: string(raw)})
	}
	n := len(result.Events)
	result.Coverage = &model.ParseCoverage{RecordsRead: n, Mapped: n, Undated: n, EmittedEvents: &n, Notes: []string{"Active indexed instances of seven selected standard classes only; no deleted carving, firing or OS execution evidence.", "Namespace literals are not resolved: all present active namespace IDs are enumerated and retained as hash IDs.", "Configuration values, exact keys, commands/scripts/SIDs and raw FILETIME metadata remain in authorized raw evidence; default projections are structural only."}}
	unavailable := 0
	for _, c := range decoded.Snapshot.Coverage {
		if c.Status == "schema_unavailable" {
			unavailable++
		}
	}
	result.Coverage.Notes = append(result.Coverage.Notes, fmt.Sprintf("Namespace IDs: %d; selected-class namespace combinations without available schema: %d. Missing schema for present indexed instances fails the source, never a successful zero.", len(decoded.Snapshot.NamespaceIDs), unavailable))
	return result, nil
}
