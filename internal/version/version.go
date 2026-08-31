// Package version holds the single source of truth for what build of
// Tracefall is running.
//
// Provenance needs it: an exported case, an analysis run and an
// integrity verification each record which build produced them, so a
// reviewer reading the export a year later can tell whether it came
// from a build whose parsers, detection rules or hashing they trust.
// Without it, "Tracefall produced this" names no particular software.
//
// It is a plain constant rather than a linker-injected variable. A
// value stamped at link time would be absent from `go run`, `go test`
// and any build that forgot the ldflags -- and provenance metadata that
// is sometimes empty is worse than provenance that is always honest
// about what it is. Bump it deliberately, in the same commit as the
// behaviour it describes.
package version

// Version is the running build's version.
//
// Phase numbering rather than semver: Tracefall is developed in
// numbered phases, each of which changes what the tool can prove, and
// naming the phase is more informative to a forensic reviewer than an
// invented release number would be.
const Version = "0.11.0-phase11"

// Name is the product name recorded alongside Version, so an export
// identifies its producer without the reader having to infer it from
// the surrounding JSON shape.
const Name = "Tracefall"

// String is the form recorded in exports and audit summaries.
func String() string { return Name + " " + Version }
