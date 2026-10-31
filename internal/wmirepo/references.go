package wmirepo

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Reference is a bounded WMI object path. Literal string keys are never
// normalized or unescaped twice. Resolution may still abstain on host scope.
type Reference struct {
	Host, Namespace, Class string
	Keys                   map[string]string
}

func identifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func ParseReference(raw string) (Reference, error) {
	out := Reference{Keys: map[string]string{}}
	bad := func() (Reference, error) { return Reference{}, fmt.Errorf("%w: WMI reference grammar", ErrUnsupported) }
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.IndexFunc(raw, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return bad()
	}
	rest := raw
	if strings.HasPrefix(rest, `\\`) {
		rest = rest[2:]
		at := strings.IndexByte(rest, '\\')
		if at < 1 {
			return bad()
		}
		out.Host = rest[:at]
		rest = rest[at+1:]
		for _, c := range out.Host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return bad()
			}
		}
	}
	// Namespace separators precede the class/key delimiter; colons in quoted
	// key strings must not be mistaken for a namespace qualifier.
	dot := strings.IndexByte(rest, '.')
	colon := strings.IndexByte(rest, ':')
	if colon >= 0 && (dot < 0 || colon < dot) {
		out.Namespace = rest[:colon]
		rest = rest[colon+1:]
		for _, part := range strings.Split(out.Namespace, `\`) {
			if !identifier(part) {
				return bad()
			}
		}
	} else if out.Host != "" {
		return bad()
	}
	dot = strings.IndexByte(rest, '.')
	if dot < 1 {
		return bad()
	}
	out.Class = rest[:dot]
	rest = rest[dot+1:]
	if !identifier(out.Class) {
		return bad()
	}
	seen := map[string]bool{}
	for {
		eq := strings.IndexByte(rest, '=')
		if eq < 1 || len(out.Keys) >= 16 {
			return bad()
		}
		key := rest[:eq]
		if !identifier(key) || seen[strings.ToLower(key)] {
			return bad()
		}
		seen[strings.ToLower(key)] = true
		rest = rest[eq+1:]
		if !strings.HasPrefix(rest, `"`) {
			return bad()
		}
		rest = rest[1:]
		var value strings.Builder
		closed := false
		for len(rest) > 0 {
			c := rest[0]
			rest = rest[1:]
			if c == '"' {
				closed = true
				break
			}
			if c == '\\' {
				if len(rest) == 0 || rest[0] != '\\' && rest[0] != '"' {
					return bad()
				}
				c = rest[0]
				rest = rest[1:]
			}
			value.WriteByte(c)
		}
		if !closed {
			return bad()
		}
		out.Keys[key] = value.String()
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return bad()
		}
		rest = rest[1:]
		if rest == "" {
			return bad()
		}
	}
	return out, nil
}

// Scope names the acquisition, not a case-wide assumed machine identity.
type Scope struct{ CaseID, CollectionID, Host, RepositoryID string }
type ScopedObject struct {
	Scope                         Scope
	NamespaceID, NativeKey, Class string
	Keys                          map[string]any
}
type ReferenceResolution struct{ Status, Reason, TargetNativeKey string }

func ResolveReference(raw, namespaceID string, scope Scope, objects []ScopedObject) ReferenceResolution {
	unresolved := func(reason string) ReferenceResolution {
		return ReferenceResolution{Status: "unresolved", Reason: reason}
	}
	ref, err := ParseReference(raw)
	if err != nil {
		return unresolved("unsupported_reference")
	}
	if scope.CaseID == "" || scope.CollectionID == "" || scope.RepositoryID == "" || !hashID(namespaceID, "NS_") {
		return unresolved("scope_unavailable")
	}
	if ref.Host != "" && (scope.Host == "" || !strings.EqualFold(ref.Host, scope.Host)) {
		return unresolved("host_mismatch")
	}
	targetNS := namespaceID
	if ref.Namespace != "" {
		targetNS = nameID("NS_", ref.Namespace)
	}
	matches := map[string]bool{}
	for _, o := range objects {
		if o.Scope.CaseID != scope.CaseID || o.Scope.CollectionID != scope.CollectionID || o.Scope.RepositoryID != scope.RepositoryID || !strings.EqualFold(o.Scope.Host, scope.Host) || o.NamespaceID != targetNS || !strings.EqualFold(o.Class, ref.Class) || len(o.Keys) != len(ref.Keys) || o.NativeKey == "" {
			continue
		}
		exact := true
		used := map[string]bool{}
		for rk, rv := range ref.Keys {
			found := false
			for k, v := range o.Keys {
				if strings.EqualFold(k, rk) {
					if used[strings.ToLower(k)] {
						exact = false
					}
					used[strings.ToLower(k)] = true
					literal, ok := v.(string)
					found = ok && literal == rv
					break
				}
			}
			if !found {
				exact = false
				break
			}
		}
		if exact {
			matches[o.NativeKey] = true
		}
	}
	if len(matches) > 1 {
		return ReferenceResolution{Status: "ambiguous", Reason: "multiple_exact_targets"}
	}
	for key := range matches {
		return ReferenceResolution{Status: "resolved", TargetNativeKey: key}
	}
	return unresolved("target_not_present")
}
