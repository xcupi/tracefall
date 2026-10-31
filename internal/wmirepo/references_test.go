package wmirepo

import (
	"reflect"
	"testing"
)

func TestReferenceGrammarEscapedAbsoluteAndMultiKey(t *testing.T) {
	tests := []struct {
		raw  string
		want Reference
	}{
		{`NeutralClass.Name="entry01"`, Reference{Class: "NeutralClass", Keys: map[string]string{"Name": "entry01"}}},
		{`NeutralClass.Name="a\\b\"c"`, Reference{Class: "NeutralClass", Keys: map[string]string{"Name": "a\\b\"c"}}},
		{`\\host01\root\branch:NeutralClass.Name="entry01",Other="x"`, Reference{Host: "host01", Namespace: `root\branch`, Class: "NeutralClass", Keys: map[string]string{"Name": "entry01", "Other": "x"}}},
		{`root\branch:NeutralClass.Name=""`, Reference{Namespace: `root\branch`, Class: "NeutralClass", Keys: map[string]string{"Name": ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseReference(tt.raw)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("reference parsed=%+v err=%v", got, err)
			}
		})
	}
	for _, raw := range []string{`Class.Name="x"tail`, `Class.Name="x",name="y"`, `Class.Name="a\q"`, `Class.Name=7`, `Class.Name="x",`, `Class.Name="x`, `\\host01\root\..:Class.Name="x"`, `\\host01:Class.Name="x"`, `Class..Name="x"`, "Class.Name=\"a\nb\""} {
		if _, err := ParseReference(raw); err == nil {
			t.Fatalf("invalid/unsupported reference accepted: %q", raw)
		}
	}
}
func TestReferenceResolutionRequiresExactAcquisitionAndIdentity(t *testing.T) {
	scope := Scope{CaseID: "case01", CollectionID: "collection01", Host: "host01", RepositoryID: "repository01"}
	ns := fixtureID("NS_", `root\branch`)
	target := ScopedObject{Scope: scope, NamespaceID: ns, NativeKey: "target01", Class: "NeutralClass", Keys: map[string]any{"Name": "entry01"}}
	for _, raw := range []string{`NeutralClass.Name="entry01"`, `\\host01\root\branch:NeutralClass.Name="entry01"`} {
		got := ResolveReference(raw, ns, scope, []ScopedObject{target})
		if got.Status != "resolved" || got.TargetNativeKey != "target01" {
			t.Fatalf("exact reference unresolved: %+v", got)
		}
	}
	for _, field := range []string{"case", "collection", "host", "repository", "namespace", "class", "key", "value"} {
		t.Run(field, func(t *testing.T) {
			x := target
			switch field {
			case "case":
				x.Scope.CaseID = "case02"
			case "collection":
				x.Scope.CollectionID = "collection02"
			case "host":
				x.Scope.Host = "host02"
			case "repository":
				x.Scope.RepositoryID = "repository02"
			case "namespace":
				x.NamespaceID = fixtureID("NS_", "root")
			case "class":
				x.Class = "OtherClass"
			case "key":
				x.Keys = map[string]any{"Other": "entry01"}
			case "value":
				x.Keys = map[string]any{"Name": "ENTRY01"}
			}
			if got := ResolveReference(`NeutralClass.Name="entry01"`, ns, scope, []ScopedObject{x}); got.Status != "unresolved" || got.TargetNativeKey != "" {
				t.Fatalf("foreign identity joined: %+v", got)
			}
		})
	}
	x := target
	x.NativeKey = "target02"
	if got := ResolveReference(`NeutralClass.Name="entry01"`, ns, scope, []ScopedObject{target, x}); got.Status != "ambiguous" || got.TargetNativeKey != "" {
		t.Fatalf("ambiguity lost: %+v", got)
	}
	if got := ResolveReference(`\\host02\root\branch:NeutralClass.Name="entry01"`, ns, scope, []ScopedObject{target}); got.Status != "unresolved" || got.Reason != "host_mismatch" {
		t.Fatalf("absolute foreign host: %+v", got)
	}
	if got := ResolveReference(`NeutralClass.Name=7`, ns, scope, []ScopedObject{target}); got.Status != "unresolved" || got.Reason != "unsupported_reference" {
		t.Fatalf("unsupported grammar hidden: %+v", got)
	}
}
