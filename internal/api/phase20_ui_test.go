package api

import (
	"strings"
	"testing"
)

// UI wiring for Phase 20. These assert what the browser will actually
// render, so a field that exists on the event but is never displayed --
// or a password field that IS displayed -- fails here rather than being
// discovered by an analyst.

// The Detail column must show the connection, not the filename. Every
// entry in one recentservers.xml shares a filename, so falling through
// would fill the column with the same value down the page.
func TestUI_FileZillaDetailShowsTheConnection(t *testing.T) {
	src := string(appJS(t))

	if !strings.Contains(src, "filezilla_server_entry: filezillaDetail(extra)") {
		t.Error("eventDetailValue does not select a FileZilla-specific detail")
	}
	fn := uiFunction(t, src, "function filezillaDetail(")
	for _, want := range []string{"server_ipv4", "server_ipv6", "server_hostname", "server_port", "server_username"} {
		if !strings.Contains(fn, want) {
			t.Errorf("filezillaDetail does not use %s", want)
		}
	}
	// The one thing it must never render.
	for _, forbidden := range []string{"password", "Pass", "secret"} {
		if strings.Contains(fn, forbidden) {
			t.Errorf("filezillaDetail references %q", forbidden)
		}
	}
}

func TestUI_ImageGPSDetailShowsTheCoordinate(t *testing.T) {
	src := string(appJS(t))
	if !strings.Contains(src, "image_gps: extra.gps_coordinates") {
		t.Error("eventDetailValue does not show the coordinate for a GPS row")
	}
}

// The FileZilla panel must answer the address question either way, and
// must never grow a password row.
func TestUI_FileZillaPanelReportsAddressAvailabilityAndNoPassword(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function filezillaPanel(")

	for _, want := range []string{
		"server_ipv4", "server_ipv6", "server_hostname",
		"ipv4_availability", // the explicit "no IPv4 here" answer
		"protocol", "server_port", "server_username", "logon_type",
		"evidence_meaning", "timestamp_basis",
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("filezillaPanel does not render %s", want)
		}
	}
	// Presence only -- never a value.
	if !strings.Contains(fn, "password_present") {
		t.Error("filezillaPanel does not report whether a password is stored")
	}
	// The forbidden reads are the VALUE fields. password_present and
	// password_storage are metadata about the secret and are required.
	for _, forbidden := range []string{"x.password_value", "x.password\"", "x.pass\b", "x.secret", "x.key"} {
		if strings.Contains(fn, forbidden) {
			t.Errorf("filezillaPanel reads %s -- a credential value", forbidden)
		}
	}
	for _, allowed := range []string{"x.password_present", "x.password_storage"} {
		if !strings.Contains(fn, allowed) {
			t.Errorf("filezillaPanel does not read %s", allowed)
		}
	}
	if !strings.Contains(fn, "not extracted") {
		t.Error("filezillaPanel does not state that the password was not extracted")
	}
}

// The whole point of the image panel: observed and derived kept apart.
func TestUI_ImagePanelSeparatesObservedFromDerived(t *testing.T) {
	src := string(appJS(t))
	fn := uiFunction(t, src, "function imageGeoPanel(")

	if !strings.Contains(fn, "Observed - stored in the file") {
		t.Error("the panel has no OBSERVED section heading")
	}
	if !strings.Contains(fn, "Derived - computed by Tracefall, not stored in the file") {
		t.Error("the panel has no DERIVED section heading")
	}

	obsIdx := strings.Index(fn, "Observed - stored in the file")
	derIdx := strings.Index(fn, "Derived - computed by Tracefall")
	if obsIdx < 0 || derIdx < 0 || obsIdx > derIdx {
		t.Fatal("the observed section must come before the derived one")
	}
	observed := fn[obsIdx:derIdx]
	derived := fn[derIdx:]

	for _, want := range []string{"gps_latitude_raw", "gps_longitude_raw", "gps_components_observed"} {
		if !strings.Contains(observed, want) {
			t.Errorf("the observed section does not render %s", want)
		}
	}
	for _, want := range []string{"gps_coordinates", "country", "geolocation_method", "geolocation_dataset"} {
		if !strings.Contains(derived, want) {
			t.Errorf("the derived section does not render %s", want)
		}
	}
	// The country must not appear as if the image stored it.
	if strings.Contains(observed, "x.country") {
		t.Error("the country is rendered in the OBSERVED section; it is derived, not stored in the image")
	}
	if !strings.Contains(fn, "country_derivation") {
		t.Error("the panel does not state that the country is derived")
	}
	// The precision caveat has to reach the reader.
	for _, want := range []string{"gps_precision", "gps_precision_note", "country_confidence"} {
		if !strings.Contains(fn, want) {
			t.Errorf("the panel does not render %s", want)
		}
	}
	// The EXIF times must keep their meanings visible.
	if !strings.Contains(fn, "_meaning") {
		t.Error("the panel renders EXIF times without their meanings")
	}
}

// Both panels must be reachable from the event detail view, and must use
// the existing Copy/Show-full control rather than a second one.
func TestUI_Phase20PanelsAreWiredAndUseTheExistingCopyControl(t *testing.T) {
	src := string(appJS(t))

	if !strings.Contains(src, "filezillaPanel(prov.event)") {
		t.Error("filezillaPanel is never called from the event detail view")
	}
	if !strings.Contains(src, "imageGeoPanel(prov.event)") {
		t.Error("imageGeoPanel is never called from the event detail view")
	}
	for _, name := range []string{"function filezillaPanel(", "function imageGeoPanel("} {
		fn := uiFunction(t, src, name)
		if !strings.Contains(fn, "detailCell(") {
			t.Errorf("%s does not use detailCell, so its long values get no Copy or Show-full control", name)
		}
	}

	css := styleCSS(t)
	if !strings.Contains(css, ".img-section") {
		t.Error("the image panel's section divider has no styling")
	}
}

// uiFunction returns the source of one top-level function, from its
// declaration to the closing brace in column 1.
func uiFunction(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("app.js has no %s", decl)
	}
	rest := src[i:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("could not find the end of %s", decl)
	}
	return rest[:end]
}
