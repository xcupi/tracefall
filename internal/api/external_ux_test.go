package api

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUI_UploadAdvertisesVirtualDisksAndMemory(t *testing.T) {
	s := appJS(t)
	start := strings.Index(string(s), `id="upload-file"`)
	end := strings.Index(string(s[start:]), "/>") + start
	picker := string(s[start:end])
	for _, ext := range []string{".vhd,", ".vhdx,", ".vmdk,", ".vmem,"} {
		if !strings.Contains(picker, ext) {
			t.Errorf("file picker hides %s", ext)
		}
	}
	overview := functionBody(t, s, "function renderOverviewTab(")
	for _, name := range []string{"VHDX", "VMDK", "memory image", "ext2/3/4"} {
		if !strings.Contains(overview, name) {
			t.Errorf("upload guidance omits %s", name)
		}
	}
	if strings.Contains(overview, "DiskDrigger") {
		t.Error("sample-specific upload guidance")
	}
}

func TestUI_ExternalCitationsResolveFullIDs(t *testing.T) {
	s := appJS(t)
	body := functionBody(t, s, "function renderNarrativeSection(")
	if !strings.Contains(body, "externalCitation(") {
		t.Error("summary citations are not interactive")
	}
	ext := functionBody(t, s, "async function renderExternalTab(")
	for _, want := range []string{"externalCitation(", "<details", "more supporting events", "wireExternalCitations("} {
		if !strings.Contains(ext, want) {
			t.Errorf("external page missing %s", want)
		}
	}
	if strings.Contains(string(s), "function externalCitation(") {
		js := "const esc=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('\\\"','&quot;');\nfunction externalCitation(" + functionBody(t, s, "function externalCitation(") + "\nconsole.log(externalCitation('event', 'event-long-id-1234567890')); console.log(externalCitation('finding', '\"<img>'));"
		out, err := exec.Command("node", "-e", js).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		for _, want := range []string{`data-source-id="event-long-id-1234567890"`, `data-source-kind="event"`, "&lt;img>", "&quot;"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("citation loses identity or escaping: %s", out)
			}
		}
	}
}

func TestUI_ExternalCardsAndRefreshKeepReadingState(t *testing.T) {
	s := appJS(t)
	body := functionBody(t, s, "async function renderExternalTab(")
	for _, want := range []string{`id="external-policy"`, `id="external-vt"`, `id="external-llm"`, "captureExternalState(", "restoreExternalState(", "previousRoot", "content.isConnected"} {
		if !strings.Contains(body, want) {
			t.Errorf("external layout / refresh missing %s", want)
		}
	}
	// Persisting consent must be conditional on the destination AND policy,
	// not just on the case; otherwise a changed provider inherits consent.
	for _, want := range []string{"eg.level", "nv.destination", "nv.model"} {
		if !strings.Contains(body, "caseId, eg.level, nv.destination, nv.model") {
			t.Errorf("consent identity must bind %s", want)
		}
	}
	if strings.Contains(string(s), "function captureExternalState(") {
		js := `const assert = require('node:assert/strict');
  const ack={checked:true}; const detail={id:'privacy',open:true};
  const payload={hidden:false,textContent:'sent facts',scrollTop:42,dataset:{hash:'hash-a'}};
  const focused={id:'nv-ack'};
  global.document={activeElement:focused};
  const root={dataset:{consentKey:'provider-a'},contains:()=>true,
    querySelector:s=>s==='#nv-ack'?ack:s==='#nv-payload-box'?payload:null,
    querySelectorAll:s=>s==='details[id]'?[detail]:[]};
  ` + "function captureExternalState(" + functionBody(t, s, "function captureExternalState(") + `
  const state=captureExternalState(root,'provider-a');
  assert.equal(state.ack,true); assert.deepEqual(state.openDetails,['privacy']);
  assert.equal(state.payload.text,'sent facts'); assert.equal(state.payload.scrollTop,42);
  assert.equal(state.focusId,'nv-ack');
  assert.equal(captureExternalState(root,'provider-b'),null);
  `
		out, err := exec.Command("node", "-e", js).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v", out, err)
		}
	}
}

func TestUI_SummarySetupMentionsBothProviders(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	s := appJS(t)
	js := "const esc=s=>String(s); const fmtTime=s=>s;\nfunction renderNarrativeSection(" + functionBody(t, s, "function renderNarrativeSection(") + "\nconsole.log(renderNarrativeSection({configured:false,findings:0}));"
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	for _, want := range []string{"codex-cli", "TRACEFALL_LLM_PROVIDER", "API", "ChatGPT"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing setup guidance %s", want)
		}
	}
}
