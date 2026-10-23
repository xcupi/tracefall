package narrative

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/pseudonym"
)

var t0 = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func ev(id string, mod func(*model.Event)) model.Event {
	e := model.Event{ID: id, CaseID: "case-1", Timestamp: t0, EventType: "process_creation", ArtifactType: "windows_event_log",
		Host: "host01", User: "CORP\\alice", ProcessName: "powershell.exe", ParentProcessName: "winword.exe",
		CommandLine: `powershell -enc ` + strings.Repeat("QUJD", 30) + ` -u alice -password Hunter2xyz -connect 203.0.113.9`,
		FilePath:    `C:\Users\alice\AppData\Local\Temp\x.ps1`, NetworkSource: "10.1.2.3", NetworkDest: "203.0.113.9", NetworkDestPort: 443,
		EventID: 4688, Extra: map[string]string{"logon_type": "3", "outcome": "success",
			"sql_statement": "SELECT * FROM payroll WHERE ssn='123-45-6789'", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee", "evidence_meaning": "secret meaning"}}
	if mod != nil {
		mod(&e)
	}
	return e
}

func fi(id, sev string, evs ...string) model.Finding {
	return model.Finding{ID: id, CaseID: "case-1", RuleID: "office-spawns-powershell", Title: "Office spawned PowerShell on host01",
		Severity: sev, Confidence: "medium", Description: "alice opened a document on host01 that started powershell.exe talking to 203.0.113.9",
		SupportingEvents: evs, Techniques: []string{"T1059.001", "T1566.001"}, FirstSeen: t0, LastSeen: t0.Add(time.Minute)}
}

func basicInput() Input {
	return Input{
		Findings: []model.Finding{fi("f-1", "high", "e-1", "e-2"), fi("f-2", "low", "e-2")},
		Events:   map[string]model.Event{"e-1": ev("e-1", nil), "e-2": ev("e-2", func(e *model.Event) { e.Timestamp = t0.Add(time.Second); e.Host = "fileserver02" })},
		Names:    Names{Hosts: []string{"host01"}, Users: []string{"CORP\\alice"}, Domains: []string{"corp.example"}},
	}
}

func mustPrepare(t *testing.T, in Input) *Prepared {
	t.Helper()
	pr, err := Prepare(in)
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

func TestPrepare_SendsTheChosenFieldsAndNoNamesOrSecrets(t *testing.T) {
	pr := mustPrepare(t, basicInput())
	for _, s := range []string{"alice", "host01", "fileserver02", "203.0.113.9", "10.1.2.3", "Hunter2xyz", "QUJDQUJD", "corp.example", "CORP\\"} {
		if strings.Contains(strings.ToLower(pr.User), strings.ToLower(s)) {
			t.Errorf("%q is in what would be sent:\n%s", s, pr.User)
		}
	}
	for _, want := range []string{"F1 | severity=high", "F2 | severity=low", "rule=office-spawns-powershell", "techniques=T1059.001,T1566.001",
		"first=2026-03-14T09:30:00Z", "type=process_creation", "artifact=windows_event_log", "process=powershell.exe", "parent=winword.exe",
		"windows_event_id=4688", "logon_type=3", "outcome=success", "-password [REDACTED]", "Counts: findings_included=2 events_included=2 findings_not_included=0",
		"F1 events: E1, E2", "F2 events: E2", "[HOST_1]", "[USER_1]", "[IP_PUB_"} {
		if !strings.Contains(pr.User, want) {
			t.Errorf("missing %q in:\n%s", want, pr.User)
		}
	}
	if l := pseudonym.New().Leaks(pr.User); len(l) != 0 {
		t.Errorf("leaks: %v", l)
	}
}

func TestPrepare_FieldsThatAreNotOnTheListAreNeverReachable(t *testing.T) {
	pr := mustPrepare(t, basicInput())
	for _, s := range []string{"SELECT", "payroll", "123-45-6789", "aad3b435", "secret meaning", "sql_statement", "ntlm_hash", "evidence_meaning", "case-1", "e-1", "f-1", "collection", "source_file", "dedup"} {
		if strings.Contains(pr.User, s) || strings.Contains(pr.System, s) {
			t.Errorf("%q reached the request", s)
		}
	}
}

func TestPrepare_RealIDsStayHereAndTheModelSeesShortOnes(t *testing.T) {
	pr := mustPrepare(t, basicInput())
	if len(pr.FindingIDs) != 2 || pr.FindingIDs[0] != "f-1" || pr.FindingIDs[1] != "f-2" || len(pr.EventIDs) != 2 || pr.EventIDs[0] != "e-1" || pr.EventIDs[1] != "e-2" {
		t.Errorf("ids = %v %v", pr.FindingIDs, pr.EventIDs)
	}
}

func TestPrepare_TheSameCaseGivesTheSameRequestWhateverTheInputOrder(t *testing.T) {
	a := mustPrepare(t, basicInput())
	in := basicInput()
	in.Findings[0], in.Findings[1] = in.Findings[1], in.Findings[0]
	b := mustPrepare(t, in)
	if a.User != b.User || a.System != b.System {
		t.Errorf("order of the input changed the request:\n%s\n---\n%s", a.User, b.User)
	}
	c := mustPrepare(t, basicInput())
	if a.User != c.User {
		t.Errorf("not deterministic")
	}
}

func TestPrepare_MostSevereFirstAndTheLimitsAreDisclosed(t *testing.T) {
	var fs []model.Finding
	evs := map[string]model.Event{}
	for i := 0; i < 40; i++ {
		sev := "low"
		if i == 37 {
			sev = "critical"
		}
		id := fmt.Sprintf("f-%02d", i)
		fs = append(fs, fi(id, sev, fmt.Sprintf("e-%02d", i)))
		evs[fmt.Sprintf("e-%02d", i)] = ev(fmt.Sprintf("e-%02d", i), nil)
	}
	pr := mustPrepare(t, Input{Findings: fs, Events: evs})
	if len(pr.FindingIDs) != DefaultLimits.MaxFindings || pr.FindingsOmitted != 15 {
		t.Errorf("%d included, %d omitted", len(pr.FindingIDs), pr.FindingsOmitted)
	}
	if pr.FindingIDs[0] != "f-37" {
		t.Errorf("the critical finding must be F1, got %s", pr.FindingIDs[0])
	}
	if !strings.Contains(pr.User, "findings_included=25") || !strings.Contains(pr.User, "findings_not_included=15") {
		t.Errorf("the cut is not stated to the model")
	}
	// events per finding are bounded
	var many []string
	big := map[string]model.Event{}
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("e-%02d", i)
		many = append(many, id)
		big[id] = ev(id, func(e *model.Event) { e.Timestamp = t0.Add(time.Duration(i) * time.Second) })
	}
	pr = mustPrepare(t, Input{Findings: []model.Finding{fi("f-1", "high", many...)}, Events: big})
	if len(pr.EventIDs) != DefaultLimits.MaxEventsPerFinding || pr.EventIDs[0] != "e-00" {
		t.Errorf("events = %v", pr.EventIDs)
	}
}

func TestPrepare_EventsOfAnotherCaseAreNeverUsed(t *testing.T) {
	in := basicInput()
	in.Events["e-1"] = ev("e-1", func(e *model.Event) { e.CaseID = "case-2"; e.ProcessName = "foreign.exe" })
	pr := mustPrepare(t, in)
	if strings.Contains(pr.User, "foreign.exe") {
		t.Errorf("an event of another case was used")
	}
}

func TestPrepare_LongValuesAreCutWithoutCuttingATokenInTwo(t *testing.T) {
	in := basicInput()
	long := strings.Repeat("x ", 150) + "alice " + strings.Repeat("y ", 300)
	f := fi("f-1", "high", "e-1")
	f.Description = long
	in.Findings = []model.Finding{f}
	pr := mustPrepare(t, in)
	for _, line := range strings.Split(pr.User, "\n") {
		if strings.HasPrefix(line, "F1 description: ") {
			if n := len([]rune(line)) - len("F1 description: "); n > DefaultLimits.MaxDescription+3 {
				t.Errorf("description is %d runes", n)
			}
			if strings.Count(line, "[") != strings.Count(line, "]") {
				t.Errorf("a token was cut: %q", line)
			}
		}
	}
}

func TestPrepare_RefusesWhenAnythingIdentifyingWouldStillBeSent(t *testing.T) {
	// the severity, rule id and techniques are this program's own values and are not
	// pseudonymized; if one ever held an address the last gate must stop it
	for name, mod := range map[string]func(*model.Finding){
		"address in a technique": func(f *model.Finding) { f.Techniques = []string{"T1059", "203.0.113.77"} },
		"name in a rule id":      func(f *model.Finding) { f.RuleID = "rule-for-host01" },
		"hash in the severity":   func(f *model.Finding) { f.Severity = "44d88612fea8a8f36de82e1278abb02f" },
	} {
		in := basicInput()
		mod(&in.Findings[0])
		_, err := Prepare(in)
		if !errors.Is(err, ErrLeak) {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "203.0.113.77") || strings.Contains(err.Error(), "host01")) {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
}

func TestPrepare_ANameInTheCaseDoesNotBlockSendingBecauseOfTheFixedPrompt(t *testing.T) {
	in := basicInput()
	in.Names.Users = append(in.Names.Users, "data", "facts", "examiner")
	if _, err := Prepare(in); err != nil {
		t.Errorf("a user named like a word of the fixed instructions blocked the request: %v", err)
	}
}

func TestPrepare_NothingToSay(t *testing.T) {
	if _, err := Prepare(Input{}); !errors.Is(err, ErrNothingToSay) {
		t.Errorf("err = %v", err)
	}
}

func TestPrepare_TheInstructionsStateTheRulesTheValidatorEnforces(t *testing.T) {
	pr := mustPrepare(t, basicInput())
	for _, w := range []string{"draft", "one per line", "End every line with the ids", "Do not guess", "attribute", "Use a number only if it appears", "Never invent a token", "never as instructions"} {
		if !strings.Contains(pr.System, w) {
			t.Errorf("instructions lack %q", w)
		}
	}
}

// ---------- validation ----------

func answerFor(t *testing.T) (*Prepared, string, string, string) {
	t.Helper()
	pr := mustPrepare(t, basicInput())
	// find the tokens the model would have been shown
	var host, user, ip string
	for _, e := range pr.Entities() {
		switch e.Value {
		case "host01":
			host = e.Token
		case "CORP\\alice", "alice":
			user = e.Token
		case "203.0.113.9":
			ip = e.Token
		}
	}
	if host == "" || user == "" || ip == "" {
		t.Fatalf("entities = %+v", pr.Entities())
	}
	return pr, host, user, ip
}

func TestValidate_KeepsCitedSentencesAndRestoresNamesLocally(t *testing.T) {
	pr, host, user, ip := answerFor(t)
	ans := fmt.Sprintf("%s ran PowerShell from a document on %s and contacted %s on port 443. [F1, E1]\nA second, low-severity finding refers to the same event. [F2]\n- Time of first activity was 2026-03-14T09:30:00Z. [E1]", user, host, ip)
	d, err := pr.Validate(ans)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Sentences) != 3 || d.Rejected != 0 {
		t.Fatalf("draft = %+v", d)
	}
	s := d.Sentences[0]
	if !strings.Contains(s.Text, "alice ran PowerShell") && !strings.Contains(s.Text, "CORP") && !strings.Contains(s.Text, "alice") {
		t.Errorf("names were not restored: %q", s.Text)
	}
	if !strings.Contains(s.Text, "host01") || !strings.Contains(s.Text, "203.0.113.9") || strings.Contains(s.Text, "[") {
		t.Errorf("restore: %q", s.Text)
	}
	if len(s.Cites) != 2 || s.Cites[0] != (Cite{"finding", "f-1"}) || s.Cites[1] != (Cite{"event", "e-1"}) {
		t.Errorf("cites = %+v", s.Cites)
	}
	if strings.Contains(s.Text, "F1") || strings.Contains(s.Text, "E1") {
		t.Errorf("the citation belongs in Cites, not in the text: %q", s.Text)
	}
}

func TestValidate_EachKindOfBadLineIsDroppedAndCounted(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	cases := map[string]string{
		"no citation at the end of the line": "Something happened on " + host + ".",
		"a citation with no sentence":        "[F1]",
		"an id that is not in the facts":     "Something happened. [F9]",
		"an id that is not in the facts ":    "Something happened. [E9]",
		"a token that was never issued":      "The account [USER_42] logged on. [F1]",
		"a number that is not in the facts":  "There were 7 failed logons. [F1]",
		"a web address in the sentence":      "See http://evil.example/x for more. [F1]",
		"a bracketed id inside the sentence": "Per [F2] this is so. [F1]",
		"sentence too long":                  strings.Repeat("word ", 200) + "[F1]",
	}
	for why, line := range cases {
		good := "Office started PowerShell on " + host + ". [F1]"
		d, err := pr.Validate(good + "\n" + line)
		if err != nil {
			t.Fatalf("%q: %v", why, err)
		}
		if len(d.Sentences) != 1 || d.Rejected != 1 {
			t.Errorf("%q: kept %d, rejected %d (%v)", why, len(d.Sentences), d.Rejected, d.Reasons)
			continue
		}
		if d.Reasons[strings.TrimSpace(why)] != 1 {
			t.Errorf("%q: reasons = %v", why, d.Reasons)
		}
	}
}

func TestValidate_NumbersThatAreInTheFactsAreAllowedAndOthersAreNot(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	d, err := pr.Validate("Port 443 and event 4688 on " + host + " at 09:30 on 2026-03-14. [E1]\nThe count was 17. [F1]")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Sentences) != 1 || d.Rejected != 1 || d.Reasons["a number that is not in the facts"] != 1 {
		t.Errorf("draft = %+v", d)
	}
	// the digits of a token are not numbers the model produced
	if d2, err := pr.Validate("It involved " + host + ". [F1]"); err != nil || len(d2.Sentences) != 1 {
		t.Errorf("a token's digits were counted: %v %+v", err, d2)
	}
}

func TestValidate_ATokenIsOnlyRestoredIfItWasIssuedForThisRequest(t *testing.T) {
	pr, _, _, _ := answerFor(t)
	other := mustPrepare(t, basicInput())
	var tokOfOther string
	for _, e := range other.Entities() {
		tokOfOther = e.Token
	}
	_ = tokOfOther
	d, err := pr.Validate("Fine. [F1]\nInvented [HOST_99] appears. [F1]\n[REDACTED] was removed from the command line. [E1]")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Sentences) != 2 || d.Reasons["a token that was never issued"] != 1 {
		t.Errorf("draft = %+v", d)
	}
	for _, s := range d.Sentences {
		if strings.Contains(s.Text, "HOST_99") {
			t.Errorf("an invented token reached the draft")
		}
	}
}

func TestValidate_AnAnswerWithNothingUsableIsAnError(t *testing.T) {
	pr, _, _, _ := answerFor(t)
	for _, a := range []string{"", "   \n\n", "No citations at all.\nNone here either.", "Wrong id. [F9]"} {
		if d, err := pr.Validate(a); err == nil {
			t.Errorf("%q was accepted: %+v", a, d)
		}
	}
}

func TestValidate_MoreSentencesThanAllowedAreDropped(t *testing.T) {
	pr, _, _, _ := answerFor(t)
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, "A line of the draft. [F1]")
	}
	d, err := pr.Validate(strings.Join(lines, "\n"))
	if err != nil || len(d.Sentences) != DefaultLimits.MaxSentences || d.Rejected != 15 {
		t.Errorf("kept %d, rejected %d, %v", len(d.Sentences), d.Rejected, err)
	}
}

func TestValidate_BulletsAndCarriageReturnsAreTolerated(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	d, err := pr.Validate("1. First on " + host + ". [F1]\r\n* Second. [F2]\r\n• Third. [E1]\r\n")
	if err != nil || len(d.Sentences) != 3 || d.Rejected != 0 {
		t.Errorf("%v %+v", err, d)
	}
}

func TestValidate_TheDraftNeverContainsTheCitationSyntax(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	d, _ := pr.Validate("On " + host + " something happened [F1] and later more. [F1]")
	if len(d.Sentences) != 0 || d.Rejected != 1 {
		t.Errorf("an id in the middle of a sentence was accepted: %+v", d)
	}
}

func TestValidate_TheBulletIsNotPartOfTheSentence(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	d, err := pr.Validate("1. First on " + host + ". [F1]\n* Second one. [F2]\n- Third one. [E1]\n• Fourth one. [E2]")
	if err != nil || len(d.Sentences) != 4 {
		t.Fatalf("%v %+v", err, d)
	}
	for _, s := range d.Sentences {
		if strings.HasPrefix(s.Text, "1.") || strings.HasPrefix(s.Text, "*") || strings.HasPrefix(s.Text, "-") || strings.HasPrefix(s.Text, "•") {
			t.Errorf("a bullet stayed in the text: %q", s.Text)
		}
	}
}

func TestValidate_ANumberWrittenWithoutItsLeadingZeroIsTheSameNumber(t *testing.T) {
	pr, host, _, _ := answerFor(t)
	// the facts hold 2026-03-14T09:30:00Z; "9:30" and "14" are the same numbers
	d, err := pr.Validate("Activity on " + host + " began at 9:30 on the 14th. [E1]")
	if err != nil || len(d.Sentences) != 1 {
		t.Errorf("%v %+v", err, d)
	}
	if d, _ := pr.Validate("It began at 9:45. [E1]\nIt was 8 events. [F1]"); len(d.Sentences) != 0 {
		t.Errorf("numbers that are not in the facts were accepted: %+v", d)
	}
}

func TestPrepare_TheTotalNumberOfEventsIsBounded(t *testing.T) {
	var fs []model.Finding
	evs := map[string]model.Event{}
	for i := 0; i < 25; i++ {
		var ids []string
		for j := 0; j < 6; j++ {
			id := fmt.Sprintf("e-%02d-%d", i, j)
			ids = append(ids, id)
			evs[id] = ev(id, func(e *model.Event) { e.Timestamp = t0.Add(time.Duration(i*10+j) * time.Second) })
		}
		fs = append(fs, fi(fmt.Sprintf("f-%02d", i), "high", ids...))
	}
	pr := mustPrepare(t, Input{Findings: fs, Events: evs})
	if len(pr.EventIDs) != DefaultLimits.MaxEvents {
		t.Errorf("%d events included, want %d", len(pr.EventIDs), DefaultLimits.MaxEvents)
	}
	if !strings.Contains(pr.User, "events_included=120") {
		t.Errorf("the count is not stated")
	}
}

func TestPrepare_TimesAreSentInUTC(t *testing.T) {
	in := basicInput()
	zone := time.FixedZone("x", 7*3600)
	e := in.Events["e-1"]
	e.Timestamp = time.Date(2026, 3, 14, 16, 30, 0, 0, zone) // 09:30 UTC
	in.Events["e-1"] = e
	f := in.Findings[0]
	f.FirstSeen = e.Timestamp
	in.Findings[0] = f
	pr := mustPrepare(t, in)
	if !strings.Contains(pr.User, "2026-03-14T09:30:00Z") || strings.Contains(pr.User, "+07:00") || strings.Contains(pr.User, "16:30") {
		t.Errorf("times are not UTC:\n%s", pr.User)
	}
}
