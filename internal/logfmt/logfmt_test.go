package logfmt

import "testing"

func TestParse_GrafanaRequestLine(t *testing.T) {
	line := `logger=context userId=0 orgId=0 uname= t=2026-10-22T08:21:07.910446864Z level=info msg="Request Completed" method=POST path=/login status=401 remote_addr=203.0.113.9 time_ms=0 duration=649.459µs size=107 referer= handler=/login status_source=server`
	p, ok := Parse(line)
	if !ok {
		t.Fatal("line rejected")
	}
	want := map[string]string{"logger": "context", "userId": "0", "uname": "", "t": "2026-10-22T08:21:07.910446864Z", "msg": "Request Completed",
		"method": "POST", "path": "/login", "status": "401", "remote_addr": "203.0.113.9", "duration": "649.459µs", "referer": "", "handler": "/login"}
	for k, v := range want {
		if got, present := p.Get(k); !present || got != v {
			t.Errorf("%s = %q (present=%v), want %q", k, got, present, v)
		}
	}
}

func TestParse_QuotedEscapesAndOrder(t *testing.T) {
	p, ok := Parse(`a=1 msg="say \"hi\" \\ there" b=two`)
	if !ok {
		t.Fatal("rejected")
	}
	if v, _ := p.Get("msg"); v != `say "hi" \ there` {
		t.Errorf("msg = %q", v)
	}
	keys := p.Keys()
	if len(keys) != 3 || keys[0] != "a" || keys[2] != "b" {
		t.Errorf("order = %v", keys)
	}
}

func TestParse_RejectsWhatIsNotLogfmt(t *testing.T) {
	for _, s := range []string{"", "   ", "plain sentence with no pairs", "=novalue", `msg="unterminated`, "just words key=value trailing words"} {
		if _, ok := Parse(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParse_FirstKeyWinsAndDuplicatesAreKept(t *testing.T) {
	p, ok := Parse("k=1 k=2")
	if !ok {
		t.Fatal("rejected")
	}
	if v, _ := p.Get("k"); v != "1" {
		t.Errorf("Get returned %q, want the first", v)
	}
	if len(p.Keys()) != 2 {
		t.Errorf("duplicate dropped: %v", p.Keys())
	}
}
