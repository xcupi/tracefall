package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/authlog"
	"tracefall/internal/parsers/packagelog"
	"tracefall/internal/parsers/syslog"
	"tracefall/internal/parsers/webaccess"
)

// A real Linux server log set: auth.log, daemon.log, dpkg.log and two Apache
// access logs. Set TRACEFALL_REAL_LINUX_LOGS to the directory that holds them
// (auth.log, daemon.log, dpkg.log, apache2/*.log) to run it. The files are not
// in the repository. Every expected number below was counted by an independent
// pass over the raw text, not by these parsers, and each file's SHA-256 is
// pinned so a different file fails loudly instead of "almost" matching.
func TestRealLinuxLogs(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_LINUX_LOGS")
	if dir == "" {
		t.Skip("set TRACEFALL_REAL_LINUX_LOGS to a directory of real Linux logs to run")
	}
	pins := map[string]string{
		"auth.log":               "730bace212f7b2e878a7b2ad31e99e25a7f8e27479a07f1e4d713e15e4a19d18",
		"daemon.log":             "83c9ab1e9babc82ed15c03b64437577dff8fb7ba60a8aae82c4206f7006eb992",
		"dpkg.log":               "7101f5b2377a61a62df17298419692f1a916a54622066e7a4afde6ed562964d4",
		"apache2/www-access.log": "5f4dcbcdc191a639f5ef1ac520c1697e9e53e079d212479a30263b631bb2c780",
		"apache2/www-media.log":  "c2d7033f54f3de47b495ad82fbdd594efaa9e27c8b6682e37e92afd88b1faf4f",
	}
	for rel, want := range pins {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s is not the file these counts were taken from", rel)
		}
	}

	var all []model.Event
	parse := func(p parsers.ArtifactParser, rel string) []model.Event {
		res, err := p.Parse(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for i := range res.Events {
			res.Events[i].ID = rel + ":" + res.Events[i].SourceReference
			res.Events[i].CaseID = "real"
			res.Events[i].SourceFileID = rel
			res.Events[i].Host = "host01"
		}
		all = append(all, res.Events...)
		return res.Events
	}
	count := func(ev []model.Event, f func(model.Event) string) map[string]int {
		m := map[string]int{}
		for _, e := range ev {
			m[f(e)]++
		}
		return m
	}
	byType := func(e model.Event) string { return e.EventType }
	byCat := func(e model.Event) string { return e.Extra["category"] }

	auth := parse(authlog.New(), "auth.log")
	want := map[string]int{
		model.EventLogonFailure: 20339, model.EventLogonSuccess: 118, model.EventAccountChange: 35,
		model.EventPrivilegeSwitch: 175, model.EventSudoCommand: 644,
	}
	for k, v := range want {
		if got := count(auth, byType)[k]; got != v {
			t.Errorf("auth.log %s = %d, want %d", k, got, v)
		}
	}

	daemon := parse(syslog.New(), "daemon.log")
	wantCat := map[string]int{"database_insecure_account": 11, "database_integrity": 10, "database_error": 2, "database_lifecycle": 24}
	for k, v := range wantCat {
		if got := count(daemon, byCat)[k]; got != v {
			t.Errorf("daemon.log category %s = %d, want %d", k, got, v)
		}
	}

	pk := parse(packagelog.New(), "dpkg.log")
	if got := count(pk, func(e model.Event) string { return e.Extra["action"] }); got["install"] != 144 || got["upgrade"] != 11 || len(pk) != 155 {
		t.Errorf("dpkg.log = %v (%d events), want 144 installs and 11 upgrades", got, len(pk))
	}

	if n := len(parse(webaccess.New(), "apache2/www-access.log")); n != 365 {
		t.Errorf("www-access.log = %d requests, want 365", n)
	}
	if n := len(parse(webaccess.New(), "apache2/www-media.log")); n != 229 {
		t.Errorf("www-media.log = %d requests, want 229", n)
	}

	var sizes []int
	web := 0
	for _, f := range Run("real", all) {
		switch f.RuleID {
		case seqRule:
			sizes = append(sizes, len(f.SupportingEvents))
		case "web-attack-indicators":
			web++
		}
	}
	if web != 0 {
		t.Errorf("%d web findings; an independent grep finds no attack pattern in these logs", web)
	}
	if len(sizes) != 12 {
		t.Errorf("%d sequence findings, want 12 (independent pass)", len(sizes))
	}
}
