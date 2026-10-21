package webattack

import (
	"strings"
	"testing"
)

func TestClassify_Attacks(t *testing.T) {
	cases := []struct {
		name, uri, ua string
		want          string
	}{
		{"union select", "/item.php?id=1+UNION+ALL+SELECT+1,2,3--", "", SQLInjection},
		{"double-encoded union", "/item.php?id=1%2520union%2520select%25201", "", SQLInjection},
		{"boolean", "/login.php?u=admin'%20or%20'1'='1", "", SQLInjection},
		{"information_schema", "/a?x=(select+table_name+from+information_schema.tables)", "", SQLInjection},
		{"time based", "/a?id=1;select+sleep(5)", "", SQLInjection},
		{"traversal", "/view?file=../../../../etc/passwd", "", PathTraversal},
		{"encoded traversal", "/view?file=..%2f..%2f..%2fetc%2fpasswd", "", PathTraversal},
		{"php wrapper", "/index.php?page=php://filter/convert.base64-encode/resource=config", "", PathTraversal},
		{"command", "/ping.php?host=127.0.0.1;cat+/etc/hostname", "", CommandInjection},
		{"command substitution", "/ping.php?host=$(id)", "", CommandInjection},
		{"shellshock", "/cgi-bin/x.cgi?a=() { :;}; /bin/id", "", CommandInjection},
		{"xss", "/search?q=<script>alert(1)</script>", "", CrossSiteScripting},
		{"known shell name", "/uploads/c99.php", "", WebShell},
		{"command parameter", "/uploads/a.php?cmd=whoami", "", WebShell},
		{"scanner", "/", "sqlmap/1.4#stable (http://sqlmap.org)", Scanner},
		{"admin probe", "/phpmyadmin/index.php", "", AdminInterfaceProbe},
		{"env file", "/.env", "", AdminInterfaceProbe},
	}
	for _, c := range cases {
		got := Classify(c.uri, c.ua)
		if !contains(got, c.want) {
			t.Errorf("%s: %q classified %v, want %s", c.name, c.uri, got, c.want)
		}
	}
}

func TestClassify_OrdinaryRequestsAreNotFlagged(t *testing.T) {
	for _, uri := range []string{
		"/", "/feed/", "/index.php?page=2", "/blog/select-a-theme", "/img/original/b99357a12d06862c0af2b98640b8bb3d-.jpg",
		"/wp-content/themes/optimize/css/style.css?ver=1.2", "/search?q=union+of+states", "/shop?id=5&sort=name",
		"/a?x=1&id=5&cat=books", "/docs/where-and-how.html", "/news?q=O%27Reilly", "/cgi-bin/count.cgi?df=site.dat",
		"/p?name=a&sh=1", "/download?file=report.pdf", "/api/v1/users/42/orders?limit=10",
	} {
		if got := Classify(uri, "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"); len(got) != 0 {
			t.Errorf("%q must not be flagged, got %v", uri, got)
		}
	}
}

func TestDecode_DoesNotLoopOrPanicOnGarbage(t *testing.T) {
	for _, s := range []string{"%", "%zz", "%2", "%25252525252525", strings.Repeat("%25", 500), "\x00\xff", ""} {
		_ = Decode(s)
		_ = Classify(s, s)
	}
	if got := Decode("a%2520b"); got != "a b" {
		t.Errorf("double-encoded space: %q", got)
	}
	if got := Decode("100%+off"); got != "100% off" {
		t.Errorf("stray percent: %q", got)
	}
}

func TestClassify_IsSortedAndDeduplicated(t *testing.T) {
	got := Classify("/x.php?cmd=id;cat+/etc/passwd&a=union+select+1", "nikto")
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not strictly sorted: %v", got)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
