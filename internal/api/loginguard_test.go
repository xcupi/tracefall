package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// ---- the counters ----

// One source can exhaust only its own budget. The account stays usable from
// elsewhere, which a single per-username counter could not offer: anyone could
// lock the administrator out by failing ten times.
func TestLoginGuard_ASourceCannotLockTheAccountForEveryoneElse(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	for i := 0; i < pairMaxFailures; i++ {
		g.failure("admin", "203.0.113.9", now)
	}
	if g.allowed("admin", "203.0.113.9", now) {
		t.Fatal("the guessing source was not stopped")
	}
	if !g.allowed("admin", "198.51.100.4", now) {
		t.Fatal("one source's failures locked the account for a different source")
	}
}

func TestLoginGuard_OneSourceSprayingManyAccountsIsStopped(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	for i := 0; i < addrMaxFailures; i++ {
		g.failure("user"+string(rune('a'+i%26))+string(rune('a'+i/26)), "203.0.113.9", now)
	}
	if g.allowed("never-tried-before", "203.0.113.9", now) {
		t.Fatal("a source that failed on 30 different accounts may still try a new one")
	}
	if !g.allowed("never-tried-before", "198.51.100.4", now) {
		t.Fatal("the spraying source's block spread to another source")
	}
}

// A guess spread over many addresses is bounded by the all-sources counter,
// and an address that has logged in as that user before is not caught by it.
func TestLoginGuard_DistributedGuessingIsBoundedButKnownAddressesGetThrough(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	g.success("admin", "192.0.2.50", now) // the administrator's own address
	for i := 0; i < userMaxFailures; i++ {
		// each failure from a different address, so no per-address limit trips
		addr := netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}).String()
		g.failure("admin", addr, now)
	}
	if g.allowed("admin", "203.0.113.200", now) {
		t.Fatal("a new address may still guess after 100 failures from many addresses")
	}
	if !g.allowed("admin", "192.0.2.50", now) {
		t.Fatal("the administrator's known address was locked out by someone else's guessing")
	}
	later := now.Add(knownAddressTTL + time.Hour)
	g.failure("admin", "203.0.113.201", later) // keeps the user counter fresh in the new window
	if !g.allowed("admin", "203.0.113.200", later.Add(20*time.Minute)) {
		t.Fatal("the block never ends")
	}
}

func TestLoginGuard_UnknownSourceFallsBackToPerUsername(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	for i := 0; i < pairMaxFailures; i++ {
		g.failure("admin", "", now)
	}
	if g.allowed("admin", "", now) {
		t.Fatal("with no known address the per-username limit did not apply")
	}
}

// A blocked client that keeps retrying writes one security-log row.
func TestLoginGuard_ABlockedRetryLoopIsLoggedOnce(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	logged := 0
	for i := 0; i < 500; i++ {
		if g.shouldLogBlock("admin", "203.0.113.9", now.Add(time.Duration(i)*time.Second)) {
			logged++
		}
	}
	if logged != 1 {
		t.Fatalf("%d rows for one blocked client", logged)
	}
	if !g.shouldLogBlock("admin", "203.0.113.9", now.Add(g.pair.window+time.Minute)) {
		t.Fatal("the next window's block was not logged")
	}
}

func TestLoginGuard_TablesStayBounded(t *testing.T) {
	g := newLoginGuard()
	now := time.Now()
	for i := 0; i < maxTrackedAddrs*3; i++ {
		u := "u" + string(rune(i))
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		g.success(u, a, now)
		g.shouldLogBlock(u, a, now)
	}
	if len(g.known) > maxTrackedAddrs || len(g.blockLogged) > maxTrackedAddrs {
		t.Fatalf("known=%d blockLogged=%d, limit %d", len(g.known), len(g.blockLogged), maxTrackedAddrs)
	}
}

// ---- which address a request is counted against ----

func reqFrom(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func TestClientAddr(t *testing.T) {
	proxy := AuthConfig{TrustedProxies: prefixes(t, "10.0.0.5/32", "10.0.1.0/24")}
	cases := []struct {
		name string
		cfg  AuthConfig
		req  *http.Request
		want string
	}{
		{"direct client", AuthConfig{}, reqFrom("203.0.113.9:5555"), "203.0.113.9"},
		{"a forged header from a client is ignored", AuthConfig{},
			reqFrom("203.0.113.9:5555", "1.2.3.4"), "203.0.113.9"},
		{"a forged header from an untrusted peer is ignored even when proxies are set", proxy,
			reqFrom("203.0.113.9:5555", "1.2.3.4"), "203.0.113.9"},
		{"trusted proxy: the client it saw", proxy,
			reqFrom("10.0.0.5:4444", "198.51.100.7"), "198.51.100.7"},
		{"the client's own forged entry is to the left and is not believed", proxy,
			reqFrom("10.0.0.5:4444", "1.2.3.4, 198.51.100.7"), "198.51.100.7"},
		{"two trusted hops", proxy,
			reqFrom("10.0.0.5:4444", "198.51.100.7, 10.0.1.9"), "198.51.100.7"},
		{"header split over lines", proxy,
			reqFrom("10.0.0.5:4444", "1.2.3.4", "198.51.100.7"), "198.51.100.7"},
		{"an unreadable entry counts the proxy, it does not guess", proxy,
			reqFrom("10.0.0.5:4444", "198.51.100.7, not-an-ip"), "10.0.0.5"},
		{"trusted proxy that sent no header", proxy, reqFrom("10.0.0.5:4444"), "10.0.0.5"},
		{"IPv6 is counted per /64", AuthConfig{},
			reqFrom("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:80"), "2001:db8:1:2::/64"},
		{"another address in the same /64 is the same source", AuthConfig{},
			reqFrom("[2001:db8:1:2:1111:2222:3333:4444]:80"), "2001:db8:1:2::/64"},
		{"an IPv4-mapped address is IPv4", AuthConfig{}, reqFrom("[::ffff:203.0.113.9]:80"), "203.0.113.9"},
		{"behind a proxy with none configured the client is unknown", AuthConfig{BehindProxy: true},
			reqFrom("127.0.0.1:4444", "198.51.100.7"), ""},
		{"unreadable peer", AuthConfig{}, reqFrom("garbage"), ""},
	}
	for _, c := range cases {
		if got := c.cfg.clientAddr(c.req); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// ---- through the real login handler ----

func newGuardFixture(t *testing.T, cfg AuthConfig) *authFixture {
	t.Helper()
	svc := newTestService(t)
	cfg.Enabled, cfg.SessionTTL = true, time.Hour
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	return &authFixture{svc: svc, mux: dashboardLike(NewRouterWithAuth(svc, logger, testMaxUploadBytes, false, cfg))}
}

func (f *authFixture) loginFrom(remote, xff, username, password string) int {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Code
}

// The administrator logs in from their own address while an attacker is blocked
// for failing ten times on the same account.
func TestLogin_AnAttackerFailingTenTimesDoesNotLockTheAdministratorOut(t *testing.T) {
	f := newGuardFixture(t, AuthConfig{})
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)

	blocked := false
	for i := 0; i < 15; i++ {
		if f.loginFrom("203.0.113.9:1000", "", "admin1", "wrong-password") == http.StatusTooManyRequests {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("the attacker was never throttled")
	}
	if code := f.loginFrom("203.0.113.9:1000", "", "admin1", "admin-password-here"); code == http.StatusOK {
		t.Fatal("the throttle let the attacker in with the right password during the block")
	}
	if code := f.loginFrom("192.0.2.50:2000", "", "admin1", "admin-password-here"); code != http.StatusOK {
		t.Fatalf("the administrator was locked out by someone else's failures: status %d", code)
	}
}

// A client that sets X-Forwarded-For itself cannot get a fresh budget by
// changing it, because the header is believed only from a configured proxy.
func TestLogin_ForgingForwardedForDoesNotResetTheBudget(t *testing.T) {
	f := newGuardFixture(t, AuthConfig{TrustedProxies: prefixes(t, "10.0.0.5/32")})
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	blocked := false
	for i := 0; i < 20; i++ {
		forged := "198.51.100." + string(rune('1'+i%9))
		if f.loginFrom("203.0.113.9:1000", forged, "alice", "wrong-password") == http.StatusTooManyRequests {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("rotating a forged X-Forwarded-For defeated the throttle")
	}
}

// Behind a proxy that is configured, each real client has their own budget.
func TestLogin_BehindATrustedProxyClientsAreCountedSeparately(t *testing.T) {
	f := newGuardFixture(t, AuthConfig{TrustedProxies: prefixes(t, "10.0.0.5/32"), BehindProxy: true})
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	for i := 0; i < 15; i++ {
		f.loginFrom("10.0.0.5:4444", "203.0.113.9", "alice", "wrong-password")
	}
	if code := f.loginFrom("10.0.0.5:4444", "198.51.100.77", "alice", "correct-horse-battery"); code != http.StatusOK {
		t.Fatalf("another client behind the same proxy was blocked: status %d", code)
	}
}

// Fifty refused retries leave one row in the security log.
func TestLogin_ABlockedRetryLoopDoesNotFloodTheSecurityLog(t *testing.T) {
	f := newGuardFixture(t, AuthConfig{})
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	for i := 0; i < pairMaxFailures; i++ {
		f.loginFrom("203.0.113.9:1000", "", "alice", "wrong-password")
	}
	before := securityRows(t, f)
	for i := 0; i < 50; i++ {
		if code := f.loginFrom("203.0.113.9:1000", "", "alice", "wrong-password"); code != http.StatusTooManyRequests {
			t.Fatalf("retry %d: status %d, want 429", i, code)
		}
	}
	if added := securityRows(t, f) - before; added > 1 {
		t.Fatalf("50 refused retries wrote %d security-log rows", added)
	}
}

func securityRows(t *testing.T, f *authFixture) int {
	t.Helper()
	rows, err := f.svc.store.ListSecurityLog(100000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if strings.Contains(r.Summary, "Login") {
			n++
		}
	}
	return n
}
