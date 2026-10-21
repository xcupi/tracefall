package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// loginGuard decides whether a login attempt may be tried, from three counters
// of failed attempts instead of one:
//
//	user+address   10 per window   the guesser's own budget against one account
//	address        30 per window   one source spraying many accounts
//	user           100 per window  all sources together, bounds a distributed guess
//
// A single per-username counter lets anyone lock any account by failing ten
// times, which is a denial of service on the administrator. With the counters
// above, a source can exhaust only its own budget. Someone who needs to lock
// the account for everyone must fail 100 times from at least four addresses in
// one window, and an address that has already logged in as that user is not
// subject to the all-sources counter at all.
//
// In memory, like loginThrottle: operational state that must not survive a
// restart or be written to the database on every guess.
type loginGuard struct {
	pair, addr, user *loginThrottle

	mu sync.Mutex
	// known remembers addresses that logged in successfully as a user.
	known map[string]time.Time
	// blockLogged marks keys whose refusal is already in the security log,
	// so a blocked client retrying in a loop writes one row, not thousands.
	blockLogged map[string]time.Time
}

const (
	pairMaxFailures = 10
	addrMaxFailures = 30
	userMaxFailures = 100
	// knownAddressTTL is how long a successful login keeps its address
	// exempt from the all-sources counter.
	knownAddressTTL = 30 * 24 * time.Hour
	maxTrackedAddrs = 10000
)

func newLoginGuard() *loginGuard {
	return &loginGuard{
		pair:        newThrottleWithMax(pairMaxFailures),
		addr:        newThrottleWithMax(addrMaxFailures),
		user:        newThrottleWithMax(userMaxFailures),
		known:       map[string]time.Time{},
		blockLogged: map[string]time.Time{},
	}
}

func pairKey(user, addr string) string { return user + "|" + addr }

// allowed reports whether another attempt may be made. addr is empty when the
// source address is not known (see AuthConfig.clientAddr); the per-address
// counter is then skipped, and the pair key degrades to the username alone.
func (g *loginGuard) allowed(user, addr string, now time.Time) bool {
	if !g.pair.allowed(pairKey(user, addr), now) {
		return false
	}
	if addr != "" && !g.addr.allowed(addr, now) {
		return false
	}
	if g.user.allowed(user, now) {
		return true
	}
	// Past the all-sources limit: only an address that has logged in as this
	// user before is still let through.
	return addr != "" && g.isKnown(user, addr, now)
}

func (g *loginGuard) failure(user, addr string, now time.Time) {
	g.pair.recordFailure(pairKey(user, addr), now)
	if addr != "" {
		g.addr.recordFailure(addr, now)
	}
	g.user.recordFailure(user, now)
}

func (g *loginGuard) success(user, addr string, now time.Time) {
	g.pair.reset(pairKey(user, addr))
	if addr == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.known) >= maxTrackedAddrs {
		for k, t := range g.known {
			if now.Sub(t) > knownAddressTTL {
				delete(g.known, k)
			}
		}
		if len(g.known) >= maxTrackedAddrs {
			return // full of live entries: do not grow
		}
	}
	g.known[pairKey(user, addr)] = now
}

func (g *loginGuard) isKnown(user, addr string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.known[pairKey(user, addr)]
	return ok && now.Sub(t) <= knownAddressTTL
}

// shouldLogBlock is true the first time a given client is refused in a window.
func (g *loginGuard) shouldLogBlock(user, addr string, now time.Time) bool {
	key := pairKey(user, addr)
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.blockLogged[key]; ok && now.Sub(t) <= g.pair.window {
		return false
	}
	if len(g.blockLogged) >= maxTrackedAddrs {
		for k, t := range g.blockLogged {
			if now.Sub(t) > g.pair.window {
				delete(g.blockLogged, k)
			}
		}
		if len(g.blockLogged) >= maxTrackedAddrs {
			return false // a flood from many sources: one row each is too many
		}
	}
	g.blockLogged[key] = now
	return true
}

// clientAddr is the address a request should be counted against. It is the
// peer's address, unless the peer is a configured trusted proxy, in which case
// it is the nearest address in X-Forwarded-For that is not itself a trusted
// proxy. The header is ignored from any other peer, because anyone can send it.
//
// IPv6 addresses are counted per /64, the smallest block an ISP hands to one
// customer; counting single addresses would give an attacker 2^64 of them.
//
// It returns "" when the real client cannot be known: the deployment is behind
// a proxy (--insecure-http) but no proxy address is configured, so every
// request would otherwise appear to come from the proxy and one attacker would
// lock everybody out.
func (c AuthConfig) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return ""
	}
	peer = peer.Unmap()
	if len(c.TrustedProxies) == 0 {
		if c.BehindProxy {
			return ""
		}
		return addrKey(peer)
	}
	if !c.trusted(peer) {
		return addrKey(peer)
	}
	// Walk X-Forwarded-For from the right: each trusted proxy appended the
	// address it saw, so the first address that is not a trusted proxy is the
	// client as the outermost trusted proxy saw it.
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addrKey(peer) // unreadable: do not guess, count the proxy
		}
		a = a.Unmap()
		if !c.trusted(a) {
			return addrKey(a)
		}
	}
	return addrKey(peer)
}

func (c AuthConfig) trusted(a netip.Addr) bool {
	for _, p := range c.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func addrKey(a netip.Addr) string {
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}
