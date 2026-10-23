// Package pseudonym replaces the names in a case with tokens before any text
// about the case is sent to an outside service, and puts them back afterwards.
//
// It is the heart of the "pseudonymized" egress level (internal/egress): what
// the outside service receives about a host, a user, an address, a domain, a
// security identifier, an e-mail address or a file hash is a token such as
// [HOST_1] or [IP_PRIV_3]. The same value always gets the same token within
// one Pseudonymizer, so the service can still reason about "the same host" or
// "the same account"; only the Pseudonymizer, which stays on this server, can
// turn a token back into the value.
//
// Names are found two ways, and both are used:
//
//   - Dictionary: the case's own hosts, users and domains are taught with
//     Learn, and every occurrence of one is replaced wherever it appears,
//     including inside a command line or a path. This catches names no
//     pattern would recognise.
//   - Patterns: addresses, e-mail, security identifiers, URLs, UNC paths, user
//     profile paths, hashes and long encoded blobs are found by shape.
//
// Secrets (a password on a command line, a bearer token) are removed, not
// tokenized: they are never reversible, because nothing about them is useful to
// an outside reader and putting one back could only cause harm.
//
// Leaks is the check run on the finished text before it leaves: if anything the
// Pseudonymizer knows is still there, the caller must not send it.
//
// Tokenizing is a risk reduction, not anonymity. Timestamps, process names and
// the shape of the activity still say something about a case; the egress level
// is the analyst's decision to accept that, which is why it is explicit.
package pseudonym

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Kind is what a token stands for.
type Kind string

const (
	Host   Kind = "HOST"
	User   Kind = "USER"
	Domain Kind = "DOMAIN"
	IPPriv Kind = "IP_PRIV"
	IPPub  Kind = "IP_PUB"
	SID    Kind = "SIDDOM"
	Email  Kind = "EMAIL"
	Hash   Kind = "HASH"
	Blob   Kind = "BLOB"
)

// Redacted replaces a secret. It is the same text every time and cannot be
// reversed.
const Redacted = "[REDACTED]"

// tokenRe matches a token this package produces (or a lookalike).
var tokenRe = regexp.MustCompile(`\[(?:HOST|USER|DOMAIN|IP_PRIV|IP_PUB|SIDDOM|EMAIL|HASH|BLOB)_\d+(?:\.\d+)?\]|\[REDACTED\]`)

// lookalikeRe matches text that already looks like a token, so that it can be
// neutralised before real tokens are inserted: otherwise Restore could put a
// value where the evidence merely contained text that resembled a token.
var lookalikeRe = regexp.MustCompile(`\[((?:HOST|USER|DOMAIN|IP_PRIV|IP_PUB|SIDDOM|EMAIL|HASH|BLOB)_\d+|REDACTED)\]`)

// notIdentifying are names that say nothing about whose system it is.
// Tokenizing them would only hide the account kind from the reader.
var notIdentifying = map[string]bool{
	"system": true, "local service": true, "network service": true, "anonymous logon": true,
	"administrator": true, "guest": true, "localhost": true, "nt authority": true, "builtin": true,
	"nt service": true, "window manager": true, "font driver host": true, "dwm-1": true, "dwm-2": true,
	"umfd-0": true, "umfd-1": true, "-": true, "n/a": true, "none": true, "unknown": true,
}

type entry struct {
	Token string
	Kind  Kind
	Value string
}

// Pseudonymizer holds the values of one case and the tokens given to them. It
// is safe for concurrent use.
type Pseudonymizer struct {
	mu      sync.Mutex
	tok     map[string]string // lower(value) -> token
	rev     map[string]string // token -> first-seen value
	kinds   map[string]Kind   // token -> kind
	next    map[Kind]int
	dict    map[byte][]string // first byte of lower(value) -> values, longest first
	dictAll map[string]Kind   // lower(value) -> kind
	dirty   bool
}

// New returns an empty Pseudonymizer.
func New() *Pseudonymizer {
	return &Pseudonymizer{tok: map[string]string{}, rev: map[string]string{}, kinds: map[string]Kind{},
		next: map[Kind]int{}, dict: map[byte][]string{}, dictAll: map[string]Kind{}}
}

// Learn teaches a value that belongs to the case: a host, a user or a domain.
// Every later occurrence of it, in any text passed to Apply, becomes a token.
//
// Learning a user given as DOMAIN\name or name@domain teaches the parts.
// Values that name no one in particular (SYSTEM, LOCAL SERVICE, ...) and
// values shorter than two characters are ignored.
func (p *Pseudonymizer) Learn(k Kind, value string) {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, '\\'); i > 0 && k == User {
		p.Learn(Domain, value[:i])
		p.Learn(User, value[i+1:])
		return
	}
	if i := strings.IndexByte(value, '@'); i > 0 && k == User && !strings.Contains(value[i+1:], "@") {
		p.Learn(User, value[:i])
		p.Learn(Domain, value[i+1:])
		return
	}
	// a machine account is the host's name with a $
	if k == User && strings.HasSuffix(value, "$") && len(value) > 2 {
		p.Learn(Host, strings.TrimSuffix(value, "$"))
		return
	}
	lv := strings.ToLower(value)
	if len(lv) < 2 || notIdentifying[lv] {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.dictAll[lv]; ok {
		return
	}
	p.dictAll[lv] = k
	p.dirty = true
}

// tokenFor returns the token for a value, creating it on first use.
func (p *Pseudonymizer) tokenFor(k Kind, value string) string {
	lv := strings.ToLower(value)
	if t, ok := p.tok[lv]; ok {
		return t
	}
	p.next[k]++
	t := fmt.Sprintf("[%s_%d]", k, p.next[k])
	p.tok[lv] = t
	p.rev[t] = value
	p.kinds[t] = k
	return t
}

func (p *Pseudonymizer) token(k Kind, value string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenFor(k, value)
}

func (p *Pseudonymizer) rebuildLocked() {
	if !p.dirty {
		return
	}
	p.dict = map[byte][]string{}
	for v := range p.dictAll {
		p.dict[v[0]] = append(p.dict[v[0]], v)
	}
	for b := range p.dict {
		l := p.dict[b]
		sort.Slice(l, func(i, j int) bool {
			if len(l[i]) != len(l[j]) {
				return len(l[i]) > len(l[j])
			}
			return l[i] < l[j]
		})
	}
	p.dirty = false
}

var (
	// secrets: the value after one of these is removed.
	secretFlagRe = regexp.MustCompile(`(?i)(^|[\s"'])((?:--?|/)(?:password|passwd|pass|pwd|secret|token|apikey|api-key|accesskey|client-secret|credential)(?:[=:]|\s+))("[^"]*"|'[^']*'|\S+)`)
	secretKVRe   = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization)\b(\s*[=:]\s*)("[^"]*"|'[^']*'|(?:bearer|basic)\s+\S+|\S+)`)
	secureStrRe  = regexp.MustCompile(`(?i)(convertto-securestring\s+)("[^"]*"|'[^']*'|\S+)`)
	netUseRe     = regexp.MustCompile(`(?i)(\bnet\s+use\s+\S+\s+)("[^"]*"|\S+)(\s+/user:)`)

	urlHostRe    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,15}://)((?:[^\s/@:"']+(?::[^\s/@"']*)?@)?)(\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*[a-z0-9])`)
	uncRe        = regexp.MustCompile(`(^|[\s"'=(,;])(\\\\)([A-Za-z0-9][A-Za-z0-9._-]*)([\\/]|\b)`)
	emailRe      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	sidRe        = regexp.MustCompile(`\bS-1-5-21-(\d{3,10})-(\d{3,10})-(\d{3,10})(-\d{1,10})?`)
	ipv4Re       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	ipv6Re       = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?\b`)
	hashRe       = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b`)
	blobRe       = regexp.MustCompile(`[A-Za-z0-9+/]{48,}={0,2}`)
	profileRe    = regexp.MustCompile(`(?i)((?:[a-z]:)?[\\/](?:users|documents and settings|home)[\\/])([^\\/\s"']+)`)
	domainWordRe = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b`)
)

// tlds are the endings that make a dotted word a host or domain name. A list
// of names is used, not "anything with a dot": System.Management.Automation and
// Microsoft.PowerShell.Core are not hosts, and tokenizing them would make a
// command line unreadable. The case's own domains are caught by the dictionary
// whatever their ending.
var tlds = map[string]bool{}

func init() {
	for _, t := range strings.Fields(`com net org edu gov mil int io co info biz xyz ru cn de uk fr jp br in au ca nl it es
		se no fi ch at be dk cz ua kr tw hk sg tr ir id vn th my mx ar za nz online site top club shop app dev cloud tech
		live pro me tv ws to su eu us local lan corp internal home intranet test example invalid localdomain onion`) {
		tlds[t] = true
	}
}

func isLoopback(a netip.Addr) bool { return a.IsLoopback() || a.IsUnspecified() }

func ipKind(a netip.Addr) Kind {
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
		return IPPriv
	}
	return IPPub
}

// Apply returns s with secrets removed and every name this Pseudonymizer knows,
// or recognises by shape, replaced by a token.
func (p *Pseudonymizer) Apply(s string) string {
	if s == "" {
		return s
	}
	// text that merely looks like a token must not be mistaken for one later
	s = lookalikeRe.ReplaceAllString(s, "($1)")

	// 1. secrets first, so that none of one is tokenized into a reversible form
	s = secretFlagRe.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = secretKVRe.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = secureStrRe.ReplaceAllString(s, "${1}"+Redacted)
	s = netUseRe.ReplaceAllString(s, "${1}"+Redacted+"${3}")

	// 2. shapes. Each works on text outside tokens only.
	s = p.outside(s, func(seg string) string {
		seg = urlHostRe.ReplaceAllStringFunc(seg, func(m string) string {
			sub := urlHostRe.FindStringSubmatch(m)
			// credentials in a URL are secrets: dropped, never tokenized
			userinfo := ""
			if sub[2] != "" {
				userinfo = Redacted + "@"
			}
			host := strings.Trim(sub[3], "[]")
			if a, err := netip.ParseAddr(host); err == nil {
				if isLoopback(a) {
					return sub[1] + userinfo + sub[3]
				}
				return sub[1] + userinfo + p.token(ipKind(a), a.String())
			}
			return sub[1] + userinfo + p.token(Domain, host)
		})
		seg = uncRe.ReplaceAllStringFunc(seg, func(m string) string {
			sub := uncRe.FindStringSubmatch(m)
			name := sub[3]
			if a, err := netip.ParseAddr(name); err == nil {
				if isLoopback(a) {
					return m
				}
				return sub[1] + sub[2] + p.token(ipKind(a), a.String()) + sub[4]
			}
			if notIdentifying[strings.ToLower(name)] {
				return m
			}
			return sub[1] + sub[2] + p.token(Host, name) + sub[4]
		})
		seg = emailRe.ReplaceAllStringFunc(seg, func(m string) string { return p.token(Email, m) })
		seg = sidRe.ReplaceAllStringFunc(seg, func(m string) string {
			sub := sidRe.FindStringSubmatch(m)
			dom := sub[1] + "-" + sub[2] + "-" + sub[3]
			return "S-1-5-21-" + p.token(SID, dom) + sub[4]
		})
		seg = hashRe.ReplaceAllStringFunc(seg, func(m string) string { return p.token(Hash, strings.ToLower(m)) })
		seg = ipv4Re.ReplaceAllStringFunc(seg, func(m string) string {
			a, err := netip.ParseAddr(m)
			if err != nil || isLoopback(a) {
				return m
			}
			return p.token(ipKind(a), a.String())
		})
		seg = ipv6Re.ReplaceAllStringFunc(seg, func(m string) string {
			a, err := netip.ParseAddr(m)
			if err != nil || isLoopback(a) {
				return m
			}
			return p.token(ipKind(a), a.String())
		})
		seg = profileRe.ReplaceAllStringFunc(seg, func(m string) string {
			sub := profileRe.FindStringSubmatch(m)
			n := sub[2]
			if notIdentifying[strings.ToLower(n)] || strings.EqualFold(n, "public") || strings.EqualFold(n, "default") || strings.EqualFold(n, "all users") || strings.EqualFold(n, "default user") {
				return m
			}
			return sub[1] + p.token(User, n)
		})
		seg = blobRe.ReplaceAllStringFunc(seg, func(m string) string {
			return p.token(Blob, fmt.Sprintf("%d-chars-%x", len(m), fnv32(m)))
		})
		// a dotted word that is not a file name is a host or domain name
		seg = domainWordRe.ReplaceAllStringFunc(seg, func(m string) string {
			i := strings.LastIndexByte(m, '.')
			if !tlds[strings.ToLower(m[i+1:])] || isAllDigits(strings.ReplaceAll(m, ".", "")) {
				return m
			}
			return p.token(Domain, m)
		})
		return seg
	})

	// 3. the case's own names, anywhere they appear
	p.mu.Lock()
	p.rebuildLocked()
	p.mu.Unlock()
	s = p.outside(s, p.replaceDict)
	return s
}

// outside applies f to the parts of s that are not tokens.
func (p *Pseudonymizer) outside(s string, f func(string) string) string {
	locs := tokenRe.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return f(s)
	}
	var b strings.Builder
	prev := 0
	for _, l := range locs {
		b.WriteString(f(s[prev:l[0]]))
		b.WriteString(s[l[0]:l[1]])
		prev = l[1]
	}
	b.WriteString(f(s[prev:]))
	return b.String()
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// replaceDict replaces learned values, longest first, only where they are not
// part of a longer word.
func (p *Pseudonymizer) replaceDict(seg string) string {
	if seg == "" {
		return seg
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.dictAll) == 0 {
		return seg
	}
	low := strings.ToLower(seg)
	if len(low) != len(seg) {
		// case folding changed the length (rare Unicode): work on the folded text,
		// which can only over-replace
		seg = low
	}
	var b strings.Builder
	i := 0
	for i < len(low) {
		matched := false
		if (i == 0 || !isWordByte(low[i-1])) && len(p.dict[low[i]]) > 0 {
			for _, v := range p.dict[low[i]] {
				if strings.HasPrefix(low[i:], v) && (i+len(v) == len(low) || !isWordByte(low[i+len(v)])) {
					b.WriteString(p.tokenFor(p.dictAll[v], seg[i:i+len(v)]))
					i += len(v)
					matched = true
					break
				}
			}
		}
		if !matched {
			b.WriteByte(seg[i])
			i++
		}
	}
	return b.String()
}

// Restore puts the values back in place of the tokens this Pseudonymizer
// issued. Text that is not one of its tokens is left alone. The case of a
// restored name is the case it was first seen in.
func (p *Pseudonymizer) Restore(s string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	s = tokenRe.ReplaceAllStringFunc(s, func(t string) string {
		if v, ok := p.rev[t]; ok {
			return v
		}
		return t
	})
	// a lookalike that Apply neutralised as (HOST_1) is not restored: it was
	// never a token, and it reads as the evidence wrote it
	return s
}

// Leaks says which kinds of identifying text are still in s. It reports kinds
// only, never values, so its result can be logged. An empty result means that
// nothing this Pseudonymizer knows, and no address, e-mail, security
// identifier or hash, remains outside a token.
func (p *Pseudonymizer) Leaks(s string) []string {
	found := map[string]bool{}
	p.mu.Lock()
	p.rebuildLocked()
	p.mu.Unlock()
	p.outside(s, func(seg string) string {
		low := strings.ToLower(seg)
		p.mu.Lock()
		for i := 0; i < len(low); i++ {
			if i > 0 && isWordByte(low[i-1]) {
				continue
			}
			for _, v := range p.dict[low[i]] {
				if strings.HasPrefix(low[i:], v) && (i+len(v) == len(low) || !isWordByte(low[i+len(v)])) {
					found["a name learned from the case ("+string(p.dictAll[v])+")"] = true
					break
				}
			}
		}
		p.mu.Unlock()
		for _, m := range ipv4Re.FindAllString(seg, -1) {
			if a, err := netip.ParseAddr(m); err == nil && !isLoopback(a) {
				found["an IPv4 address"] = true
			}
		}
		if emailRe.MatchString(seg) {
			found["an e-mail address"] = true
		}
		if sidRe.MatchString(seg) {
			found["a domain security identifier"] = true
		}
		if hashRe.MatchString(seg) {
			found["a hash"] = true
		}
		if secretFlagRe.MatchString(seg) || secretKVRe.MatchString(seg) {
			found["a secret"] = true
		}
		return seg
	})
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Entry is one token and the value it stands for.
type Entry struct {
	Token string `json:"token"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Entries lists what has been tokenized so far, by token. The values are the
// case's names: this is for the analyst's eyes on this server, never for the
// outside service.
func (p *Pseudonymizer) Entries() []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Entry, 0, len(p.rev))
	for t, v := range p.rev {
		out = append(out, Entry{Token: t, Kind: string(p.kinds[t]), Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// Tokens returns the tokens that appear in s, in order, each once.
func Tokens(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tokenRe.FindAllString(s, -1) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// Issued reports whether this Pseudonymizer issued the token (or it is the
// fixed redaction mark). A token that merely has the right shape, such as one
// a model made up, is not issued.
func (p *Pseudonymizer) Issued(token string) bool {
	if token == Redacted {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.rev[token]
	return ok
}

// TruncateRunes shortens s to at most n runes without cutting a token in two:
// half of a token is neither a token nor a name, and would only confuse a
// reader. A cut text ends with an ellipsis.
func TruncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := string(r[:n])
	if i := strings.LastIndexByte(cut, '['); i >= 0 && !strings.Contains(cut[i:], "]") {
		cut = cut[:i]
	}
	return cut + "..."
}
