package modkit

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"golang.org/x/net/publicsuffix"
)

const cookiePolicyCacheSize = 4096
const cookiePolicyVersionsPerScope = 8

// CookiePolicy is the security-relevant, non-secret portion of one Set-Cookie
// header. Values are intentionally not retained.
type CookiePolicy struct {
	Name        string
	Domain      string
	Path        string
	SameSite    string
	Secure      bool
	HTTPOnly    bool
	Partitioned bool

	// ValueFingerprint binds attributes to the cookie instance that supplied
	// them without retaining or exposing the secret value.
	ValueFingerprint string
}

func cookieValueFingerprint(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

// ParseSetCookiePolicy parses attributes by token name rather than substring.
func ParseSetCookiePolicy(raw string) (CookiePolicy, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= len("set-cookie:") && strings.EqualFold(raw[:len("set-cookie:")], "set-cookie:") {
		raw = strings.TrimSpace(raw[len("set-cookie:"):])
	}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return CookiePolicy{}, false
	}
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameValue) != 2 || strings.TrimSpace(nameValue[0]) == "" {
		return CookiePolicy{}, false
	}
	p := CookiePolicy{
		Name:             strings.TrimSpace(nameValue[0]),
		ValueFingerprint: cookieValueFingerprint(nameValue[1]),
	}
	for _, part := range parts[1:] {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		name := strings.ToLower(strings.TrimSpace(kv[0]))
		value := ""
		if len(kv) == 2 {
			value = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
		switch name {
		case "secure":
			p.Secure = true
		case "httponly":
			p.HTTPOnly = true
		case "partitioned":
			p.Partitioned = true
		case "domain":
			p.Domain = strings.TrimPrefix(strings.ToLower(value), ".")
		case "path":
			p.Path = value
		case "samesite":
			p.SameSite = strings.ToLower(value)
		}
	}
	return p, true
}

// LikelySessionCookie reports whether a cookie name carries authentication or
// session state. CSRF tokens are explicitly excluded.
func LikelySessionCookie(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") {
		return false
	}
	for _, marker := range []string{"session", "sess", "sid", "auth", "access_token", "id_token", "jwt", "sso", "login", "remember"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// RequestCookieNames parses the names from a Cookie request header.
func RequestCookieNames(header string) []string {
	var names []string
	for _, pair := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) != "" {
			names = append(names, strings.TrimSpace(kv[0]))
		}
	}
	return names
}

// CookiePolicyRegistry retains bounded, scan-local cookie posture by origin.
type CookiePolicyRegistry struct {
	once  sync.Once
	mu    sync.Mutex
	cache *lru.Cache[string, []CookiePolicy]
}

func (r *CookiePolicyRegistry) get() *lru.Cache[string, []CookiePolicy] {
	r.once.Do(func() { r.cache, _ = lru.New[string, []CookiePolicy](cookiePolicyCacheSize) })
	return r.cache
}

func cookiePolicyKey(host, name string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strings.ToLower(strings.TrimSpace(name))
}

func (r *CookiePolicyRegistry) Add(host string, policy CookiePolicy) {
	if r == nil || host == "" || policy.Name == "" {
		return
	}
	scopeHost := strings.ToLower(strings.TrimSpace(host))
	if policy.Domain != "" {
		scopeHost = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(policy.Domain), "."))
		policy.Domain = scopeHost
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := cookiePolicyKey(scopeHost, policy.Name)
	existing, _ := r.get().Get(key)
	updated := make([]CookiePolicy, 0, min(len(existing)+1, cookiePolicyVersionsPerScope))
	updated = append(updated, policy)
	for _, previous := range existing {
		if strings.EqualFold(previous.Domain, policy.Domain) && previous.Path == policy.Path && previous.ValueFingerprint == policy.ValueFingerprint {
			continue
		}
		updated = append(updated, previous)
		if len(updated) == cookiePolicyVersionsPerScope {
			break
		}
	}
	r.get().Add(key, updated)
}

func (r *CookiePolicyRegistry) Get(host, name string) (CookiePolicy, bool) {
	return r.Resolve(host, "/", name)
}

// Resolve selects the most specific policy that could have produced a cookie
// carried to host/path. Host-only cookies never flow to sibling subdomains;
// Domain cookies do, and the longest matching Path wins when names collide.
func (r *CookiePolicyRegistry) Resolve(host, path, name string) (CookiePolicy, bool) {
	return r.resolve(host, path, name, "")
}

func (r *CookiePolicyRegistry) resolve(host, path, name, valueFingerprint string) (CookiePolicy, bool) {
	if r == nil {
		return CookiePolicy{}, false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || name == "" {
		return CookiePolicy{}, false
	}
	if path == "" || path[0] != '/' {
		path = "/"
	}

	bestScore := -1
	var best CookiePolicy
	for _, scopeHost := range cookieDomainScopes(host) {
		policies, ok := r.get().Get(cookiePolicyKey(scopeHost, name))
		if !ok {
			continue
		}
		for _, policy := range policies {
			if valueFingerprint != "" && policy.ValueFingerprint != "" && policy.ValueFingerprint != valueFingerprint {
				continue
			}
			if policy.Domain == "" {
				if scopeHost != host {
					continue
				}
			} else if !cookieDomainMatches(host, policy.Domain) {
				continue
			}
			if !cookiePathMatches(path, policy.Path) {
				continue
			}
			score := len(policy.Path)
			if score > bestScore {
				bestScore = score
				best = policy
			}
		}
	}
	return best, bestScore >= 0
}

// browserAcceptsCookiePolicy rejects policies a browser would ignore. Keeping
// them as cross-request evidence could otherwise promote a CORS/CSRF candidate
// using a cookie that was never browser-sendable.
func browserAcceptsCookiePolicy(host, scheme string, policy CookiePolicy) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	secureOrigin := strings.EqualFold(scheme, "https") || host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		secureOrigin = secureOrigin || ip.IsLoopback()
		if policy.Domain != "" && policy.Domain != host {
			return false
		}
	} else if policy.Domain != "" {
		if !cookieDomainMatches(host, policy.Domain) {
			return false
		}
		if suffix, icann := publicsuffix.PublicSuffix(policy.Domain); suffix == policy.Domain && (icann || strings.Contains(policy.Domain, ".")) {
			return false
		}
	}

	if policy.Secure && !secureOrigin {
		return false
	}
	if policy.SameSite == "none" && !policy.Secure {
		return false
	}
	if policy.Partitioned && !policy.Secure {
		return false
	}
	name := strings.ToLower(policy.Name)
	if strings.HasPrefix(name, "__secure-") && (!policy.Secure || !secureOrigin) {
		return false
	}
	if strings.HasPrefix(name, "__host-") && (!policy.Secure || !secureOrigin || policy.Domain != "" || policy.Path != "/") {
		return false
	}
	if strings.HasPrefix(name, "__http-") && (!policy.Secure || !policy.HTTPOnly || !secureOrigin) {
		return false
	}
	if strings.HasPrefix(name, "__host-http-") && (!policy.Secure || !policy.HTTPOnly || !secureOrigin || policy.Domain != "" || policy.Path != "/") {
		return false
	}
	return true
}

func cookieDomainScopes(host string) []string {
	scopes := []string{host}
	for i := strings.IndexByte(host, '.'); i >= 0 && i+1 < len(host); i = strings.IndexByte(host, '.') {
		host = host[i+1:]
		scopes = append(scopes, host)
	}
	return scopes
}

func cookieDomainMatches(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func cookiePathMatches(requestPath, cookiePath string) bool {
	if cookiePath == "" {
		cookiePath = "/"
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || (len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/')
}

func defaultCookiePath(requestPath string) string {
	if requestPath == "" || requestPath[0] != '/' || requestPath == "/" {
		return "/"
	}
	lastSlash := strings.LastIndexByte(requestPath, '/')
	if lastSlash <= 0 {
		return "/"
	}
	return requestPath[:lastSlash]
}

// ObserveResponseCookies records every Set-Cookie policy from an HTTP exchange.
func (sc *ScanContext) ObserveResponseCookies(rr *httpmsg.HttpRequestResponse) {
	if sc == nil || rr == nil || rr.Response() == nil {
		return
	}
	u, err := rr.URL()
	if err != nil {
		return
	}
	for _, h := range rr.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if policy, ok := ParseSetCookiePolicy(h.Value); ok {
			if policy.Path == "" || !strings.HasPrefix(policy.Path, "/") {
				policy.Path = defaultCookiePath(u.Path)
			}
			if browserAcceptsCookiePolicy(u.Hostname(), u.Scheme, policy) {
				sc.cookiePolicies().Add(u.Hostname(), policy)
			}
		}
	}
}

// RequestCookiePolicies resolves policies previously observed for cookies used
// by this request. Unknown cookies are omitted.
func (sc *ScanContext) RequestCookiePolicies(rr *httpmsg.HttpRequestResponse) []CookiePolicy {
	if sc == nil || rr == nil || rr.Request() == nil {
		return nil
	}
	u, err := rr.URL()
	if err != nil {
		return nil
	}
	var policies []CookiePolicy
	for _, pair := range strings.Split(rr.Request().Header("Cookie"), ";") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
			continue
		}
		name := strings.TrimSpace(kv[0])
		fingerprint := cookieValueFingerprint(kv[1])
		if p, ok := sc.cookiePolicies().resolve(u.Hostname(), u.Path, name, fingerprint); ok {
			policies = append(policies, p)
		}
	}
	return policies
}
