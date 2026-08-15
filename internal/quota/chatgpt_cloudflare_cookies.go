package quota

import (
	"crypto/sha256"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// chatGPTCloudflareCookieJarPool retains process-local Cloudflare cookies
// without allowing ChatGPT session or account cookies into shared state.
// Jars are isolated by credential and effective proxy route because
// Cloudflare cookies can be associated with the observed egress path.
type chatGPTCloudflareCookieJarPool struct {
	mu   sync.Mutex
	jars map[chatGPTCloudflareCookieJarKey]http.CookieJar
}

type chatGPTCloudflareCookieJarKey struct {
	credentialID string
	proxyHash    [sha256.Size]byte
}

func newChatGPTCloudflareCookieJarPool() *chatGPTCloudflareCookieJarPool {
	return &chatGPTCloudflareCookieJarPool{jars: make(map[chatGPTCloudflareCookieJarKey]http.CookieJar)}
}

func (p *chatGPTCloudflareCookieJarPool) jarFor(credentialID string, effectiveProxyURL string) http.CookieJar {
	if p == nil {
		return nil
	}
	key := chatGPTCloudflareCookieJarKey{
		credentialID: strings.TrimSpace(credentialID),
		proxyHash:    sha256.Sum256([]byte(strings.TrimSpace(effectiveProxyURL))),
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.jars[key]; existing != nil {
		return existing
	}
	inner, errJar := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if errJar != nil {
		return nil
	}
	jar := &chatGPTCloudflareCookieJar{inner: inner}
	p.jars[key] = jar
	return jar
}

type chatGPTCloudflareCookieJar struct {
	inner http.CookieJar
}

func (j *chatGPTCloudflareCookieJar) SetCookies(target *url.URL, cookies []*http.Cookie) {
	if j == nil || j.inner == nil || !isAllowedChatGPTCookieURL(target) {
		return
	}
	allowed := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || !isAllowedCloudflareCookieName(cookie.Name) {
			continue
		}
		copyCookie := *cookie
		allowed = append(allowed, &copyCookie)
	}
	if len(allowed) > 0 {
		j.inner.SetCookies(target, allowed)
	}
}

func (j *chatGPTCloudflareCookieJar) Cookies(target *url.URL) []*http.Cookie {
	if j == nil || j.inner == nil || !isAllowedChatGPTCookieURL(target) {
		return nil
	}
	cookies := j.inner.Cookies(target)
	allowed := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie != nil && isAllowedCloudflareCookieName(cookie.Name) {
			allowed = append(allowed, cookie)
		}
	}
	return allowed
}

func isAllowedChatGPTCookieURL(target *url.URL) bool {
	if target == nil || !strings.EqualFold(strings.TrimSpace(target.Scheme), "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(target.Hostname()))
	switch host {
	case "chatgpt.com", "chat.openai.com", "chatgpt-staging.com":
		return true
	default:
		return strings.HasSuffix(host, ".chatgpt.com") || strings.HasSuffix(host, ".chatgpt-staging.com")
	}
}

func isAllowedCloudflareCookieName(name string) bool {
	name = strings.TrimSpace(name)
	switch name {
	case "__cf_bm", "__cflb", "__cfruid", "__cfseq", "__cfwaitingroom", "_cfuvid", "cf_clearance", "cf_ob_info", "cf_use_ob":
		return true
	default:
		return strings.HasPrefix(name, "cf_chl_")
	}
}
