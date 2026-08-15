package quota

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
)

func TestChatGPTCloudflareCookieJarKeepsOnlyInfrastructureCookies(t *testing.T) {
	pool := newChatGPTCloudflareCookieJarPool()
	jar := pool.jarFor("credential-a", "http://proxy.example:8080")
	target := mustQuotaCookieURL(t, "https://chatgpt.com/backend-api/wham/usage")
	jar.SetCookies(target, []*http.Cookie{
		{Name: "_cfuvid", Value: "visitor", Path: "/", Secure: true},
		{Name: "cf_clearance", Value: "clearance", Path: "/", Secure: true},
		{Name: "__Secure-next-auth.session-token", Value: "account-session", Path: "/", Secure: true},
	})
	cookies := jar.Cookies(target)
	if len(cookies) != 2 || cookies[0].Name != "_cfuvid" || cookies[1].Name != "cf_clearance" {
		t.Fatalf("stored cookie names = %v, want Cloudflare allowlist only", quotaCookieNames(cookies))
	}
	if got := jar.Cookies(mustQuotaCookieURL(t, "https://api.openai.com/v1/responses")); len(got) != 0 {
		t.Fatalf("cookies escaped to non-ChatGPT host: %v", quotaCookieNames(got))
	}
}

func TestChatGPTCloudflareCookieJarRejectsLookalikeAndPlainHTTPHosts(t *testing.T) {
	pool := newChatGPTCloudflareCookieJarPool()
	jar := pool.jarFor("credential-a", "")
	for _, rawURL := range []string{
		"http://chatgpt.com/backend-api/wham/usage",
		"https://evilchatgpt.com/backend-api/wham/usage",
		"https://chatgpt.com.evil.example/backend-api/wham/usage",
	} {
		target := mustQuotaCookieURL(t, rawURL)
		jar.SetCookies(target, []*http.Cookie{{Name: "_cfuvid", Value: "visitor", Path: "/"}})
		if got := jar.Cookies(target); len(got) != 0 {
			t.Fatalf("cookies accepted for %s: %v", rawURL, quotaCookieNames(got))
		}
	}
}

func TestCollectorDefaultCodexHTTPClientReusesAndIsolatesCookieJars(t *testing.T) {
	currentProxy := "http://proxy-one.invalid:8080"
	collector := NewCollector(newCollectorTestRepository(t), Options{
		GlobalProxyURLProvider: func() string { return currentProxy },
	})
	authA := &coreauth.Auth{ID: "credential-a", Provider: "codex"}
	authB := &coreauth.Auth{ID: "credential-b", Provider: "codex"}
	target := mustQuotaCookieURL(t, "https://chatgpt.com/backend-api/wham/usage")

	first := mustCollectorQuotaClient(t, collector, authA)
	first.Jar.SetCookies(target, []*http.Cookie{{Name: "_cfuvid", Value: "visitor", Path: "/", Secure: true}})
	second := mustCollectorQuotaClient(t, collector, authA)
	if got := second.Jar.Cookies(target); len(got) != 1 || got[0].Name != "_cfuvid" {
		t.Fatalf("same credential and proxy did not reuse Cloudflare jar: %v", quotaCookieNames(got))
	}

	otherCredential := mustCollectorQuotaClient(t, collector, authB)
	if got := otherCredential.Jar.Cookies(target); len(got) != 0 {
		t.Fatalf("Cloudflare cookies crossed credential boundary: %v", quotaCookieNames(got))
	}

	currentProxy = "http://proxy-two.invalid:8080"
	otherProxy := mustCollectorQuotaClient(t, collector, authA)
	if got := otherProxy.Jar.Cookies(target); len(got) != 0 {
		t.Fatalf("Cloudflare cookies crossed proxy boundary: %v", quotaCookieNames(got))
	}
}

func mustCollectorQuotaClient(t *testing.T, collector *Collector, auth *coreauth.Auth) *http.Client {
	t.Helper()
	client, errClient := collector.options.HTTPClient(auth, time.Second)
	if errClient != nil {
		t.Fatalf("HTTPClient() error = %v", errClient)
	}
	if client.Jar == nil {
		t.Fatal("Codex HTTP client does not have a Cloudflare cookie jar")
	}
	return client
}

func mustQuotaCookieURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		t.Fatalf("url.Parse(%q) error = %v", rawURL, errParse)
	}
	return parsed
}

func quotaCookieNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie != nil {
			names = append(names, cookie.Name)
		}
	}
	return names
}
