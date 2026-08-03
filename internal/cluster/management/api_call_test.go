package management

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
)

func TestAPICallAuthMatchesOAuthFileName(t *testing.T) {
	t.Parallel()

	auth := &coreauth.Auth{
		ID:       "7f2f0f1d-40d1-4f9a-9045-4b83412c8188",
		Index:    "7f2f0f1d-40d1-4f9a-9045-4b83412c8188",
		Provider: "codex",
		Label:    "codex-user",
		Metadata: map[string]any{
			"type":     "codex",
			"filename": "codex-user.json",
		},
	}

	for _, selector := range []string{
		auth.ID,
		auth.Index,
		"codex-user.json",
		"codex-user",
	} {
		selector := selector
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if !apiCallAuthMatches(auth.Clone(), selector) {
				t.Fatalf("apiCallAuthMatches returned false for selector %q", selector)
			}
		})
	}
}

func TestAPICallTransportUsesOAuthMetadataProxyURL(t *testing.T) {
	t.Parallel()

	auth := &coreauth.Auth{
		ID:       "codex-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"type":      "codex",
			"proxy_url": "http://codex-proxy.example.com:8080",
		},
	}
	transport := (&Handler{}).apiCallTransport(auth)
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", transport)
	}

	req, errRequest := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if errRequest != nil {
		t.Fatalf("http.NewRequest returned error: %v", errRequest)
	}
	proxyURL, errProxy := httpTransport.Proxy(req)
	if errProxy != nil {
		t.Fatalf("httpTransport.Proxy returned error: %v", errProxy)
	}
	if proxyURL == nil || proxyURL.String() != "http://codex-proxy.example.com:8080" {
		t.Fatalf("proxy URL = %v, want http://codex-proxy.example.com:8080", proxyURL)
	}
}

func TestAPICallCodexUsageRefreshTriggersAuthoritativeRecollect(t *testing.T) {
	trigger := &fakeQuotaRecollectTrigger{accepted: 1}
	handler := &Handler{quotaRecollect: trigger}
	parsedURL, errParse := url.Parse("https://chatgpt.com/backend-api/wham/usage?source=management")
	if errParse != nil {
		t.Fatalf("url.Parse() error = %v", errParse)
	}
	auth := &coreauth.Auth{ID: "codex-quota-refresh", Provider: "codex"}

	handler.maybeTriggerCodexQuotaRecollect(context.Background(), http.MethodGet, parsedURL, http.StatusOK, auth)

	if trigger.calls != 1 {
		t.Fatalf("quota recollect calls = %d, want 1", trigger.calls)
	}
	if _, ok := trigger.credentialIDs[auth.ID]; !ok || len(trigger.credentialIDs) != 1 {
		t.Fatalf("quota recollect credential filters = %v, want only %s", trigger.credentialIDs, auth.ID)
	}
	if _, ok := trigger.providers["codex"]; !ok || len(trigger.providers) != 1 {
		t.Fatalf("quota recollect provider filters = %v, want only codex", trigger.providers)
	}
}

func TestAPICallQuotaRecollectRejectsUnverifiedSurfaces(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		rawURL     string
		statusCode int
		provider   string
	}{
		{name: "non codex auth", method: http.MethodGet, rawURL: "https://chatgpt.com/backend-api/wham/usage", statusCode: http.StatusOK, provider: "claude"},
		{name: "plaintext transport", method: http.MethodGet, rawURL: "http://chatgpt.com/backend-api/wham/usage", statusCode: http.StatusOK, provider: "codex"},
		{name: "lookalike host", method: http.MethodGet, rawURL: "https://chatgpt.com.example.test/backend-api/wham/usage", statusCode: http.StatusOK, provider: "codex"},
		{name: "different path", method: http.MethodGet, rawURL: "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits", statusCode: http.StatusOK, provider: "codex"},
		{name: "non get", method: http.MethodPost, rawURL: "https://chatgpt.com/backend-api/wham/usage", statusCode: http.StatusOK, provider: "codex"},
		{name: "upstream failure", method: http.MethodGet, rawURL: "https://chatgpt.com/backend-api/wham/usage", statusCode: http.StatusTooManyRequests, provider: "codex"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsedURL, errParse := url.Parse(test.rawURL)
			if errParse != nil {
				t.Fatalf("url.Parse() error = %v", errParse)
			}
			trigger := &fakeQuotaRecollectTrigger{accepted: 1}
			handler := &Handler{quotaRecollect: trigger}
			handler.maybeTriggerCodexQuotaRecollect(context.Background(), test.method, parsedURL, test.statusCode, &coreauth.Auth{ID: "credential", Provider: test.provider})
			if trigger.calls != 0 {
				t.Fatalf("quota recollect calls = %d, want 0", trigger.calls)
			}
		})
	}
}
