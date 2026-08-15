package quota

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
)

func TestQuotaHTTPClientUsesUTLSOnlyForCodex(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantUTLS bool
	}{
		{name: "codex", provider: "codex", wantUTLS: true},
		{name: "claude", provider: "claude", wantUTLS: false},
		{name: "kimi", provider: "kimi", wantUTLS: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, errClient := quotaHTTPClient(&coreauth.Auth{Provider: test.provider}, "http://127.0.0.1:7890", 7*time.Second)
			if errClient != nil {
				t.Fatalf("quotaHTTPClient() error = %v", errClient)
			}
			_, isUTLS := client.Transport.(*codexQuotaUTLSRoundTripper)
			if isUTLS != test.wantUTLS {
				t.Fatalf("transport = %T, want uTLS = %v", client.Transport, test.wantUTLS)
			}
			if client.Timeout != 7*time.Second {
				t.Fatalf("client timeout = %v", client.Timeout)
			}
		})
	}
}

func TestCodexQuotaUTLSTransportKeepsHTTPFallback(t *testing.T) {
	called := false
	transport := &codexQuotaUTLSRoundTripper{fallback: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	req, errRequest := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}
	resp, errRoundTrip := transport.RoundTrip(req)
	if errRoundTrip != nil {
		t.Fatalf("RoundTrip() error = %v", errRoundTrip)
	}
	defer func() { _ = resp.Body.Close() }()
	if !called || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("fallback called = %v, status = %d", called, resp.StatusCode)
	}
}

func TestDialCodexQuotaContextStopsAtDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, errDial := dialCodexQuotaContext(ctx, blockingQuotaDialer{release: release}, "tcp", "chatgpt.com:443")
	if !errors.Is(errDial, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want context deadline exceeded", errDial)
	}
}

type blockingQuotaDialer struct {
	release <-chan struct{}
}

func (d blockingQuotaDialer) Dial(_, _ string) (net.Conn, error) {
	<-d.release
	return nil, errors.New("released")
}
