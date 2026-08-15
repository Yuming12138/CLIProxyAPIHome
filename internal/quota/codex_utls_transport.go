package quota

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPIHome/internal/proxyutil"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// codexQuotaUTLSRoundTripper gives ChatGPT quota requests the same Chrome-like
// TLS fingerprint used by CPA's Codex executor. Each probe gets a fresh HTTP/2
// connection so short-lived quota clients do not leave idle connections behind.
type codexQuotaUTLSRoundTripper struct {
	dialer   proxy.Dialer
	fallback http.RoundTripper
}

func newCodexQuotaUTLSRoundTripper(proxyURL string) (*codexQuotaUTLSRoundTripper, error) {
	dialer := proxy.Dialer(proxy.Direct)
	fallback := http.RoundTripper(proxyutil.NewDirectTransport())
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		proxyDialer, _, errDialer := proxyutil.BuildDialer(proxyURL)
		if errDialer != nil {
			return nil, errDialer
		}
		if proxyDialer != nil {
			dialer = proxyDialer
		}
		fallbackTransport, _, errTransport := proxyutil.BuildHTTPTransport(proxyURL)
		if errTransport != nil {
			return nil, errTransport
		}
		if fallbackTransport != nil {
			fallback = fallbackTransport
		}
	}
	return &codexQuotaUTLSRoundTripper{dialer: dialer, fallback: fallback}, nil
}

func (t *codexQuotaUTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("codex quota transport: request URL is unavailable")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return t.fallback.RoundTrip(req)
	}

	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	conn, errDial := dialCodexQuotaContext(req.Context(), t.dialer, "tcp", net.JoinHostPort(hostname, port))
	if errDial != nil {
		return nil, errDial
	}
	if deadline, ok := req.Context().Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tlsConn := tls.UClient(conn, &tls.Config{ServerName: hostname}, tls.HelloChrome_Auto)
	if errHandshake := tlsConn.HandshakeContext(req.Context()); errHandshake != nil {
		_ = conn.Close()
		return nil, errHandshake
	}
	if negotiated := tlsConn.ConnectionState().NegotiatedProtocol; negotiated != http2.NextProtoTLS {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("codex quota transport: upstream negotiated %q instead of HTTP/2", negotiated)
	}

	h2Transport := &http2.Transport{}
	h2Conn, errH2 := h2Transport.NewClientConn(tlsConn)
	if errH2 != nil {
		_ = tlsConn.Close()
		return nil, errH2
	}
	resp, errRoundTrip := h2Conn.RoundTrip(req)
	if errRoundTrip != nil {
		_ = h2Conn.Close()
		return nil, errRoundTrip
	}
	if resp.Body == nil {
		_ = h2Conn.Close()
		return resp, nil
	}
	resp.Body = &closeCodexQuotaConnBody{ReadCloser: resp.Body, closeConn: h2Conn.Close}
	return resp, nil
}

type codexQuotaDialResult struct {
	conn net.Conn
	err  error
}

func dialCodexQuotaContext(ctx context.Context, dialer proxy.Dialer, network, addr string) (net.Conn, error) {
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, network, addr)
	}
	result := make(chan codexQuotaDialResult)
	go func() {
		conn, errDial := dialer.Dial(network, addr)
		select {
		case result <- codexQuotaDialResult{conn: conn, err: errDial}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case outcome := <-result:
		return outcome.conn, outcome.err
	}
}

type closeCodexQuotaConnBody struct {
	io.ReadCloser
	closeOnce sync.Once
	closeConn func() error
}

func (b *closeCodexQuotaConnBody) Close() error {
	errBody := b.ReadCloser.Close()
	var errConn error
	b.closeOnce.Do(func() {
		if b.closeConn != nil {
			errConn = b.closeConn()
		}
	})
	if errBody != nil {
		return errBody
	}
	return errConn
}
