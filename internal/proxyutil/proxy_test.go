package proxyutil

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestBuildDialerUsesHTTPConnectProxy(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	defer func() { _ = listener.Close() }()

	serverResult := make(chan error, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			serverResult <- errAccept
			return
		}
		defer func() { _ = conn.Close() }()
		request, errRead := http.ReadRequest(bufio.NewReader(conn))
		if errRead != nil {
			serverResult <- errRead
			return
		}
		if request.Method != http.MethodConnect || request.Host != "chatgpt.com:443" {
			serverResult <- fmt.Errorf("CONNECT request = %s %s", request.Method, request.Host)
			return
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-user:test-password"))
		if gotAuth := request.Header.Get("Proxy-Authorization"); gotAuth != wantAuth {
			serverResult <- fmt.Errorf("Proxy-Authorization = %q", gotAuth)
			return
		}
		_, errWrite := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		serverResult <- errWrite
	}()

	proxyURL := fmt.Sprintf("http://test-user:test-password@%s", listener.Addr().String())
	dialer, mode, errBuild := BuildDialer(proxyURL)
	if errBuild != nil {
		t.Fatalf("BuildDialer() error = %v", errBuild)
	}
	if mode != ModeProxy || dialer == nil {
		t.Fatalf("BuildDialer() mode = %v, dialer = %T", mode, dialer)
	}
	conn, errDial := dialer.Dial("tcp", "chatgpt.com:443")
	if errDial != nil {
		t.Fatalf("Dial() error = %v", errDial)
	}
	_ = conn.Close()

	select {
	case errServer := <-serverResult:
		if errServer != nil {
			t.Fatalf("proxy server error = %v", errServer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CONNECT request")
	}
}
