/*
Copyright 2026 The kube-rbac-proxy Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"golang.org/x/net/http2"
)

// TestHTTP2HealthCheckClosesStalledHeaders verifies the end-to-end behavior of
// the HTTP/2 health check: a raw client that sends a partial HEADERS frame and
// never answers PINGs is closed after roughly read-idle + ping timeout, and a
// connection with the check disabled (--http2-read-idle-timeout <= 0) is still
// open past that window.
func TestHTTP2HealthCheckClosesStalledHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end stall test with real timers")
	}

	run := func(t *testing.T, readIdle, ping time.Duration, wantClosed bool) {
		t.Helper()
		o := options.NewProxyRunOptions()
		o.HTTP2ReadIdleTimeout = readIdle
		o.HTTP2PingTimeout = ping

		srv := &http.Server{Handler: http.NotFoundHandler()}
		h2opts := &http2.Server{
			IdleTimeout:     -1, // disabled: the health check is what must close the conn
			ReadIdleTimeout: o.HTTP2ReadIdleTimeout,
			PingTimeout:     o.HTTP2PingTimeout,
		}
		if h2opts.ReadIdleTimeout > 0 && h2opts.PingTimeout <= 0 {
			h2opts.PingTimeout = options.DefaultHTTP2PingTimeout
		}
		if _, err := configureHTTP2Server(srv, h2opts); err != nil {
			t.Fatalf("configureHTTP2Server: %v", err)
		}

		cert := testSelfSigned(t)
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			NextProtos:   []string{"h2"},
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() { _ = srv.Serve(ln) }()

		// Trust the fixture certificate; do not disable verification.
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			NextProtos: []string{"h2"},
			RootCAs:    roots,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) // client preface
		_, _ = conn.Write([]byte{0, 0, 0, 0x4, 0, 0, 0, 0, 0})        // empty SETTINGS
		time.Sleep(100 * time.Millisecond)
		// Partial HEADERS on stream 1: announces a 9-byte block, sends 4 bytes, stalls.
		_, _ = conn.Write([]byte{0, 0, 9, 1, 0x4, 0, 0, 0, 1})
		_, _ = conn.Write([]byte{0x82, 0x86, 0x41, 0x0f})

		// With 1s/1s timers the check closes at ~2s; allow 8s before
		// declaring the stall unbounded.
		const window = 8 * time.Second
		_ = conn.SetReadDeadline(time.Now().Add(window))

		// A single draining reader reports the terminal read result:
		// data received before closure is drained and reading continues;
		// a timeout means the connection is still open; EOF or any other
		// error means it was closed.
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := conn.Read(buf); err != nil {
					done <- err
					return
				}
			}
		}()

		var closed bool
		select {
		case err := <-done:
			closed = !isTimeoutErr(err)
		case <-time.After(window + 5*time.Second):
			closed = false
		}

		if wantClosed && !closed {
			t.Fatalf("health check enabled (readIdle=%v ping=%v): connection still open after %v, want closed at ~%v", readIdle, ping, window, readIdle+ping)
		}
		if !wantClosed && closed {
			t.Fatal("health check disabled: connection closed within the window, want still open")
		}
	}

	t.Run("enabled closes stalled headers", func(t *testing.T) {
		run(t, 1*time.Second, 1*time.Second, true)
	})
	t.Run("disabled leaves stalled headers open", func(t *testing.T) {
		run(t, 0, 0, false)
	})
}

func isTimeoutErr(err error) bool {
	type timeout interface{ Timeout() bool }
	te, ok := err.(timeout)
	return ok && te.Timeout()
}

func testSelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
