//go:build !go1.27 || http2legacy

/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

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
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestH2CShutdownSendsGoAway(t *testing.T) {
	requestStarted := make(chan string, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseHandler)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestStarted <- r.URL.Path
		if r.URL.Path == "/active" {
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server, transport := newH2CTestServer(t, handler, &http2.Server{MaxConcurrentStreams: 10})
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	firstDone := make(chan error, 1)
	go func() {
		response, err := client.Get(server.URL + "/active")
		if response != nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		firstDone <- err
	}()
	select {
	case path := <-requestStarted:
		if path != "/active" {
			t.Fatalf("first request path = %q, want /active", path)
		}
	case err := <-firstDone:
		t.Fatalf("first h2c request: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("first h2c request did not reach the handler")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	shutdownErr := server.Config.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		t.Fatalf("shutdown h2c server: %v", shutdownErr)
	}
	releaseHandler()
	if err := <-firstDone; err != nil {
		t.Fatalf("first h2c response: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	secondDone := make(chan error, 1)
	go func() {
		response, err := client.Get(server.URL + "/second")
		if response != nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		secondDone <- err
	}()
	select {
	case path := <-requestStarted:
		t.Fatalf("request %q reached handler after shutdown", path)
	case err := <-secondDone:
		if err == nil {
			t.Fatal("second h2c request succeeded after shutdown")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("second h2c request did not finish after shutdown")
	}
}
