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
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/google/go-cmp/cmp"
)

func Test_parseAuthorizationConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "configfile.yaml")

	tests := []struct {
		name        string
		fileContent string
		want        *authz.Config
		wantErr     bool
		wantErrSub  string
	}{
		{
			name: "resources",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      resource: namespaces
      subresource: metrics
      namespace: default
      verb: get`,
			want: &authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{
						Name: "namespace",
					},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Resource:    "namespaces",
					Subresource: "metrics",
					Namespace:   "{{ .Value }}",
				},
				Static: []authz.StaticAuthorizationConfig{
					{
						User: authz.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: true,
						Resource:        "namespaces",
						Subresource:     "metrics",
						Namespace:       "default",
						Verb:            "get",
					},
				},
			},
		},
		{
			name: "non-resources",
			fileContent: `authorization:
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: false
      verb: get
      path: /metrics`,
			want: &authz.Config{
				Static: []authz.StaticAuthorizationConfig{
					{
						User: authz.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: false,
						Verb:            "get",
						Path:            "/metrics",
					},
				},
			},
		},
		{
			name: "Format1 and Format2 in same file",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  endpoints:
    - path: /api/v1/evaluations/jobs/*/events
      mappings:
        - methods: [post]
          resources:
            - rewrites:
                byHttpHeader:
                  name: X-Tenant
              resourceAttributes:
                namespace: "{{.FromHeader}}"
                apiGroup: trustyai.opendatahub.io
                resource: status-events
                verb: create`,
			want: &authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Resource:    "namespaces",
					Subresource: "metrics",
					Namespace:   "{{ .Value }}",
				},
				Endpoints: []authz.Endpoint{{
					Path: "/api/v1/evaluations/jobs/*/events",
					Mappings: []authz.EndpointMapping{{
						Methods: []string{"post"},
						Resources: []authz.EndpointResourceRule{{
							Rewrites: authz.SubjectAccessReviewRewrites{
								ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "X-Tenant"},
							},
							ResourceAttributes: authz.ResourceAttributes{
								Namespace: "{{.FromHeader}}",
								APIGroup:  "trustyai.opendatahub.io",
								Resource:  "status-events",
								Verb:      "create",
							},
						}},
					}},
				}},
			},
		},
		{
			name: "Format2 mapping rejects empty methods list",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/x
      mappings:
        - methods: []
          resources:
            - resourceAttributes:
                resource: pods
                verb: get`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "non-empty methods",
		},
		{
			name: "Format2 mapping rejects omitted methods",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/y
      mappings:
        - resources:
            - resourceAttributes:
                resource: pods
                verb: get`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "non-empty methods",
		},
		{
			name: "Format2 mapping rejects empty resources list",
			fileContent: `authorization:
  endpoints:
    - path: /api/v1/z
      mappings:
        - methods: [get]
          resources: []`,
			want:       nil,
			wantErr:    true,
			wantErrSub: "resource rule",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filePath, []byte(tt.fileContent), 0666); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			got, err := parseAuthorizationConfigFile(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthorizationConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.wantErrSub != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrSub)) {
					t.Errorf("parseAuthorizationConfigFile() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAuthorizationConfigFile(): %s", cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestConfigureHTTP2ServerConfiguresMultipleServers(t *testing.T) {
	baseOptions := &http2.Server{MaxConcurrentStreams: 10}
	wantBaseOptions := &http2.Server{MaxConcurrentStreams: 10}

	proxyOptions, err := configureHTTP2Server(&http.Server{TLSConfig: &tls.Config{}}, baseOptions)
	if err != nil {
		t.Fatalf("configure proxy server: %v", err)
	}
	endpointsOptions, err := configureHTTP2Server(&http.Server{TLSConfig: &tls.Config{}}, baseOptions)
	if err != nil {
		t.Fatalf("configure proxy endpoints server: %v", err)
	}
	if proxyOptions == endpointsOptions {
		t.Fatal("HTTP/2 servers share configured options")
	}

	if !reflect.DeepEqual(baseOptions, wantBaseOptions) {
		t.Fatal("configuring HTTP/2 servers mutated the base options")
	}
}

func newH2CTestServer(t *testing.T, handler http.Handler, baseOptions *http2.Server) (*httptest.Server, *http2.Transport) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	h2cOptions, err := configureHTTP2Server(server.Config, baseOptions)
	if err != nil {
		t.Fatalf("configure h2c server: %v", err)
	}
	server.Config.Handler = h2c.NewHandler(handler, h2cOptions)
	server.Start()
	t.Cleanup(server.Close)

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return server, transport
}

func TestConfigureHTTP2ServerSupportsPlaintextH2C(t *testing.T) {
	server, transport := newH2CTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{MaxConcurrentStreams: 10})

	plainClient := &http.Client{Transport: &http.Transport{Proxy: nil}}
	plainResponse, err := plainClient.Get(server.URL)
	if err != nil {
		t.Fatalf("HTTP/1 request: %v", err)
	}
	plainResponse.Body.Close()
	if plainResponse.ProtoMajor != 1 || plainResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTP/1 response = %s %d, want HTTP/1.x %d", plainResponse.Proto, plainResponse.StatusCode, http.StatusNoContent)
	}

	h2Client := &http.Client{Transport: transport}
	h2Response, err := h2Client.Get(server.URL)
	if err != nil {
		t.Fatalf("h2c request: %v", err)
	}
	h2Response.Body.Close()
	if h2Response.ProtoMajor != 2 || h2Response.StatusCode != http.StatusNoContent {
		t.Fatalf("h2c response = %s %d, want HTTP/2 %d", h2Response.Proto, h2Response.StatusCode, http.StatusNoContent)
	}
}
