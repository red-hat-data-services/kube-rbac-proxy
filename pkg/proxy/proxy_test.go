/*
Copyright 2017 Frederic Branczyk All rights reserved.

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

package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/google/go-cmp/cmp"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestGeneratingAuthorizerAttributes(t *testing.T) {
	cases := []struct {
		desc     string
		authzCfg *authz.Config
		req      *http.Request
		expected []authorizer.Attributes
		wantErr  string
	}{
		{
			"without resource attributes and rewrites",
			&authz.Config{},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "",
					APIGroup:        "",
					APIVersion:      "",
					Resource:        "",
					Subresource:     "",
					Name:            "",
					ResourceRequest: false,
					Path:            "/accounts",
				},
			},
			"",
		},
		{
			"without rewrites config",
			&authz.Config{ResourceAttributes: &authz.ResourceAttributes{Namespace: "tenant1", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"}},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"with query param rewrites config",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(map[string][]string{"namespace": {"tenant1"}}, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"with query param rewrites config but missing URL query",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
			"",
		},
		{
			"with http header rewrites config",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, map[string][]string{"namespace": {"tenant1"}}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"with http header rewrites config and additional header",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, map[string][]string{"namespace": {"tenant1", "tenant2"}}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant2",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"with http header rewrites config but missing header",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
			"",
		},
		{
			"with http header and query param rewrites config",
			&authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByHTTPHeader:     &authz.HTTPHeaderRewriteConfig{Name: "namespace"},
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(
				map[string][]string{"namespace": {"tenant1"}},
				map[string][]string{"namespace": {"tenant2"}},
			),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant2",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"Format2 endpoint match takes precedence over Format1",
			&authz.Config{
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
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Namespace:   "{{ .Value }}",
					APIVersion:  "v1",
					Resource:    "namespace",
					Subresource: "metrics",
				},
			},
			func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/job-1/events?namespace=wrong-ns", nil)
				r.Header.Set("X-Tenant", "tenant-a")
				return r
			}(),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "create",
					Namespace:       "tenant-a",
					APIGroup:        "trustyai.opendatahub.io",
					APIVersion:      "",
					Resource:        "status-events",
					Subresource:     "",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
		{
			"Format2 missing required header returns error",
			&authz.Config{
				Endpoints: []authz.Endpoint{{
					Path: "/api/v1/evaluations/jobs/*/events",
					Mappings: []authz.EndpointMapping{{
						Methods: []string{"post"},
						Resources: []authz.EndpointResourceRule{{
							Rewrites: authz.SubjectAccessReviewRewrites{
								ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "X-Tenant"},
							},
							ResourceAttributes: authz.ResourceAttributes{Namespace: "{{.FromHeader}}", Verb: "create"},
						}},
					}},
				}},
			},
			httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/j1/events", nil),
			nil,
			"required header",
		},
		{
			"no Format2 endpoint match uses Format1",
			&authz.Config{
				Endpoints: []authz.Endpoint{{
					Path: "/api/v1/other",
					Mappings: []authz.EndpointMapping{{
						Methods: []string{"get"},
						Resources: []authz.EndpointResourceRule{{
							ResourceAttributes: authz.ResourceAttributes{Resource: "wrong"},
						}},
					}},
				}},
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Namespace:   "{{ .Value }}",
					APIVersion:  "v1",
					Resource:    "namespace",
					Subresource: "metrics",
				},
			},
			createRequest(map[string][]string{"namespace": {"format1-ns"}}, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "format1-ns",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
			"",
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			t.Log(c.req.URL.Query())
			if c.authzCfg != nil {
				c.authzCfg.PrepareEndpoints()
			}
			n := krpAuthorizerAttributesGetter{authzConfig: c.authzCfg}
			res, err := n.GetRequestAttributes(nil, c.req)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want err containing %q, got err=%v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !cmp.Equal(res, c.expected) {
				t.Errorf("Generated authorizer attributes are not correct. Expected %v, recieved %v", c.expected, res)
			}
		})
	}
}

func TestGetRequestAttributes_nilAuthorizationReturnsError(t *testing.T) {
	n := krpAuthorizerAttributesGetter{authzConfig: nil}
	_, err := n.GetRequestAttributes(nil, httptest.NewRequest(http.MethodGet, "/accounts", nil))
	if err == nil || err.Error() != "error during authorization" {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGetRequestAttributes_Format2PathMatchedWrongHTTPMethod(t *testing.T) {
	cfg := &authz.Config{
		Endpoints: []authz.Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []authz.EndpointMapping{{
				Methods: []string{"post"},
				Resources: []authz.EndpointResourceRule{{
					ResourceAttributes: authz.ResourceAttributes{Verb: "create", Resource: "status-events"},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()
	n := krpAuthorizerAttributesGetter{authzConfig: cfg}
	_, err := n.GetRequestAttributes(nil, httptest.NewRequest(http.MethodGet, "/api/v1/evaluations/jobs/j1/events", nil))
	if !errors.Is(err, authz.ErrEndpointMethodNotAllowed) {
		t.Fatalf("got err=%v, want ErrEndpointMethodNotAllowed", err)
	}
}

func createRequest(queryParams, headers map[string][]string) *http.Request {
	r := httptest.NewRequest("GET", "/accounts", nil)
	if queryParams != nil {
		q := r.URL.Query()
		for key, values := range queryParams {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		r.URL.RawQuery = q.Encode()
	}
	for key, values := range headers {
		for _, value := range values {
			r.Header.Add(key, value)
		}
	}
	return r
}
