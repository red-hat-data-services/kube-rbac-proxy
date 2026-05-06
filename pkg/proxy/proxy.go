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
	"bytes"
	"fmt"
	"net/http"
	"text/template"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/klog/v2"
)

// Config holds proxy authorization and authentication settings
type Config struct {
	Authentication *authn.AuthnConfig
	Authorization  *authz.Config
}

func NewKubeRBACProxyAuthorizerAttributesGetter(authzConfig *authz.Config) *krpAuthorizerAttributesGetter {
	return &krpAuthorizerAttributesGetter{authzConfig}
}

type krpAuthorizerAttributesGetter struct {
	authzConfig *authz.Config
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
// When authorization.endpoints matches the request path, only Format2 endpoint rules apply.
// Otherwise top-level resourceAttributes and rewrites (Format1) are used.
func (n krpAuthorizerAttributesGetter) GetRequestAttributes(u user.Info, r *http.Request) ([]authorizer.Attributes, error) {
	// Non-nil authorization is enforced in Complete before the server starts; this branch is defensive.
	if n.authzConfig == nil {
		klog.Error("GetRequestAttributes: authorization config is nil")
		return nil, fmt.Errorf("error during authorization")
	}

	// When Format2 endpoints are configured, try path/method-scoped rules before Format1.
	if len(n.authzConfig.Endpoints) > 0 {
		attrs, matched, err := authz.EndpointAttributesFromRequest(u, r, n.authzConfig)
		// Propagate errors from endpoint rules (e.g. required header or query missing).
		if err != nil {
			return nil, err
		}
		// If the request path matched an endpoint entry, use only those attributes (errors from
		// rules, e.g. ErrEndpointMethodNotAllowed, are propagated; empty attrs without error is still possible for misconfigured empty resources).
		if matched {
			for _, a := range attrs {
				klog.V(5).Infof("kube-rbac-proxy request attributes (endpoint rule): attrs=%#+v", a)
			}
			return attrs, nil
		}
	}

	apiVerb := "*"
	switch r.Method {
	case "POST":
		apiVerb = "create"
	case "GET":
		apiVerb = "get"
	case "PUT":
		apiVerb = "update"
	case "PATCH":
		apiVerb = "patch"
	case "DELETE":
		apiVerb = "delete"
	}

	// If Format1 resourceAttributes supplies an explicit verb, it overrides the verb inferred from HTTP method.
	if n.authzConfig.ResourceAttributes != nil && n.authzConfig.ResourceAttributes.Verb != "" {
		apiVerb = n.authzConfig.ResourceAttributes.Verb
	}

	var allAttrs []authorizer.Attributes

	defer func() {
		for _, attrs := range allAttrs {
			klog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#+v", attrs)
		}
	}()

	// Format1 with no resource block: authorize as a non-resource request against the incoming URL path.
	if n.authzConfig.ResourceAttributes == nil {
		allAttrs = append(allAttrs, authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       "",
			APIGroup:        "",
			APIVersion:      "",
			Resource:        "",
			Subresource:     "",
			Name:            "",
			ResourceRequest: false,
			Path:            r.URL.Path,
		})
		return allAttrs, nil
	}

	// Format1 with fixed resourceAttributes and no rewrites: emit a single resource SAR with literal fields.
	if n.authzConfig.Rewrites == nil {
		allAttrs = append(allAttrs, authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       n.authzConfig.ResourceAttributes.Namespace,
			APIGroup:        n.authzConfig.ResourceAttributes.APIGroup,
			APIVersion:      n.authzConfig.ResourceAttributes.APIVersion,
			Resource:        n.authzConfig.ResourceAttributes.Resource,
			Subresource:     n.authzConfig.ResourceAttributes.Subresource,
			Name:            n.authzConfig.ResourceAttributes.Name,
			ResourceRequest: true,
		})
		return allAttrs, nil
	}

	params := authz.CollectRewriteParams(r, n.authzConfig.Rewrites)

	// Rewrites are configured but no header/query values were found: return empty (caller treats as bad request).
	if len(params) == 0 {
		return allAttrs, nil
	}

	// Format1 with rewrites: one SAR per collected rewrite value, expanding {{ .Value }} in resource field templates.
	for _, param := range params {
		attrs := authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       templateWithValue(n.authzConfig.ResourceAttributes.Namespace, param),
			APIGroup:        templateWithValue(n.authzConfig.ResourceAttributes.APIGroup, param),
			APIVersion:      templateWithValue(n.authzConfig.ResourceAttributes.APIVersion, param),
			Resource:        templateWithValue(n.authzConfig.ResourceAttributes.Resource, param),
			Subresource:     templateWithValue(n.authzConfig.ResourceAttributes.Subresource, param),
			Name:            templateWithValue(n.authzConfig.ResourceAttributes.Name, param),
			ResourceRequest: true,
		}
		allAttrs = append(allAttrs, attrs)
	}
	return allAttrs, nil
}

func templateWithValue(templateString, value string) string {
	tmpl, _ := template.New("valueTemplate").Parse(templateString)
	out := bytes.NewBuffer(nil)
	err := tmpl.Execute(out, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return out.String()
}
