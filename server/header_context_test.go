// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/fault"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/google/uuid"
)

func TestMetadataHeaders(t *testing.T) {
	h := &multitenantContext{
		&Handler{
			orgName:       "org",
			envName:       "*",
			isMultitenant: true,
		},
		"env",
	}
	authContext := &auth.Context{
		Context:        h,
		ClientID:       "clientid",
		AccessToken:    "accesstoken",
		Application:    "application",
		APIProducts:    []string{"prod1", "prod2"},
		DeveloperEmail: "dev@google.com",
		Scopes:         []string{"scope1", "scope2"},
	}
	api := "api"
	mh := metadataHeaders(api, authContext)
	headers := map[string]string{}
	for _, o := range mh {
		headers[o.Header.Key] = o.Header.Value
	}

	equal := func(key, want string) {
		if headers[key] != want {
			t.Errorf("got: '%s', want: '%s'", headers[key], want)
		}
	}

	equal(headerAccessToken, authContext.AccessToken)
	equal(headerAPI, api)
	equal(headerAPIProducts, strings.Join(authContext.APIProducts, ","))
	equal(headerApplication, authContext.Application)
	equal(headerClientID, authContext.ClientID)
	equal(headerDeveloperEmail, authContext.DeveloperEmail)
	equal(headerEnvironment, authContext.Environment())
	equal(headerOrganization, authContext.Organization())
	equal(headerScope, strings.Join(authContext.Scopes, " "))

	api2, ac2 := h.decodeMetadataHeaders(headers)
	if api != api2 {
		t.Errorf("got: '%s', want: '%s'", api2, api)
	}

	if !reflect.DeepEqual(*authContext, *ac2) {
		t.Errorf("\ngot:\n%#v,\nwant\n%#v\n", *ac2, *authContext)
	}
}

func TestMetadataHeadersExceptions(t *testing.T) {
	mh := metadataHeaders("api", nil)
	if len(mh) != 0 {
		t.Errorf("should return nil if no context")
	}

	h := &Handler{
		orgName: "org",
		envName: "*",
	}
	h.apiHeader = "api"
	header := map[string]string{
		"api":             "api",
		headerEnvironment: "test",
	}

	api, ac := h.decodeMetadataHeaders(header)
	if ac.Environment() != "*" {
		t.Errorf("got: %s, want: %s", ac.Environment(), "*")
	}
	if api != "api" {
		t.Errorf("got: %s, want: %s", api, "api")
	}

	h.isMultitenant = true
	api, ac = h.decodeMetadataHeaders(header)
	if api != "api" {
		t.Errorf("got: %s, want: %s", api, "api")
	}
	if ac.Organization() != h.orgName {
		t.Errorf("got: %s, want: %s", ac.Organization(), h.orgName)
	}
	if ac.Environment() != "test" {
		t.Errorf("got: %s, want: %s", ac.Environment(), "test")
	}

	h.apiHeader = "missing"
	api, ac = h.decodeMetadataHeaders(header)
	if api != "" {
		t.Errorf("api should be empty")
	}
	if ac != nil {
		t.Errorf("authContext should be nil")
	}

}

func TestDynamicDataHeaders(t *testing.T) {
	org := "disorg"
	env := "tundra"
	api := "DoTheThingAPI"
	msgID := uuid.NewString()
	basePath := "/basepath"
	revision := "27"
	tests := []struct {
		desc                 string
		org, env, api, msgID string
		apiSpec              *config.APISpec
		fault                *fault.AdapterFault
		requiredHeaders      map[string]interface{}
		excludedHeaders      []string
	}{
		{
			desc:  "non-fault headers with apispec",
			org:   org,
			env:   env,
			api:   api,
			msgID: msgID,
			apiSpec: &config.APISpec{
				BasePath:   basePath,
				RevisionID: revision,
			},
			fault: fault.NewAdapterFault("", rpc.OK, 0),
			requiredHeaders: map[string]interface{}{
				headerOrganization:  org,
				headerEnvironment:   env,
				headerProxy:         api,
				headerMessageID:     msgID,
				headerProxyBasepath: basePath,
			},
			excludedHeaders: []string{headerFaultSource, headerFaultFlag, headerFaultRevision, headerFaultCode},
		},
		{
			desc: "give uuid if msgID is empty",
			org:  org,
			env:  env,
			api:  api,
			apiSpec: &config.APISpec{
				BasePath:   basePath,
				RevisionID: revision,
			},
			fault: fault.NewAdapterFault("", rpc.OK, 0),
			requiredHeaders: map[string]interface{}{
				headerOrganization:  org,
				headerEnvironment:   env,
				headerProxy:         api,
				headerMessageID:     regexp.MustCompile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
				headerProxyBasepath: basePath,
			},
			excludedHeaders: []string{headerFaultSource, headerFaultFlag, headerFaultRevision, headerFaultCode},
		},
		{
			desc:  "non-fault headers without apispec",
			org:   org,
			env:   env,
			api:   api,
			msgID: msgID,
			fault: fault.NewAdapterFault("", rpc.OK, 0),
			requiredHeaders: map[string]interface{}{
				headerOrganization: org,
				headerEnvironment:  env,
				headerProxy:        api,
				headerMessageID:    msgID,
			},
			excludedHeaders: []string{headerProxyBasepath, headerFaultSource, headerFaultFlag, headerFaultRevision, headerFaultCode},
		},
		{
			desc:  "fault headers with apispec",
			org:   org,
			env:   env,
			api:   api,
			msgID: msgID,
			apiSpec: &config.APISpec{
				BasePath:   basePath,
				RevisionID: revision,
			},
			fault: fault.NewAdapterFault("", rpc.INTERNAL, 0),
			requiredHeaders: map[string]interface{}{
				headerOrganization:  org,
				headerEnvironment:   env,
				headerProxy:         api,
				headerMessageID:     msgID,
				headerFaultSource:   "ARC",
				headerFaultFlag:     "true",
				headerFaultRevision: revision,
				headerFaultCode:     "apiProxy.InternalError",
			},
		},
		{
			desc:  "fault headers with no apispec",
			org:   org,
			env:   env,
			api:   api,
			msgID: msgID,
			fault: fault.NewAdapterFault("x-apigee-test", rpc.INTERNAL, 0),
			requiredHeaders: map[string]interface{}{
				headerOrganization: org,
				headerEnvironment:  env,
				headerProxy:        api,
				headerMessageID:    msgID,
				headerFaultSource:  "ARC",
				headerFaultFlag:    "true",
				headerFaultCode:    "x-apigee-test",
			},
			excludedHeaders: []string{headerFaultRevision},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			hvOptions := apigeeDynamicDataHeaders(tc.org, tc.env, tc.api, tc.msgID, tc.apiSpec, tc.fault)
			headers := make(map[string]string)
			for _, h := range hvOptions {
				headers[h.Header.Key] = h.Header.Value
			}
			for k, v := range tc.requiredHeaders {
				switch val := v.(type) {
				case string:
					if headers[k] != val {
						t.Errorf("invalid value for %q: (got: %q, want: %q)", k, headers[k], val)
					}
				case *regexp.Regexp:
					if !val.MatchString(headers[k]) {
						t.Errorf("invalid value for %q: (got: %q, want: %q", k, headers[k], val)
					}
				}
			}
			for _, name := range tc.excludedHeaders {
				if _, ok := headers[name]; ok {
					t.Errorf("unexpected header: %q", name)
				}
			}
		})
	}
}
