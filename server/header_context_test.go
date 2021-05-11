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
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
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
	okResponse := &envoy_auth.OkHttpResponse{}
	addMetadataHeaders(okResponse, api, authContext)
	headers := map[string]string{}
	for _, o := range okResponse.Headers {
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
	okResponse := &envoy_auth.OkHttpResponse{}
	addMetadataHeaders(okResponse, "api", nil)
	if okResponse.Headers != nil {
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
