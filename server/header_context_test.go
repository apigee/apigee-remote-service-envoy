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

// Package protostruct supports operations on the protocol buffer Struct message.
package server

import (
	"reflect"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
)

func TestMetadataHeaders(t *testing.T) {
	var opts []*core.HeaderValueOption
	h := &Handler{
		orgName: "org",
		envName: "env",
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
	opts = makeMetadataHeaders(api, authContext)
	headers := map[string]string{}
	for _, o := range opts {
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
	opts := makeMetadataHeaders("api", nil)
	if opts != nil {
		t.Errorf("should return nil if no context")
	}

	h := &Handler{
		orgName: "org",
		envName: "env",
	}
	h.targetHeader = "target"
	header := map[string]string{"target": "target"}
	api, ac := h.decodeMetadataHeaders(header)
	if api != "target" {
		t.Errorf("got: %s, want: %s", api, "target")
	}
	if ac.Organization() != h.orgName {
		t.Errorf("got: %s, want: %s", ac.Organization(), h.orgName)
	}
	if ac.Environment() != h.envName {
		t.Errorf("got: %s, want: %s", ac.Environment(), h.envName)
	}

	h.targetHeader = "missing"
	api, ac = h.decodeMetadataHeaders(header)
	if api != "" {
		t.Errorf("api should be empty")
	}
	if ac != nil {
		t.Errorf("authContext should be nil")
	}

}
