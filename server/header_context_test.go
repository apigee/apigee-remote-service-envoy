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
	ac := &auth.Context{
		Context:        h,
		ClientID:       "clientid",
		AccessToken:    "accesstoken",
		Application:    "application",
		APIProducts:    []string{"prod1", "prod2"},
		DeveloperEmail: "dev@google.com",
		Scopes:         []string{"scope1", "scope2"},
	}
	api := "api"
	opts = makeMetadataHeaders(api, ac)
	headers := map[string]string{}
	for _, o := range opts {
		headers[o.Header.Key] = o.Header.Value
	}

	equal := func(key, want string) {
		if headers[key] != want {
			t.Errorf("got: '%s', want: '%s'", headers[key], want)
		}
	}

	equal(headerAccessToken, ac.AccessToken)
	equal(headerAPI, api)
	equal(headerAPIProducts, strings.Join(ac.APIProducts, ","))
	equal(headerApplication, ac.Application)
	equal(headerClientID, ac.ClientID)
	equal(headerDeveloperEmail, ac.DeveloperEmail)
	equal(headerEnvironment, ac.Environment())
	equal(headerOrganization, ac.Organization())
	equal(headerScopes, strings.Join(ac.Scopes, ","))

	api2, ac2 := h.decodeMetadataHeaders(headers)
	if api != api2 {
		t.Errorf("got: '%s', want: '%s'", api2, api)
	}

	if !reflect.DeepEqual(*ac, *ac2) {
		t.Errorf("\ngot:\n%#v,\nwant\n%#v\n", *ac2, *ac)
	}
}
