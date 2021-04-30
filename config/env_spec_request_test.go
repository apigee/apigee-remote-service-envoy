// Copyright 2021 Google LLC
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

// Package config defines the API Runtime Control config and provides
// the config loading and validation functions.

package config

import (
	"testing"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func TestBasicEnvSpecRequest(t *testing.T) {
	configFile := "./testdata/good_config.yaml"
	c := &Config{}
	if err := c.Load(configFile, "", "", false); err != nil {
		t.Fatalf("c.Load() returns unexpected: %v", err)
	}

	apiKey := "myapikey"
	envoyReq := &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/v1/petstore",
					Headers: map[string]string{
						"x-api-key": apiKey,
					},
				},
			},
		},
	}
	specName := "good-env-config"
	spec := c.EnvironmentSpecsByID[specName]
	if spec == nil {
		t.Fatalf("spec not found: %s", specName)
	}
	req := spec.NewEnvironmentSpecRequest(envoyReq)

	api := req.GetAPISpec()
	if api == nil {
		t.Errorf("APISpec not found for req")
	}
	op := req.GetOperation()
	if op == nil {
		t.Errorf("Operation not found for req")
	}

	if req.HasAuthentication() {
		t.Errorf("Operation should not meet authentication requirements")
	}

	got := req.GetAPIKey()
	if got != apiKey {
		t.Errorf("api key incorrect. got: %s, want: %s", got, apiKey)
	}
}
