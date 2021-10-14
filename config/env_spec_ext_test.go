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
)

func TestNewEnvironmentSpecExt(t *testing.T) {

	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if l := len(specExt.JWTAuthentications()); l != 8 {
		t.Errorf("should be 8 JWTAuthentications, got %d", l)
	}

	if specExt.apiPathTree == nil {
		t.Errorf("must not be nil")
	}

	if specExt.opPathTree == nil {
		t.Errorf("must not be nil")
	}

	if len(specExt.compiledTemplates) != 10 {
		t.Errorf("want %d templates, got %d: %#v", 10, len(specExt.compiledTemplates), specExt.compiledTemplates)
	}
}

func TestConsumerAuthorizationIsEmpty(t *testing.T) {
	ca := ConsumerAuthorization{}

	if !ca.isEmpty() {
		t.Errorf("should be empty")
	}
}

func TestAuthorizationRequirementIsEmpty(t *testing.T) {
	tests := []struct {
		desc  string
		reqs  AuthenticationRequirements
		empty bool
	}{
		{"just jwt", JWTAuthentication{}, false},
		{"empty any", AnyAuthenticationRequirements{}, true},
		{"empty all", AllAuthenticationRequirements{}, true},
		{"jwt in all", AllAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: JWTAuthentication{},
			},
		}, false},
		{"jwt in any", AnyAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: JWTAuthentication{},
			},
		}, false},
		{"nested empty", AnyAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: AllAuthenticationRequirements{
					AuthenticationRequirement{
						Requirements: AnyAuthenticationRequirements{},
					},
				},
			},
		}, true},
		{"nested jwt", AllAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: AnyAuthenticationRequirements{
					AuthenticationRequirement{},
					AuthenticationRequirement{
						Requirements: JWTAuthentication{},
					},
				},
			},
		}, false},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			req := AuthenticationRequirement{
				Requirements: test.reqs,
			}
			if test.empty != req.IsEmpty() {
				t.Errorf("expected empty == %t", test.empty)
			}
		})
	}
}

func TestHTTPRequestTransformsIsEmpty(t *testing.T) {
	transforms := HTTPRequestTransforms{}
	if !transforms.isEmpty() {
		t.Errorf("expected empty")
	}
	transforms.PathTransform = ""
	transforms.HeaderTransforms = NameValueTransforms{}
	transforms.QueryTransforms = NameValueTransforms{}
	if !transforms.isEmpty() {
		t.Errorf("expected empty")
	}
	transforms.HeaderTransforms = NameValueTransforms{
		Add:    []AddNameValue{},
		Remove: []string{},
	}
	transforms.QueryTransforms = NameValueTransforms{
		Add:    []AddNameValue{},
		Remove: []string{},
	}
	if !transforms.isEmpty() {
		t.Errorf("expected empty")
	}
	transforms.PathTransform = "x"
	if transforms.isEmpty() {
		t.Errorf("expected not empty")
	}
	transforms.PathTransform = ""
	transforms.HeaderTransforms.Add = []AddNameValue{{"x", "x", false}}
	if transforms.isEmpty() {
		t.Errorf("expected not empty")
	}
	transforms.HeaderTransforms.Add = []AddNameValue{}
	transforms.QueryTransforms.Add = []AddNameValue{{"x", "x", false}}
	if transforms.isEmpty() {
		t.Errorf("expected not empty")
	}
	transforms.QueryTransforms.Add = []AddNameValue{}
	transforms.HeaderTransforms.Remove = []string{"x"}
	if transforms.isEmpty() {
		t.Errorf("expected not empty")
	}
	transforms.HeaderTransforms.Remove = []string{}
	transforms.QueryTransforms.Remove = []string{"x"}
	if transforms.isEmpty() {
		t.Errorf("expected not empty")
	}
}
