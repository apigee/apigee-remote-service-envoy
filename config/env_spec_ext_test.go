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
	"net/http"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"google.golang.org/api/option"
)

func TestNewEnvironmentSpecExt(t *testing.T) {

	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if l := len(specExt.JWTAuthentications()); l != 9 {
		t.Errorf("should be 9 JWTAuthentications, got %d", l)
	}

	if specExt.apiPathTree == nil {
		t.Errorf("must not be nil")
	}

	httpPrefix := strings.Split("/v1", "/")
	httpPrefix = append([]string{"/"}, httpPrefix...)
	if result, _ := specExt.apiPathTree.FindPrefix(httpPrefix, 0); result == nil {
		t.Errorf("gRPC prefix for apispec1 not found in apiPathTree")
	}

	gRPCPrefix := strings.Split("/foo.petstore.PetstoreService", "/")
	gRPCPrefix = append([]string{"/"}, gRPCPrefix...)
	if result, _ := specExt.apiPathTree.FindPrefix(gRPCPrefix, 0); result == nil {
		t.Errorf("gRPC prefix for grpcapispec not found in apiPathTree")
	}

	if specExt.opPathTree == nil {
		t.Errorf("must not be nil")
	}

	httpSplit := strings.Split("/petstore", "/")
	if result, _ := specExt.opPathTree.FindPrefix(append([]string{"apispec1", "GET"}, httpSplit...), 0); result == nil {
		t.Errorf("HTTP op for op-1 not found in opPathTree")
	}

	grpcSplit := strings.Split("/ListPets", "/")
	if result, _ := specExt.opPathTree.FindPrefix(append([]string{"grpcapispec", "POST"}, grpcSplit...), 0); result == nil {
		t.Errorf("gRPC op for ListPets not found in opPathTree")
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

func TestNewEnvironmentSpecExtError(t *testing.T) {
	srv := testutil.IAMServer()
	defer srv.Close()

	opts := []option.ClientOption{
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(http.DefaultClient),
	}

	tests := []struct {
		desc string
		spec *EnvironmentSpec
		opts []EnvironmentSpecExtOption
	}{
		{
			desc: "missing iam service at the API level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					ContextVariables: []ContextVariable{{
						Name:  "iam_token",
						Value: GoogleIAMCredentials{},
					}},
				}},
			},
		},
		{
			desc: "missing service account at the API level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					ContextVariables: []ContextVariable{{
						Name: "iam_token",
						Value: GoogleIAMCredentials{
							Token: AccessToken{},
						},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
		{
			desc: "access token info missing scopes at the API level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					ContextVariables: []ContextVariable{{
						Name: "iam_token",
						Value: GoogleIAMCredentials{
							ServiceAccountEmail: "foo@bar.com",
							Token:               AccessToken{},
						},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
		{
			desc: "id token info missing audience at the API level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					ContextVariables: []ContextVariable{{
						Name: "iam_token",
						Value: GoogleIAMCredentials{
							ServiceAccountEmail: "foo@bar.com",
							Token:               IdentityToken{},
						},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
		{
			desc: "missing iam service at the operation level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					Operations: []APIOperation{{
						ContextVariables: []ContextVariable{{
							Name:  "iam_token",
							Value: GoogleIAMCredentials{},
						}},
					}},
				}},
			},
		},
		{
			desc: "missing service account at the operation level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					Operations: []APIOperation{{
						ContextVariables: []ContextVariable{{
							Name: "iam_token",
							Value: GoogleIAMCredentials{
								Token: AccessToken{},
							},
						}},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
		{
			desc: "access token info missing scopes at the operation level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					Operations: []APIOperation{{
						ContextVariables: []ContextVariable{{
							Name: "iam_token",
							Value: GoogleIAMCredentials{
								Token: AccessToken{},
							},
						}},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
		{
			desc: "id token info missing audience at the operation level",
			spec: &EnvironmentSpec{
				APIs: []APISpec{{
					Operations: []APIOperation{{
						ContextVariables: []ContextVariable{{
							Name: "iam_token",
							Value: GoogleIAMCredentials{
								Token: IdentityToken{},
							},
						}},
					}},
				}},
			},
			opts: []EnvironmentSpecExtOption{WithIAMClientOptions(opts...)},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := NewEnvironmentSpecExt(test.spec, test.opts...)
			if err == nil {
				t.Errorf("NewEnvironmentSpecExt(...) err == nil, wanted error")
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
