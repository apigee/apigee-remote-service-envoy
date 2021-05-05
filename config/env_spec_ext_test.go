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
	specExt := NewEnvironmentSpecExt(&envSpec)

	if len(specExt.jwtAuthentications) != 2 {
		t.Errorf("should be 2")
	}

	if specExt.apiPathTree == nil {
		t.Errorf("must not be nil")
	}

	if specExt.opPathTree == nil {
		t.Errorf("must not be nil")
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

func TestAllJWTRequirements(t *testing.T) {
	tests := []struct {
		desc  string
		reqs  AuthenticationRequirements
		count int
	}{
		{"just jwt", JWTAuthentication{}, 1},
		{"jwt in all", AllAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: JWTAuthentication{
					Name: "1",
				},
			},
		}, 1},
		{"jwt in any", AnyAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: JWTAuthentication{
					Name: "1",
				},
			},
		}, 1},
		{"nested empty", AnyAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: AllAuthenticationRequirements{
					AuthenticationRequirement{
						Requirements: AnyAuthenticationRequirements{},
					},
				},
			},
		}, 0},
		{"nested jwts", AllAuthenticationRequirements{
			AuthenticationRequirement{
				Requirements: AnyAuthenticationRequirements{
					AuthenticationRequirement{
						Requirements: JWTAuthentication{
							Name: "1",
						},
					},
					AuthenticationRequirement{
						Requirements: JWTAuthentication{
							Name: "2",
						},
					},
				},
			},
		}, 2},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			req := AuthenticationRequirement{
				Requirements: test.reqs,
			}
			nameMap := map[string]*JWTAuthentication{}
			req.mapJWTRequirements(nameMap)
			if test.count != len(nameMap) {
				t.Errorf("expected %d, got %d", test.count, len(nameMap))
			}
		})
	}
}
