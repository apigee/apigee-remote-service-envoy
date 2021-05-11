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

// NOTE: This file should be kept free from any additional dependencies,
// especially those that are not commonly used libraries.
import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestValidateEnvironmentSpecs(t *testing.T) {
	tests := []struct {
		desc    string
		configs []EnvironmentSpec
		hasErr  bool
		wantErr string
	}{
		{
			desc:    "good environment configs",
			configs: []EnvironmentSpec{createGoodEnvSpec()},
		},
		{
			desc: "duplicate environment config ids",
			configs: []EnvironmentSpec{
				{
					ID: "duplicate-config",
				},
				{
					ID: "duplicate-config",
				},
			},
			hasErr:  true,
			wantErr: "environment config IDs must be unique, got multiple duplicate-config",
		},
		{
			desc: "duplicate operation names",
			configs: []EnvironmentSpec{
				{
					ID: "config",
					APIs: []APISpec{
						{
							Operations: []APIOperation{
								{
									Name: "duplicate-op",
								},
								{
									Name: "duplicate-op",
								},
							},
						},
					},
				},
			},
			hasErr:  true,
			wantErr: "operation names within each API must be unique, got multiple duplicate-op",
		},
		{
			desc: "duplicate jwt authentication requirement names",
			configs: []EnvironmentSpec{
				{
					ID: "config",
					APIs: []APISpec{
						{
							Authentication: AuthenticationRequirement{
								Requirements: AllAuthenticationRequirements([]AuthenticationRequirement{
									{
										Requirements: JWTAuthentication{Name: "duplicate-jwt"},
									},
									{
										Requirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
											{
												Requirements: JWTAuthentication{Name: "duplicate-jwt"},
											},
										}),
									},
								}),
							},
						},
					},
				},
			},
			hasErr:  true,
			wantErr: "JWT authentication requirement names within each API or operation must be unique, got multiple duplicate-jwt",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if err := ValidateEnvironmentSpecs(test.configs); (err != nil) != test.hasErr {
				t.Errorf("c.ValidateEnvironmentSpecs() returns no error, should have got error")
			} else if test.wantErr != "" && test.wantErr != err.Error() {
				t.Errorf("c.ValidateEnvironmentSpecs() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestMarshalAndUnmarshalAuthenticationRequirement(t *testing.T) {
	tests := []struct {
		desc string
		want *AuthenticationRequirement
	}{
		{
			desc: "valid jwt",
			want: &AuthenticationRequirement{
				Requirements: JWTAuthentication{
					Name:       "foo",
					Issuer:     "bar",
					In:         []APIOperationParameter{{Match: Header("header")}},
					JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
				},
			},
		},
		{
			desc: "valid any enclosing jwt",
			want: &AuthenticationRequirement{
				Requirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						Requirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []APIOperationParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						Requirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []APIOperationParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid all enclosing jwt",
			want: &AuthenticationRequirement{
				Requirements: AllAuthenticationRequirements([]AuthenticationRequirement{
					{
						Requirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []APIOperationParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						Requirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []APIOperationParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid any enclosing all and jwt",
			want: &AuthenticationRequirement{
				Requirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						Requirements: AllAuthenticationRequirements([]AuthenticationRequirement{
							{
								Requirements: JWTAuthentication{
									Name:       "foo",
									Issuer:     "bar",
									In:         []APIOperationParameter{{Match: Header("header")}},
									JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
								},
							},
							{
								Requirements: JWTAuthentication{
									Name:       "bar",
									Issuer:     "foo",
									In:         []APIOperationParameter{{Match: Query("query")}},
									JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
								},
							},
						}),
					},
					{
						Requirements: JWTAuthentication{
							Name:       "bac",
							Issuer:     "foo",
							In:         []APIOperationParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url3", CacheDuration: 2 * time.Hour},
						},
					},
				}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			out, err := yaml.Marshal(test.want)
			if err != nil {
				t.Fatalf("yaml.Marshal() returns unexpected: %v", err)
			}
			got := &AuthenticationRequirement{}
			if err := yaml.Unmarshal(out, got); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Marshal and unmarshal results in unexpected AuthenticationRequirement diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalAuthenticationRequirementError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc: "bad jwt format",
			data: []byte(`jwt: bad`),
		},
		{
			desc: "any and jwt coexist",
			data: []byte(`
any:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
jwt:
  name: bar
  issuer: foo
  in:
  - query: query
  remote_jwks:
    url: url2
    cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
		{
			desc: "all and jwt coexist",
			data: []byte(`
all:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
jwt:
  name: bar
  issuer: foo
  in:
  - query: query
  remote_jwks:
    url: url2
    cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
		{
			desc: "all and any coexist",
			data: []byte(`
all:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
any:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			a := &AuthenticationRequirement{}
			if err := yaml.Unmarshal(test.data, a); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, should have got error")
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestMarshalAndUnmarshalJWTAuthentication(t *testing.T) {
	tests := []struct {
		desc string
		want *JWTAuthentication
	}{
		{
			desc: "valid remote_jwks",
			want: &JWTAuthentication{
				Name:       "foo",
				Issuer:     "bar",
				In:         []APIOperationParameter{{Match: Header("header")}, {Match: Query("query")}},
				JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			out, err := yaml.Marshal(test.want)
			t.Log(string(out))
			if err != nil {
				t.Fatalf("yaml.Marshal() returns unexpected: %v", err)
			}
			got := &JWTAuthentication{}
			if err := yaml.Unmarshal(out, got); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Marshal and unmarshal results in unexpected JWTAuthentication diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalJWTAuthenticationError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc: "no jwks source",
			data: []byte(`
name: foo
issuer: bar
in:
- header: header
`),
			wantErr: "remote jwks not found",
		},
		{
			desc: "bad audiences format",
			data: []byte(`
name: foo
issuer: bar
audiences: bad
remote_jwks:
  url: url
in:
- header: header
`),
		},
		{
			desc: "bad jwks source format",
			data: []byte(`
name: foo
issuer: bar
remote_jwks: bad
in:
- header: header
`),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &JWTAuthentication{}
			if err := yaml.Unmarshal(test.data, p); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, should have got error")
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

type testJWKSSource string

func (testJWKSSource) jwksSource() {}

func TestMarshalJWTAuthenticationError(t *testing.T) {

	p := JWTAuthentication{
		Name:       "foo",
		Issuer:     "bar",
		In:         []APIOperationParameter{{Match: Header("header")}},
		JWKSSource: testJWKSSource("bad"),
	}
	wantErr := "unsupported jwks source"

	if _, err := yaml.Marshal(p); err == nil {
		t.Errorf("yaml.Marshal() returns no error, should have got error")
	} else if err.Error() != wantErr {
		t.Errorf("yaml.Marshal() returns error %v, want %s", err, wantErr)
	}
}

func TestMarshalAndUnmarshalAPIOperationParameter(t *testing.T) {
	tests := []struct {
		desc string
		want *APIOperationParameter
	}{
		{
			desc: "valid API operation parameter with header",
			want: &APIOperationParameter{Match: Header("header")},
		},
		{
			desc: "valid API operation parameter with query",
			want: &APIOperationParameter{Match: Query("query")},
		},
		{
			desc: "valid API operation parameter with jwt claim",
			want: &APIOperationParameter{Match: JWTClaim{Requirement: "foo", Name: "bar"}},
		},
		{
			desc: "valid API operation parameter with jwt claim and transformation",
			want: &APIOperationParameter{
				Match:          JWTClaim{Requirement: "foo", Name: "bar"},
				Transformation: StringTransformation{Template: "temp", Substitution: "sub"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			out, err := yaml.Marshal(test.want)
			if err != nil {
				t.Fatalf("yaml.Marshal() returns unexpected: %v", err)
			}
			got := &APIOperationParameter{}
			if err := yaml.Unmarshal(out, got); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Marshal and unmarshal results in unexpected APIOperationParameter diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalAPIOperationParameterError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc: "transformation in bad format",
			data: []byte(`
header: header
transformation: bad
`),
		},
		{
			desc: "jwt_claim in bad format",
			data: []byte(`
jwt_claim: bad
`),
		},
		{
			desc: "jwt claim and header coexist",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
header: header
`),
			wantErr: "precisely one header, query or jwt_claim should be set, got 2",
		},
		{
			desc: "jwt claim and query coexist",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set, got 2",
		},
		{
			desc: "header and query coexist",
			data: []byte(`
header: header
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set, got 2",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &APIOperationParameter{}
			if err := yaml.Unmarshal(test.data, p); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, should have got error")
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

type testParamMatch string

func (testParamMatch) paramMatch() {}

func TestMarshalAPIOperationParameterError(t *testing.T) {

	p := APIOperationParameter{
		Match: testParamMatch("bad"),
	}
	wantErr := "unsupported match type"

	if _, err := yaml.Marshal(p); err == nil {
		t.Errorf("yaml.Marshal() returns no error, should have got error")
	} else if err.Error() != wantErr {
		t.Errorf("yaml.Marshal() returns error %v, want %s", err, wantErr)
	}
}

func TestAuthenticationRequirementTypes(t *testing.T) {
	j := JWTAuthentication{}
	j.authenticationRequirements()

	any := AnyAuthenticationRequirements{}
	any.authenticationRequirements()

	all := AllAuthenticationRequirements{}
	all.authenticationRequirements()
}

func TestJWKSSourceTypes(t *testing.T) {
	j := RemoteJWKS{}
	j.jwksSource()
}

func TestParamMatchTypes(t *testing.T) {
	h := Header("header")
	h.paramMatch()

	q := Query("query")
	q.paramMatch()

	j := JWTClaim{}
	j.paramMatch()
}

func createGoodEnvSpec() EnvironmentSpec {
	return EnvironmentSpec{
		ID: "good-env-config",
		APIs: []APISpec{
			{
				ID:       "apispec1",
				BasePath: "/v1",
				Authentication: AuthenticationRequirement{
					Requirements: AnyAuthenticationRequirements{
						AuthenticationRequirement{
							Requirements: AllAuthenticationRequirements{
								AuthenticationRequirement{
									Requirements: JWTAuthentication{
										Name:       "foo",
										Issuer:     "issuer",
										JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
										In:         []APIOperationParameter{{Match: Header("jwt")}},
									},
								},
							},
						},
					},
				},
				ConsumerAuthorization: ConsumerAuthorization{
					In: []APIOperationParameter{
						{Match: Query("x-api-key")},
						{Match: Header("x-api-key")},
					},
				},
				Operations: []APIOperation{
					{
						Name: "op-1",
						HTTPMatches: []HTTPMatch{
							{
								PathTemplate: "/petstore",
								Method:       "GET",
							},
						},
					},
					{
						Name: "op-2",
						HTTPMatches: []HTTPMatch{
							{
								PathTemplate: "/bookshop",
								Method:       "POST",
							},
						},
					},
				},
				HTTPRequestTransforms: HTTPRequestTransformations{
					SetHeaders: map[string]string{
						"x-apigee-target": "target",
					},
					URLPathTransformations: URLPathTransformations{
						AddPrefix: "/target_prefix/",
					},
				},
			},
			{
				ID:       "apispec2",
				BasePath: "/v2",
				Operations: []APIOperation{
					{
						Name: "op-3",
						HTTPMatches: []HTTPMatch{
							{
								PathTemplate: "/petstore",
								Method:       "GET",
							},
						},
						Authentication: AuthenticationRequirement{
							Requirements: JWTAuthentication{
								Name:       "foo",
								Issuer:     "issuer",
								JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
								In:         []APIOperationParameter{{Match: Header("jwt")}},
							},
						},
						ConsumerAuthorization: ConsumerAuthorization{
							In: []APIOperationParameter{
								{Match: Query("x-api-key2")},
								{Match: Header("x-api-key2")},
							},
						},
					},
				},
			},
		},
	}
}
