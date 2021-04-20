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
	"fmt"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestLoadEnvironmentConfigs(t *testing.T) {
	tests := []struct {
		desc          string
		filename      string
		wantEnvConfig EnvironmentConfig
	}{
		{
			desc:     "good config file with references to env config files",
			filename: "./testdata/good_config.yaml",
			wantEnvConfig: EnvironmentConfig{
				ID: "good-env-config",
				APIs: []APIConfig{
					{
						BasePath: "/v1",
						Authentication: AuthenticationRequirement{
							AuthenticationRequirements: JWTAuthentication{
								Name:       "foo",
								Issuer:     "bar",
								JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
								In:         []APIOperationParameter{{Match: Header("header")}},
							},
						},
						ConsumerAuthorization: ConsumerAuthorization{
							In: []APIOperationParameter{{Match: Header("x-api-key")}},
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
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			c := &Config{}
			if err := c.Load(test.filename, "", "", false); err != nil {
				t.Errorf("c.Load() returns unexpected: %v", err)
			}
			if l := len(c.EnvironmentConfigs.Inline); l != 1 {
				t.Fatalf("c.Load() results in %d EnvironmentConfig, wanted 1", l)
			}
			if diff := cmp.Diff(test.wantEnvConfig, c.EnvironmentConfigs.Inline[0]); diff != "" {
				t.Errorf("c.Load() results in unexpected EnvironmentConfig diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadEnvironmentConfigsError(t *testing.T) {
	tests := []struct {
		desc     string
		filename string
	}{
		{
			desc:     "bad env config files",
			filename: "./testdata/bad_config_1.yaml",
		},
		{
			desc:     "non-existent env config files",
			filename: "./testdata/bad_config_2.yaml",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			c := &Config{}
			if err := c.Load(test.filename, "", "", false); err == nil {
				t.Errorf("c.Load() returns no error, should have got error")
			}
		})
	}
}

func TestValidateEnvironmentConfigs(t *testing.T) {
	tests := []struct {
		desc    string
		cfg     *Config
		hasErr  bool
		wantErr error
	}{
		{
			desc: "good environment configs",
			cfg: &Config{
				EnvironmentConfigs: EnvironmentConfigs{
					Inline: []EnvironmentConfig{
						{
							ID: "good-env-config",
							APIs: []APIConfig{
								{
									BasePath: "/v1",
									Authentication: AuthenticationRequirement{
										AuthenticationRequirements: JWTAuthentication{
											Name:       "foo",
											Issuer:     "bar",
											JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
											In:         []APIOperationParameter{{Match: Header("header")}},
										},
									},
									ConsumerAuthorization: ConsumerAuthorization{
										In: []APIOperationParameter{{Match: Header("x-api-key")}},
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
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "duplicate environment config ids",
			cfg: &Config{
				EnvironmentConfigs: EnvironmentConfigs{
					Inline: []EnvironmentConfig{
						{
							ID: "duplicate-config",
						},
						{
							ID: "duplicate-config",
						},
					},
				},
			},
			hasErr: true,
			wantErr: &errorset.Error{
				Errors: []error{
					fmt.Errorf("environment config IDs must be unique, got multiple duplicate-config"),
				},
			},
		},
		{
			desc: "duplicate operation names",
			cfg: &Config{
				EnvironmentConfigs: EnvironmentConfigs{
					Inline: []EnvironmentConfig{
						{
							ID: "config",
							APIs: []APIConfig{
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
				},
			},
			hasErr: true,
			wantErr: &errorset.Error{
				Errors: []error{
					fmt.Errorf("operation names within each API must be unique, got multiple duplicate-op"),
				},
			},
		},
		{
			desc: "duplicate jwt authentication requirement names",
			cfg: &Config{
				EnvironmentConfigs: EnvironmentConfigs{
					Inline: []EnvironmentConfig{
						{
							ID: "config",
							APIs: []APIConfig{
								{
									Authentication: AuthenticationRequirement{
										AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
											{
												AuthenticationRequirements: JWTAuthentication{Name: "duplicate-jwt"},
											},
											{
												AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
													{
														AuthenticationRequirements: JWTAuthentication{Name: "duplicate-jwt"},
													},
												}),
											},
										}),
									},
								},
							},
						},
					},
				},
			},
			hasErr: true,
			wantErr: &errorset.Error{
				Errors: []error{
					fmt.Errorf("JWT authentication requirement names within each API or operation must be unique, got multiple duplicate-jwt"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if err := test.cfg.validateEnvConfigs(); (err != nil) != test.hasErr {
				t.Errorf("c.validateEnvConfigs() returns no error, should have got error")
			} else if test.wantErr != nil && test.wantErr.Error() != err.Error() {
				t.Errorf("c.validateEnvConfigs() returns error %v, want %s", err, test.wantErr)
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
				AuthenticationRequirements: JWTAuthentication{
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
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []APIOperationParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
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
				AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []APIOperationParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
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
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "foo",
									Issuer:     "bar",
									In:         []APIOperationParameter{{Match: Header("header")}},
									JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
								},
							},
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "bar",
									Issuer:     "foo",
									In:         []APIOperationParameter{{Match: Query("query")}},
									JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
								},
							},
						}),
					},
					{
						AuthenticationRequirements: JWTAuthentication{
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
