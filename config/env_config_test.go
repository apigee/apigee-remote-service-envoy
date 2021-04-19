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
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestLoadEnvironmentConfigs(t *testing.T) {
	//TODO
}

func TestUnmarshalAuthenticationRequirementYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *AuthenticationRequirement
	}{
		{
			desc: "valid jwt",
			data: []byte(`
jwt:
  name: foo
  issuer: bar
  in:
  - header: header
  remote_jwks:
    url: url
    cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: JWTAuthentication{
					Name:       "foo",
					Issuer:     "bar",
					In:         []HTTPParameter{{Match: Header("header")}},
					JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
				},
			},
		},
		{
			desc: "valid any enclosing jwt",
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
- jwt:
    name: bar
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url2
      cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []HTTPParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid all enclosing jwt",
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
- jwt:
    name: bar
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url2
      cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []HTTPParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid any enclosing all and jwt",
			data: []byte(`
any:
- all:
  - jwt:
      name: foo
      issuer: bar
      in:
      - header: header
      remote_jwks:
        url: url1
        cache_duration: 1h
  - jwt:
      name: bar
      issuer: foo
      in:
      - query: query
      remote_jwks:
        url: url2
        cache_duration: 1h
- jwt:
    name: bac
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url3
      cache_duration: 2h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "foo",
									Issuer:     "bar",
									In:         []HTTPParameter{{Match: Header("header")}},
									JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
								},
							},
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "bar",
									Issuer:     "foo",
									In:         []HTTPParameter{{Match: Query("query")}},
									JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
								},
							},
						}),
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bac",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url3", CacheDuration: 2 * time.Hour},
						},
					},
				}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			a := &AuthenticationRequirement{}
			if err := yaml.Unmarshal(test.data, a); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, a); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected AuthenticationRequirement diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalAuthenticationRequirementYAMLError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
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
				t.Errorf("yaml.Unmarshal() returns no error, want %s", test.wantErr)
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestUnmarshalJWTAuthenticationYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *JWTAuthentication
	}{
		{
			desc: "valid remote_jwks",
			data: []byte(`
name: foo
issuer: bar
in:
- header: header
remote_jwks:
  url: url
  cache_duration: 1h
`),
			want: &JWTAuthentication{
				Name:   "foo",
				Issuer: "bar",
				In: []HTTPParameter{
					{
						Match: Header("header"),
					},
				},
				JWKSSource: RemoteJWKS{
					URL:           "url",
					CacheDuration: time.Hour,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			j := &JWTAuthentication{}
			if err := yaml.Unmarshal(test.data, j); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, j); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected JWTAuthentication diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalHTTPParameterYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *HTTPParameter
	}{
		{
			desc: "valid http parameter with header",
			data: []byte(`header: header`),
			want: &HTTPParameter{
				Match: Header("header"),
			},
		},
		{
			desc: "valid http parameter with query",
			data: []byte(`query: query`),
			want: &HTTPParameter{
				Match: Query("query"),
			},
		},
		{
			desc: "valid http parameter with jwt claim",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
`),
			want: &HTTPParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        "bar",
				},
			},
		},
		{
			desc: "valid http parameter with jwt claim and transformation",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
transformation:
  template: temp
  substitution: sub
`),
			want: &HTTPParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        "bar",
				},
				Transformation: StringTransformation{
					Template:     "temp",
					Substitution: "sub",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := yaml.Unmarshal(test.data, p); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, p); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected HTTPParamter diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalHTTPParameterYAMLError(t *testing.T) {
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
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "jwt claim and query coexist",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "header and query coexist",
			data: []byte(`
header: header
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := yaml.Unmarshal(test.data, p); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, want %s", test.wantErr)
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
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
