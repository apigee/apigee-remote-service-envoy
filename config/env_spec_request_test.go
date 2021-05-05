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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	jwtv "github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func TestNilReceivers(t *testing.T) {
	// no panics
	var s *EnvironmentSpecRequest
	s.GetAPIKey()
	s.GetAPISpec()
	s.GetOperation()
	s.GetParamValue(APIOperationParameter{})
	s.IsAuthenticated()
	s.verifyJWTAuthentication("")
	s.getAuthenticationRequirement()
	s.meetsAuthenticatationRequirements(AuthenticationRequirement{})
	s.getConsumerAuthorization()
}

func TestUnknownAuthenticationRequirementType(t *testing.T) {
	authReqs := AuthenticationRequirement{
		Requirements: unknownAR{},
	}
	req := EnvironmentSpecRequest{}
	if req.meetsAuthenticatationRequirements(authReqs) {
		t.Errorf("should be false")
	}
}

type unknownAR struct {
}

func (u unknownAR) authenticationRequirements() {}

func TestBasicEnvSpecRequest(t *testing.T) {
	configFile := "./testdata/good_config.yaml"
	c := &Config{}
	if err := c.Load(configFile, "", "", false); err != nil {
		t.Fatalf("c.Load() returns unexpected: %v", err)
	}

	apiKey := "myapikey"
	envoyReq := testutil.NewEnvoyRequest(http.MethodGet, "/v1/petstore", map[string]string{"x-api-key": apiKey}, nil)
	specName := "good-env-config"
	spec := c.EnvironmentSpecsByID[specName]
	if spec == nil {
		t.Fatalf("spec not found: %s", specName)
	}
	req := NewEnvironmentSpecRequest(spec, envoyReq)
	req.verifier = &mockJWTVerifier{}

	api := req.GetAPISpec()
	if api == nil {
		t.Errorf("APISpec not found for req")
	}
	op := req.GetOperation()
	if op == nil {
		t.Errorf("Operation not found for req")
	}

	if req.IsAuthenticated() {
		t.Errorf("Operation should not meet authentication requirements")
	}

	got := req.GetAPIKey()
	if got != apiKey {
		t.Errorf("api key incorrect. got: %s, want: %s", got, apiKey)
	}
}

func TestGetAPISpec(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)
	api := &envSpec.APIs[0]

	tests := []struct {
		desc   string
		method string
		path   string
		want   *APISpec
	}{
		{"root", http.MethodGet, "/", nil},
		{"v1 root", http.MethodGet, "/v1", api},
		{"v1 trailing", http.MethodGet, "/v1/", api},
		{"other method /", http.MethodPost, "/v1/petstore/", api},
		{"no prefix /", http.MethodGet, "v1/petstore/", api},
		{"trailing /", http.MethodGet, "/v1/petstore/", api},
		{"no trailing", http.MethodGet, "/v1/petstore", api},
		{"querystring", http.MethodGet, "/v1/petstore?foo=bar", api},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, nil, nil)
			specReq := NewEnvironmentSpecRequest(specExt, envoyReq)

			got := specReq.GetAPISpec()
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetOperation(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)
	if envSpec.APIs[0].ID != "apispec1" {
		t.Fatalf("incorrect API: %v", envSpec.APIs[0])
	}
	petstore := &envSpec.APIs[0].Operations[0]
	bookshop := &envSpec.APIs[0].Operations[1]

	tests := []struct {
		desc   string
		method string
		path   string
		want   *APIOperation
	}{
		{"root", http.MethodGet, "/", nil},
		{"basepath", http.MethodGet, "/v1", nil},
		{"base slash", http.MethodGet, "/v1/", nil},
		{"petstore wrong method", http.MethodPost, "/v1/petstore/", nil},
		{"petstore", http.MethodGet, "/v1/petstore", petstore},
		{"petstore/", http.MethodGet, "/v1/petstore/", petstore},
		{"petstore with query", http.MethodGet, "/v1/petstore?foo=bar", petstore},
		{"bookshop", http.MethodPost, "/v1/bookshop/", bookshop},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, nil, nil)
			specReq := NewEnvironmentSpecRequest(specExt, envoyReq)

			gotAPI := specReq.GetOperation()
			if diff := cmp.Diff(test.want, gotAPI); diff != "" {
				t.Errorf("diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetParamValueQuery(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)

	tests := []struct {
		desc string
		path string
		want string
	}{
		{"no query", "/", ""},
		{"no path", "?key=value", "value"},
		{"no trailing /", "/something?key=value", "value"},
		{"trailing /", "/something/?key=value", "value"},
		{"no keys", "/something?keyvalue", ""},
		{"dup keys", "/something?key=value&key=value1", "value"},
		{"extra key", "/something?key2=value2&key=value", "value"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			param := APIOperationParameter{
				Match: Query("key"),
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			specReq := NewEnvironmentSpecRequest(specExt, envoyReq)
			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestGetParamValueHeader(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)

	tests := []struct {
		desc    string
		headers map[string]string
		key     string
		want    string
	}{
		{"no headers", map[string]string{}, "key", ""},
		{"single header", map[string]string{"key": "value"}, "key", "value"},
		{"missing key", map[string]string{"key1": "value1"}, "key", ""},
		{"multiple headers", map[string]string{"key1": "value1", "key": "value"}, "key", "value"},
		{"case insensitive", map[string]string{"key": "value"}, "KEY", "value"},
		{"multiple headers values", map[string]string{"key": "value,value2"}, "key", "value"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			param := APIOperationParameter{
				Match: Header(test.key),
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, "/", test.headers, nil)
			specReq := NewEnvironmentSpecRequest(specExt, envoyReq)
			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestGetParamValueJWTClaim(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)

	tests := []struct {
		desc      string
		jwtClaims map[string]interface{}
		key       string
		want      string
	}{
		{"no claims", map[string]interface{}{}, "key", ""},
		{"single claim", map[string]interface{}{"key": "value"}, "key", "value"},
		{"missing claim", map[string]interface{}{"key1": "value1"}, "key", ""},
		{"multiple claims", map[string]interface{}{"key1": "value1", "key": "value"}, "key", "value"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			param := APIOperationParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        test.key,
				},
			}

			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			jwtString, err := generateJWT(privateKey, test.jwtClaims)
			if err != nil {
				t.Fatalf("generateJWT() failed: %v", err)
			}

			headers := map[string]string{
				"header": jwtString,
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, "/v1/petstore", headers, nil)
			specReq := NewEnvironmentSpecRequest(specExt, envoyReq)

			specReq.verifier = &mockJWTVerifier{}

			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwtClaims := map[string]interface{}{"key": "value"}
	jwtString, err := generateJWT(privateKey, jwtClaims)
	if err != nil {
		t.Fatalf("generateJWT() failed: %v", err)
	}

	headers := map[string]string{
		"header": jwtString,
	}

	tests := []struct {
		desc string
		path string
	}{
		{"auth in api", "/v1/petstore"},
		{"auth in operation", "/v2/petstore"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, headers, nil)
			req := NewEnvironmentSpecRequest(specExt, envoyReq)

			if req.IsAuthenticated() {
				t.Errorf("IsAuthenticated should be false")
			}

			// internal: err should be cached
			if ok := req.verifyJWTAuthentication("foo"); ok {
				t.Errorf("cache hit should also be correct")
			}
			if req.jwtResults["foo"].err == nil {
				t.Errorf("should have cached err")
			}
			if req.jwtResults["foo"].claims != nil {
				t.Errorf("should not have cached claims")
			}

			// fix the verifier so it works
			req.verifier = &mockJWTVerifier{}
			req.jwtResults = make(map[string]*jwtResult)
			if !req.IsAuthenticated() {
				t.Errorf("IsAuthenticated should be true")
			}

			// internal: claims should be cached
			if ok := req.verifyJWTAuthentication("foo"); !ok {
				t.Errorf("cache hit should also be correct")
			}
			if req.jwtResults["foo"].err != nil {
				t.Errorf("should not have cached err")
			}
			if req.jwtResults["foo"].claims == nil {
				t.Errorf("should have cached claims")
			}

			// test verifyJWTAuthentication directly with bad key
			if ok := req.verifyJWTAuthentication("bad"); ok {
				t.Errorf("verifyJWTAuthentication should return false for bad name")
			}
		})
	}
}

func TestGetAPIKey(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt := NewEnvironmentSpecExt(&envSpec)

	apiKey := "myapikey"
	tests := []struct {
		desc    string
		path    string
		headers map[string]string
		want    string
	}{
		{"api no key", "/v1/petstore", nil, ""},
		{"api key in query", "/v1/petstore?x-api-key=" + apiKey, map[string]string{}, apiKey},
		{"api key in header", "/v1/petstore", map[string]string{"x-api-key": apiKey}, apiKey},
		{"op no key", "/v2/petstore", nil, ""},
		{"op key in query", "/v2/petstore?x-api-key2=" + apiKey, map[string]string{}, apiKey},
		{"op key in header", "/v2/petstore", map[string]string{"x-api-key2": apiKey}, apiKey},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, test.headers, nil)
			req := NewEnvironmentSpecRequest(specExt, envoyReq)
			got := req.GetAPIKey()

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func generateJWT(privateKey *rsa.PrivateKey, claims map[string]interface{}) (string, error) {
	key, err := jwk.New(privateKey)
	if err != nil {
		return "", err
	}
	if err := key.Set("kid", "1"); err != nil {
		return "", err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return "", err
	}

	token := jwt.New()
	for k, v := range claims {
		if err = token.Set(k, v); err != nil {
			return "", err
		}
	}

	payload, err := jwt.Sign(token, jwa.RS256, key)
	return string(payload), err
}

type mockJWTVerifier struct {
}

func (f mockJWTVerifier) Start() {
}

func (f mockJWTVerifier) Stop() {
}

func (f mockJWTVerifier) AddProvider(p jwtv.Provider) {
}

func (f mockJWTVerifier) EnsureProvidersLoaded(context.Context) error {
	return nil
}

func (f mockJWTVerifier) Parse(raw string, p jwtv.Provider) (map[string]interface{}, error) {
	token, err := jwt.Parse([]byte(raw))
	if err != nil {
		return nil, err
	}
	return token.AsMap(context.Background())
}
