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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	s.GetConsumerAuthorization()
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

func TestGetAPISpec(t *testing.T) {
	envSpec := EnvironmentSpec{
		ID: "env-config",
		APIs: []APISpec{
			{
				ID:       "root",
				BasePath: "/",
			},
			{
				ID:       "petstore",
				BasePath: "/v1",
			},
			{
				ID:       "bookshop",
				BasePath: "/v1/bookshop",
			},
		},
	}
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

	apis := make(map[string]*APISpec)
	for i := range envSpec.APIs {
		api := &envSpec.APIs[i]
		apis[api.ID] = api
	}

	tests := []struct {
		desc   string
		method string
		path   string
		want   *APISpec
	}{
		{"root", http.MethodGet, "/", apis["root"]},
		{"v1 root", http.MethodGet, "/v1", apis["petstore"]},
		{"v1 trailing", http.MethodGet, "/v1/", apis["petstore"]},
		{"other method /", http.MethodPost, "/v1/petstore/", apis["petstore"]},
		{"no prefix /", http.MethodGet, "v1/petstore/", apis["petstore"]},
		{"trailing /", http.MethodGet, "/v1/petstore/", apis["petstore"]},
		{"no trailing", http.MethodGet, "/v1/petstore", apis["petstore"]},
		{"querystring", http.MethodGet, "/v1/petstore?foo=bar", apis["petstore"]},
		{"bookshop", http.MethodGet, "/v1/bookshop?foo=bar", apis["bookshop"]},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, nil, nil)
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			got := specReq.GetAPISpec()
			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreUnexported(APISpec{})); diff != "" {
				t.Errorf("diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetOperation(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
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
		{"noop", http.MethodPost, "/v3/bookshop/", synthesizedOperation},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, nil, nil)
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			gotAPI := specReq.GetOperation()
			if diff := cmp.Diff(test.want, gotAPI, cmpopts.IgnoreUnexported(APIOperation{})); diff != "" {
				t.Errorf("diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetParamValueQuery(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

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
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestGetParamValueHeader(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

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
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestGetParamValueJWTClaim(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

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
			jwtString, err := testutil.GenerateJWT(privateKey, test.jwtClaims)
			if err != nil {
				t.Fatalf("generateJWT() failed: %v", err)
			}

			headers := map[string]string{
				"jwt": jwtString,
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, "/v1/petstore", headers, nil)
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			specReq.verifier = &testutil.MockJWTVerifier{}

			got := specReq.GetParamValue(param)

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwtClaims := map[string]interface{}{
		"key": "value",
		"iss": "issuer",
	}
	jwtString, err := testutil.GenerateJWT(privateKey, jwtClaims)
	if err != nil {
		t.Fatalf("generateJWT() failed: %v", err)
	}

	tests := []struct {
		desc string
		path string
	}{
		// {"auth in api", "/v1/petstore"},
		// {"auth in operation", "/v2/petstore"},
		{"auth in api, no op", "/v3/petstore"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// not authenticated
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

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

			// authenticated
			headers := map[string]string{"jwt": jwtString}
			envoyReq = testutil.NewEnvoyRequest(http.MethodGet, test.path, headers, nil)
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

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

func TestAuthenticationRequirementDisabled(t *testing.T) {
	tests := []struct {
		desc string
		path string
		api  bool
	}{
		{"auth in api", "/v1/petstore", true},
		{"auth in operation", "/v2/petstore", false},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			// not authenticated
			envSpec := createGoodEnvSpec()
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if req.IsAuthenticated() {
				t.Errorf("IsAuthenticated should be false")
			}

			// both tests disabled at API Level, api hit should be ok
			envSpec = createGoodEnvSpec()
			envSpec.APIs[0].Authentication.Disabled = true
			envSpec.APIs[1].Authentication.Disabled = true
			specExt, err = NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq = testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if req.IsAuthenticated() != test.api {
				t.Errorf("IsAuthenticated should be %t", test.api)
			}

			// both tests disabled at operation Level, only operation hit should be ok
			envSpec = createGoodEnvSpec()
			envSpec.APIs[0].Operations[0].Authentication.Disabled = true
			envSpec.APIs[1].Operations[0].Authentication.Disabled = true
			specExt, err = NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq = testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if req.IsAuthenticated() == test.api {
				t.Errorf("IsAuthenticated should be %t", !test.api)
			}
		})
	}
}

func TestGetAPIKey(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

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
		{"op key in bearer", "/v2/petstore", map[string]string{"authorization": "Bearer " + apiKey}, apiKey},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			// enabled
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, test.headers, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got := req.GetAPIKey()

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}

			// disabled
			envSpec.APIs[0].ConsumerAuthorization.Disabled = true
			envSpec.APIs[1].Operations[0].ConsumerAuthorization.Disabled = true
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got = req.GetAPIKey()

			if "" != got {
				t.Errorf("want: %q, got: %q", "", got)
			}
		})
	}
}

func TestEnvSpecRequestJWTAuthentications(t *testing.T) {
	tests := []struct {
		desc   string
		path   string
		jwtLen int
	}{
		{"auth in api", "/v1/petstore", 1},
		{"auth in operation", "/v2/petstore/pets", 2},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			// not authenticated
			envSpec := createGoodEnvSpec()
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}

			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if l := len(req.JWTAuthentications()); l != test.jwtLen {
				t.Errorf("req.JWTAuthentications() = %d, want %d", l, test.jwtLen)
			}
		})
	}
}

type testAuthMan struct {
}

func (a *testAuthMan) Close() {}
func (a *testAuthMan) Authenticate(ctx context.Context, apiKey string, claims map[string]interface{},
	apiKeyClaimKey string) (*auth.Context, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *testAuthMan) ParseJWT(jwtString string, provider jwt.Provider) (map[string]interface{}, error) {
	return testutil.MockJWTVerifier{}.Parse(jwtString, provider)
}

// if operation, do that
// if operation miss, fail
// if no operation, do no op
