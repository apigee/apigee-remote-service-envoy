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
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/fault"
	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/api/option"
)

func TestNilReceivers(t *testing.T) {
	// no panics
	var s *EnvironmentSpecRequest
	s.GetAPIKey()
	s.GetAPISpec()
	s.GetOperation()
	s.GetParamValue(APIOperationParameter{})
	s.Authenticate()
	s.verifyJWTAuthentication("")
	s.getAuthenticationRequirement()
	s.verifyAuthenticatationRequirements(AuthenticationRequirement{})
	s.GetConsumerAuthorization()
}

func TestUnknownAuthenticationRequirementType(t *testing.T) {
	authReqs := AuthenticationRequirement{
		Requirements: unknownAR{},
	}
	req := EnvironmentSpecRequest{}
	if req.verifyAuthenticatationRequirements(authReqs) == nil {
		t.Errorf("should return error")
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
			{
				ID:       "wildcard-bookshop",
				BasePath: "/*/bookshop",
			},
			{
				ID:       "cafe",
				BasePath: "/v2/*/cafe",
			},
			{
				ID:          "grpc-petshop",
				GrpcService: "com.example.PetshopService",
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
		{"wildcard bookshop", http.MethodGet, "/v3/bookshop?foo=bar", apis["wildcard-bookshop"]},
		{"cafe", http.MethodGet, "/v2/blue/cafe", apis["cafe"]},
		{"grpc native", http.MethodPost, "/com.example.PetshopService/ListPets", apis["grpc-petshop"]},
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
	empty := &envSpec.APIs[3].Operations[0]
	grpcList := &envSpec.APIs[4].Operations[0]

	tests := []struct {
		desc       string
		method     string
		path       string
		headers    map[string]string
		opPath     string
		targetPath string
		want       *APIOperation
	}{
		{"root", http.MethodGet, "/", nil, "", "", nil},
		{"basepath", http.MethodGet, "/v1", nil, "", "", nil},
		{"base slash", http.MethodGet, "/v1/", nil, "/", "", nil},
		{"petstore wrong method", http.MethodPost, "/v1/petstore/", nil, "/petstore/", "", nil},
		{"petstore", http.MethodGet, "/v1/petstore", nil, "/petstore", "/petstore", petstore},
		{"petstore/", http.MethodGet, "/v1/petstore/", nil, "/petstore/", "/petstore/", petstore},
		{"petstore with query", http.MethodGet, "/v1/petstore?foo=bar", nil, "/petstore", "/petstore", petstore},
		{"bookshop", http.MethodPost, "/v1/bookshop/", nil, "/bookshop/", "/bookshop/", bookshop},
		{"noop", http.MethodPost, "/v3/bookshop/", nil, "/bookshop/", "/bookshop/", defaultOperation},
		// The basepath for this one is "/v4/*" so expecting "/v4/do" to be trimmed.
		{"empty", http.MethodPost, "/v4/do/whatever/", nil, "/whatever/", "/whatever/", empty},
		// Empty operation should match the below two request paths represent zero and
		{"empty", http.MethodPost, "/v4/do/what/ever", nil, "/what/ever", "/what/ever", empty},
		{"empty", http.MethodPost, "/v4/do", nil, "/", "/", empty},
		{"grpc with specified op", http.MethodPost, "/foo.petstore.PetstoreService/ListPets", map[string]string{"content-type": "application/grpc"}, "/ListPets", "/foo.petstore.PetstoreService/ListPets", grpcList},
		{"grpc with unspecified op", http.MethodPost, "/foo.petstore.PetstoreService/GetPet", map[string]string{"content-type": "application/grpc"}, "/GetPet", "/foo.petstore.PetstoreService/GetPet", nil},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, test.headers, nil)
			specReq := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			gotOperation := specReq.GetOperation()
			if diff := cmp.Diff(test.want, gotOperation, cmpopts.IgnoreUnexported(APIOperation{})); diff != "" {
				t.Errorf("diff (-want +got):\n%s", diff)
			}

			if gotOperation != nil {
				if test.opPath != specReq.GetOperationPath() {
					t.Errorf("unexpected operation path: got %q, want %q", specReq.GetOperationPath(), test.opPath)
				}
			}

			if test.targetPath != specReq.GetTargetRequestPath() {
				t.Errorf("unexpected target request path: got %q, want %q", specReq.GetTargetRequestPath(), test.targetPath)
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
		{"no query", "/v1", ""},
		{"no op path", "v1?key=value", "value"},
		{"no trailing slash", "/v1/petstore?key=value", "value"},
		{"trailing slash", "v1/petstore/?key=value", "value"},
		{"incorrect querystring", "v1/petstore?keyvalue", ""},
		{"dup queries", "v1/petstore?key=value&key=value1", "value,value1"},
		{"other queries", "v1/petstore?key2=value2&key=value", "value"},
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

			got := specReq.GetParamValue(param)
			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
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
		"aud": []string{"foo", "bar"},
	}
	jwtString, err := testutil.GenerateJWT(privateKey, jwtClaims)
	if err != nil {
		t.Fatalf("generateJWT() failed: %v", err)
	}

	tests := []struct {
		desc string
		path string
	}{
		{"auth in api", "/v1/petstore"},
		{"auth in operation", "/v2/petstore"},
		{"auth in api, no op", "/v3/petstore"},
		{"auth in operation, aud claim has partial match", "/v1/airport"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// not authenticated
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if err := req.Authenticate(); err == nil {
				t.Fatalf("Authenticate should return error")
			}

			// internal: err should be cached
			if err := req.verifyJWTAuthentication("foo"); err == nil {
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
			if err := req.Authenticate(); err != nil {
				t.Errorf("Authenticate() should be successful")
			}

			// internal: claims should be cached
			if err := req.verifyJWTAuthentication("foo"); err != nil {
				t.Errorf("cache hit should also be correct")
			}
			if req.jwtResults["foo"].err != nil {
				t.Errorf("should not have cached err")
			}
			if req.jwtResults["foo"].claims == nil {
				t.Errorf("should have cached claims")
			}

			// test verifyJWTAuthentication directly with bad key
			if err := req.verifyJWTAuthentication("bad"); err == nil {
				t.Errorf("verifyJWTAuthentication should return false for bad name")
			}
		})
	}
}

func TestIsAuthorizationRequired(t *testing.T) {
	envSpec := createGoodEnvSpec()
	specExt, err := NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}

	tests := []struct {
		desc string
		path string
		want bool
	}{
		{"authz in api", "/v1/petstore", true},
		{"authz disabled in operation", "/v1/noauthz", false},
	}

	for _, test := range tests {
		envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
		req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

		if got := req.IsAuthorizationRequired(); got != test.want {
			t.Errorf("req.IsAuthorizationRequired() = %v, want %v", got, test.want)
		}
	}
}

func TestAuthenticationRequirementDisabled(t *testing.T) {
	tests := []struct {
		desc     string
		path     string
		authnErr *fault.AdapterFault
	}{
		{"auth in api", "/v1/petstore", nil},
		{"auth in operation", "/v2/petstore", fault.CreateAdapterFaultWithRpcCode(rpc.UNAUTHENTICATED)},
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

			if err := req.Authenticate(); err == nil {
				t.Errorf("Authenticate should be unsuccessful")
			}

			// both operations disabled at API Level, api hit should be ok
			envSpec = createGoodEnvSpec()
			envSpec.APIs[0].Authentication.Disabled = true
			envSpec.APIs[1].Authentication.Disabled = true
			specExt, err = NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq = testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if err := req.Authenticate(); errors.Is(err, test.authnErr) {
				t.Errorf("Authenticate() result mismatch, want: %v, \ngot:  %v", test.authnErr, err)
			}

			// both operations disabled, both operations should be ok
			envSpec = createGoodEnvSpec()
			envSpec.APIs[0].Operations[0].Authentication.Disabled = true
			envSpec.APIs[1].Operations[0].Authentication.Disabled = true
			specExt, err = NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq = testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if err := req.Authenticate(); err != nil {
				t.Errorf("Authenticate should be successful")
			}
		})
	}
}

func TestGetAPIKey(t *testing.T) {
	envSpec := createGoodEnvSpec()

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
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, test.headers, nil)

			// enabled
			envSpec.APIs[0].ConsumerAuthorization.Disabled = false
			envSpec.APIs[1].Operations[0].ConsumerAuthorization.Disabled = false
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got := req.GetAPIKey()

			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}

			// disabled
			envSpec.APIs[0].ConsumerAuthorization.Disabled = true
			envSpec.APIs[1].Operations[0].ConsumerAuthorization.Disabled = true
			specExt, err = NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			req = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			got = req.GetAPIKey()

			if got != "" {
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

func TestGetHTTPRequestTransforms(t *testing.T) {
	envSpec := &EnvironmentSpec{
		ID: "good-env-config",
		APIs: []APISpec{{
			ID:       "apispec1",
			BasePath: "/",
			Operations: []APIOperation{{
				Name: "op",
				HTTPMatches: []HTTPMatch{{
					PathTemplate: "/operation",
				}},
				HTTPRequestTransforms: HTTPRequestTransforms{
					PathTransform: "operation",
				},
			}},
			HTTPRequestTransforms: HTTPRequestTransforms{
				PathTransform: "api",
			},
		}},
	}

	specExt, err := NewEnvironmentSpecExt(envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	envoyReq := testutil.NewEnvoyRequest(http.MethodGet, "/operation", nil, nil)
	envRequest := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

	// ensure operation transform is checked if operation is selected and operation transform exists
	transforms := envRequest.GetHTTPRequestTransforms()
	if transforms.PathTransform != "operation" {
		t.Fatalf("got %q, want operation transform", transforms.PathTransform)
	}

	// ensure api transform is checked if operation is not selected
	envoyReq = testutil.NewEnvoyRequest(http.MethodGet, "/", nil, nil)
	envRequest = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
	transforms = envRequest.GetHTTPRequestTransforms()
	if transforms.PathTransform != "api" {
		t.Fatal("want api transform")
	}

	// ensure api transform is checked if operation is selected, but operation transform doesn't exist
	envSpec.APIs[0].Operations[0].HTTPRequestTransforms = HTTPRequestTransforms{}
	specExt, err = NewEnvironmentSpecExt(envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	envoyReq = testutil.NewEnvoyRequest(http.MethodGet, "/operation", nil, nil)
	envRequest = NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
	transforms = envRequest.GetHTTPRequestTransforms()
	if transforms.PathTransform != "api" {
		t.Fatal("want api transform")
	}
}

func TestVariables(t *testing.T) {
	envSpec := &EnvironmentSpec{
		ID: "good-env-config",
		APIs: []APISpec{{
			BasePath: "/good",
			ID:       "apispec1",
			Operations: []APIOperation{{
				Name: "op",
				HTTPMatches: []HTTPMatch{{
					PathTemplate: "/seg1/{pathsegment}",
				}},
			}},
			HTTPRequestTransforms: HTTPRequestTransforms{
				HeaderTransforms: NameValueTransforms{
					Add: []AddNameValue{
						{"setheader", "new-{headers.setheader}", false},
					},
					Remove: []string{"removeheader"},
				},
				QueryTransforms: NameValueTransforms{
					Add: []AddNameValue{
						{"setquery", "new-{query.setquery}", false},
					},
					Remove: []string{"removequery"},
				},
				PathTransform: "/trans/{path.pathsegment}",
			},
		}},
	}

	specExt, err := NewEnvironmentSpecExt(envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	reqHeaders := map[string]string{
		"setheader":    "oldvalue",
		"removeheader": "oldvalue",
	}
	opPath := "/seg1/value"
	reqPath := fmt.Sprintf("%s%s", envSpec.APIs[0].BasePath, opPath)
	reqQueryString := "setquery=oldvalue&removequery=oldvalue"
	envoyReq := testutil.NewEnvoyRequest(http.MethodGet, fmt.Sprintf("%s?%s", reqPath, reqQueryString), reqHeaders, nil)
	envRequest := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

	transforms := envRequest.GetHTTPRequestTransforms()
	t.Logf("%#v", transforms)
	vars := envRequest.variables
	t.Logf("%#v", envRequest.variables)

	wantRequestVars := map[string]string{
		RequestPath:        opPath,
		RequestQuerystring: reqQueryString,
	}
	if diff := cmp.Diff(wantRequestVars, vars[RequestNamespace]); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(reqHeaders, vars[HeaderNamespace]); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}

	wantQueryVars := map[string]string{
		"setquery":    "oldvalue",
		"removequery": "oldvalue",
	}
	if diff := cmp.Diff(wantQueryVars, envRequest.GetQueryParams()); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}

	wantPathVars := map[string]string{
		"pathsegment": "value",
	}
	if diff := cmp.Diff(wantPathVars, vars[PathNamespace]); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}

	// path
	want := "/trans/value"
	got := envRequest.Reify("/trans/{path.pathsegment}")
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	// header
	want = "new-oldvalue"
	got = envRequest.Reify("new-{headers.setheader}")
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	// query
	want = "new-oldvalue"
	got = envRequest.Reify("new-{query.setquery}")
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}
}

func TestIsCors(t *testing.T) {
	tests := []struct {
		desc         string
		method       string
		path         string
		originHeader string
		isCors       bool
		isPreflight  bool
	}{
		{"not CORS request", http.MethodOptions, "/v1/petstore", "", false, false},
		{"CORS preflight", http.MethodOptions, "/v1/petstore", "origin", true, true},
		{"CORS main", http.MethodGet, "/v1/petstore", "origin", true, false},
		{"no CORS policy", http.MethodGet, "/v2/petstore", "origin", false, false},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envSpec := createGoodEnvSpec()
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatal(err)
			}

			headers := map[string]string{CORSOriginHeader: test.originHeader}
			envoyReq := testutil.NewEnvoyRequest(test.method, test.path, headers, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			if test.isPreflight != req.IsCORSPreflight() {
				t.Errorf("want isPreflight %v, got %v", test.isPreflight, req.IsCORSPreflight())
			}
			if test.isCors != req.IsCORSRequest() {
				t.Errorf("want isCors %v, got %v", test.isCors, req.IsCORSRequest())
			}
		})
	}
}

func TestAllowedOrigin(t *testing.T) {
	tests := []struct {
		desc                string
		allowOrigins        []string
		allowOriginsRegexes []string
		requestOrigin       string
		wantOrigin          string
		wantVary            bool
	}{
		{
			desc:                "nothing",
			allowOrigins:        []string{},
			allowOriginsRegexes: []string{},
			requestOrigin:       "",
			wantOrigin:          "",
			wantVary:            false,
		},
		{
			desc:                "wildcard",
			allowOrigins:        []string{"*"},
			allowOriginsRegexes: []string{},
			requestOrigin:       "origin",
			wantOrigin:          "*",
			wantVary:            true,
		},
		{
			desc:                "exact",
			allowOrigins:        []string{"foo", "origin"},
			allowOriginsRegexes: []string{},
			requestOrigin:       "origin",
			wantOrigin:          "origin",
			wantVary:            true,
		},
		{
			desc:                "regex",
			allowOrigins:        []string{},
			allowOriginsRegexes: []string{"bar", "ori"},
			requestOrigin:       "origin",
			wantOrigin:          "origin",
			wantVary:            true,
		},
		{
			desc:                "no match",
			allowOrigins:        []string{"foo"},
			allowOriginsRegexes: []string{"bar"},
			requestOrigin:       "origin",
			wantOrigin:          "",
			wantVary:            true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envSpec := createGoodEnvSpec()
			envSpec.APIs[0].Cors.AllowOrigins = test.allowOrigins
			envSpec.APIs[0].Cors.AllowOriginsRegexes = test.allowOriginsRegexes
			specExt, err := NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatal(err)
			}

			headers := map[string]string{CORSOriginHeader: test.requestOrigin}
			envoyReq := testutil.NewEnvoyRequest(http.MethodOptions, "/v1/petstore", headers, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			origin, vary := req.AllowedOrigin()
			if test.wantOrigin != origin {
				t.Errorf("want %v, got %v", test.wantOrigin, origin)
			}
			if test.wantVary != vary {
				t.Errorf("want vary %v, got %v", test.wantVary, vary)
			}

		})
	}
}

func TestPrepareVariable(t *testing.T) {
	srv := testutil.IAMServer()
	defer srv.Close()

	envSpec := &EnvironmentSpec{
		APIs: []APISpec{
			{
				ID:       "petstore", // required for the test to work
				BasePath: "/v1",
				ContextVariables: []ContextVariable{{
					Name:      "iam_token",
					Namespace: "_internal",
					Value: GoogleIAMCredentials{
						ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
						Token: AccessToken{
							Scopes: []string{ApigeeAPIScope},
						},
					},
				}},
				Operations: []APIOperation{
					{
						Name: "op1",
						HTTPMatches: []HTTPMatch{{
							PathTemplate: "/op-1",
						}},
					},
					{
						Name: "op2",
						HTTPMatches: []HTTPMatch{{
							PathTemplate: "/op-2",
						}},
						ContextVariables: []ContextVariable{{
							Name:      "iam_token",
							Namespace: "_internal",
							Value: GoogleIAMCredentials{
								ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
								Token: IdentityToken{
									Audience: "aud",
								},
							},
						}},
					},
				},
			},
			{
				ID:       "bookstore",
				BasePath: "/v2",
				ContextVariables: []ContextVariable{{
					Name:      "iam_token",
					Namespace: "_internal",
					Value: GoogleIAMCredentials{
						ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
						Token: IdentityToken{
							Audience: "aud",
						},
					},
				}},
				Operations: []APIOperation{
					{
						Name: "op1",
						HTTPMatches: []HTTPMatch{{
							PathTemplate: "/op-1",
						}},
					},
					{
						Name: "op2",
						HTTPMatches: []HTTPMatch{{
							PathTemplate: "/op-2",
						}},
						ContextVariables: []ContextVariable{{
							Name:      "iam_token",
							Namespace: "_internal",
							Value: GoogleIAMCredentials{
								ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
								Token: AccessToken{
									Scopes: []string{ApigeeAPIScope},
								},
							},
						}},
					},
				},
			},
			{
				BasePath: "/v3",
			},
		},
	}

	opts := []option.ClientOption{
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(http.DefaultClient),
	}
	specExt, err := NewEnvironmentSpecExt(envSpec, WithIAMClientOptions(opts...))
	if err != nil {
		t.Fatal(err)
	}

	defer specExt.Close()

	tests := []struct {
		desc           string
		path           string
		wantTargetAuth string
	}{
		{
			desc:           "access token at api level",
			path:           "/v1/op-1",
			wantTargetAuth: "Bearer access-token",
		},
		{
			desc:           "id token at op level",
			path:           "/v1/op-2",
			wantTargetAuth: "Bearer id-token",
		},
		{
			desc:           "id token at api level",
			path:           "/v2/op-1",
			wantTargetAuth: "Bearer id-token",
		},
		{
			desc:           "access token at op level",
			path:           "/v2/op-2",
			wantTargetAuth: "Bearer access-token",
		},
		{
			desc:           "none",
			path:           "/v3",
			wantTargetAuth: "",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envoyReq := testutil.NewEnvoyRequest(http.MethodGet, test.path, nil, nil)
			req := NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)
			err := req.PrepareVariables()
			if err != nil {
				t.Fatalf("PrepareVariables() err = %v, wanted no error", err)
			}
			if got := req.variables["_internal"]["iam_token"]; test.wantTargetAuth != got {
				t.Errorf("{_internal.iam_token} = %q, wanted %q", got, test.wantTargetAuth)
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
