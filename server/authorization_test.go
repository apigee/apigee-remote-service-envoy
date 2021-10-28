// Copyright 2020 Google LLC
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

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	apigeeContext "github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRegister(t *testing.T) {
	opts := []grpc.ServerOption{}
	grpcServer := grpc.NewServer(opts...)
	server := AuthorizationServer{}
	h := &Handler{}
	server.Register(grpcServer, h)
	if h != server.handler {
		t.Errorf("want: %v, got: %v", h, server.handler)
	}
	grpcServer.Stop()
}

func TestAddHeaderTransforms(t *testing.T) {
	tests := []struct {
		desc            string
		requestHeaders  map[string]string
		addHeaders      []config.AddNameValue
		removeHeaders   []string
		expectedAdds    int // +1 to include :path
		expectedRemoves int
		expectedLog     string
	}{
		{
			desc:            "test0",
			requestHeaders:  map[string]string{"existing": "value"},
			addHeaders:      []config.AddNameValue{},
			removeHeaders:   []string{},
			expectedAdds:    1,
			expectedRemoves: 0,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n",
		},
		{
			desc:           "test1",
			requestHeaders: map[string]string{"remove1": "remove"},
			addHeaders: []config.AddNameValue{
				{Name: "append", Value: "append1", Append: true},
				{Name: "set", Value: "set1", Append: false},
			},
			removeHeaders:   []string{"remove1"},
			expectedAdds:    3,
			expectedRemoves: 1,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n  + \"append\": \"appen...\"\n  = \"set\": \"set1\"\n   - \"remove1\"\n",
		},
		{
			desc:           "test2",
			requestHeaders: map[string]string{"remove1": "remove", "skip": "don't remove"},
			addHeaders: []config.AddNameValue{
				{Name: "append", Value: "append1", Append: true},
				{Name: "append", Value: "append2", Append: true},
				{Name: "set", Value: "set1", Append: false},
			},
			removeHeaders:   []string{"Remove1", "missing"},
			expectedAdds:    4,
			expectedRemoves: 1,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n  + \"append\": \"appen...\"\n  + \"append\": \"appen...\"\n  = \"set\": \"set1\"\n   - \"remove1\"\n",
		},
		{
			desc:            "test3",
			requestHeaders:  map[string]string{"remove1": "remove", "remove2": "remove", "skip": "don't remove"},
			addHeaders:      []config.AddNameValue{},
			removeHeaders:   []string{"Remove*"},
			expectedAdds:    1,
			expectedRemoves: 2,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n   - \"remove1\"\n   - \"remove2\"\n",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envSpec := createAuthEnvSpec()

			envSpec.APIs[0].HTTPRequestTransforms = config.HTTPRequestTransforms{
				HeaderTransforms: config.NameValueTransforms{
					Add:    test.addHeaders,
					Remove: test.removeHeaders,
				},
			}
			specExt, err := config.NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq := testutil.NewEnvoyRequest("GET", "/v1/petstore", test.requestHeaders, nil)
			specReq := config.NewEnvironmentSpecRequest(nil, specExt, envoyReq)
			okResponse := &authv3.OkHttpResponse{}

			addRequestHeaderTransforms(envoyReq, specReq, okResponse)

			if test.expectedAdds != len(okResponse.Headers) {
				t.Errorf("expected %d header adds got: %d", test.expectedAdds, len(okResponse.Headers))
			}
			if test.expectedRemoves != len(okResponse.HeadersToRemove) {
				t.Errorf("expected %d header removes got: %d", test.expectedRemoves, len(okResponse.HeadersToRemove))
			}

			for _, kv := range test.addHeaders {
				if !hasHeaderAdd(okResponse.Headers, kv.Name, kv.Value, kv.Append) {
					t.Errorf("expected header mod: %q: %q (%t)", kv.Name, kv.Value, kv.Append)
				}
			}
			for _, k := range test.removeHeaders {
				if _, ok := test.requestHeaders[k]; ok && !hasHeaderRemove(okResponse, k) {
					t.Errorf("expected header remove: %q", k)
				}
				if _, ok := test.requestHeaders[k]; !ok && hasHeaderRemove(okResponse, k) {
					t.Errorf("did not expect header remove: %q", k)
				}
			}

			logged := printHeaderMods(okResponse)
			if test.expectedLog != logged {
				t.Errorf("want: %q\n, got: %q\n", test.expectedLog, logged)
			}
		})
	}
}

func hasHeaderAdd(headers []*corev3.HeaderValueOption, key, value string, append bool) bool {
	for _, h := range headers {
		if key == h.Header.Key &&
			value == h.Header.Value &&
			append == h.Append.Value {
			return true
		}
	}
	return false
}

func getHeaderValueOption(headers []*corev3.HeaderValueOption, key string) *corev3.HeaderValueOption {
	for _, h := range headers {
		if key == h.Header.Key {
			return h
		}
	}
	return nil
}

func hasHeaderRemove(okr *authv3.OkHttpResponse, key string) bool {
	for _, h := range okr.HeadersToRemove {
		if h == key {
			return true
		}
	}
	return false
}

func TestPathTransforms(t *testing.T) {
	tests := []struct {
		desc          string
		path          string
		pathTransform string
		addQueries    []config.AddNameValue
		removeQueries []string
		targetPath    string
	}{
		{
			desc:          "test0",
			path:          "/v1/petstore?query=value",
			pathTransform: "",
			addQueries:    []config.AddNameValue{},
			removeQueries: []string{},
			targetPath:    "/petstore?query=value",
		},
		{
			desc:          "test1",
			path:          "/v1/petstore?remove1=test",
			pathTransform: "/v2/{request.path}",
			addQueries: []config.AddNameValue{
				{Name: "append", Value: "append1", Append: true},
				{Name: "set", Value: "set1", Append: false},
			},
			removeQueries: []string{"remove*"},
			targetPath:    "/v2/petstore?append=append1&set=set1",
		},
		{
			desc:          "test2",
			path:          "/v1/petstore?remove1=test",
			pathTransform: "/v2/{request.path}",
			addQueries: []config.AddNameValue{
				{Name: "append", Value: "append1", Append: true},
				{Name: "append", Value: "append2", Append: true},
				{Name: "query", Value: "{query.remove1}", Append: false},
			},
			removeQueries: []string{"Remove1", "missing"},
			targetPath:    "/v2/petstore?append=append1&append=append2&query=test",
		},
		{
			desc:          "test3",
			path:          "/v1/petstore?remove1=test&remove2=test",
			pathTransform: "/v2/{request.path}",
			addQueries:    []config.AddNameValue{},
			removeQueries: []string{"Remove*"},
			targetPath:    "/v2/petstore",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envSpec := createAuthEnvSpec()

			envSpec.APIs[0].HTTPRequestTransforms = config.HTTPRequestTransforms{
				PathTransform: test.pathTransform,
				QueryTransforms: config.NameValueTransforms{
					Add:    test.addQueries,
					Remove: test.removeQueries,
				},
			}
			specExt, err := config.NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq := testutil.NewEnvoyRequest("GET", test.path, nil, nil)
			specReq := config.NewEnvironmentSpecRequest(nil, specExt, envoyReq)
			okResponse := &authv3.OkHttpResponse{}

			addRequestHeaderTransforms(envoyReq, specReq, okResponse)

			// path
			pathSet := getHeaderValueOption(okResponse.Headers, envoyPathHeader)
			if pathSet == nil {
				t.Errorf("expected :path header mod")
			} else if pathSet.Append.Value {
				t.Errorf("expected :path set, got append")
			} else if pathSet.Header.Value != test.targetPath {
				want, err := url.Parse(test.targetPath)
				if err != nil {
					t.Fatalf("%v", err)
				}
				got, err := url.Parse(pathSet.Header.Value)
				if err != nil {
					t.Fatalf("%v", err)
				}
				if want.Path != got.Path {
					t.Errorf("expected path: %q, got: %q", want.Path, got.Path)
				}
				if diff := cmp.Diff(want.Query(), got.Query()); diff != "" {
					t.Errorf("query diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestEnvRequestCheck(t *testing.T) {
	envSpec := createAuthEnvSpec()
	specExt, err := config.NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	environmentSpecsByID := map[string]*config.EnvironmentSpecExt{
		specExt.ID: specExt,
	}

	testAuthMan := &testAuthMan{}
	testProductMan := &testProductMan{
		api:     "api",
		resolve: true,
		products: product.ProductsNameMap{
			"product1": &product.APIProduct{
				DisplayName: "product1",
			},
		},
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			apiKeyClaim:           headerClientID, // ignored
			apiHeader:             headerAPI,      // ignored
			apiKeyHeader:          "x-api-key",    // ignored
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
			analyticsMan:          testAnalyticsMan,
			envSpecsByID:          environmentSpecsByID,
			ready:                 util.NewAtomicBool(true),
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwtClaims := map[string]interface{}{
		"iss": "issuer",
		"aud": []string{"aud1", "aud2"},
	}
	jwtString, err := testutil.GenerateJWT(privateKey, jwtClaims)
	if err != nil {
		t.Fatalf("generateJWT() failed: %v", err)
	}

	uri := "/v1/petstore?x-api-key=foo"
	contextExtensions := map[string]string{
		envSpecContextKey: specExt.ID,
	}

	tests := []struct {
		desc        string
		method      string
		path        string
		headers     map[string]string
		authContext *auth.Context
		authErr     error
		statusCode  int32
		wantHeaders []string
		wantValues  []string
		wantAppends []bool
		immediateAX int
	}{
		{
			desc:        "missing api",
			method:      http.MethodGet,
			path:        "/v0/missing",
			statusCode:  int32(rpc.NOT_FOUND),
			immediateAX: 1,
		},
		{
			desc:        "missing operation",
			method:      http.MethodGet,
			path:        "/v1/missing",
			statusCode:  int32(rpc.NOT_FOUND),
			immediateAX: 1,
		},
		{
			desc:        "bad authentication",
			method:      http.MethodGet,
			path:        uri,
			statusCode:  int32(rpc.UNAUTHENTICATED),
			immediateAX: 1,
		},
		{
			desc:   "bad authentication because op overrides the auth req",
			method: http.MethodGet,
			path:   "/v1/airport",
			headers: map[string]string{
				"jwt": jwtString,
			},
			statusCode:  int32(rpc.UNAUTHENTICATED),
			immediateAX: 1,
		},
		{
			desc:   "good authentication, bad authorization",
			method: http.MethodGet,
			path:   uri,
			headers: map[string]string{
				"jwt": jwtString,
			},
			authErr:     auth.ErrBadAuth,
			statusCode:  int32(rpc.PERMISSION_DENIED),
			immediateAX: 1,
		},
		{
			desc:   "good authn/z, network failure w/ fail open",
			method: http.MethodGet,
			path:   uri,
			headers: map[string]string{
				"jwt": jwtString,
			},
			authErr:     auth.ErrNetworkError,
			statusCode:  int32(rpc.OK),
			immediateAX: 0,
		},
		{
			desc:   "good request",
			method: http.MethodGet,
			path:   uri,
			headers: map[string]string{
				"jwt": jwtString,
			},
			authContext: &auth.Context{
				APIProducts: []string{"product1"},
			},
			statusCode: int32(rpc.OK),
			wantHeaders: []string{
				":path",
				"target",
				"target",
			},
			wantValues: []string{
				"/petstore?x-api-key=foo",
				"add",
				"append",
			},
			wantAppends: []bool{false, false, true},
			immediateAX: 0,
		},
		{
			desc:       "no consumerauthorization required",
			method:     http.MethodGet,
			path:       "/v2/noauthz",
			statusCode: int32(rpc.OK),
			wantHeaders: []string{
				":path",
			},
			wantValues: []string{
				"/noauthz",
			},
			wantAppends: []bool{false},
			immediateAX: 0,
		},
		{
			desc:       "no consumerauthorization required in operation level",
			method:     http.MethodGet,
			path:       "/v3/noauthz-op",
			statusCode: int32(rpc.OK),
			wantHeaders: []string{
				":path",
			},
			wantValues: []string{
				"/noauthz-op",
			},
			wantAppends: []bool{false},
			immediateAX: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			req := testutil.NewEnvoyRequest(test.method, test.path, test.headers, nil)
			req.Attributes.ContextExtensions = contextExtensions
			testAuthMan.sendAuth(test.authContext, test.authErr)
			resp, err := server.Check(context.Background(), req)
			if err != nil {
				t.Errorf("should not get error. got: %s", err)
			}
			if resp.Status.Code != test.statusCode {
				t.Errorf("got: %d, want: %d", resp.Status.Code, test.statusCode)
			}
			if len(testAnalyticsMan.records) != test.immediateAX {
				t.Errorf("want %d immediate analytics record, got: %d", test.immediateAX, len(testAnalyticsMan.records))
			}
			testAnalyticsMan.records = []analytics.Record{}
			if test.statusCode == int32(rpc.OK) {
				okr, ok := resp.HttpResponse.(*authv3.CheckResponse_OkResponse)
				if !ok {
					t.Fatal("must be OkResponse")
				}
				for i, h := range test.wantHeaders {
					if !hasHeaderAdd(okr.OkResponse.GetHeaders(), h, test.wantValues[i], test.wantAppends[i]) {
						if test.wantAppends[i] {
							t.Errorf("%q not appended to header %q", test.wantValues[i], h)
						} else {
							t.Errorf("%q header should be: %q", h, test.wantValues[i])
						}
					}
				}
				// Test selected Apigee dynamic data response header
				if !hasHeaderAdd(okr.OkResponse.GetResponseHeadersToAdd(), headerDPColor, os.Getenv("APIGEE_DPCOLOR"), false) {
					t.Errorf("expected response header add: %q", headerDPColor)
				}
			}
		})
	}
}

func TestBasePathStripping(t *testing.T) {
	envSpec := createAuthEnvSpec()
	specExt, err := config.NewEnvironmentSpecExt(&envSpec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	environmentSpecsByID := map[string]*config.EnvironmentSpecExt{
		specExt.ID: specExt,
	}

	testAuthMan := &testAuthMan{}
	testAuthMan.sendAuth(&auth.Context{
		APIProducts: []string{"product1"},
	}, nil)
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwtClaims := map[string]interface{}{
		"iss": "issuer",
		"aud": []string{"aud1", "aud2"},
	}
	jwtString, err := testutil.GenerateJWT(privateKey, jwtClaims)
	if err != nil {
		t.Fatalf("generateJWT() failed: %v", err)
	}
	headers := map[string]string{
		"jwt": jwtString,
	}

	uri := "/v1/petstore?x-api-key=foo"
	contextExtensions := map[string]string{
		envSpecContextKey: specExt.ID,
	}

	tests := []struct {
		desc         string
		opConfigType string
		path         string
	}{
		{
			desc:         "base path stripped for proxy mode",
			opConfigType: "proxy",
			path:         "/petstore",
		},
		{
			desc: "base path stripped by default",
			path: "/petstore",
		},
		{
			desc:         "base path stripped for remoteservice mode",
			opConfigType: "remoteservice",
			path:         "/petstore",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			testProductMan := &testProductMan{
				api:     "api",
				resolve: true,
				products: product.ProductsNameMap{
					"product1": &product.APIProduct{
						DisplayName: "product1",
					},
				},
				path: test.path,
			}
			server := AuthorizationServer{
				handler: &Handler{
					authMan:             testAuthMan,
					productMan:          testProductMan,
					quotaMan:            testQuotaMan,
					analyticsMan:        testAnalyticsMan,
					envSpecsByID:        environmentSpecsByID,
					operationConfigType: test.opConfigType,
					ready:               util.NewAtomicBool(true),
				},
			}
			req := testutil.NewEnvoyRequest("GET", uri, headers, nil)
			req.Attributes.ContextExtensions = contextExtensions
			resp, err := server.Check(context.Background(), req)
			if err != nil {
				t.Errorf("should not get error. got: %s", err)
			}
			if resp.Status.Code != int32(rpc.OK) {
				t.Errorf("expected status code OK, got %d", resp.Status.Code)
			}
		})
	}
}

func TestGlobalCheck(t *testing.T) {

	jwtClaims := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"apigee": {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"api_product_list": {
								Kind: &structpb.Value_StringValue{
									StringValue: "product1,product2",
								},
							},
						},
					},
				},
			},
		},
	}

	headers := map[string]string{}

	products := product.ProductsNameMap{
		"product1": &product.APIProduct{
			DisplayName: "product1",
		},
	}

	uri := "path?x-api-key=foo"
	req := testutil.NewEnvoyRequest(http.MethodGet, uri, headers,
		map[string]*structpb.Struct{
			jwtFilterMetadataKey: jwtClaims,
		})

	testAuthMan := &testAuthMan{}
	testProductMan := &testProductMan{
		api:     "api",
		resolve: true,
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			apiKeyClaim:           headerClientID,
			apiHeader:             headerAPI,
			apiKeyHeader:          "x-api-key",
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
			analyticsMan:          testAnalyticsMan,
			ready:                 util.NewAtomicBool(false),
		},
	}

	// not ready
	var resp *authv3.CheckResponse
	var err error
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAVAILABLE) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAVAILABLE))
	}
	server.handler.ready.SetTrue()

	// no api header
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}
	headers[headerAPI] = "api"

	// ErrNoAuth
	testAuthMan.sendAuth(nil, auth.ErrNoAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}

	// ErrBadAuth
	testAuthMan.sendAuth(nil, auth.ErrBadAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// ErrInternalError
	testAuthMan.sendAuth(nil, auth.ErrInternalError)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// reset auth error
	testAuthMan.sendAuth(nil, nil)

	// no products
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// no matched products
	testAuthMan.sendAuth(&auth.Context{
		APIProducts: []string{"no match"},
	}, nil)
	testProductMan.products = products
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}
	testProductMan.resolve = true

	// no products authenticated
	testAuthMan.sendAuth(&auth.Context{
		APIProducts: []string{},
	}, nil)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// valid auth
	testAuthMan.sendAuth(&auth.Context{
		APIProducts: []string{"product1"},
	}, nil)

	// quota exceeded
	products["product1"].QuotaLimitInt = 2
	testQuotaMan.exceeded = 2
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.RESOURCE_EXHAUSTED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.RESOURCE_EXHAUSTED))
	}
	code := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code
	if code != http.StatusTooManyRequests {
		t.Errorf("got: %d, want: %d", code, http.StatusTooManyRequests)
	}
	testQuotaMan.exceeded = 0

	// quota error
	testQuotaMan.sendError = errors.New("quota error")
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}
	testQuotaMan.sendError = nil

	// all OK
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// bad api in context metadata
	req.Attributes.ContextExtensions = map[string]string{}
	req.Attributes.ContextExtensions[apiContextKey] = "bad-api"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// good api in context supersedes even if api header is bad
	headers[headerAPI] = "bad-api"
	req.Attributes.ContextExtensions[apiContextKey] = "api"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}
	delete(req.Attributes.ContextExtensions, apiContextKey)
	headers[headerAPI] = "api"

	// testAuthMan.ctx
	if testAuthMan.apiKey != "foo" {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKey, "foo")
	}
	// testAuthMan.claims
	if testAuthMan.apiKeyClaimKey != headerClientID {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKeyClaimKey, headerClientID)
	}

	// non-existing jwtProviderKey
	server.handler.jwtProviderKey = "not-apigee"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// testAuthMan.claims should be nil
	if len(testAuthMan.claims) != 0 {
		t.Errorf("got: %d, want: empty claims", len(testAuthMan.claims))
	}

	// empty jwtProviderKey to enter the claims loop
	server.handler.jwtProviderKey = ""
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// testAuthMan.claims should be nil
	if len(testAuthMan.claims) != 1 {
		t.Errorf("got: %d, want: claims length to be 1", len(testAuthMan.claims))
	}

	// check deny when allowUnauthorized = true
	server.handler.allowUnauthorized = true
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// improper context, not multitenant
	server.handler.envName = "test"
	req.Attributes.ContextExtensions[envContextKey] = "prod"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// multitenant missing context
	server.handler.envName = "*"
	server.handler.isMultitenant = true
	delete(req.Attributes.ContextExtensions, envContextKey)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// multitenant receives context
	req.Attributes.ContextExtensions[envContextKey] = "test"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}
}

func TestImmediateAnalytics(t *testing.T) {

	jwtClaims := &structpb.Struct{}

	headers := map[string]string{
		"User-Agent":      "User-Agent",
		"X-Forwarded-For": "X-Forwarded-For",
		headerAPI:         "api",
	}

	requestPath := "path"
	uri := requestPath + "?x-api-key=foo"
	requestTime := time.Now()
	nowProto := timestamppb.New(requestTime)

	req := testutil.NewEnvoyRequest(http.MethodGet, uri, headers, map[string]*structpb.Struct{
		jwtFilterMetadataKey: jwtClaims,
	})
	req.Attributes.Request.Time = nowProto

	testAuthMan := &testAuthMan{}
	ac := &auth.Context{
		ClientID:       "client id",
		AccessToken:    "token",
		Application:    "app",
		APIProducts:    []string{"product1"},
		Expires:        time.Now(),
		DeveloperEmail: "email",
		Scopes:         []string{"scope"},
		APIKey:         "apikey",
	}
	testAuthMan.sendAuth(ac, auth.ErrBadAuth)

	testProductMan := &testProductMan{
		resolve: true,
		api:     "api",
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			orgName:               "org",
			envName:               "env",
			apiKeyClaim:           headerClientID,
			apiHeader:             headerAPI,
			apiKeyHeader:          "x-api-key",
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			analyticsMan:          testAnalyticsMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
			ready:                 util.NewAtomicBool(true),
		},
		gatewaySource: managedGatewaySource,
	}

	var resp *authv3.CheckResponse
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	if len(testAnalyticsMan.records) != 1 {
		t.Fatalf("got: %d, want: %d", len(testAnalyticsMan.records), 1)
	}

	// Check selected Apigee dynamic data header
	if !hasHeaderAdd(resp.GetDeniedResponse().GetHeaders(), headerFaultFlag, "true", false) {
		t.Errorf("expected response header add: %q", headerFaultFlag)
	}

	got := testAnalyticsMan.records[0]
	want := analytics.Record{
		ClientReceivedStartTimestamp: requestTime.UnixNano() / 1000000,
		ClientReceivedEndTimestamp:   requestTime.UnixNano() / 1000000,
		TargetSentStartTimestamp:     0,
		TargetSentEndTimestamp:       0,
		TargetReceivedStartTimestamp: 0,
		TargetReceivedEndTimestamp:   0,
		RecordType:                   "APIAnalytics",
		APIProxy:                     headers[headerAPI],
		RequestURI:                   uri,
		RequestPath:                  requestPath,
		RequestVerb:                  http.MethodGet,
		ClientIP:                     headers["X-Forwarded-For"],
		UserAgent:                    headers["User-Agent"],
		APIProxyRevision:             0,
		ResponseStatusCode:           http.StatusForbidden,
		DeveloperEmail:               ac.DeveloperEmail,
		DeveloperApp:                 ac.Application,
		AccessToken:                  ac.AccessToken,
		ClientID:                     ac.ClientID,
		APIProduct:                   ac.APIProducts[0],
		Organization:                 server.handler.orgName,
		Environment:                  server.handler.envName,
		GatewaySource:                managedGatewaySource,
		// the following fields vary, ignore them
		ClientSentStartTimestamp: got.ClientSentStartTimestamp,
		ClientSentEndTimestamp:   got.ClientSentEndTimestamp,
		GatewayFlowID:            got.GatewayFlowID,
	}

	if got.ClientSentStartTimestamp < requestTime.Unix() {
		t.Errorf("got: %d, want >=: %d", got.ClientSentStartTimestamp, requestTime.Unix())
	}
	if got.ClientSentEndTimestamp < got.ClientSentStartTimestamp {
		t.Errorf("got: %d, want >=: %d", got.ClientSentEndTimestamp, got.ClientSentStartTimestamp)
	}
	if got.GatewayFlowID == "" {
		t.Errorf("GatewayFlowID should not be empty")
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %#v, want: %#v", got, want)
	}
}

func TestCORSResponseHeaders(t *testing.T) {
	tests := []struct {
		desc          string
		requestOrigin string
		setHeaders    map[string]string
		expectedLog   string
	}{
		{
			desc:          "not cors",
			requestOrigin: "",
			setHeaders:    map[string]string{},
			expectedLog:   "",
		},
		{
			desc:          "origin",
			requestOrigin: "origin",
			setHeaders: map[string]string{
				config.CORSAllowOrigin:      "origin",
				config.CORSAllowHeaders:     "AllowHeaders",
				config.CORSExposeHeaders:    "ExposeHeaders",
				config.CORSAllowMethods:     "AllowMethods",
				config.CORSMaxAge:           "42",
				config.CORSAllowCredentials: "true",
				config.CORSVary:             config.CORSVaryOrigin,
			},
			expectedLog: "Response header mods:\n  = \"access-control-allow-credentials\": \"true\"\n  = \"access-control-allow-headers\": \"Allow...\"\n  = \"access-control-allow-methods\": \"Allow...\"\n  = \"access-control-allow-origin\": \"origi...\"\n  = \"access-control-expose-headers\": \"Expos...\"\n  = \"access-control-max-age\": \"42\"\n  = \"vary\": \"Origi...\"\n",
		},
		{
			desc:          "wildcard",
			requestOrigin: "foo",
			setHeaders: map[string]string{
				config.CORSAllowOrigin:   "*",
				config.CORSAllowHeaders:  "AllowHeaders",
				config.CORSExposeHeaders: "ExposeHeaders",
				config.CORSAllowMethods:  "AllowMethods",
				config.CORSMaxAge:        "42",
				config.CORSVary:          config.CORSVaryOrigin,
			},
			expectedLog: "Response header mods:\n  = \"access-control-allow-headers\": \"Allow...\"\n  = \"access-control-allow-methods\": \"Allow...\"\n  = \"access-control-allow-origin\": \"*\"\n  = \"access-control-expose-headers\": \"Expos...\"\n  = \"access-control-max-age\": \"42\"\n  = \"vary\": \"Origi...\"\n",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {

			envSpec := createAuthEnvSpec()
			specExt, err := config.NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatal(err)
			}

			headers := map[string]string{config.CORSOriginHeader: test.requestOrigin}
			envoyReq := testutil.NewEnvoyRequest(http.MethodOptions, "/v1/petstore", headers, nil)
			req := config.NewEnvironmentSpecRequest(&testAuthMan{}, specExt, envoyReq)

			headerOptions := corsResponseHeaders(req)

			if len(test.setHeaders) != len(headerOptions) {
				t.Errorf("expected %d headers, got: %d: %v", len(test.setHeaders), len(headerOptions), headerOptions)
			}

			for k, v := range test.setHeaders {
				if !hasHeaderAdd(headerOptions, k, v, false) {
					t.Errorf("expected header set: %q: %q", k, v)
				}
			}

			okResponse := &authv3.OkHttpResponse{ResponseHeadersToAdd: headerOptions}
			logged := printHeaderMods(okResponse)
			if test.expectedLog != logged {
				t.Errorf("want: %q\n, got: %q\n", test.expectedLog, logged)
			}
		})
	}
}

func TestPrepareContextVariable(t *testing.T) {
	srv := testutil.IAMServer()
	defer srv.Close()

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server not ready", http.StatusInternalServerError)
	}))

	goodEnvSpec := &config.EnvironmentSpec{
		ID: "good-iam",
		APIs: []config.APISpec{
			{
				ID:       "petstore",
				BasePath: "/v1",
				ContextVariables: []config.ContextVariable{{
					Name: "iam_token",
					Value: config.GoogleIAMCredentials{
						ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
						Token: config.AccessToken{
							Scopes: []string{config.ApigeeAPIScope},
						},
					},
				}},
				HTTPRequestTransforms: config.HTTPRequestTransforms{
					HeaderTransforms: config.NameValueTransforms{
						Add: []config.AddNameValue{
							{Name: "authorization", Value: "{context.iam_token}"},
							{Name: "x-forwarded-authorization", Value: "{headers.authorization}"},
						},
					},
				},
				Operations: []config.APIOperation{
					{
						Name: "op1",
						HTTPMatches: []config.HTTPMatch{{
							PathTemplate: "/op-1",
						}},
					},
					{
						Name: "op2",
						HTTPMatches: []config.HTTPMatch{{
							PathTemplate: "/op-2",
						}},
						ContextVariables: []config.ContextVariable{{
							Name: "iam_token",
							Value: config.GoogleIAMCredentials{
								ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
								Token: config.IdentityToken{
									Audience: "aud",
								},
							},
						}},
					},
					{
						Name: "op3",
						HTTPMatches: []config.HTTPMatch{{
							PathTemplate: "/op-3",
						}},
						// Remove original auth header
						HTTPRequestTransforms: config.HTTPRequestTransforms{
							HeaderTransforms: config.NameValueTransforms{
								Add: []config.AddNameValue{
									{Name: "authorization", Value: "{context.iam_token}"},
								},
								// Remove should happen before add so this should not break anything.
								Remove: []string{"authorization"},
							},
						},
					},
				},
			},
		},
	}

	badEnvSpec := &config.EnvironmentSpec{
		ID: "bad_iam",
		APIs: []config.APISpec{
			{
				ID:       "petstore",
				BasePath: "/v1",
				ContextVariables: []config.ContextVariable{{
					Name: "iam_token",
					Value: config.GoogleIAMCredentials{
						ServiceAccountEmail: "foo@bar.iam.gserviceaccount.com",
						Token: config.AccessToken{
							Scopes: []string{config.ApigeeAPIScope},
						},
					},
				}},
				ConsumerAuthorization: config.ConsumerAuthorization{
					In: []config.APIOperationParameter{{
						Match: config.Header("x-api-key"),
					}},
					FailOpen: true,
				},
				Operations: []config.APIOperation{
					{
						HTTPMatches: []config.HTTPMatch{{
							PathTemplate: "/op-1",
						}},
					},
					{
						HTTPMatches: []config.HTTPMatch{{
							PathTemplate: "/op-2",
						}},
						ConsumerAuthorization: config.ConsumerAuthorization{Disabled: true},
					},
				},
			},
		},
	}

	opts := []option.ClientOption{
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(http.DefaultClient),
	}
	specExt, err := config.NewEnvironmentSpecExt(goodEnvSpec, config.WithIAMClientOptions(opts...))
	if err != nil {
		t.Fatal(err)
	}
	badOpts := []option.ClientOption{
		option.WithEndpoint(badSrv.URL),
		option.WithHTTPClient(http.DefaultClient),
	}
	badSpecExt, err := config.NewEnvironmentSpecExt(badEnvSpec, config.WithIAMClientOptions(badOpts...))
	if err != nil {
		t.Fatal(err)
	}
	environmentSpecsByID := map[string]*config.EnvironmentSpecExt{
		goodEnvSpec.ID: specExt,
		badSpecExt.ID:  badSpecExt,
	}

	testAuthMan := &testAuthMan{}
	testProductMan := &testProductMan{
		api:     "petstore",
		resolve: true,
		products: product.ProductsNameMap{
			"product1": &product.APIProduct{
				DisplayName: "product1",
			},
		},
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
			analyticsMan:          testAnalyticsMan,
			envSpecsByID:          environmentSpecsByID,
			ready:                 util.NewAtomicBool(true),
		},
	}

	tests := []struct {
		desc        string
		path        string
		headers     map[string]string
		wantHeaders map[string]string // header -> value
		specExtID   string
		statusCode  int32
		authContext *auth.Context
		authErr     error
	}{
		{
			desc:      "access token at api level",
			path:      "/v1/op-1",
			specExtID: goodEnvSpec.ID,
			wantHeaders: map[string]string{
				"authorization": "Bearer access-token",
			},
		},
		{
			desc:      "id token at api level",
			path:      "/v1/op-2",
			specExtID: goodEnvSpec.ID,
			wantHeaders: map[string]string{
				"authorization": "Bearer id-token",
			},
		},
		{
			desc:      "original auth forwarded",
			path:      "/v1/op-1",
			specExtID: goodEnvSpec.ID,
			headers: map[string]string{
				"authorization": "original",
			},
			wantHeaders: map[string]string{
				"authorization":             "Bearer access-token",
				"x-forwarded-authorization": "original",
			},
		},
		{
			desc:      "original auth not forwarded because it's configured to be removed",
			path:      "/v1/op-3",
			specExtID: goodEnvSpec.ID,
			headers: map[string]string{
				"authorization": "original",
			},
			wantHeaders: map[string]string{
				"authorization": "Bearer access-token",
			},
		},
		{
			desc:      "denied response w/ auth from access token fetching error",
			path:      "/v1/op-1",
			specExtID: badEnvSpec.ID,
			headers: map[string]string{
				"x-api-key": "key",
			},
			authContext: &auth.Context{
				APIProducts: []string{"product1"},
			},
			statusCode: int32(rpc.PERMISSION_DENIED),
		},
		{
			desc:      "denied response w/ auth from access token fetching error",
			path:      "/v1/op-1",
			specExtID: badEnvSpec.ID,
			headers: map[string]string{
				"x-api-key": "key",
			},
			authContext: &auth.Context{
				APIProducts: []string{"product1"},
			},
			statusCode: int32(rpc.PERMISSION_DENIED),
		},
		{
			desc:       "denied response w/ auth failed open from access token fetching error",
			path:       "/v1/op-1",
			specExtID:  badEnvSpec.ID,
			authErr:    auth.ErrNetworkError,
			statusCode: int32(rpc.PERMISSION_DENIED),
		},
		{
			desc:      "denied response w/o auth from access token fetching error",
			path:      "/v1/op-2",
			specExtID: badEnvSpec.ID,
			authContext: &auth.Context{
				APIProducts: []string{"product1"},
			},
			statusCode: int32(rpc.PERMISSION_DENIED),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			req := testutil.NewEnvoyRequest(http.MethodGet, test.path, test.headers, nil)
			req.Attributes.ContextExtensions = map[string]string{
				envSpecContextKey: test.specExtID,
			}
			testAuthMan.sendAuth(test.authContext, test.authErr)
			resp, err := server.Check(context.Background(), req)
			if err != nil {
				t.Fatalf("Check(...) err = %v, wanted no error", err)
			}
			if code := resp.GetStatus().GetCode(); code != test.statusCode {
				t.Fatalf("Check(...) status = %d, wanted %d", code, test.statusCode)
			}
			if resp.GetStatus().GetCode() == int32(rpc.OK) {
				okr := resp.GetOkResponse()
				if okr == nil {
					t.Fatal("OkResponse is nil")
				}
				for h, v := range test.wantHeaders {
					if !hasHeaderAdd(okr.GetHeaders(), h, v, false) {
						t.Errorf("%q header should be: %q", h, v)
					}
				}
			}
		})
	}
}

type testAuthMan struct {
	ctx             apigeeContext.Context
	apiKey          string
	claims          map[string]interface{}
	apiKeyClaimKey  string
	makeContextFunc func(ctx apigeeContext.Context) (*auth.Context, error)
}

func (a *testAuthMan) Close() {}
func (a *testAuthMan) Authenticate(ctx apigeeContext.Context, apiKey string, claims map[string]interface{},
	apiKeyClaimKey string) (*auth.Context, error) {
	a.ctx = ctx
	a.apiKey = apiKey
	a.claims = claims
	a.apiKeyClaimKey = apiKeyClaimKey

	return a.makeContextFunc(ctx)
}

func (a *testAuthMan) sendAuth(ac *auth.Context, err error) {
	if ac == nil {
		ac = &auth.Context{}
	}
	a.makeContextFunc = func(ctx apigeeContext.Context) (*auth.Context, error) {
		ac.Context = ctx
		return ac, err
	}
}

func (a *testAuthMan) ParseJWT(jwtString string, provider jwt.Provider) (map[string]interface{}, error) {
	return testutil.MockJWTVerifier{}.Parse(jwtString, provider)
}

type testProductMan struct {
	products map[string]*product.APIProduct
	api      string
	resolve  bool
	path     string
}

func (p *testProductMan) Close() {}
func (p *testProductMan) Products() product.ProductsNameMap {
	return p.products
}
func (p *testProductMan) Authorize(ac *auth.Context, api, path, method string) []product.AuthorizedOperation {
	if !p.resolve {
		return nil
	}
	if api != p.api {
		return nil
	}
	if p.path != "" && p.path != path {
		return nil
	}
	values := []product.AuthorizedOperation{}
	for _, p := range p.products {
		values = append(values, product.AuthorizedOperation{
			ID:         p.DisplayName,
			QuotaLimit: 42,
		})
	}
	return values
}

type testQuotaMan struct {
	exceeded  int64
	sendError error
}

func (q *testQuotaMan) Start() {}
func (q *testQuotaMan) Close() {}
func (q *testQuotaMan) Apply(auth *auth.Context, p product.AuthorizedOperation, args quota.Args) (*quota.Result, error) {
	if q.sendError != nil {
		return nil, q.sendError
	}
	return &quota.Result{
		Exceeded: q.exceeded,
	}, nil
}

func createAuthEnvSpec() config.EnvironmentSpec {
	envSpecs := []config.EnvironmentSpec{{
		ID: "good-env-config",
		APIs: []config.APISpec{
			{
				ID:       "api",
				BasePath: "/v1",
				Authentication: config.AuthenticationRequirement{
					Requirements: config.JWTAuthentication{
						Name:                 "jwt",
						Issuer:               "issuer",
						Audiences:            []string{"aud1"},
						JWKSSource:           config.RemoteJWKS{URL: "url", CacheDuration: time.Hour},
						In:                   []config.APIOperationParameter{{Match: config.Header("jwt")}},
						ForwardPayloadHeader: "jwt",
					},
				},
				ConsumerAuthorization: config.ConsumerAuthorization{
					In: []config.APIOperationParameter{
						{Match: config.Query("x-api-key")},
					},
					FailOpen: true,
				},
				Operations: []config.APIOperation{
					{
						Name: "op",
						HTTPMatches: []config.HTTPMatch{
							{
								PathTemplate: "/petstore",
								Method:       "",
							},
						},
					},
					{
						Name: "op2",
						HTTPMatches: []config.HTTPMatch{
							{
								PathTemplate: "/airport",
								Method:       "",
							},
						},
						Authentication: config.AuthenticationRequirement{
							Requirements: config.JWTAuthentication{
								Name:                 "jwt",
								Issuer:               "issuer",
								Audiences:            []string{"aud1"},
								JWKSSource:           config.RemoteJWKS{URL: "url", CacheDuration: time.Hour},
								In:                   []config.APIOperationParameter{{Match: config.Query("jwt")}},
								ForwardPayloadHeader: "jwt",
							},
						},
					},
				},
				HTTPRequestTransforms: config.HTTPRequestTransforms{
					HeaderTransforms: config.NameValueTransforms{
						Add: []config.AddNameValue{
							{Name: "target", Value: "add"},
							{Name: "target", Value: "append", Append: true},
						},
						Remove: []string{"jw*"},
					},
				},
				Cors: config.CorsPolicy{
					AllowOrigins:     []string{"origin", "*"},
					AllowHeaders:     []string{"AllowHeaders"},
					AllowMethods:     []string{"AllowMethods"},
					ExposeHeaders:    []string{"ExposeHeaders"},
					MaxAge:           42,
					AllowCredentials: true,
				},
			},
			{
				ID:       "api-without-authorization",
				BasePath: "/v2",
				ConsumerAuthorization: config.ConsumerAuthorization{
					Disabled: true,
				},
			},
			{
				ID:       "op-without-authorization",
				BasePath: "/v3",
				ConsumerAuthorization: config.ConsumerAuthorization{
					In: []config.APIOperationParameter{
						{Match: config.Query("x-api-key")},
					},
				},
				Operations: []config.APIOperation{
					{
						Name: "op",
						HTTPMatches: []config.HTTPMatch{
							{
								PathTemplate: "/noauthz-op",
								Method:       "",
							},
						},
						ConsumerAuthorization: config.ConsumerAuthorization{
							Disabled: true,
						},
					},
				},
			},
		},
	}}
	_ = config.ValidateEnvironmentSpecs(envSpecs)
	return envSpecs[0]
}
