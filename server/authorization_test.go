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
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	libAuth "github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	apigeeContext "github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
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
		appendHeaders   []config.KeyValue
		setHeaders      map[string]string // don't add > 1 element as log order can change
		removeHeaders   []string
		expectedAdds    int // +1 to include :path
		expectedRemoves int
		expectedLog     string
	}{
		{
			desc:            "test1",
			requestHeaders:  map[string]string{"remove1": "remove"},
			appendHeaders:   []config.KeyValue{{Key: "append", Value: "append1"}},
			setHeaders:      map[string]string{"set": "set1"},
			removeHeaders:   []string{"remove1"},
			expectedAdds:    3,
			expectedRemoves: 1,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n  = \"set\": \"set1\"\n  + \"append\": \"appen...\"\n",
		},
		{
			desc:           "test2",
			requestHeaders: map[string]string{"remove1": "remove", "skip": "don't remove"},
			appendHeaders: []config.KeyValue{
				{Key: "append", Value: "append1"},
				{Key: "append2", Value: "append2"},
			},
			setHeaders:      map[string]string{"set": "set1"},
			removeHeaders:   []string{"Remove1", "missing"},
			expectedAdds:    4,
			expectedRemoves: 1,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n  = \"set\": \"set1\"\n  + \"append\": \"appen...\"\n  + \"append2\": \"appen...\"\n",
		},
		{
			desc:            "test3",
			requestHeaders:  map[string]string{"remove1": "remove", "remove2": "remove", "skip": "don't remove"},
			appendHeaders:   []config.KeyValue{},
			setHeaders:      map[string]string{},
			removeHeaders:   []string{"Remove*"},
			expectedAdds:    1,
			expectedRemoves: 2,
			expectedLog:     "Request header mods:\n  = \":path\": \"/pets...\"\n",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			envSpec := createAuthEnvSpec()

			envSpec.APIs[0].HTTPRequestTransforms = config.HTTPRequestTransformations{
				AppendHeaders: test.appendHeaders,
				SetHeaders:    test.setHeaders,
				RemoveHeaders: test.removeHeaders,
			}
			specExt, err := config.NewEnvironmentSpecExt(&envSpec)
			if err != nil {
				t.Fatalf("%v", err)
			}
			envoyReq := testutil.NewEnvoyRequest("GET", "/v1/petstore", test.requestHeaders, nil)
			specReq := config.NewEnvironmentSpecRequest(nil, specExt, envoyReq)
			okResponse := &authv3.OkHttpResponse{}

			addHeaderTransforms(envoyReq, specReq, okResponse)

			if test.expectedAdds != len(okResponse.Headers) {
				t.Errorf("expected %d header adds got: %d", test.expectedAdds, len(okResponse.Headers))
			}
			if test.expectedRemoves != len(okResponse.HeadersToRemove) {
				t.Errorf("expected %d header removes got: %d", test.expectedRemoves, len(okResponse.HeadersToRemove))
			}

			for _, v := range test.appendHeaders {
				if !hasHeaderAdd(okResponse, v.Key, v.Value, true) {
					t.Errorf("expected header append: %q: %q", v.Key, v.Value)
				}
			}
			for k, v := range test.setHeaders {
				if !hasHeaderAdd(okResponse, k, v, false) {
					t.Errorf("expected header set: %q: %q", k, v)
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

			logged := logHeaderValueOptions(okResponse)
			if test.expectedLog != logged {
				t.Errorf("want: %q\n, got: %q\n", test.expectedLog, logged)
			}
		})
	}
}

func hasHeaderAdd(okr *authv3.OkHttpResponse, key, value string, append bool) bool {
	for _, h := range okr.Headers {
		arr := []interface{}{h.Header.Key, h.Header.Value, h.Append.Value}
		fmt.Printf("arr: %v", arr)
		if key == h.Header.Key &&
			value == h.Header.Value &&
			append == h.Append.Value {
			return true
		}
	}
	return false
}

func hasHeaderRemove(okr *authv3.OkHttpResponse, key string) bool {
	for _, h := range okr.HeadersToRemove {
		if h == key {
			return true
		}
	}
	return false
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
	var req *authv3.CheckRequest
	var resp *authv3.CheckResponse

	// missing api
	req = testutil.NewEnvoyRequest(http.MethodGet, "/v2/missing", nil, nil)
	req.Attributes.ContextExtensions = contextExtensions
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.NOT_FOUND) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.NOT_FOUND))
	}

	// missing operation
	req = testutil.NewEnvoyRequest(http.MethodGet, "/v1/missing", nil, nil)
	req.Attributes.ContextExtensions = contextExtensions
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.NOT_FOUND) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.NOT_FOUND))
	}

	// Cannot authenticate
	req = testutil.NewEnvoyRequest(http.MethodGet, uri, nil, nil)
	req.Attributes.ContextExtensions = contextExtensions
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}

	// good authentication, bad authorization
	headers := map[string]string{
		"jwt": jwtString,
	}
	req = testutil.NewEnvoyRequest(http.MethodGet, uri, headers, nil)
	req.Attributes.ContextExtensions = contextExtensions
	testAuthMan.sendAuth(nil, libAuth.ErrBadAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// good authentication, authorization network fail w/ FailOpen
	testAuthMan.sendAuth(nil, libAuth.ErrNetworkError)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// good request
	testAuthMan.sendAuth(&auth.Context{
		APIProducts: []string{"product1"},
	}, nil)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	okr, ok := resp.HttpResponse.(*authv3.CheckResponse_OkResponse)
	if !ok {
		t.Fatal("must be OkResponse")
	}

	wantPath := "/petstore?x-api-key=foo"
	if !hasHeaderAdd(okr.OkResponse, ":path", wantPath, false) {
		t.Errorf(":path header should be: %s", wantPath)
	}
	if !hasHeaderAdd(okr.OkResponse, "target", "add", false) {
		t.Errorf("add header option not found")
	}
	if !hasHeaderAdd(okr.OkResponse, "target", "append", true) {
		t.Errorf("append header option not found")
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
		},
	}

	// no api header
	var resp *authv3.CheckResponse
	var err error
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}
	headers[headerAPI] = "api"

	// ErrNoAuth
	testAuthMan.sendAuth(nil, libAuth.ErrNoAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}

	// ErrBadAuth
	testAuthMan.sendAuth(nil, libAuth.ErrBadAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// ErrInternalError
	testAuthMan.sendAuth(nil, libAuth.ErrInternalError)
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
		},
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
		ResponseStatusCode:           int(rpc.PERMISSION_DENIED),
		DeveloperEmail:               ac.DeveloperEmail,
		DeveloperApp:                 ac.Application,
		AccessToken:                  ac.AccessToken,
		ClientID:                     ac.ClientID,
		APIProduct:                   ac.APIProducts[0],
		Organization:                 server.handler.orgName,
		Environment:                  server.handler.envName,
		GatewaySource:                gatewaySource,
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
	return config.EnvironmentSpec{
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
				},
				HTTPRequestTransforms: config.HTTPRequestTransformations{
					SetHeaders: map[string]string{
						"target": "add",
					},
					AppendHeaders: []config.KeyValue{
						{Key: "target", Value: "append"},
					},
					RemoveHeaders: []string{
						"jw*",
					},
				},
			},
		},
	}
}
