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

// Package protostruct supports operations on the protocol buffer Struct message.
package server

import (
	"context"
	"errors"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/auth"
	libAuth "github.com/apigee/apigee-remote-service-golib/auth"
	apigeeContext "github.com/apigee/apigee-remote-service-golib/context"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/apigee/apigee-remote-service-golib/quota"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gogo/googleapis/google/rpc"
	pb "github.com/golang/protobuf/ptypes/struct"
)

func TestCheck(t *testing.T) {

	jwtClaims := &pb.Struct{
		Fields: map[string]*pb.Value{
			"s": &pb.Value{
				Kind: &pb.Value_StringValue{StringValue: "x"},
			},
		},
	}

	headers := map[string]string{
		headerClientID: "clientID",
		// headerAPI: "api",
		// headerAPIProducts:    "product1,product2",
		// headerAccessToken:    "token",
		// headerApplication:    "app",
		// headerDeveloperEmail: "email@google.com",
		// headerEnvironment:    "env",
		// headerOrganization:   "org",
		// headerScope:          "scope1 scope2",
	}

	products := product.ProductsMap{
		"product1": &product.APIProduct{
			DisplayName: "product1",
		},
	}

	// protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	// fieldsMap := protoBufStruct.GetFields()

	uri := "path?x-api-key=foo"
	req := &v2.CheckRequest{
		Attributes: &v2.AttributeContext{
			Request: &v2.AttributeContext_Request{
				Http: &v2.AttributeContext_HttpRequest{
					Path:    uri,
					Headers: headers,
				},
			},
			MetadataContext: &core.Metadata{
				FilterMetadata: map[string]*pb.Struct{
					jwtFilterMetadataKey: jwtClaims,
				},
			},
		},
	}
	req.Attributes.GetMetadataContext()

	testAuthMan := &testAuthMan{}
	testProductMan := &testProductMan{
		resolve: true,
	}
	testQuotaMan := &testQuotaMan{}
	server := AuthorizationServer{
		handler: &Handler{
			rejectUnauthorized: true,
			apiKeyClaim:        headerClientID,
			targetHeader:       headerAPI,
			apiKeyHeader:       "x-api-key",
			authMan:            testAuthMan,
			productMan:         testProductMan,
			quotaMan:           testQuotaMan,
		},
	}

	// no target header
	var resp *v2.CheckResponse
	var err error
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}
	headers[headerAPI] = "api"

	// ErrNoAuth
	testAuthMan.sendError = libAuth.ErrNoAuth
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}

	// ErrBadAuth
	testAuthMan.sendError = libAuth.ErrBadAuth
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// ErrInternalError
	testAuthMan.sendError = libAuth.ErrInternalError
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// reset auth error
	testAuthMan.sendError = nil

	// no products
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// no matched products
	testProductMan.products = products
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}
	testProductMan.resolve = true

	// quota exceeded
	products["product1"].QuotaLimitInt = 2
	testQuotaMan.exceeded = 2
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.RESOURCE_EXHAUSTED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.RESOURCE_EXHAUSTED))
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

	// testAuthMan.ctx
	if testAuthMan.apiKey != "foo" {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKey, "foo")
	}
	// testAuthMan.claims
	if testAuthMan.apiKeyClaimKey != headerClientID {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKeyClaimKey, headerClientID)
	}

	// check deny when rejectUnauthorized = false
	server.handler.rejectUnauthorized = false
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}
}

type testAuthMan struct {
	sendError      error
	ctx            apigeeContext.Context
	apiKey         string
	claims         map[string]interface{}
	apiKeyClaimKey string
}

func (a *testAuthMan) Close() {}
func (a *testAuthMan) Authenticate(ctx apigeeContext.Context, apiKey string, claims map[string]interface{},
	apiKeyClaimKey string) (*auth.Context, error) {
	a.ctx = ctx
	a.apiKey = apiKey
	a.claims = claims
	a.apiKeyClaimKey = apiKeyClaimKey

	if a.sendError != nil {
		return nil, a.sendError
	}

	ac := &auth.Context{
		Context:     ctx,
		APIProducts: []string{"product 1"},
		// ClientID: claims[apiKeyClaimKey].(string),
	}
	return ac, nil
}

type testProductMan struct {
	products map[string]*product.APIProduct
	resolve  bool
}

func (p *testProductMan) Close() {}
func (p *testProductMan) Products() product.ProductsMap {
	return p.products
}
func (p *testProductMan) Resolve(ac *auth.Context, api, path string) []*product.APIProduct {
	if !p.resolve {
		return nil
	}
	values := []*product.APIProduct{}
	for _, value := range p.products {
		values = append(values, value)
	}
	return values
}

type testQuotaMan struct {
	exceeded  int64
	sendError error
}

func (q *testQuotaMan) Start() {}
func (q *testQuotaMan) Close() {}
func (q *testQuotaMan) Apply(auth *auth.Context, p *product.APIProduct, args quota.Args) (*quota.Result, error) {
	if q.sendError != nil {
		return nil, q.sendError
	}
	return &quota.Result{
		Exceeded: q.exceeded,
	}, nil
}
