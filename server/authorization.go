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
	"net/url"
	"strings"

	aauth "github.com/apigee/apigee-remote-service-golib/auth"
	libAuth "github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/quota"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
)

// AuthorizationServer server
type AuthorizationServer struct {
	handler *Handler
}

// Register registers
func (a *AuthorizationServer) Register(s *grpc.Server, handler *Handler) {
	auth.RegisterAuthorizationServer(s, a)
	a.handler = handler
}

// Check does check
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	api, ok := req.Attributes.Request.Http.Headers[a.handler.targetHeader]
	if !ok {
		log.Debugf("missing target header %s", a.handler.targetHeader)
		return a.unauthenticated(), nil
	}

	// check for JWT from Envoy filter
	protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	fieldsMap := protoBufStruct.GetFields()
	var claims map[string]interface{}
	// TODO: just using the first for now, should configure and/or support multiple
	for k, v := range fieldsMap {
		log.Debugf("Using JWT at key: %s", k)
		claims = DecodeToMap(v.GetStructValue())
	}

	splitPath := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)
	path := splitPath[0]

	apiKey, ok := req.Attributes.Request.Http.Headers[a.handler.apiKeyHeader] // grab from header

	if !ok && len(splitPath) > 1 { // look in querystring if not in header
		if qs, err := url.ParseQuery(splitPath[1]); err == nil {
			if keys, ok := qs[a.handler.apiKeyHeader]; ok {
				apiKey = keys[0]
			}
		}
	}

	authContext, err := a.handler.authMan.Authenticate(a.handler, apiKey, claims, a.handler.apiKeyClaim)
	switch err {
	case libAuth.ErrNoAuth:
		return a.unauthenticated(), nil
	case libAuth.ErrBadAuth:
		return a.unauthorized(authContext, api), nil
	case libAuth.ErrInternalError:
		return a.internalError(err), nil
	}

	if len(authContext.APIProducts) == 0 {
		return a.unauthorized(authContext, api), nil
	}

	// match products
	products := a.handler.productMan.Resolve(authContext, api, path)
	if len(products) == 0 {
		return a.unauthorized(authContext, api), nil
	}

	// apply quotas to all matched products
	var quotaArgs = quota.Args{QuotaAmount: 1}
	var exceeded bool
	var anyError error
	for _, p := range products {
		if p.QuotaLimitInt > 0 {
			result, err := a.handler.quotaMan.Apply(authContext, p, quotaArgs)
			if err != nil {
				log.Errorf("quota check: %v", err)
				anyError = err
			} else if result.Exceeded > 0 {
				log.Debugf("quota exceeded: %v", p.Name)
				exceeded = true
			}
		}
	}
	if anyError != nil {
		return a.internalError(anyError), nil
	}
	if exceeded {
		return a.quotaExceeded(authContext, api), nil
	}

	return a.authOK(authContext, api), nil
}

func (a *AuthorizationServer) authOK(authContext *aauth.Context, api string) *auth.CheckResponse {

	headers := makeMetadataHeaders(api, authContext)
	headers = append(headers, &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   headerAuthorized,
			Value: "true",
		},
	})

	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func (a *AuthorizationServer) unauthenticated() *auth.CheckResponse {
	return a.createDenyResponse(nil, "", rpc.UNAUTHENTICATED)
}

func (a *AuthorizationServer) internalError(err error) *auth.CheckResponse {
	log.Errorf("sending internal error: %v", err)
	return a.createDenyResponse(nil, "", rpc.INTERNAL)
}

func (a *AuthorizationServer) unauthorized(authContext *aauth.Context, api string) *auth.CheckResponse {
	return a.createDenyResponse(authContext, api, rpc.PERMISSION_DENIED)
}

func (a *AuthorizationServer) quotaExceeded(authContext *aauth.Context, api string) *auth.CheckResponse {
	return a.createDenyResponse(authContext, api, rpc.RESOURCE_EXHAUSTED)
}

func (a *AuthorizationServer) createDenyResponse(authContext *aauth.Context, api string, code rpc.Code) *auth.CheckResponse {

	if a.handler.rejectUnauthorized || authContext == nil { // send reject
		log.Debugf("sending denied: %s", code.String())

		return &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(code),
			},
		}
	}

	log.Debugf("sending ok (actual: %s)", code.String())
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: makeMetadataHeaders(api, authContext),
			},
		},
	}
}
