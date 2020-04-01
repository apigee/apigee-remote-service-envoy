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
	// "encoding/json"

	"net/url"
	"strings"

	aauth "github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/quota"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"golang.org/x/net/context"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
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

const (
	apiKeyKey            = "x-api-key"
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
)

// Check does check
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	// check for JWT from Envoy filter
	protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	fieldsMap := protoBufStruct.GetFields()
	var claims map[string]interface{}
	// TODO: just using the first for now, should configure and/or support multiple
	for k, v := range fieldsMap {
		log.Debugf("Using JWT at key: %s", k)
		claims = DecodeToMap(v.GetStructValue())
	}

	splits := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)
	path := splits[0]

	apiKey := req.Attributes.Request.Http.Headers[apiKeyKey] // grab from header

	if apiKey == "" && len(splits) > 1 { // look in query if not in header
		if qs, err := url.ParseQuery(splits[1]); err != nil {
			if keys, ok := qs[apiKeyKey]; ok {
				apiKey = keys[0]
			}
		}
	}

	authContext, err := a.handler.authMan.Authenticate(a.handler, apiKey, claims, a.handler.apiKeyClaimKey)
	if err != nil {
		return internalError(err), nil
	}

	if len(authContext.APIProducts) == 0 {
		return unauthorized(), nil
	}

	// match products
	api := req.Attributes.Request.Http.GetHost()
	products := a.handler.productMan.Resolve(authContext, api, path)
	if len(products) == 0 {
		return unauthorized(), nil
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
		return internalError(anyError), nil
	}
	if exceeded {
		log.Debugf("quota exceeded: %v", err)
		return quotaExceeded(), nil
	}

	return authOK(authContext, api, path), nil
}

func authOK(authContext *aauth.Context, api, path string) *auth.CheckResponse {

	hc := makeHeaderContext(api, authContext)
	data := hc.encode()

	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   headerContextKey,
							Value: data,
						},
					},
				},
			},
		},
	}
}

func unauthenticated() *auth.CheckResponse {
	log.Debugf("unauthenticated")
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Body: "Authorization malformed or not provided",
			},
		},
	}
}

func unauthorized() *auth.CheckResponse {
	log.Debugf("unauthorized")
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.PERMISSION_DENIED),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Body: "Authenticated caller is not authorized for this action",
			},
		},
	}
}

func quotaExceeded() *auth.CheckResponse {
	log.Debugf("quota exceeded")
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.RESOURCE_EXHAUSTED),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_TooManyRequests,
				},
				Body: "Quota exceeded",
			},
		},
	}
}

func internalError(err error) *auth.CheckResponse {
	log.Errorf("internal error: %v", err)
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.INTERNAL),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_InternalServerError,
				},
				Body: "Server error",
			},
		},
	}
}
