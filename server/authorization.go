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
	"encoding/json"
	"net/url"
	"strings"

	aauth "github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
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
	handler *handler
}

// Register registers
func (a *AuthorizationServer) Register(s *grpc.Server, handler *handler) {
	auth.RegisterAuthorizationServer(s, a)
	a.handler = handler
}

const (
	apiKeyKey            = "x-api-key"
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
)

// Check does check
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	if log.DebugEnabled() {
		if b, err := json.MarshalIndent(req.Attributes.Request.Http.Headers, "", "  "); err == nil {
			log.Debugf("Inbound Headers: %s", string(b))
		}

		if ct, err := json.MarshalIndent(req.Attributes.ContextExtensions, "", "  "); err == nil {
			log.Debugf("Context Extensions: %s", string(ct))
		}
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
		log.Errorf("authenticating: %v", err)
		return unauthenticated(), nil
	}

	if len(authContext.APIProducts) == 0 {
		return unauthorized(), nil
	}

	api := req.Attributes.Request.Http.GetHost()
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
	log.Infof("unauthenticated")
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
	log.Infof("unauthorized")
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
