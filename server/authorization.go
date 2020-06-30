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
	"fmt"
	"net/url"
	"strings"
	"time"

	aauth "github.com/apigee/apigee-remote-service-golib/auth"
	libAuth "github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/quota"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

	tracker := prometheusRequestTracker(a.handler)
	defer tracker.record()

	api, ok := req.Attributes.Request.Http.Headers[a.handler.targetHeader]
	if !ok {
		log.Debugf("missing target header %s", a.handler.targetHeader)
		return a.unauthorized(tracker), nil
	}

	// check for JWT from Envoy filter
	protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	fieldsMap := protoBufStruct.GetFields()
	var claims map[string]interface{}
	claimsStruct, ok := fieldsMap[a.handler.jwtProviderKey]
	if ok {
		log.Debugf("Using JWT at provider key: %s", a.handler.jwtProviderKey)
		claims = DecodeToMap(claimsStruct.GetStructValue())
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
		return a.unauthorized(tracker), nil
	case libAuth.ErrBadAuth:
		return a.denied(tracker, authContext, api), nil
	case libAuth.ErrInternalError:
		return a.internalError(tracker, err), nil
	}

	if len(authContext.APIProducts) == 0 {
		return a.denied(tracker, authContext, api), nil
	}

	// match products
	products := a.handler.productMan.Resolve(authContext, api, path)
	if len(products) == 0 {
		return a.denied(tracker, authContext, api), nil
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
		return a.internalError(tracker, anyError), nil
	}
	if exceeded {
		return a.quotaExceeded(tracker, authContext, api), nil
	}

	return a.authOK(tracker, authContext, api), nil
}

func (a *AuthorizationServer) authOK(tracker *prometheusRequestMetricTracker, authContext *aauth.Context, api string) *auth.CheckResponse {

	headers := makeMetadataHeaders(api, authContext)
	headers = append(headers, &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   headerAuthorized,
			Value: "true",
		},
	})

	tracker.statusCode = envoy_type.StatusCode_OK
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

func (a *AuthorizationServer) unauthorized(tracker *prometheusRequestMetricTracker) *auth.CheckResponse {
	return a.createDenyResponse(tracker, nil, "", rpc.UNAUTHENTICATED)
}

func (a *AuthorizationServer) internalError(tracker *prometheusRequestMetricTracker, err error) *auth.CheckResponse {
	log.Errorf("sending internal error: %v", err)
	return a.createDenyResponse(tracker, nil, "", rpc.INTERNAL)
}

func (a *AuthorizationServer) denied(tracker *prometheusRequestMetricTracker, authContext *aauth.Context, api string) *auth.CheckResponse {
	return a.createDenyResponse(tracker, authContext, api, rpc.PERMISSION_DENIED)
}

func (a *AuthorizationServer) quotaExceeded(tracker *prometheusRequestMetricTracker, authContext *aauth.Context, api string) *auth.CheckResponse {
	return a.createDenyResponse(tracker, authContext, api, rpc.RESOURCE_EXHAUSTED)
}

func (a *AuthorizationServer) createDenyResponse(tracker *prometheusRequestMetricTracker, authContext *aauth.Context, api string, code rpc.Code) *auth.CheckResponse {

	// use intended code, not OK
	switch code {
	case rpc.UNAUTHENTICATED:
		tracker.statusCode = envoy_type.StatusCode_Unauthorized

	case rpc.INTERNAL:
		tracker.statusCode = envoy_type.StatusCode_InternalServerError

	case rpc.PERMISSION_DENIED:
		tracker.statusCode = envoy_type.StatusCode_Forbidden

	case rpc.RESOURCE_EXHAUSTED: // Envoy doesn't automatically map this code, force it
		tracker.statusCode = envoy_type.StatusCode_TooManyRequests
	}

	if a.handler.rejectUnauthorized || authContext == nil { // send reject to client
		log.Debugf("sending denied: %s", code.String())

		response := &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(code),
			},
		}

		// Envoy doesn't automatically map this code, force it
		if code == rpc.RESOURCE_EXHAUSTED {
			response.HttpResponse = &auth.CheckResponse_DeniedResponse{
				DeniedResponse: &auth.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: tracker.statusCode,
					},
				},
			}
		}

		return response
	}

	// allow request to continue upstream
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

// prometheus metrics
var (
	prometheusAuthSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "auth",
		Name:      "requests_seconds",
		Help:      "Time taken to process authorization requests by code",
		Buckets:   prometheus.DefBuckets,
	}, []string{"org", "env", "code"})
)

type prometheusRequestMetricTracker struct {
	handler    *Handler
	startTime  time.Time
	statusCode envoy_type.StatusCode
}

// set statusCode before calling record()
func prometheusRequestTracker(h *Handler) *prometheusRequestMetricTracker {
	return &prometheusRequestMetricTracker{
		handler:    h,
		startTime:  time.Now(),
		statusCode: envoy_type.StatusCode_InternalServerError,
	}
}

// set statusCode before calling
func (t *prometheusRequestMetricTracker) record() {
	codeLabel := fmt.Sprintf("%d", t.statusCode)
	httpDuration := time.Since(t.startTime)
	prometheusAuthSeconds.WithLabelValues(t.handler.orgName, t.handler.envName, codeLabel).Observe(httpDuration.Seconds())
}
