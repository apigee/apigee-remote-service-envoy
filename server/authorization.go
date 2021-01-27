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
	gocontext "context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/context"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/quota"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
	envContextKey        = "apigee_environment"
)

// AuthorizationServer server
type AuthorizationServer struct {
	handler *Handler
}

// Register registers
func (a *AuthorizationServer) Register(s *grpc.Server, handler *Handler) {
	envoy_auth.RegisterAuthorizationServer(s, a)
	a.handler = handler
}

// Check does check
func (a *AuthorizationServer) Check(ctx gocontext.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {

	var rootContext context.Context = a.handler
	if a.handler.isMultitenant {
		if env, override := req.Attributes.ContextExtensions[envContextKey]; override {
			rootContext = &multitenantContext{
				a.handler,
				env,
			}
		} else {
			err := fmt.Errorf("Envoy must be configured to send Apigee env in ContextExtensions[%s] in multitenant mode.", envContextKey)
			log.Errorf(err.Error())
			return nil, err
		}
	}

	tracker := prometheusRequestTracker(rootContext)
	defer tracker.record()

	target, ok := req.Attributes.Request.Http.Headers[a.handler.targetHeader]
	if !ok {
		log.Debugf("missing target header %s", a.handler.targetHeader)
		return a.unauthorized(tracker), nil
	}

	// check for JWT from Envoy filter
	protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	fieldsMap := protoBufStruct.GetFields()
	var claims map[string]interface{}

	// use jwtProviderKey check if jwtProviderKey is set in config
	if a.handler.jwtProviderKey != "" {
		claimsStruct, ok := fieldsMap[a.handler.jwtProviderKey]
		if ok {
			log.Debugf("Using JWT at provider key: %s", a.handler.jwtProviderKey)
			claims = DecodeToMap(claimsStruct.GetStructValue())
		}
	} else { // otherwise iterate over apiKeyClaim loop
		for k, v := range fieldsMap {
			vFields := v.GetStructValue().GetFields()
			if vFields[a.handler.apiKeyClaim] != nil || vFields["api_product_list"] != nil {
				log.Debugf("Using JWT with provider key: %s", k)
				claims = DecodeToMap(v.GetStructValue())
			}
		}
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

	authContext, err := a.handler.authMan.Authenticate(rootContext, apiKey, claims, a.handler.apiKeyClaim)
	switch err {
	case auth.ErrNoAuth:
		return a.unauthorized(tracker), nil
	case auth.ErrBadAuth:
		return a.denied(tracker, authContext, target), nil
	case auth.ErrInternalError:
		return a.internalError(tracker, err), nil
	}

	if len(authContext.APIProducts) == 0 {
		return a.denied(tracker, authContext, target), nil
	}

	// authorize against products
	method := req.Attributes.Request.Http.Method
	authorizedOps := a.handler.productMan.Authorize(authContext, target, path, method)
	if len(authorizedOps) == 0 {
		return a.denied(tracker, authContext, target), nil
	}

	// apply quotas to matched operations
	var quotaArgs = quota.Args{QuotaAmount: 1}
	var exceeded bool
	var anyError error
	for _, op := range authorizedOps {
		if op.QuotaLimit > 0 {
			result, err := a.handler.quotaMan.Apply(authContext, op, quotaArgs)
			if err != nil {
				log.Errorf("quota check: %v", err)
				anyError = err
			} else if result.Exceeded > 0 {
				log.Debugf("quota exceeded: %v", op.ID)
				exceeded = true
			}
		}
	}
	if anyError != nil {
		return a.internalError(tracker, anyError), nil
	}
	if exceeded {
		return a.quotaExceeded(tracker, authContext, target), nil
	}

	return a.authOK(tracker, authContext, target), nil
}

func (a *AuthorizationServer) authOK(tracker *prometheusRequestMetricTracker, authContext *auth.Context, target string) *envoy_auth.CheckResponse {

	headers := makeMetadataHeaders(target, authContext)
	headers = append(headers, &envoy_core.HeaderValueOption{
		Header: &envoy_core.HeaderValue{
			Key:   headerAuthorized,
			Value: "true",
		},
	})

	tracker.statusCode = envoy_type.StatusCode_OK
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func (a *AuthorizationServer) unauthorized(tracker *prometheusRequestMetricTracker) *envoy_auth.CheckResponse {
	return a.createDenyResponse(tracker, nil, "", rpc.UNAUTHENTICATED)
}

func (a *AuthorizationServer) internalError(tracker *prometheusRequestMetricTracker, err error) *envoy_auth.CheckResponse {
	log.Errorf("sending internal error: %v", err)
	return a.createDenyResponse(tracker, nil, "", rpc.INTERNAL)
}

func (a *AuthorizationServer) denied(tracker *prometheusRequestMetricTracker, authContext *auth.Context, target string) *envoy_auth.CheckResponse {
	return a.createDenyResponse(tracker, authContext, target, rpc.PERMISSION_DENIED)
}

func (a *AuthorizationServer) quotaExceeded(tracker *prometheusRequestMetricTracker, authContext *auth.Context, target string) *envoy_auth.CheckResponse {
	return a.createDenyResponse(tracker, authContext, target, rpc.RESOURCE_EXHAUSTED)
}

func (a *AuthorizationServer) createDenyResponse(tracker *prometheusRequestMetricTracker, authContext *auth.Context, target string, code rpc.Code) *envoy_auth.CheckResponse {

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

		response := &envoy_auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(code),
			},
		}

		// Envoy doesn't automatically map this code, force it
		if code == rpc.RESOURCE_EXHAUSTED {
			response.HttpResponse = &envoy_auth.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_auth.DeniedHttpResponse{
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
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: makeMetadataHeaders(target, authContext),
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
	rootContext context.Context
	startTime   time.Time
	statusCode  envoy_type.StatusCode
}

// set statusCode before calling record()
func prometheusRequestTracker(rootContext context.Context) *prometheusRequestMetricTracker {
	return &prometheusRequestMetricTracker{
		rootContext: rootContext,
		startTime:   time.Now(),
		statusCode:  envoy_type.StatusCode_InternalServerError,
	}
}

// set statusCode before calling
func (t *prometheusRequestMetricTracker) record() {
	codeLabel := fmt.Sprintf("%d", t.statusCode)
	httpDuration := time.Since(t.startTime)
	prometheusAuthSeconds.WithLabelValues(t.rootContext.Organization(), t.rootContext.Environment(), codeLabel).Observe(httpDuration.Seconds())
}

type multitenantContext struct {
	*Handler
	env string
}

func (o *multitenantContext) Environment() string {
	return o.env
}
