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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	golibutil "github.com/apigee/apigee-remote-service-golib/v2/util"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
	envContextKey        = "apigee_environment"
	apiContextKey        = "apigee_api"
	envSpecContextKey    = "apigee_env_config"
	envoyPathHeader      = ":path"
)

// AuthorizationServer server
type AuthorizationServer struct {
	handler *Handler
}

// Register registers
func (a *AuthorizationServer) Register(s *grpc.Server, handler *Handler) {
	authv3.RegisterAuthorizationServer(s, a)
	a.handler = handler
}

// Check does check
func (a *AuthorizationServer) Check(ctx gocontext.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {

	var rootContext context.Context = a.handler
	var err error
	envFromEnvoy, envFromEnvoyExists := req.Attributes.ContextExtensions[envContextKey]
	if a.handler.isMultitenant {
		if envFromEnvoyExists && envFromEnvoy != "" {
			rootContext = &multitenantContext{
				a.handler,
				envFromEnvoy,
			}
		} else {
			err = fmt.Errorf("no %s metadata for multi-tentant mode", envContextKey)
		}
	} else if envFromEnvoyExists && envFromEnvoy != rootContext.Environment() {
		err = fmt.Errorf("%s metadata (%s) disallowed when not in multi-tentant mode", envContextKey, rootContext.Environment())
	}

	tracker := prometheusRequestTracker(rootContext)
	defer tracker.record()

	if err != nil {
		return a.internalError(req, nil, tracker, err), nil
	}

	var envSpec *config.EnvironmentSpecExt
	var operation *config.APIOperation
	if envSpecID, ok := req.Attributes.ContextExtensions[envSpecContextKey]; ok {
		if spec, ok := a.handler.envSpecsByID[envSpecID]; ok {
			envSpec = spec
		}
	}

	path, queryString := func(path string) (base, qs string) {
		pathSplits := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)
		base = pathSplits[0]
		if len(pathSplits) > 1 {
			qs = pathSplits[1]
		}
		return
	}(req.Attributes.Request.Http.Path)

	var api string
	var apiKey string
	var claims map[string]interface{}

	// EnvSpec found, takes priority over global settings
	var envRequest *config.EnvironmentSpecRequest
	if envSpec != nil {
		envRequest = config.NewEnvironmentSpecRequest(a.handler.authMan, envSpec, req)
		log.Debugf("environment spec: %s", envRequest.ID)

		apiSpec := envRequest.GetAPISpec()
		if apiSpec == nil {
			log.Debugf("api not found for environment spec %s", envSpec.ID)
			return a.notFound(req, envRequest, tracker), nil
		}
		api = apiSpec.ID
		log.Debugf("api: %s", apiSpec.ID)

		operation = envRequest.GetOperation()
		if operation == nil {
			log.Debugf("no valid operation found for api %s", apiSpec.ID)
			return a.notFound(req, envRequest, tracker), nil
		}
		log.Debugf("operation: %s", operation.Name)

		// strip the basepath off path
		if a.handler.operationConfigType == product.ProxyOperationConfigType {
			path = envRequest.GetOperationPath()
		}

		if !envRequest.IsAuthenticated() {
			log.Debugf("authentication requirements not met")
			return a.unauthenticated(req, envRequest, tracker), nil
		}

		apiKey = envRequest.GetAPIKey()

	} else { // global authentication

		if v, ok := req.Attributes.ContextExtensions[apiContextKey]; ok { // api specified in context metadata
			api = v
			log.Debugf("api from context: %s", api)
		} else {
			api, ok = req.Attributes.Request.Http.Headers[a.handler.apiHeader]
			if !ok {
				log.Debugf("missing api header %s", a.handler.apiHeader)
				return a.unauthenticated(req, envRequest, tracker), nil
			}
			log.Debugf("api from header: %s", api)
		}

		// check for JWT from Envoy filter
		protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
		fieldsMap := protoBufStruct.GetFields()

		// use jwtProviderKey check if jwtProviderKey is set in config
		if a.handler.jwtProviderKey != "" {
			claimsStruct, ok := fieldsMap[a.handler.jwtProviderKey]
			if ok {
				log.Debugf("Using JWT at provider key: %s", a.handler.jwtProviderKey)
				claims = util.DecodeToMap(claimsStruct.GetStructValue())
			}
		} else { // otherwise iterate over apiKeyClaim loop
			for k, v := range fieldsMap {
				vFields := v.GetStructValue().GetFields()
				if vFields[a.handler.apiKeyClaim] != nil || vFields["api_product_list"] != nil {
					log.Debugf("Using JWT with provider key: %s", k)
					claims = util.DecodeToMap(v.GetStructValue())
				}
			}
		}

		apiKey = req.Attributes.Request.Http.Headers[a.handler.apiKeyHeader] // grab from header

		if apiKey == "" && queryString != "" { // look in querystring if not in header
			if qs, err := url.ParseQuery(queryString); err == nil {
				if keys, ok := qs[a.handler.apiKeyHeader]; ok {
					apiKey = keys[0]
				}
			}
		}
	}

	authContext, err := a.handler.authMan.Authenticate(rootContext, apiKey, claims, a.handler.apiKeyClaim)
	switch err {
	case auth.ErrNoAuth:
		return a.unauthenticated(req, envRequest, tracker), nil
	case auth.ErrBadAuth:
		return a.denied(req, envRequest, tracker, authContext, api), nil
	case auth.ErrInternalError:
		return a.internalError(req, envRequest, tracker, err), nil
	case auth.ErrNetworkError:
		if envRequest != nil && envRequest.GetConsumerAuthorization().FailOpen {
			log.Debugf("FailOpen on operation: %v", envRequest.GetOperation().Name)
			return a.authOK(req, tracker, authContext, api, envRequest), nil
		} else {
			return a.internalError(req, envRequest, tracker, err), nil
		}
	}

	if len(authContext.APIProducts) == 0 {
		return a.denied(req, envRequest, tracker, authContext, api), nil
	}

	// authorize against products
	method := req.Attributes.Request.Http.Method
	authorizedOps := a.handler.productMan.Authorize(authContext, api, path, method)
	if len(authorizedOps) == 0 {
		return a.denied(req, envRequest, tracker, authContext, api), nil
	}

	// apply quotas to matched operations
	exceeded, quotaError := a.applyQuotas(authorizedOps, authContext)
	if quotaError != nil {
		return a.internalError(req, envRequest, tracker, quotaError), nil
	}
	if exceeded {
		return a.quotaExceeded(req, envRequest, tracker, authContext, api), nil
	}

	return a.authOK(req, tracker, authContext, api, envRequest), nil
}

// apply quotas to all matched operations
// returns an error if any quota failed
func (a *AuthorizationServer) applyQuotas(ops []product.AuthorizedOperation, authC *auth.Context) (exceeded bool, errors error) {
	var quotaArgs = quota.Args{QuotaAmount: 1}
	for _, op := range ops {
		if op.QuotaLimit > 0 {
			result, err := a.handler.quotaMan.Apply(authC, op, quotaArgs)
			if err != nil {
				log.Errorf("quota check: %v", err)
				errors = errorset.Append(errors, err)
			} else if result.Exceeded > 0 {
				log.Debugf("quota exceeded: %v", op.ID)
				exceeded = true
			}
		}
	}
	return
}

func (a *AuthorizationServer) authOK(req *authv3.CheckRequest, tracker *prometheusRequestMetricTracker,
	authContext *auth.Context, api string, envRequest *config.EnvironmentSpecRequest) *authv3.CheckResponse {

	okResponse := &authv3.OkHttpResponse{}

	if a.handler.appendMetadataHeaders {
		addMetadataHeaders(okResponse, api, authContext)
	}

	addHeaderValueOption(okResponse, headerAuthorized, "true", false)
	addHeaderTransforms(req, envRequest, okResponse)

	tracker.statusCode = typev3.StatusCode_OK
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: okResponse,
		},
		DynamicMetadata: encodeExtAuthzMetadata(api, authContext, true),
	}
}

// includes any JWTAuthentication.ForwardPayloadHeader requests
func addHeaderTransforms(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	okResponse *authv3.OkHttpResponse) {
	if envRequest != nil {
		if apiOperation := envRequest.GetOperation(); apiOperation != nil {

			// add ForwardPayloadHeaders
			for _, ja := range envRequest.JWTAuthentications() {
				claims, _ := envRequest.GetJWTResult(ja.Name)
				if claims != nil && ja.ForwardPayloadHeader != "" {
					b, err := json.Marshal(claims)
					if err != nil {
						log.Errorf("unable to marshal ForwardPayloadHeader for %s", ja.Name)
						continue
					}
					encodedClaims := base64.URLEncoding.EncodeToString(b)
					addHeaderValueOption(okResponse, ja.ForwardPayloadHeader, encodedClaims, true)
				}
			}

			// strip proxy base path from request path
			addHeaderValueOption(okResponse, envoyPathHeader, envRequest.GetOperationPath(), false)

			// header transforms from env config
			transforms := envRequest.GetHTTPRequestTransformations()
			for _, rhpat := range transforms.RemoveHeaders {
				rhpat = strings.ToLower(rhpat)
				for hdr := range req.Attributes.Request.Http.Headers {
					if util.SimpleGlobMatch(rhpat, hdr) {
						okResponse.HeadersToRemove = append(okResponse.HeadersToRemove, hdr)
					}
				}
			}
			for k, v := range transforms.SetHeaders {
				addHeaderValueOption(okResponse, k, v, false)
			}
			for _, v := range transforms.AppendHeaders {
				addHeaderValueOption(okResponse, v.Key, v.Value, true)
			}
		}
		if log.DebugEnabled() {
			log.Debugf(logHeaderValueOptions(okResponse))
		}
	}
}

func logHeaderValueOptions(okResponse *authv3.OkHttpResponse) string {
	var b strings.Builder
	b.WriteString("Request header mods:\n")
	if len(okResponse.Headers) > 0 {
		for _, h := range okResponse.Headers {
			addAppend := "="
			if h.Append.Value {
				addAppend = "+"
			}
			b.WriteString(fmt.Sprintf("  %s %q: %q\n", addAppend, h.Header.Key,
				golibutil.Truncate(h.Header.Value, config.TruncateDebugRequestValuesAt)))
		}
	}
	if len(okResponse.HeadersToRemove) > 0 {
		var b strings.Builder
		for _, h := range okResponse.HeadersToRemove {
			b.WriteString(fmt.Sprintf("   - %q\n", h))
		}
	}
	return b.String()
}

func addHeaderValueOption(ok *authv3.OkHttpResponse, key, value string, appnd bool) {
	if value == "" {
		return
	}
	ok.Headers = append(ok.Headers, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   key,
			Value: value,
		},
		Append: wrapperspb.Bool(appnd),
	})
}

func (a *AuthorizationServer) notFound(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker) *authv3.CheckResponse {
	return a.createDenyResponse(req, envRequest, tracker, nil, "", rpc.NOT_FOUND)
}

func (a *AuthorizationServer) unauthenticated(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker) *authv3.CheckResponse {
	return a.createDenyResponse(req, envRequest, tracker, nil, "", rpc.UNAUTHENTICATED)
}

func (a *AuthorizationServer) internalError(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker, err error) *authv3.CheckResponse {
	log.Errorf("sending internal error: %v", err)
	return a.createDenyResponse(req, envRequest, tracker, nil, "", rpc.INTERNAL)
}

func (a *AuthorizationServer) denied(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *authv3.CheckResponse {
	return a.createDenyResponse(req, envRequest, tracker, authContext, api, rpc.PERMISSION_DENIED)
}

func (a *AuthorizationServer) quotaExceeded(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *authv3.CheckResponse {
	return a.createDenyResponse(req, envRequest, tracker, authContext, api, rpc.RESOURCE_EXHAUSTED)
}

func (a *AuthorizationServer) createDenyResponse(req *authv3.CheckRequest, envRequest *config.EnvironmentSpecRequest,
	tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string, code rpc.Code) *authv3.CheckResponse {

	// use intended code, not OK
	switch code {
	case rpc.NOT_FOUND:
		tracker.statusCode = typev3.StatusCode_NotFound

	case rpc.UNAUTHENTICATED:
		tracker.statusCode = typev3.StatusCode_Unauthorized

	case rpc.INTERNAL:
		tracker.statusCode = typev3.StatusCode_InternalServerError

	case rpc.PERMISSION_DENIED:
		tracker.statusCode = typev3.StatusCode_Forbidden

	case rpc.RESOURCE_EXHAUSTED:
		tracker.statusCode = typev3.StatusCode_TooManyRequests
	}

	if authContext == nil || !a.handler.allowUnauthorized { // send reject to client
		log.Debugf("sending denied: %s", code.String())

		response := &authv3.CheckResponse{
			Status: &status.Status{
				Code: int32(code),
			},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{
						Code: tracker.statusCode,
					},
				},
			},
		}

		// Envoy does not send metadata to ALS on a reject, so we create the
		// analytics record here and the ALS handler can ignore the metadataless record.
		if api != "" && authContext != nil {
			start := req.Attributes.Request.Time.AsTime().UnixNano() / 1000000
			duration := time.Now().Unix() - tracker.startTime.Unix()
			sent := start + duration                                                   // use Envoy's start time to calculate
			requestPath := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)[0] // Apigee doesn't want query params in requestPath
			record := analytics.Record{
				ClientReceivedStartTimestamp: start,
				ClientReceivedEndTimestamp:   start,
				TargetSentStartTimestamp:     0,
				TargetSentEndTimestamp:       0,
				TargetReceivedStartTimestamp: 0,
				TargetReceivedEndTimestamp:   0,
				ClientSentStartTimestamp:     sent,
				ClientSentEndTimestamp:       sent,
				APIProxy:                     api,
				RequestURI:                   req.Attributes.Request.Http.Path,
				RequestPath:                  requestPath,
				RequestVerb:                  req.Attributes.Request.Http.Method,
				UserAgent:                    req.Attributes.Request.Http.Headers["User-Agent"],
				ResponseStatusCode:           int(code),
				GatewaySource:                gatewaySource,
				ClientIP:                     req.Attributes.Request.Http.Headers["X-Forwarded-For"],
			}

			// this may be more efficient to batch, but changing the golib impl would require
			// a rewrite as it assumes the same authContext for all records
			records := []analytics.Record{record}
			err := a.handler.analyticsMan.SendRecords(authContext, records)
			if err != nil {
				log.Warnf("Unable to send ax: %v", err)
			}
		}

		return response
	}

	okResponse := &authv3.OkHttpResponse{}

	if a.handler.appendMetadataHeaders {
		addMetadataHeaders(okResponse, api, authContext)
	}

	addHeaderTransforms(req, envRequest, okResponse)

	// allow request to continue upstream
	log.Debugf("sending ok (actual: %s)", code.String())
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: okResponse,
		},
		DynamicMetadata: encodeExtAuthzMetadata(api, authContext, false),
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
	statusCode  typev3.StatusCode
}

// set statusCode before calling record()
func prometheusRequestTracker(rootContext context.Context) *prometheusRequestMetricTracker {
	return &prometheusRequestMetricTracker{
		rootContext: rootContext,
		startTime:   time.Now(),
		statusCode:  typev3.StatusCode_InternalServerError,
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
