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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/apigee/apigee-remote-service-envoy/v2/fault"
	"github.com/apigee/apigee-remote-service-envoy/v2/transform"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
)

const TruncateDebugRequestValuesAt = 5

const (
	ContentTypeHeader = "content-type"
	GRPCContentType   = "application/grpc"

	CORSOriginHeader   = "origin"
	CORSOriginWildcard = "*"
	CORSRequestMethod  = "access-control-request-method"
	CORSRequestHeaders = "access-control-request-headers"
	CORSVary           = "vary"
	CORSVaryOrigin     = "Origin"

	CORSAllowOrigin           = "access-control-allow-origin"
	CORSAllowHeaders          = "access-control-allow-headers"
	CORSAllowMethods          = "access-control-allow-methods"
	CORSExposeHeaders         = "access-control-expose-headers"
	CORSMaxAge                = "access-control-max-age"
	CORSAllowCredentials      = "access-control-allow-credentials"
	CORSAllowCredentialsValue = "true"

	VariableNamespaceSeparator = "."
	RequestNamespace           = "request"
	QueryNamespace             = "query"
	PathNamespace              = "path"
	HeaderNamespace            = "headers"
	InternalNamespace          = "_internal"
	RequestPath                = "path"
	RequestQuerystring         = "querystring"
)

// a "match all" operation for apis without operations
var defaultOperation = &APIOperation{
	Name: "default",
}

// ErrUnsupportedJwkSoource is raised when unsupported JWK source is encountered
var ErrUnsupportedJwkSource = errors.New("unsupported JWK Source")

// ErrMissingIssuerInClaim is raised when the required issuer value is missing from the supported claims
var ErrMissingIssuerInClaim = errors.New("issuer value not in claim")

// ErrMissingAudienceInClaim is raised when the required audience value is missing from the supported claims
var ErrMissingAudienceInClaim = errors.New("audience value not in claim")

// ErrJwtParsingFailure is raised when JWT Parsing fails
var ErrJwtParsingFailure = errors.New("jwt parsing failed")

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func NewEnvironmentSpecRequest(authMan auth.Manager, e *EnvironmentSpecExt, req *authv3.CheckRequest) *EnvironmentSpecRequest {
	esr := &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		authMan:            authMan,
		Request:            req,
		jwtResults:         make(map[string]*jwtResult),
	}
	esr.parseRequest()
	return esr
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec.
// Create using NewEnvironmentSpecRequest()
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	Request               *authv3.CheckRequest
	originalRequestPath   string
	authMan               auth.Manager
	jwtResults            map[string]*jwtResult // JWTAuthentication.Name ->
	apiSpec               *APISpec
	operation             *APIOperation
	consumerAuthorization *ConsumerAuthorization
	variables             requestVariables // for template reification
}

func (e *EnvironmentSpecRequest) parseRequest() {

	path, queryString := func() (string, string) {
		pathSplits := strings.SplitN(e.Request.Attributes.Request.Http.Path, "?", 2)
		path := pathSplits[0]
		var queryString string
		if len(pathSplits) > 1 {
			queryString = pathSplits[1]
		}
		return path, queryString
	}()
	// Save the original path, pre-basepath removal, in case we need it (e.g., for gRPC requests).
	e.originalRequestPath = path

	// find API
	pathSegments := strings.Split(path, "/")
	pathSegments = append([]string{"/"}, pathSegments...)
	result, length := e.apiPathTree.FindPrefix(pathSegments, 0)
	if result == nil {
		return
	}
	e.apiSpec = result.(*APISpec)

	// trim api base path
	// ignore the first two elements - "/" and "" - when joining the segments
	// but add it back afterwards.
	matchedBasePath := "/" + strings.Join(pathSegments[2:length], "/")
	opPath := strings.TrimPrefix(path, matchedBasePath)
	if !strings.HasPrefix(opPath, "/") {
		opPath = "/" + opPath
	}

	var pathTemplate *transform.Template
	if len(e.apiSpec.Operations) == 0 { // if no operations, match any for api
		e.operation = defaultOperation
	} else {
		// find operation
		pathSplits := strings.Split(opPath, "/")
		// prepend method for search
		method := e.Request.Attributes.Request.Http.Method
		if e.IsCORSPreflight() {
			method = e.Request.Attributes.Request.Http.Headers[CORSRequestMethod]
		}
		pathSplits = append([]string{e.apiSpec.ID, method}, pathSplits...)
		if result := e.opPathTree.Find(pathSplits, 0); result != nil {
			match := result.(*OpTemplateMatch)
			e.operation = match.operation
			pathTemplate = match.template
		}
	}
	e.variables = e.parseRequestVariables(pathTemplate, opPath, queryString)
}

type jwtClaims map[string]interface{}

type jwtResult struct {
	claims jwtClaims
	err    error
}

func (e *EnvironmentSpecRequest) parseRequestVariables(pathTemplate *transform.Template, opPath, queryString string) map[string]map[string]string {
	vars := make(map[string]map[string]string)
	vars[PathNamespace] = pathTemplate.Extract(opPath)
	vars[HeaderNamespace] = e.Request.GetAttributes().GetRequest().GetHttp().GetHeaders()
	vars[RequestNamespace] = make(map[string]string)
	vars[QueryNamespace] = make(map[string]string)

	vars[RequestNamespace][RequestPath] = opPath
	vars[RequestNamespace][RequestQuerystring] = queryString

	if queryString != "" {
		vals, err := url.ParseQuery(queryString)
		if err != nil {
			log.Warnf("error parsing querystring: %q, error: %v", queryString, err)
		}
		for k, vs := range vals {
			vars[QueryNamespace][k] = strings.Join(vs, ",") // eliminate duplicated query names
		}
	}

	return vars
}

type requestVariables map[string]map[string]string // namespace -> variables

func (rv requestVariables) LookupValue(name string) (string, bool) {
	splits := strings.SplitN(name, VariableNamespaceSeparator, 2)

	var mapping map[string]string
	if len(splits) > 1 {
		mapping = rv[splits[0]]
	}

	if mapping == nil {
		return "", false
	}

	val, ok := mapping[splits[1]]
	return val, ok
}

// PrepareVariables go over all the variables for the specific request
// and populate them for the http request transform.
func (e *EnvironmentSpecRequest) PrepareVariables() error {
	if e == nil || e.apiSpec == nil {
		return nil
	}
	variables := e.apiVariables[e.apiSpec.ID]
	if vs := e.opVariables[e.apiSpec.ID][e.GetOperation().Name]; len(vs) != 0 {
		variables = vs
	}
	for _, v := range variables {
		val, err := v.Value()
		if err != nil {
			return err
		}
		if e.variables[v.Namespace()] == nil {
			e.variables[v.Namespace()] = make(map[string]string)
		}
		e.variables[v.Namespace()][v.Name()] = val
	}
	return nil
}

// GetQueryParams returns a safe copy of the QueryParams map
func (e *EnvironmentSpecRequest) GetQueryParams() map[string]string {
	copy := make(map[string]string)
	if e != nil {
		for k, v := range e.variables[QueryNamespace] {
			copy[k] = v
		}
	}
	return copy
}

// Reify will return a string with known {variables} replaced.
// If the template is unknown, the unmodified template will be returned.
// If a {variable} is unknown, it will be replaced by an empty string.
func (e *EnvironmentSpecRequest) Reify(template string) string {
	if e != nil {
		ct := e.compiledTemplates[template]
		if ct != nil {
			return ct.Reify(e.variables)
		}
	}
	return template
}

// GetJWTResult returns the claims and error if a JWTAuthentication of the passed name was
// verified, nil if it was not verified or does not exist
func (e *EnvironmentSpecRequest) GetJWTResult(name string) (map[string]interface{}, error) {
	if e != nil {
		if jwtResult := e.jwtResults[name]; jwtResult != nil {
			return jwtResult.claims, jwtResult.err
		}
	}
	return nil, nil
}

func (e *EnvironmentSpecRequest) GetAPISpec() *APISpec {
	if e == nil {
		return nil
	}
	return e.apiSpec
}

// isGRPCRequest returns true if this request looks like a gRPC request.
func (e *EnvironmentSpecRequest) isGRPCRequest() bool {
	return e.apiSpec != nil &&
		e.apiSpec.GrpcService != "" &&
		e.variables[HeaderNamespace][ContentTypeHeader] == GRPCContentType &&
		e.Request.Attributes.Request.Http.Method == "POST"
}

// GetTargetRequestPath returns the path for the request that should be sent to the target.
// The returned value is prior to {path,query,header} transformation.
func (e *EnvironmentSpecRequest) GetTargetRequestPath() string {
	if e.isGRPCRequest() {
		return e.originalRequestPath
	}
	return e.GetOperationPath()
}

// GetOperationPath returns path of Operation, no basepath or querystring
// The returned value is prior to {path,query,header} transformation.
func (e *EnvironmentSpecRequest) GetOperationPath() string {
	if e.GetOperation() == nil {
		return ""
	}
	return e.variables[RequestNamespace][RequestPath]
}

// GetOperation uses HttpMatch to return an APIOperation
// If this is a CORS preflight, it will return the target operation per CORS
func (e *EnvironmentSpecRequest) GetOperation() *APIOperation {
	if e == nil {
		return nil
	}
	return e.operation
}

// GetParamValue extracts a potentially tranformed value from request using Match
func (e *EnvironmentSpecRequest) GetParamValue(param APIOperationParameter) string {
	if e == nil || param.Match == nil {
		return ""
	}
	var value string
	switch m := param.Match.(type) {
	case Header:
		key := strings.ToLower(string(m))
		value = e.Request.Attributes.Request.Http.Headers[key]
		// Per Envoy: If multiple headers share the same key, they are merged per HTTP spec.
		// So, we're just grabbing the first value (up to any comma).
		if indx := strings.Index(value, ","); indx > 0 {
			value = value[:indx]
		}
		log.Debugf("param from header %q: %q", key, util.Truncate(value, TruncateDebugRequestValuesAt))
	case Query:
		key := string(m)
		value = e.variables[QueryNamespace][key]
		log.Debugf("param from query %q: %q", key, util.Truncate(value, TruncateDebugRequestValuesAt))
	case JWTClaim:
		value = e.getClaimValue(m)
		log.Debugf("param from claim %q: %q", m, util.Truncate(value, TruncateDebugRequestValuesAt))
	}
	return e.Transform(param.Transformation.Template, param.Transformation.Substitution, value)
}

func (e *EnvironmentSpecRequest) getClaimValue(claim JWTClaim) string {
	if e != nil {
		r, ok := e.jwtResults[claim.Requirement]
		if !ok {
			// error is ignored here, but is cached and retrieved during verification
			_ = e.verifyJWTAuthentication(claim.Requirement)
			r = e.jwtResults[claim.Requirement]
		}
		if r != nil && r.claims != nil && r.claims[claim.Name] != nil {
			return r.claims[claim.Name].(string)
		}
	}
	return ""
}

// JWTAuthentications returns a list of JWTAuthentication specific to the request.
func (e *EnvironmentSpecRequest) JWTAuthentications() []*JWTAuthentication {
	var auths []*JWTAuthentication
	for _, v := range e.GetOperation().jwtAuthentications {
		auths = append(auths, v)
	}
	if len(auths) != 0 {
		return auths
	}
	for _, v := range e.GetAPISpec().jwtAuthentications {
		auths = append(auths, v)
	}
	return auths
}

// looks up the JWTAuthentication by name and runs verification
// return error if not found, or not verified
// any error can be in e.jwtResults[name]
func (e *EnvironmentSpecRequest) verifyJWTAuthentication(name string) error {
	if e == nil {
		return fault.NewAdapterFault(fault.InternalError, rpc.UNAUTHENTICATED, 0)
	}
	var jwtReq *JWTAuthentication
	if len(e.GetOperation().jwtAuthentications) > 0 {
		jwtReq = e.GetOperation().jwtAuthentications[name]
	} else {
		jwtReq = e.GetAPISpec().jwtAuthentications[name]
	}
	if jwtReq == nil {
		log.Debugf("JWTAuthentication %q not found", name)
		return fault.NewAdapterFault(fault.JwtUnknownException, rpc.UNAUTHENTICATED, 0)
	}
	if result := e.jwtResults[name]; result != nil { // return from cache
		if result.err == nil {
			return nil
		} else {
			return adapterFaultForJwtErr(result.err)
		}
	}

	// uncached, parse it
	setResult := func(claims map[string]interface{}, err error) {
		if err != nil {
			log.Debugf("JWTAuthentication %q verification error: %s", name, err)
		} else {
			log.Debugf("JWTAuthentication %q verified, claims: %v", name, claims)
		}
		e.jwtResults[name] = &jwtResult{
			claims: claims,
			err:    err,
		}
	}

	var err error
	var claims map[string]interface{}
	for _, p := range jwtReq.In {
		jwksSource, ok := jwtReq.JWKSSource.(RemoteJWKS) // only RemoteJWKS supported for now
		if !ok {
			setResult(nil, fmt.Errorf("%w. JWKSSource must be RemoteJWKS, got: %#v", ErrUnsupportedJwkSource, jwtReq.JWKSSource))
		}
		jwtString := e.GetParamValue(p)
		provider := jwt.Provider{JWKSURL: jwksSource.URL}

		claims, err = e.authMan.ParseJWT(jwtString, provider)
		// If parsing failed, log and wrap the error
		if err != nil {
			log.Warnf("error in jwt parsing %v", err)
			err = errors.Wrap(ErrJwtParsingFailure, err.Error())
		}

		if err == nil {
			err = mustBeInClaim(jwtReq.Issuer, "iss", claims, ErrMissingIssuerInClaim)
		}
		if err == nil {
			for _, aud := range jwtReq.Audiences {
				err = mustBeInClaim(aud, "aud", claims, ErrMissingAudienceInClaim)
				// Any intersection between allowed audiences and
				// those in the "aud" claim is accepted.
				if err == nil {
					break
				}
			}
			// No intersection exists, break and return false.
			if err != nil {
				break
			}
		}

		setResult(claims, err)
		// First match wins
		if err == nil {
			return nil
		}
	}

	return adapterFaultForJwtErr(err)
}

func adapterFaultForJwtErr(err error) *fault.AdapterFault {
	switch {
	case err == nil:
		return fault.NewAdapterFault(fault.JwtUnknownException, rpc.UNAUTHENTICATED, 0)
	case errors.Is(err, ErrUnsupportedJwkSource):
		return fault.NewAdapterFault(fault.JwtInvalidToken, rpc.UNAUTHENTICATED, 0)
	case errors.Is(err, ErrMissingIssuerInClaim):
		return fault.NewAdapterFault(fault.JwtIssuerMismatch, rpc.UNAUTHENTICATED, 0)
	case errors.Is(err, ErrMissingAudienceInClaim):
		return fault.NewAdapterFault(fault.JwtAudienceMismatch, rpc.UNAUTHENTICATED, 0)
	case errors.Is(err, ErrJwtParsingFailure):
		return fault.NewAdapterFault(fault.JwtInvalidToken, rpc.UNAUTHENTICATED, 0)
	default:
		return fault.NewAdapterFault(fault.JwtUnknownException, rpc.UNAUTHENTICATED, 0)
	}
}

// returns error if passed value is not in claim as string or []string
func mustBeInClaim(value, name string, claims map[string]interface{}, errToWrap error) error {
	if value == "" {
		return nil
	}
	switch claim := claims[name].(type) {
	case string:
		if value == claim {
			return nil
		}
	case []string:
		for _, ea := range claim {
			if value == ea {
				return nil
			}
		}
	}
	return fmt.Errorf("%w. %q not in claim %q", errToWrap, value, name)
}

// Authenticate returns error if AuthenticationRequirements are not met for the request.
// Empty or disabled requirements are considered  valid.
func (e *EnvironmentSpecRequest) Authenticate() error {
	return e.verifyAuthenticationRequirements(e.getAuthenticationRequirement())
}

func (e *EnvironmentSpecRequest) getAuthenticationRequirement() (auth AuthenticationRequirement) {
	if e != nil {
		op := e.GetOperation()
		if op != nil && !op.Authentication.IsEmpty() {
			auth = op.Authentication
			log.Debugf("using AuthenticationRequirement from operation %q", op.Name)
		} else if api := e.GetAPISpec(); api != nil {
			auth = api.Authentication
			log.Debugf("using AuthenticationRequirement from api %q", api.ID)
		}
	}
	return auth
}

// IsAuthorizationRequired returns true if Authorization is required.
func (e *EnvironmentSpecRequest) IsAuthorizationRequired() bool {
	return !e.GetConsumerAuthorization().Disabled && !e.GetConsumerAuthorization().isEmpty()
}

func (e *EnvironmentSpecRequest) GetHTTPRequestTransforms() (transforms HTTPRequestTransforms) {
	if e != nil {
		op := e.GetOperation()
		if op != nil && !op.HTTPRequestTransforms.isEmpty() {
			transforms = op.HTTPRequestTransforms
			log.Debugf("using HTTPRequestTransforms from operation %q", op.Name)
		} else if api := e.GetAPISpec(); api != nil {
			transforms = api.HTTPRequestTransforms
			log.Debugf("using HTTPRequestTransforms from api %q", api.ID)
		}
	}
	return transforms
}

func (e *EnvironmentSpecRequest) DynamicMetadata() (metadata map[string]interface{}) {
	if e != nil {
		op := e.GetOperation()
		if op != nil && op.DynamicMetadata != nil {
			metadata = op.DynamicMetadata
			log.Debugf("using DynamicMetadata from operation %q", op.Name)
		} else if api := e.GetAPISpec(); api != nil {
			metadata = api.DynamicMetadata
			log.Debugf("using DynamicMetadata from api %q", api.ID)
		}
	}
	return metadata
}

func (e *EnvironmentSpecRequest) verifyAuthenticationRequirements(auth AuthenticationRequirement) error {
	if e == nil {
		return fault.NewAdapterFault(fault.InternalError, rpc.UNAUTHENTICATED, 0)
	}
	if auth.Requirements == nil || auth.Disabled {
		return nil
	}
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return e.verifyJWTAuthentication(a.Name)
	case AnyAuthenticationRequirements:
		var err error
		for _, r := range []AuthenticationRequirement(a) {
			if err = e.verifyAuthenticationRequirements(r); err == nil {
				return nil
			}
		}
		// none of the authentication requirements matched, returning the last error
		return err
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			// returing the first failing authentication requirement
			if err := e.verifyAuthenticationRequirements(r); err != nil {
				return err
			}
		}
		return nil
	default:
		return fault.NewAdapterFault(fault.InternalError, rpc.UNAUTHENTICATED, 0)
	}
}

// GetAPIKey uses ConsumerAuthorization of Operation or APISpec as appropriate
// to retrieve the API Key. This does not check if the request is authenticated.
// Returns "" if ConsumerAuthorization is disabled.
func (e *EnvironmentSpecRequest) GetAPIKey() (key string) {
	if e != nil {
		auth := e.GetConsumerAuthorization()
		if !auth.Disabled {
			for _, authorization := range auth.In {
				if key := e.GetParamValue(authorization); key != "" {
					// First match wins.
					return key
				}
			}
		}
	}
	return ""
}

// GetConsumerAuthorization returns the ConsumerAuthorization of Operation or APISpec as appropriate
func (e *EnvironmentSpecRequest) GetConsumerAuthorization() (auth ConsumerAuthorization) {
	if e != nil {
		if e.consumerAuthorization == nil {
			// use operation if valid
			if op := e.GetOperation(); op != nil && !op.ConsumerAuthorization.isEmpty() {
				log.Debugf("using ConsumerAuthorization from operation %q", op.Name)
				e.consumerAuthorization = &op.ConsumerAuthorization
				return op.ConsumerAuthorization
			}
			// if op auth not valid, use api's
			if api := e.GetAPISpec(); !api.ConsumerAuthorization.Disabled {
				log.Debugf("using ConsumerAuthorization from api %q", e.GetAPISpec().ID)
				e.consumerAuthorization = &api.ConsumerAuthorization
				return api.ConsumerAuthorization
			} else {
				log.Debugf("no enabled ConsumerAuthorization for api %q", e.GetAPISpec().ID)
				e.consumerAuthorization = &ConsumerAuthorization{}
			}
		}
		return *e.consumerAuthorization
	}
	return
}

// IsCORSRequest returns true if request is a CORS request and there is a CORS Policy
func (e *EnvironmentSpecRequest) IsCORSRequest() bool {
	if e == nil || e.GetAPISpec() == nil {
		return false
	}
	origin := e.Request.Attributes.Request.Http.Headers[CORSOriginHeader]
	return origin != "" && !e.GetAPISpec().Cors.IsEmpty()
}

// IsCORSPreflight returns true if IsCORSRequest() is true and is OPTIONS methodd
func (e *EnvironmentSpecRequest) IsCORSPreflight() bool {
	return e.IsCORSRequest() && e.Request.Attributes.Request.Http.Method == http.MethodOptions
}

// AllowedOrigin returns the proper header value for Access-Control-Allow-Origin
// (if any - empty is do not set) and a boolean indicating if the header
// `Vary: Origin` should be set as the origin calculation was dynamic.
func (e *EnvironmentSpecRequest) AllowedOrigin() (origin string, vary bool) {
	if !e.IsCORSRequest() {
		return
	}
	origin = e.Request.Attributes.Request.Http.Headers[CORSOriginHeader]
	api := e.GetAPISpec()
	vary = e.corsVary[api.ID]

	if allowedMap, ok := e.corsAllowedOrigins[api.ID]; ok {
		if allowed := allowedMap[origin]; allowed {
			return
		}
	}

	for _, regexString := range api.Cors.AllowOriginsRegexes {
		if compiledRegex, ok := e.compiledRegExps[regexString]; ok {
			if compiledRegex.MatchString(origin) {
				return
			}
		}
	}

	if ok := e.corsAllowedOrigins[api.ID][wildcard]; ok {
		origin = wildcard
		return
	}

	origin = ""
	return
}

// Transform uses StringTransformation syntax to transform the passed string.
func (e EnvironmentSpecRequest) Transform(source, target, input string) string {
	if source == "" && target == "" {
		return input
	}
	template := e.compiledTemplates[source]
	substitution := e.compiledTemplates[target]
	return transform.Substitute(template, substitution, input)
}
