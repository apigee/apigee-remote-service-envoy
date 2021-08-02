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

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const TruncateDebugRequestValuesAt = 5

const (
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
)

// a "match all" operation for apis without operations
var defaultOperation = &APIOperation{
	Name: "default",
}

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func NewEnvironmentSpecRequest(authMan auth.Manager, e *EnvironmentSpecExt, req *authv3.CheckRequest) *EnvironmentSpecRequest {
	esr := &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		authMan:            authMan,
		Request:            req,
		jwtResults:         make(map[string]*jwtResult),
	}
	return esr
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec.
// Create using NewEnvironmentSpecRequest()
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	Request               *authv3.CheckRequest
	authMan               auth.Manager
	jwtResults            map[string]*jwtResult // JWTAuthentication.Name ->
	verifier              jwt.Verifier
	apiSpec               *APISpec
	operation             *APIOperation
	queryValues           url.Values
	operationPath         string
	consumerAuthorization *ConsumerAuthorization
}

type jwtClaims map[string]interface{}

type jwtResult struct {
	claims jwtClaims
	err    error
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
	if e.apiSpec == nil {
		path := strings.Split(strings.SplitN(e.Request.Attributes.Request.Http.Path, "?", 2)[0], "/") // strip querystring and split
		path = append([]string{"/"}, path...)
		if result := e.apiPathTree.Find(path, 0); result != nil {
			e.apiSpec = result.(*APISpec)
		}
	}
	return e.apiSpec
}

// GetOperationPath returns path of Operation - no basepath, includes query string
func (e *EnvironmentSpecRequest) GetOperationPath() string {
	e.GetOperation() // ensures operationPath is populated
	return e.operationPath
}

// GetOperation uses HttpMatch to return an APIOperation
// If this is a CORS preflight, it will return the target operation per CORS
func (e *EnvironmentSpecRequest) GetOperation() *APIOperation {
	if e == nil {
		return nil
	}
	if e.operation == nil {
		if api := e.GetAPISpec(); api != nil {
			e.operationPath = strings.TrimPrefix(e.Request.Attributes.Request.Http.Path, api.BasePath)
			if len(api.Operations) == 0 { // if no operations, match any for api
				e.operation = defaultOperation
			} else {
				pathSplits := strings.Split(strings.SplitN(e.operationPath, "?", 2)[0], "/") // strip querystring and split
				// prepend method for search
				method := e.Request.Attributes.Request.Http.Method
				if e.IsCORSPreflight() {
					method = e.Request.Attributes.Request.Http.Headers[CORSRequestMethod]
				}
				pathSplits = append([]string{e.apiSpec.ID, method}, pathSplits...)
				if result := e.opPathTree.Find(pathSplits, 0); result != nil {
					e.operation = result.(*APIOperation)
				}
			}
		}
	}
	return e.operation
}

// GetParamValue extracts a value from request using Match
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
		if e.queryValues == nil {
			q := strings.SplitN(e.Request.Attributes.Request.Http.Path, "?", 2)
			if len(q) > 1 {
				vals, _ := url.ParseQuery(q[1])
				e.queryValues = vals
			}
			key := string(m)
			value = e.queryValues.Get(key)
			log.Debugf("param from query %q: %q", key, util.Truncate(value, TruncateDebugRequestValuesAt))
		}
	case JWTClaim:
		value = e.getClaimValue(m)
		log.Debugf("param from claim %q: %q", m, util.Truncate(value, TruncateDebugRequestValuesAt))
	}
	return e.transform(param.Transformation, value)
}

func (e *EnvironmentSpecRequest) getClaimValue(claim JWTClaim) string {
	if e != nil {
		r, ok := e.jwtResults[claim.Requirement]
		if !ok {
			e.verifyJWTAuthentication(claim.Requirement)
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
// returns true if found and verified
// any error can be in e.jwtResults[name]
func (e *EnvironmentSpecRequest) verifyJWTAuthentication(name string) bool {
	if e == nil {
		return false
	}
	var jwtReq *JWTAuthentication
	if len(e.GetOperation().jwtAuthentications) > 0 {
		jwtReq = e.GetOperation().jwtAuthentications[name]
	} else {
		jwtReq = e.GetAPISpec().jwtAuthentications[name]
	}
	if jwtReq == nil {
		log.Debugf("JWTAuthentication %q not found", name)
		return false
	}
	if result := e.jwtResults[name]; result != nil { // return from cache
		return result.err == nil
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

	for _, p := range jwtReq.In {
		jwksSource, ok := jwtReq.JWKSSource.(RemoteJWKS) // only RemoteJWKS supported for now
		if !ok {
			setResult(nil, fmt.Errorf("JWKSSource must be RemoteJWKS, got: %#v", jwtReq.JWKSSource))
		}
		jwtString := e.GetParamValue(p)
		provider := jwt.Provider{JWKSURL: jwksSource.URL}

		claims, err := e.authMan.ParseJWT(jwtString, provider)
		if err == nil {
			err = mustBeInClaim(jwtReq.Issuer, "iss", claims)
		}
		if err == nil {
			for _, aud := range jwtReq.Audiences {
				err = mustBeInClaim(aud, "aud", claims)
				if err != nil {
					break
				}
			}
		}

		setResult(claims, err)
		if err != nil {
			return false
		}
	}
	return true
}

// returns error if passed value is not in claim as string or []string
func mustBeInClaim(value, name string, claims map[string]interface{}) error {
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
	return fmt.Errorf("%q not in claim %q", value, name)
}

// IsAuthenticated returns true if AuthenticatationRequirements are met for the request
// Returns true if AuthenticatationRequirements are empty or disabled.
func (e *EnvironmentSpecRequest) IsAuthenticated() bool {
	return e.meetsAuthenticatationRequirements(e.getAuthenticationRequirement())
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
	return !e.GetConsumerAuthorization().isEmpty()
}

func (e *EnvironmentSpecRequest) GetHTTPRequestTransformations() (transforms HTTPRequestTransformations) {
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

// returns true if auth is empty or disabled
func (e *EnvironmentSpecRequest) meetsAuthenticatationRequirements(auth AuthenticationRequirement) bool {
	if e == nil {
		return false
	}
	if auth.Requirements == nil || auth.Disabled {
		return true
	}
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return e.verifyJWTAuthentication(a.Name)
	case AnyAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if e.meetsAuthenticatationRequirements(r) {
				return true
			}
		}
		return false
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !e.meetsAuthenticatationRequirements(r) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// GetAPIKey uses ConsumerAuthorization of Operation or APISpec as appropriate
// to retrieve the API Key. This does not check if the request is authenticated.
// Returns "" if ConsumerAuthorization is disabled.
func (e *EnvironmentSpecRequest) GetAPIKey() (key string) {
	auth := e.GetConsumerAuthorization()
	if !auth.Disabled {
		for _, authorization := range auth.In {
			if key = e.GetParamValue(authorization); key != "" {
				return key
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
