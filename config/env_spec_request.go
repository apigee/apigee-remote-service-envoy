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
	"net/url"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func NewEnvironmentSpecRequest(authMan auth.Manager, e *EnvironmentSpecExt, req *authv3.CheckRequest) *EnvironmentSpecRequest {
	esr := &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		authMan:            authMan,
		request:            req,
		jwtResults:         make(map[string]*jwtResult),
	}
	if api := esr.GetAPISpec(); api != nil {
		esr.jwtAuthentications = e.jwtAuthentications[api.ID]
	}
	return esr
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec.
// Create using NewEnvironmentSpecRequest()
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	request            *authv3.CheckRequest
	authMan            auth.Manager
	jwtAuthentications map[string]*JWTAuthentication // JWTAuthentication.Name ->
	jwtResults         map[string]*jwtResult         // JWTAuthentication.Name ->
	verifier           jwt.Verifier
	apiSpec            *APISpec
	operation          *APIOperation
	queryValues        url.Values
	operationPath      string
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
		path := strings.Split(strings.SplitN(e.request.Attributes.Request.Http.Path, "?", 2)[0], "/") // strip querystring and split
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
func (e *EnvironmentSpecRequest) GetOperation() *APIOperation {
	if e == nil {
		return nil
	}
	if e.operation == nil {
		if api := e.GetAPISpec(); api != nil {
			e.operationPath = strings.TrimPrefix(e.request.Attributes.Request.Http.Path, api.BasePath) // strip base path
			pathSplits := strings.Split(strings.SplitN(e.operationPath, "?", 2)[0], "/")               // strip querystring and split
			// prepend method for search
			pathSplits = append([]string{e.apiSpec.ID, e.request.Attributes.Request.Http.Method}, pathSplits...)

			if result := e.opPathTree.Find(pathSplits, 0); result != nil {
				e.operation = result.(*APIOperation)
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
		value = e.request.Attributes.Request.Http.Headers[strings.ToLower(string(m))]
		// Per Envoy: If multiple headers share the same key, they are merged per HTTP spec.
		// So, we're just grabbing the first value (up to any comma).
		if indx := strings.Index(value, ","); indx > 0 {
			value = value[:indx]
		}
	case Query:
		if e.queryValues == nil {
			q := strings.SplitN(e.request.Attributes.Request.Http.Path, "?", 2)
			if len(q) > 1 {
				vals, _ := url.ParseQuery(q[1])
				e.queryValues = vals
			}
			value = e.queryValues.Get(string(m))
		}
	case JWTClaim:
		value = e.getClaimValue(m)
	}
	return param.Transformation.Transform(value)
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

// looks up the JWTAuthentication by name and runs verification
// returns true if found and verified
// any error can be in e.jwtResults[name]
func (e *EnvironmentSpecRequest) verifyJWTAuthentication(name string) bool {
	if e == nil {
		return false
	}
	jwtReq := e.jwtAuthentications[name]
	if jwtReq == nil {
		return false
	}
	if result := e.jwtResults[name]; result != nil { // return from cache
		return result.err == nil
	}

	// uncached, parse it
	setResult := func(claims map[string]interface{}, err error) {
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
	return fmt.Errorf("%s doesn't match", name)
}

// IsAuthenticated returns true if AuthenticatationRequirements are met for the request
func (e *EnvironmentSpecRequest) IsAuthenticated() bool {
	return e.meetsAuthenticatationRequirements(e.getAuthenticationRequirement())
}

func (req *EnvironmentSpecRequest) getAuthenticationRequirement() (auth AuthenticationRequirement) {
	if req != nil {
		op := req.GetOperation()
		if op != nil && !op.ConsumerAuthorization.isEmpty() {
			auth = op.Authentication
		} else if api := req.GetAPISpec(); api != nil {
			auth = api.Authentication
		}
	}
	return auth
}

func (req *EnvironmentSpecRequest) GetHTTPRequestTransformations() (transforms HTTPRequestTransformations) {
	if req != nil {
		op := req.GetOperation()
		if op != nil && !op.HTTPRequestTransforms.isEmpty() {
			transforms = op.HTTPRequestTransforms
		} else if api := req.GetAPISpec(); api != nil {
			transforms = api.HTTPRequestTransforms
		}
	}
	return transforms
}

func (e *EnvironmentSpecRequest) meetsAuthenticatationRequirements(auth AuthenticationRequirement) bool {
	if e == nil {
		return false
	}
	if auth.Requirements == nil {
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
func (req *EnvironmentSpecRequest) GetAPIKey() (key string) {
	auth := req.getConsumerAuthorization()
	for _, authorization := range auth.In {
		if key = req.GetParamValue(authorization); key != "" {
			return key
		}
	}
	return ""
}

func (req *EnvironmentSpecRequest) getConsumerAuthorization() (auth ConsumerAuthorization) {
	if req != nil {
		op := req.GetOperation()
		if op != nil && !op.ConsumerAuthorization.isEmpty() {
			auth = op.ConsumerAuthorization
		} else if api := req.GetAPISpec(); api != nil {
			auth = api.ConsumerAuthorization
		}
	}
	return auth
}
