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

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func NewEnvironmentSpecRequest(e *EnvironmentSpecExt, req *authv3.CheckRequest) *EnvironmentSpecRequest {
	esr := &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		request:            req,
		jwtResults:         make(map[string]*jwtResult),
	}
	if api := esr.GetAPISpec(); api != nil {
		esr.jwtRequirements = make(map[string]*JWTAuthentication)
		for _, j := range e.ApiJwtRequirements[api.ID] {
			esr.jwtRequirements[j.Name] = j
		}
	}
	return esr
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec.
// Create using NewEnvironmentSpecRequest()
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	jwtRequirements map[string]*JWTAuthentication // JWTAuthentication.Name ->
	request         *authv3.CheckRequest
	jwtResults      map[string]*jwtResult // JWTAuthentication.Name ->
	verifier        jwt.Verifier
	apiSpec         *APISpec
	operation       *APIOperation
	queryValues     url.Values
}

type jwtClaims map[string]interface{}

type jwtResult struct {
	claims jwtClaims
	err    error
}

// GetAPI uses the base path to return an APISpec
func (e *EnvironmentSpecRequest) GetAPISpec() *APISpec {
	if e == nil {
		return nil
	}
	if e.apiSpec == nil {
		path := strings.Split(e.getRequestPath(), "/")
		if result := e.ApiPathTree.Find(path, 0); result != nil {
			e.apiSpec = result.(*APISpec)
		}
	}
	return e.apiSpec
}

// path without querystring
func (e *EnvironmentSpecRequest) getRequestPath() string {
	return strings.SplitN(e.request.Attributes.Request.Http.Path, "?", 2)[0]
}

// path with base path stripped
func (e *EnvironmentSpecRequest) getAPISubPath() string {
	if api := e.GetAPISpec(); api != nil {
		return strings.TrimPrefix(e.getRequestPath(), api.BasePath)
	}
	return ""
}

// GetOperation uses HttpMatch to return an APIOperation
func (e *EnvironmentSpecRequest) GetOperation() *APIOperation {
	if e == nil {
		return nil
	}
	if e.operation == nil {
		sp := e.getAPISubPath()
		fmt.Printf("%s", sp)
		pathSplits := strings.Split(e.getAPISubPath(), "/")
		// prepend method for search
		pathSplits = append([]string{e.request.Attributes.Request.Http.Method}, pathSplits...)

		if result := e.OpPathTree.Find(pathSplits, 0); result != nil {
			e.operation = result.(*APIOperation)
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
			e.verifyJWTRequirement(claim.Requirement)
			r = e.jwtResults[claim.Requirement]
		}
		if r != nil && r.claims != nil && r.claims[claim.Name] != nil {
			return r.claims[claim.Name].(string)
		}
	}
	return ""
}

func (e *EnvironmentSpecRequest) verifyJWTRequirement(requirementName string) bool {
	if e == nil {
		return false
	}
	jwtReq := e.jwtRequirements[requirementName]
	if jwtReq == nil {
		return false
	}
	if result := e.jwtResults[requirementName]; result != nil && result.err != nil {
		return false
	}

	// uncached, parse it
	setResult := func(claims map[string]interface{}, err error) {
		e.jwtResults[requirementName] = &jwtResult{
			claims: claims,
			err:    err,
		}
	}

	for _, p := range jwtReq.In {
		jwksSource, ok := jwtReq.JWKSSource.(RemoteJWKS) // only Remote supported for now
		if !ok {
			setResult(nil, fmt.Errorf("JWKSSource must be RemoteJWKS, got: %#v", jwtReq.JWKSSource))
		}
		jwtString := e.GetParamValue(p)
		provider := jwt.Provider{JWKSURL: jwksSource.URL}
		claims, err := e.verifier.Parse(jwtString, provider)
		setResult(claims, err)
		if err != nil {
			return false
		}
	}
	return true
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

func (e *EnvironmentSpecRequest) meetsAuthenticatationRequirements(auth AuthenticationRequirement) bool {
	if e == nil || auth.Requirements == nil {
		return false
	}
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return e.verifyJWTRequirement(a.Name)
	case AnyAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if e.meetsAuthenticatationRequirements(r) {
				return true
			}
		}
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !e.meetsAuthenticatationRequirements(r) {
				return false
			}
		}
	}
	return true
}

// GetAPIKey uses ConsumerAuthorization of Operation or APISpec as appropriate
// TODO: should this error if IsAuthenticated == false?
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
