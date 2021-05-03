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
	"net/url"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func (e *EnvironmentSpecExt) NewEnvironmentSpecRequest(req *authv3.CheckRequest) *EnvironmentSpecRequest {
	return &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		request:            req,
	}
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	jwtRequirements map[string]*JWTAuthentication // JWTAuthentication.Name ->
	request         *authv3.CheckRequest
	jwtResults      map[string]*jwtResult // JWTAuthentication.Name ->
	verifier        jwt.Verifier
	apiSpec         *APISpec
	operation       *APIOperation
}

type jwtClaims map[string]interface{}

type jwtResult struct {
	claims jwtClaims
	err    error
}

// GetAPI uses the base path to return an APISpec
func (e *EnvironmentSpecRequest) GetAPISpec() *APISpec {
	if e.apiSpec == nil {
		splitPath := strings.SplitN(e.request.Attributes.Request.Http.Path, "?", 2)
		path := strings.Split(splitPath[0], "/") // todo: special case / ?

		if result := e.ApiPathTree.Find(path, 0); result != nil {
			e.apiSpec = result.(*APISpec)
		}
	}
	return e.apiSpec
}

// GetOperation uses HttpMatch to return an APIOperation
func (e *EnvironmentSpecRequest) GetOperation() *APIOperation {
	if e.operation == nil {
		if api := e.GetAPISpec(); api != nil {
			subPath := strings.TrimPrefix(e.request.Attributes.Request.Http.Path, api.BasePath) // strip basepath
			splitPath := strings.SplitN(subPath, "?", 2)
			path := strings.Split(splitPath[0], "/") // todo: special case / ?
			path = append([]string{e.request.Attributes.Request.Http.Method}, path...)

			if result := e.OpPathTree.Find(path, 0); result != nil {
				e.operation = result.(*APIOperation)
			}
		}
	}
	return e.operation
}

// GetParamValue extracts a value from request using Match
func (e *EnvironmentSpecRequest) GetParamValue(param APIOperationParameter) string {
	var value string
	switch m := param.Match.(type) {
	case Header:
		value = e.request.Attributes.Request.Http.Headers[string(m)]
	case Query:
		if u, err := url.ParseRequestURI(e.request.Attributes.Request.Http.Path); err != nil {
			value = u.Query().Get(string(m))
		}
	case JWTClaim:
		value = e.getClaimValue(m)
	}
	return param.Transformation.Transform(value)
}

func (e *EnvironmentSpecRequest) getClaimValue(claim JWTClaim) string {
	r, ok := e.jwtResults[claim.Requirement]
	if !ok {
		e.verifyJWTRequirement(claim.Requirement)
		r = e.jwtResults[claim.Requirement]
	}
	return r.claims[claim.Name].(string)
}

func (e *EnvironmentSpecRequest) verifyJWTRequirement(requirementName string) bool {
	jwtReq, ok := e.jwtRequirements[requirementName]
	if !ok {
		return false
	}
	if result, ok := e.jwtResults[requirementName]; ok {
		return result.err == nil
	}

	// uncached, parse it
	for _, p := range jwtReq.In {
		jwtString := e.GetParamValue(p)
		url := jwtReq.JWKSSource.(RemoteJWKS).URL // only remote supported for now
		provider := jwt.Provider{JWKSURL: url}
		claims, err := e.verifier.Parse(jwtString, provider)
		result := &jwtResult{
			claims: claims,
			err:    err,
		}
		e.jwtResults[requirementName] = result
		if result.err != nil {
			return true
		}
	}
	return false
}

// HasAuthentication returns true if AuthenticatationRequirements are met for the request
func (e *EnvironmentSpecRequest) HasAuthentication() bool {
	if !e.GetOperation().Authentication.IsEmpty() {
		return e.meetsAuthenticatationRequirements(e.GetOperation().Authentication)
	} else {
		return e.meetsAuthenticatationRequirements(e.GetAPISpec().Authentication)
	}
}

func (e *EnvironmentSpecRequest) meetsAuthenticatationRequirements(auth AuthenticationRequirement) bool {
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
func (req *EnvironmentSpecRequest) GetAPIKey() (key string) {
	getAPIKey := func(auth ConsumerAuthorization) string {
		for _, authorization := range auth.In {
			if key = req.GetParamValue(authorization); key != "" {
				return key
			}
		}
		return ""
	}
	if !req.GetOperation().ConsumerAuthorization.isEmpty() {
		return getAPIKey(req.GetOperation().ConsumerAuthorization)
	} else {
		return getAPIKey(req.GetAPISpec().ConsumerAuthorization)
	}
}
