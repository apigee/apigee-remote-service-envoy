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
	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// NewEnvironmentSpecRequest creates a new EnvironmentSpecRequest
func (e *EnvironmentSpecExt) NewEnvironmentSpecRequest(req *envoy.CheckRequest) *EnvironmentSpecRequest {
	return &EnvironmentSpecRequest{
		EnvironmentSpecExt: e,
		request:            req,
	}
}

// EnvironmentSpecRequest extends a request to support operations within an EnvironmentSpec
type EnvironmentSpecRequest struct {
	*EnvironmentSpecExt
	jwtRequirements map[string]*JWTAuthentication // JWTAuthentication.Name ->
	request         *envoy.CheckRequest
	jwtResults      map[string]*jwtResult // JWTAuthentication.Name ->
	verifier        jwt.Verifier
}

type jwtClaims map[string]interface{}

type jwtResult struct {
	claims jwtClaims
	err    error
}

// GetAPI uses the base path to return an APISpec
func (e *EnvironmentSpecRequest) GetAPISpec() *APISpec {
	splitPath := strings.SplitN(e.request.Attributes.Request.Http.Path, "?", 2)
	path := strings.Split(splitPath[0], "/") // todo: special case / ?

	if result := e.ApiPathTree.Find(path, 0); result != nil {
		return result.(*APISpec)
	}
	return nil
}

// GetOperation uses HttpMatch to return an APIOperation
func (e EnvironmentSpecRequest) GetOperation() *APIOperation {
	api := e.GetAPISpec()
	if api != nil {
		subPath := strings.TrimPrefix(api.BasePath, e.request.Attributes.Request.Http.Path) // strip basepath
		splitPath := strings.SplitN(subPath, "?", 2)
		path := strings.Split(splitPath[0], "/") // todo: special case / ?
		path = append([]string{e.request.Attributes.Request.Http.Method}, path...)

		if result := e.OpPathTree.Find(path, 0); result != nil {
			return result.(*APIOperation)
		}
	}

	return nil
}

// GetParamValue extracts a value from request using Match
func (e EnvironmentSpecRequest) GetParamValue(param APIOperationParameter) string {
	switch m := param.Match.(type) {
	case Header:
		return e.request.Attributes.Request.Http.Headers[string(m)]
	case Query:
		if u, err := url.ParseRequestURI(e.request.Attributes.Request.Http.Path); err != nil {
			u.Query().Get(string(m))
		}
	case JWTClaim:
		return e.getClaimValue(m)
	}
	return ""
}

func (e *EnvironmentSpecRequest) getClaimValue(claim JWTClaim) string {
	r, ok := e.jwtResults[claim.Requirement]
	if !ok {
		e.verifyJWTRequirement(claim.Requirement)
		r = e.jwtResults[claim.Requirement]
	}
	return r.claims[claim.Name].(string) // todo: interface{} type?
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
		// todo: templating
		jwtString := e.GetParamValue(p)           // todo: circular?
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

// MeetsAuthenticatationRequirements returns true if AuthenticatationRequirements are met for the request
func (e *EnvironmentSpecRequest) MeetsAuthenticatationRequirements(auth AuthenticationRequirement) bool {
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return e.verifyJWTRequirement(a.Name)
	case AnyAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if e.MeetsAuthenticatationRequirements(r) {
				return true
			}
		}
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !e.MeetsAuthenticatationRequirements(r) {
				return false
			}
		}
	}
	return true
}
