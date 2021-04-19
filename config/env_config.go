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
	"time"

	"gopkg.in/yaml.v3"
)

// EnvironmentConfigs contains directly inlined Environment configs and references to Environment configs.
type EnvironmentConfigs struct {
	// A list of URIs referencing Environment configurations. Supported schemes:
	// - `file`: An RFC 8089 file path where the configuration is stored on the local file system, e.g. `file://path/to/config.yaml`.
	References []string `yaml:"references,omitempty" json:"references,omitempty"`

	// A list of environment configs.
	Inline []EnvironmentConfig `yaml:"inline,omitempty" json:"inline,omitempty"`
}

// EnvironmentConfig contains a snapshot of the set of API configurations associated with an Apigee Environment.
type EnvironmentConfig struct {
	// Unique ID of the environment config
	ID string `yaml:"id" json:"id"`

	// A list of API configs.
	APIs []APIConfig `yaml:"apis" json:"apis"`
}

// APIConfig contains authentication, authorization, and transformation settings for a group of API Operations.
type APIConfig struct {
	// ID of the API, used to match the api_source of API Product Operations.
	ID string `yaml:"id" json:"id"`

	// Base path for this API.
	BasePath string `yaml:"base_path,omitempty" json:"base_path,omitempty"`

	// The default authentication requirements for this API.
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// The default consumer authorization requirements for this API.
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" json:"consumer_authorization,omitempty"`

	// Transformation rules applied to HTTP requests.
	HTTPRequestTransforms HTTPRequestTransformations `yaml:"http_request_transforms,omitempty" json:"http_request_transforms,omitempty"`

	// A list of API Operations, names of which must be unique within the API.
	Operations []APIOperation `yaml:"operations" json:"operations"`
}

// An APIOperation associates a set of rules with a set of request matching settings.
type APIOperation struct {
	// Name of the API Operation. Unique within a API.
	Name string `yaml:"name" json:"name"`

	// The authentication requirements for thie Operation. If specified, this overrides the default AuthenticationRequirement specified at the API level.
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// The consumer authorization requirement for this Operation. If specified, this overrides the default ConsumerAuthorization specified at the API level.
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" json:"consumer_authorization,omitempty"`

	// HTTP matching rules for this Operation. If omitted, this API Operation will match all HTTP requests not matched by another API Operation.
	HTTPMatches []HTTPMatch `yaml:"http_match,omitempty" json:"http_match,omitempty"`

	// Transformation rules applied to HTTP requests for this Operation. Overrides the rules set at the API level.
	HTTPRequestTransforms HTTPRequestTransformations `yaml:"http_request_transforms,omitempty" json:"http_request_transforms,omitempty"`
}

// HTTPRequestTransformations are rules for modifying HTTP requests.
type HTTPRequestTransformations struct {
	// Header values to append. If a specified header is already present in the request, an additional value is added.
	AppendHeaders map[string]string `yaml:"append_headers,omitempty" json:"append_headers,omitempty"`

	// Header values to set. If a specified header is already present, the value here will overwrite it.
	SetHeaders map[string]string `yaml:"set_headers,omitempty" json:"set_headers,omitempty"`

	// Headers to remove. Supports single wildcard globbing e.g. `x-apigee-*`.
	RemoveHeaders []string `yaml:"remove_headers,omitempty" json:"remove_headers,omitempty"`
}

// AuthenticationRequirement defines the authentication requirement. It can be jwt, any or all.
type AuthenticationRequirement struct {
	AuthenticationRequirements AuthenticationRequirements `yaml:"-" json:"-"`
}

type authenticationRequirementsWrapper struct {
	JWT *JWTAuthentication             `yaml:"jwt,omitempty" json:"jwt,omitempty"`
	Any *AnyAuthenticationRequirements `yaml:"any,omitempty" json:"any,omitempty"`
	All *AllAuthenticationRequirements `yaml:"all,omitempty" json:"all,omitempty"`
}

// UnmarshalYAML implements the custom unmarshal method for
// AuthenticationRequirement with input yaml bytes
func (a *AuthenticationRequirement) UnmarshalYAML(node *yaml.Node) error {
	w := &authenticationRequirementsWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}

	ctr := 0
	if w.JWT != nil {
		a.AuthenticationRequirements = *w.JWT
		ctr += 1
	}
	if w.Any != nil {
		a.AuthenticationRequirements = *w.Any
		ctr += 1
	}
	if w.All != nil {
		a.AuthenticationRequirements = *w.All
		ctr += 1
	}
	if ctr != 1 {
		return fmt.Errorf("precisely one of jwt, any or all should be set")
	}

	return nil
}

// AuthenticationRequirement is the interface defining the authentication requirement.
type AuthenticationRequirements interface {
	authenticationRequirements()
}

// AnyAuthenticationRequirements requires any of enclosed requirements to be satisfied for a successful authentication.
type AnyAuthenticationRequirements []AuthenticationRequirement

func (AnyAuthenticationRequirements) authenticationRequirements() {}

// AllAuthenticationRequirements requires all of enclosed requirements to be satisfied for a successful authentication.
type AllAuthenticationRequirements []AuthenticationRequirement

func (AllAuthenticationRequirements) authenticationRequirements() {}

// JWTAuthentication defines a JWT authentication requirement.
type JWTAuthentication struct {
	// Name of this JWT requirement, unique within the API.
	Name string `yaml:"name" json:"name"`

	// JWT issuer ("iss" claim)
	Issuer string `yaml:"issuer" json:"issuer"`

	// The JWKS source.
	JWKSSource JWKSSource `yaml:"-" json:"-"`

	// Audiences contains a list of audiences.
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`

	// Header name that will contain decoded JWT payload in requests forwarded to
	// target.
	ForwardPayloadHeader string `yaml:"forward_payload_header,omitempty" json:"forward_payload_header,omitempty"`

	// Locations where JWT may be found. First match wins.
	In []APIOperationParameter `yaml:"in" json:"in"`
}

func (JWTAuthentication) authenticationRequirements() {}

type jwksSourceWrapper struct {
	RemoteJWKS *RemoteJWKS `yaml:"remote_jwks,omitempty" json:"remote_jwks,omitempty"`
}

// UnmarshalYAML implements the custom unmarshal method for
// JWTAuthentication with yaml bytes
func (j *JWTAuthentication) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh JWTAuthentication
	if err := node.Decode((*Unmarsh)(j)); err != nil {
		return err
	}

	w := &jwksSourceWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}

	if w.RemoteJWKS == nil {
		return fmt.Errorf("remote jwks not found")
	}
	j.JWKSSource = *w.RemoteJWKS

	return nil
}

// JWKSSource is the JWKS source.
type JWKSSource interface {
	jwksSource()
}

// RemoteJWKS contains information for remote JWKS.
type RemoteJWKS struct {
	// URL of the JWKS.
	URL string `yaml:"url" json:"url"`

	// CacheDuration of the JWKS.
	CacheDuration time.Duration `yaml:"cache_duration,omitempty" json:"cache_duration,omitempty"`
}

func (RemoteJWKS) jwksSource() {}

// ConsumerAuthorization is the configuration of API consumer authorization.
type ConsumerAuthorization struct {
	// Allow requests to be forwarded even if the consumer credential cannot be
	// verified by the API Key provider due to service unavailability.
	FailOpen bool `yaml:"fail_open,omitempty" json:"fail_open,omitempty"`

	// Locations of API consumer credential (API Key). First match wins.
	In []APIOperationParameter `yaml:"in" json:"in"`
}

// HTTPMatch is an HTTP request matching rule.
type HTTPMatch struct {
	// URL path template using to match incoming requests and optionally identify
	// path variables.
	PathTemplate string `yaml:"path_template" json:"path_template"`

	// HTTP method (e.g. GET, POST, PUT, etc.)
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
}

// APIOperationParameter describes an input value to an API Operation.
type APIOperationParameter struct {
	// One of Query, Header, or JWTClaim.
	Match ParamMatch `yaml:"-" json:"-"`

	// Optional transformation of the parameter value (e.g. "Bearer " for Authorization tokens).
	Transformation StringTransformation `yaml:"transformation,omitempty" json:"transformation,omitempty"`
}

type apiOperationParameterWrapper struct {
	Header   *Header   `yaml:"header,omitempty" json:"header,omitempty"`
	Query    *Query    `yaml:"query,omitempty" json:"query,omitempty"`
	JWTClaim *JWTClaim `yaml:"jwt_claim,omitempty" json:"jwt_claim,omitempty"`
}

// UnmarshalYAML implements the custom unmarshal method
// for HTTPParamter with input yaml bytes
func (p *APIOperationParameter) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh APIOperationParameter
	if err := node.Decode((*Unmarsh)(p)); err != nil {
		return err
	}

	w := &apiOperationParameterWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}
	ctr := 0
	if w.Header != nil {
		ctr += 1
		p.Match = *w.Header
	}
	if w.Query != nil {
		ctr += 1
		p.Match = *w.Query
	}
	if w.JWTClaim != nil {
		ctr += 1
		p.Match = *w.JWTClaim
	}
	if ctr != 1 {
		return fmt.Errorf("precisely one header, query or jwt_claim should be set")
	}

	return nil
}

func (p *APIOperationParameter) MarshalYAML() (interface{}, error) {
	type Marsh APIOperationParameter
	out, err := yaml.Marshal((*Marsh)(p))
	if err != nil {
		return nil, err
	}
	w := &apiOperationParameterWrapper{}
	switch p.Match.(type) {
	case Header:
		w.Header = p.Match.(*Header)
	case Query:
		w.Query = p.Match.(*Query)
	case JWTClaim:
		w.JWTClaim = p.Match.(*JWTClaim)
	default:
		return nil, fmt.Errorf("unknown match type")
	}
	b, err := yaml.Marshal(w)
	if err != nil {
		return nil, err
	}

	return append(out, b...), nil
}

// ParamMatch tells the location of the HTTP paramter.
type ParamMatch interface {
	paramMatch()
}

// Name of an HTTP query string parameter.
type Query string

func (Query) paramMatch() {}

// Name of an HTTP header.
type Header string

func (Header) paramMatch() {}

// JWTClaim is reference to a JWT claim.
type JWTClaim struct {
	// Name of the JWT requirement.
	Requirement string `yaml:"requirement" json:"requirement"`

	// Name of the claim.
	Name string `yaml:"name" json:"name"`
}

func (JWTClaim) paramMatch() {}

// StringTransformation uses simple template syntax.
// e.g. template: "prefix-{foo}-{bar}-suffix"
//      substitution: "{foo}_{bar}"
//      -->
//      input: "prefix-hello-world-suffix"
//      output: "hello_world"
type StringTransformation struct {
	// String template, optionally containing variable declarations.
	Template string `yaml:"template,omitempty" json:"template,omitempty"`

	// Substitution string, optionally using variables declared in the template.
	Substitution string `yaml:"substitution,omitempty" json:"substitution,omitempty"`
}
