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

// Package arcconfig defines the API Runtime Control config and provides
// the config loading and validation functions.
package arcconfig

import "time"

// EnvironmentConfig is an Apigee Environment-level config for
// Envoy Adapter. It contains a list of operations for the adapter to
// perform request authentication and authorization.
type EnvironmentConfig struct {
	// Unique ID of the environment config
	ID string `yaml:"id" json:"id"`

	// A list of proxy configs
	ProxyConfigs []ProxyConfig
}

// ProxyConfig has the proxy configuration
type ProxyConfig struct {
	// Top-level basepath for the proxy config
	Basepath string `yaml:"basepath,omitempty" json:"basepath,omitempty"`

	// A list of Operations, names of which must be unique within the proxy config.
	Operations []Operation `yaml:"operations,omitempty" json:"operations,omitempty"`
}

// An API Operation associates a set of rules with a set of request matching
// settings.
type Operation struct {
	// Name of the operation. Unique within a APIRuntimeControlConfig.
	Name string `yaml:"name" json:"name"`

	// Authentication defines the AuthenticationRequirement
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// ConsumerAuthorization defines the ConsumerAuthorization
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" json:"consumer_authorization,omitempty"`

	// HTTP matching rules for this operation.
	HTTPMatches []HTTPMatch `yaml:"http_match,omitempty" json:"http_match,omitempty"`

	// Name of the target server for this operation. This will be sent to Envoy
	// for routing to the corresponding upstream cluster upon a successful
	// authorization of the operation.
	Target string `yaml:"target" json:"target"`
}

// AuthenticationRequirement defines the authentication requirement.
// Precisely one of JWT, Any and All should be set.
type AuthenticationRequirement struct {
	// JWT defines the JWTAuthentication
	JWT JWTAuthentication `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// Any contains a list of AuthenticationRequirements.
	// A successful authentication requires one of them being satisfied.
	Any []AuthenticationRequirement `yaml:"any,omitempty" json:"any,omitempty"`

	// All contains a list of AuthenticationRequirements.
	// A successful authentication requires all of them being satisfied.
	All []AuthenticationRequirement `yaml:"all,omitempty" json:"all,omitempty"`
}

// JWTAuthentication defines the JWT authentication
type JWTAuthentication struct {
	// Name of this JWT Provider, unique within the Proxy.
	Name string `yaml:"name" json:"name"`

	// JWT issuer ("iss" claim)
	Issuer string `yaml:"issuer" json:"issuer"`

	// A remote JWKS source
	RemoteJWKS RemoteJWKS `yaml:"remote_jwks" json:"remote_jwks"`

	// Audiences contains a list of audiences
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`

	// Header name that will contain decoded JWT payload in requests forwarded to
	// target.
	ForwardPayloadHeader string `yaml:"forward_payload_header,omitempty" json:"forward_payload_header,omitempty"`

	// Locations where JWT may be found. First match wins.
	In []HTTPParameter `yaml:"in" json:"in"`
}

// RemoteJWKS contains information for remote JWKS
type RemoteJWKS struct {
	// URL of the JWKS
	URL string `yaml:"url" json:"url"`

	// CacheDuration of the JWKS
	CacheDuration time.Duration `yaml:"cache_duration,omitempty" json:"cache_duration,omitempty"`
}

// ConsumerAuthorization is the configuration of API consumer authorization
type ConsumerAuthorization struct {
	FailOpen bool `yaml:"fail_open,omitempty" json:"fail_open,omitempty"`

	// Locations of API consumer credential (API Key). First match wins.
	In []HTTPParameter `yaml:"in" json:"in"`
}

// HTTPMatch is an HTTP request matching rule
type HTTPMatch struct {
	// URL path template using to match incoming requests and optionally identify
	// path variables.
	PathTemplate string `yaml:"path_template" json:"path_template"`

	// HTTP method (e.g. GET, POST, PUT, etc.)
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
}

// HTTPParameter defines an HTTP paramter
// Precisely one of Query, Header or JWTClaim should be set.
type HTTPParameter struct {
	// Name of a query paramter
	Query string `yaml:"query,omitempty" json:"query,omitempty"`

	// Name of a header
	Header string `yaml:"header,omitempty" json:"header,omitempty"`

	// A JWTClaim
	JWTClaim JWTClaim `yaml:"jwt_claim,omitempty" json:"jwt_claim,omitempty"`

	// Prefix to strip off matched value (e.g. "Bearer " for Authorization
	// tokens).
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// JWTClaim is reference to a JWT claim.
type JWTClaim struct {
	// Name of the JWT provider
	Provider string `yaml:"provider" json:"provider"`

	// Name of the claim
	Name string `yaml:"name" json:"name"`
}
