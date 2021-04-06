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

// Package arcconfig defines the Apigee Runtime Control config and provides
// the config loading and validation functions.
package arcconfig

import "time"

// ApigeeRuntimeControlConfig is an Apigee Environment-level config for
// Envoy Adapter. It contains a list of operations for the adapter to
// perform request authentication and authorization.
type ApigeeRuntimeControlConfig struct {
	// Name of the config
	Name string `yaml:"name"`

	// Revision of the config
	Revision string `yaml:"revision"`

	// A list of Operations, names of which must be unique within the config.
	Operations []*Operation `yaml:"operations,omitempty"`
}

// An API Operation associates a set of rules with a set of request matching
// settings.
type Operation struct {
	// Name of the operation. Unique within a ApigeeRuntimeControlConfig.
	Name string `yaml:"name"`

	// Authentication defines the AuthenticationRequirement
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty"`

	// Authorization defines the ConsumerAuthorization
	Authorization ConsumerAuthorization `yaml:"authorization,omitempty"`

	// HTTP matching rules for this operation.
	// The path templates within which should be fully denormalized.
	HTTPMatches []HTTPMatch `yaml:"http_match,omitempty"`

	// Name of the target server for this operation. This will be sent to Envoy
	// for routing to the corresponding upstream cluster upon a successful
	// authorization of the operation.
	Target string `yaml:"target"`
}

// AuthenticationRequirement defines the authentication requirement.
// Precisely one of JWT, Any and All should be set.
type AuthenticationRequirement struct {
	// JWT defines the JWTAuthentication
	JWT JWTAuthentication `yaml:"jwt,omitempty"`

	// Any contains a list of AuthenticationRequirements.
	// A successful authentication requires one of them being satisfied.
	Any []AuthenticationRequirement `yaml:"any,omitempty"`

	// All contains a list of AuthenticationRequirements.
	// A successful authentication requires all of them being satisfied.
	All []AuthenticationRequirement `yaml:"all,omitempty"`
}

// JWTAuthentication defines the JWT authentication
type JWTAuthentication struct {
	// Name of this JWT Provider, unique within the Proxy.
	Name string `yaml:"name"`

	// JWT issuer ("iss" claim)
	Issuer string `yaml:"issuer"`

	// A remote JWKS source
	RemoteJWKS RemoteJWKS `yaml:"remote_jwks"`

	// Audiences contains a list of audiences
	Audiences []string `yaml:"audiences,omitempty"`

	// Header name that will contain decoded JWT payload in requests forwarded to
	// target.
	ForwardPayloadHeader string `yaml:"forward_payload_header,omitempty"`

	// Locations where JWT may be found. First match wins.
	In []HTTPParameter `yaml:"in"`
}

// RemoteJWKS contains information for remote JWKS
type RemoteJWKS struct {
	// URL of the JWKS
	URL string `yaml:"url"`

	// CacheDuration of the JWKS
	CacheDuration time.Duration `yaml:"cache_duration,omitempty"`
}

// ConsumerAuthorization is the configuration of API consumer authorization
type ConsumerAuthorization struct {
	FailOpen bool `yaml:"fail_open,omitempty"`

	// Locations of API consumer credential (API Key). First match wins.
	In []HTTPParameter `yaml:"in"`

	// Quota identifier (optional)
	QuotaIdentifier string `yaml:"quota_identifier,omitempty"`
}

// HTTPMatch is an HTTP request matching rule
type HTTPMatch struct {
	// URL path template using to match incoming requests and optionally identify
	// path variables. This should be fully denormalized as there is no global
	// basepath defined anywhere.
	PathTemplate string `yaml:"path_template"`

	// HTTP method
	Method HTTPMethod `yaml:"method,omitempty"`
}

// HTTPParameter defines an HTTP paramter
// Precisely one of Query, Header or JWTClaim should be set.
type HTTPParameter struct {
	// Name of a query paramter
	Query string `yaml:"query,omitempty"`

	// Name of a header
	Header string `yaml:"header,omitempty"`

	// A JWTClaim
	JWTClaim JWTClaim `yaml:"jwt_claim,omitempty"`

	// Prefix to strip off matched value (e.g. "Bearer " for Authorization
	// tokens).
	Prefix string `yaml:"prefix,omitempty"`
}

// JWTClaim has reference to a JWT claim.
type JWTClaim struct {
	// Name of the JWT provider
	Provider string `yaml:"provider"`

	// Name of the claim
	Name string `yaml:"name"`
}

type HTTPMethod int

const (
	UnknownMethod HTTPMethod = iota
	HTTPGet
	HTTPPost
	HTTPPut
	HTTPDelete
	HTTPPatch
	HTTPOptions
	HTTPHead
	HTTPConnect
	HTTPTrace
)
