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

// NOTE: This file should be kept free from any additional dependencies,
// especially those that are not commonly used libraries.
import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const anyMethod = ""

// lookup for all HTTP verbs
var allMethods = map[string]interface{}{"GET": nil, "POST": nil, "PUT": nil,
	"PATCH": nil, "DELETE": nil, "HEAD": nil, "OPTIONS": nil, "CONNECT": nil, "TRACE": nil}

// Validate HTTP Request Transforms.
//   * If GrpcService is specified on the API
func validateHttpRequestTransforms(api *APISpec, t HTTPRequestTransforms) error {
	if api.GrpcService == "" {
		return nil
	}

	if len(t.QueryTransforms.Add) > 0 || len(t.QueryTransforms.Remove) > 0 {
		return fmt.Errorf("cannot use HTTP Query transforms with GRPC services.")
	}
	if t.PathTransform != "" {
		return fmt.Errorf("cannot use HTTP Path transform with GRPC services.")
	}
	return nil
}

// ValidateEnvironmentSpecs checks if there are
//   * environment configs with the same ID,
//   * API configs under the same environment config with the same ID,
//   * JWT authentication requirement under the same API or operation with the same name
// and report them as errors.
//   * missing basepaths (unless GrpcService is set, in which case that is allowed)
// jwtAuthentications of each API and Operation will be populated upon successful
func ValidateEnvironmentSpecs(ess []EnvironmentSpec) error {
	configIDSet := make(map[string]bool)
	for i := range ess {
		es := &ess[i]
		if es.ID == "" {
			return fmt.Errorf("environment spec IDs must be non-empty")
		}
		if configIDSet[es.ID] {
			return fmt.Errorf("environment spec IDs must be unique, got multiple %s", es.ID)
		}
		configIDSet[es.ID] = true
		basePathsSet := make(map[string]bool)
		gRPCServiceSet := make(map[string]bool)
		for j := range es.APIs {
			api := &es.APIs[j]
			if api.ID == "" {
				return fmt.Errorf("API spec IDs must be non-empty")
			}
			// if GrpcService is not set, then BasePath must be.
			if api.GrpcService == "" && api.BasePath == "" {
				return fmt.Errorf("API %q does not have a BasePath set. BasePath is required unless GrpcService is specified.", api.ID)
			}
			if api.BasePath != "" {
				if basePathsSet[api.BasePath] {
					return fmt.Errorf("API spec basepaths within each environment spec must be unique, got multiple %s", api.BasePath)
				}
				basePathsSet[api.BasePath] = true
			}
			if api.GrpcService != "" {
				if gRPCServiceSet[api.GrpcService] {
					return fmt.Errorf("API spec grpc_service must be unique within each environment, found multiple APIs for %q", api.GrpcService)
				}
				gRPCServiceSet[api.GrpcService] = true
			}
			if err := validateHttpRequestTransforms(api, api.HTTPRequestTransforms); err != nil {
				return fmt.Errorf("API %q: error validating HttpRequestTransforms: %w", api.ID, err)
			}

			api.jwtAuthentications = make(map[string]*JWTAuthentication)
			if err := validateJWTAuthenticationName(&api.Authentication, api.jwtAuthentications); err != nil {
				return err
			}
			for _, p := range api.ConsumerAuthorization.In {
				if err := validateAPIOperationParameter(&p, api.jwtAuthentications); err != nil {
					return err
				}
			}
			opNameSet := make(map[string]bool)
			for k := range api.Operations {
				op := &api.Operations[k]
				if op.Name == "" {
					return fmt.Errorf("operation names must be non-empty")
				}
				if opNameSet[op.Name] {
					return fmt.Errorf("operation names within each API must be unique, got multiple %s", op.Name)
				}
				opNameSet[op.Name] = true
				op.jwtAuthentications = make(map[string]*JWTAuthentication)
				if err := validateJWTAuthenticationName(&op.Authentication, op.jwtAuthentications); err != nil {
					return err
				}
				if err := validateHttpRequestTransforms(api, op.HTTPRequestTransforms); err != nil {
					return fmt.Errorf("API %q, Operation %q: error validating HttpRequestTransforms: %w", api.ID, op.Name, err)
				}

				for _, p := range op.ConsumerAuthorization.In {
					if err := validateAPIOperationParameter(&p, op.jwtAuthentications, api.jwtAuthentications); err != nil {
						return err
					}
				}
				for _, p := range op.HTTPMatches {
					if p.Method != anyMethod {
						if _, ok := allMethods[p.Method]; !ok {
							return fmt.Errorf("operation %q uses an invalid HTTP method %q", op.Name, p.Method)
						}
					}
				}
			}
		}
	}
	return nil
}

// validateJWTAuthenticationName checks if the JWTAuthentication has non-empty and unique
// name within the given AuthenticationRequirement. It also validates the APIOperationParameter
// of the JWTAuthentication. The passed map will be populated.
func validateJWTAuthenticationName(a *AuthenticationRequirement, m map[string]*JWTAuthentication) error {
	var err error
	switch v := a.Requirements.(type) {
	case JWTAuthentication:
		if v.Name == "" {
			return fmt.Errorf("JWT authentication requirement names must be non-empty")
		}
		if _, ok := m[v.Name]; ok {
			return fmt.Errorf("JWT authentication requirement names within each API or operation must be unique, got multiple %s", v.Name)
		}
		m[v.Name] = &v
		for _, p := range v.In {
			if err := validateAPIOperationParameter(&p); err != nil {
				return err
			}
		}
	case AnyAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			err = validateJWTAuthenticationName(&val, m)
		}
	case AllAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			err = validateJWTAuthenticationName(&val, m)
		}
	}
	return err
}

// validateAPIOperationParameter checks if all headers and queries are non-empty
// and JWT claims have non-empty names.
func validateAPIOperationParameter(p *APIOperationParameter, maps ...map[string]*JWTAuthentication) error {
	switch v := p.Match.(type) {
	case Header:
		if len(string(v)) == 0 {
			return fmt.Errorf("header in API operation parameter match must be non-empty")
		}
	case Query:
		if len(string(v)) == 0 {
			return fmt.Errorf("query in API operation parameter match must be non-empty")
		}
	case JWTClaim:
		if v.Name == "" {
			return fmt.Errorf("JWT claim name in API operation parameter match must be non-empty")
		}
		fail := true
		for _, m := range maps {
			if _, ok := m[v.Requirement]; ok {
				fail = false
				break
			}
		}
		if fail {
			return fmt.Errorf("JWT claim requirement %q does not exist", v.Requirement)
		}
	}
	return nil
}

// EnvironmentSpecs contains directly inlined Environment configs and references to Environment configs.
type EnvironmentSpecs struct {
	// A list of URIs referencing Environment configurations. Supported schemes:
	// - `file`: An RFC 8089 file path where the configuration is stored on the local file system, e.g. `file://path/to/config.yaml`.
	// The URI can refer to a directory, in which case the files directly under it will be read.
	// Note that subdirectories will not be taken into account.
	References []string `yaml:"references,omitempty" mapstructure:"references,omitempty"`

	// A list of environment configs. Not supported yet for inline loading.
	// TODO: Support reading this via viper.Unmarshal()
	Inline []EnvironmentSpec `yaml:"inline,omitempty"`
}

// EnvironmentSpec contains a snapshot of the set of API configurations associated with an Apigee Environment.
type EnvironmentSpec struct {
	// Unique ID of the environment config
	ID string `yaml:"id" mapstructure:"id"`

	// A list of API configs.
	APIs []APISpec `yaml:"apis" mapstructure:"apis"`
}

// APISpec contains authentication, authorization, and transformation settings for a group of API Operations.
type APISpec struct {
	// ID of the API, used to match the api_source of API Product Operations.
	ID string `yaml:"id" mapstructure:"id"`

	// Name of the gRPC service provided by this API. Used to map native gRPC method calls.
	GrpcService string `yaml:"grpc_service,omitempty" mapstructure:"grpc_service,omitempty"`

	// Base path for this API.
	BasePath string `yaml:"base_path,omitempty" mapstructure:"base_path,omitempty"`

	// The default authentication requirements for this API.
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" mapstructure:"authentication,omitempty"`

	// The default consumer authorization requirements for this API.
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" mapstructure:"consumer_authorization,omitempty"`

	// Transformation rules applied to HTTP requests.
	HTTPRequestTransforms HTTPRequestTransforms `yaml:"http_request_transforms,omitempty" mapstructure:"http_request_transforms,omitempty"`

	// A list of API Operations, names of which must be unique within the API.
	Operations []APIOperation `yaml:"operations" mapstructure:"operations"`

	// CORS Policy
	Cors CorsPolicy `yaml:"cors,omitempty" mapstructure:"cors,omitempty"`

	// TargetAuthentication configures how to authenticate the request to the backend.
	// Can be overridden at the operation level.
	TargetAuthentication TargetAuthentication `yaml:"target_authentication,omitempty" mapstructure:"target_authentication,omitempty"`

	// JWTAuthentication.Name -> *JWTAuthentication
	jwtAuthentications map[string]*JWTAuthentication `yaml:"-" mapstructure:"-"`
}

// An APIOperation associates a set of rules with a set of request matching settings.
type APIOperation struct {
	// Name of the API Operation. Unique within a API.
	Name string `yaml:"name" mapstructure:"name"`

	// The authentication requirements for thie Operation. If specified, this overrides the default AuthenticationRequirement specified at the API level.
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" mapstructure:"authentication,omitempty"`

	// The consumer authorization requirement for this Operation. If specified, this overrides the default ConsumerAuthorization specified at the API level.
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" mapstructure:"consumer_authorization,omitempty"`

	// HTTP matching rules for this Operation. If omitted, this API Operation will match all HTTP requests not matched by another API Operation.
	HTTPMatches []HTTPMatch `yaml:"http_match,omitempty" mapstructure:"http_match,omitempty"`

	// Transformation rules applied to HTTP requests for this Operation. Overrides the rules set at the API level.
	HTTPRequestTransforms HTTPRequestTransforms `yaml:"http_request_transforms,omitempty" mapstructure:"http_request_transforms,omitempty"`

	// TargetAuthentication configures how to authenticate the request to the backend.
	// Overrides the API (proxy) level settings.
	TargetAuthentication TargetAuthentication `yaml:"target_authentication,omitempty" mapstructure:"target_authentication,omitempty"`

	// JWTAuthentication.Name -> *JWTAuthentication
	jwtAuthentications map[string]*JWTAuthentication `yaml:"-" mapstructure:"-"`
}

// HTTPRequestTransforms are rules for modifying HTTP requests.
type HTTPRequestTransforms struct {
	// Header transformations
	HeaderTransforms NameValueTransforms `yaml:"headers,omitempty" mapstructure:"headers,omitempty"`

	// QueryParam transformations
	QueryTransforms NameValueTransforms `yaml:"query,omitempty" mapstructure:"headers,omitempty"`

	// PathTransform will rewrite the request path per the provided specification including
	// constant values and replacement variable names from the path_template, headers, or
	// query parameters, surrounded by {}. For example:
	// set_path: "/constant/{path.wildcard}/{header.name}/{query.name}"
	// If a query string is included, it will replace any query parameters on the request.
	// If a query string is not included, the query parameters on the request are retained.
	PathTransform string `yaml:"path,omitempty" mapstructure:"path,omitempty"`
}

type NameValueTransforms struct {
	Add    []AddNameValue `yaml:"add,omitempty" mapstructure:"add,omitempty"`
	Remove []string       `yaml:"remove,omitempty" mapstructure:"remove,omitempty"`
}

type AddNameValue struct {
	// Name is the name.
	Name string
	// Value is the value.
	Value string
	// Append is true to append a value to name, false to replace all values at name
	Append bool
}

// AuthenticationRequirement defines the authentication requirement. It can be jwt, any or all.
type AuthenticationRequirement struct {
	// If Disabled is true, do not process AuthenticationRequirements.
	Disabled bool `yaml:"disabled,omitempty" mapstructure:"disabled,omitempty"`

	Requirements AuthenticationRequirements `yaml:"-"`
}

type authenticationRequirementWrapper struct {
	Disabled bool                           `yaml:"disabled,omitempty" mapstructure:"disabled,omitempty"`
	JWT      *JWTAuthentication             `yaml:"jwt,omitempty" mapstructure:"jwt,omitempty"`
	Any      *AnyAuthenticationRequirements `yaml:"any,omitempty" mapstructure:"any,omitempty"`
	All      *AllAuthenticationRequirements `yaml:"all,omitempty" mapstructure:"all,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (a *AuthenticationRequirement) UnmarshalYAML(node *yaml.Node) error {
	w := &authenticationRequirementWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}
	a.Disabled = w.Disabled

	ctr := 0
	if w.JWT != nil {
		a.Requirements = *w.JWT
		ctr++
	}
	if w.Any != nil {
		a.Requirements = *w.Any
		ctr++
	}
	if w.All != nil {
		a.Requirements = *w.All
		ctr++
	}
	if !w.Disabled && ctr != 1 {
		return fmt.Errorf("precisely one of jwt, any or all should be set")
	}

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (a AuthenticationRequirement) MarshalYAML() (interface{}, error) {
	w := authenticationRequirementWrapper{
		Disabled: a.Disabled,
	}

	switch v := a.Requirements.(type) {
	case JWTAuthentication:
		w.JWT = &v
	case AnyAuthenticationRequirements:
		w.Any = &v
	case AllAuthenticationRequirements:
		w.All = &v
	}

	return w, nil
}

// AuthenticationRequirements is the interface defining the authentication requirement.
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
	Name string `yaml:"name" mapstructure:"name"`

	// JWT issuer ("iss" claim)
	Issuer string `yaml:"issuer" mapstructure:"issuer"`

	// The JWKS source.
	JWKSSource JWKSSource `yaml:"-"`

	// Audiences contains a list of audiences allowed to access.
	// A JWT containing any of these audiences will be accepted.
	// If not specified, the audiences in JWT will not be checked.
	Audiences []string `yaml:"audiences,omitempty" mapstructure:"audiences,omitempty"`

	// Header name that will contain decoded JWT payload in requests forwarded to
	// target.
	ForwardPayloadHeader string `yaml:"forward_payload_header,omitempty" mapstructure:"forward_payload_header,omitempty"`

	// Locations where JWT may be found. First match wins.
	In []APIOperationParameter `yaml:"in" mapstructure:"in"`
}

func (JWTAuthentication) authenticationRequirements() {}

type jwtAuthenticationWrapper struct {
	Name                 string                  `yaml:"name" mapstructure:"name"`
	Issuer               string                  `yaml:"issuer" mapstructure:"issuer"`
	RemoteJWKS           *RemoteJWKS             `yaml:"remote_jwks,omitempty" mapstructure:"remote_jwks,omitempty"`
	Audiences            []string                `yaml:"audiences,omitempty" mapstructure:"audiences,omitempty"`
	ForwardPayloadHeader string                  `yaml:"forward_payload_header,omitempty" mapstructure:"forward_payload_header,omitempty"`
	In                   []APIOperationParameter `yaml:"in" mapstructure:"in"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (j *JWTAuthentication) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh JWTAuthentication
	if err := node.Decode((*Unmarsh)(j)); err != nil {
		return err
	}

	w := &jwtAuthenticationWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}

	if w.RemoteJWKS == nil {
		return fmt.Errorf("remote jwks not found")
	}
	j.JWKSSource = *w.RemoteJWKS

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (j JWTAuthentication) MarshalYAML() (interface{}, error) {
	w := jwtAuthenticationWrapper{
		Name:                 j.Name,
		Issuer:               j.Issuer,
		Audiences:            j.Audiences,
		ForwardPayloadHeader: j.ForwardPayloadHeader,
		In:                   j.In,
	}

	switch v := j.JWKSSource.(type) {
	case RemoteJWKS:
		w.RemoteJWKS = &v
	default:
		return nil, fmt.Errorf("unsupported jwks source")
	}

	return w, nil
}

// JWKSSource is the JWKS source.
type JWKSSource interface {
	jwksSource()
}

// RemoteJWKS contains information for remote JWKS.
type RemoteJWKS struct {
	// URL of the JWKS.
	URL string `yaml:"url" mapstructure:"url"`

	// CacheDuration of the JWKS.
	CacheDuration time.Duration `yaml:"cache_duration,omitempty" mapstructure:"cache_duration,omitempty"`
}

func (RemoteJWKS) jwksSource() {}

// ConsumerAuthorization is the configuration of API consumer authorization.
type ConsumerAuthorization struct {
	// If Disabled is true, do not process ConsumerAuthorization requirements.
	Disabled bool `yaml:"disabled,omitempty" mapstructure:"disabled,omitempty"`

	// Allow requests to be forwarded even if the consumer credential cannot be
	// verified by the API Key provider due to service unavailability.
	FailOpen bool `yaml:"fail_open,omitempty" mapstructure:"fail_open,omitempty"`

	// Locations of API consumer credential (API Key). First match wins.
	In []APIOperationParameter `yaml:"in" mapstructure:"in"`
}

// HTTPMatch is an HTTP request matching rule.
type HTTPMatch struct {
	// URL path template using to match incoming requests and optionally identify
	// path variables. Wildcard ("*") and double wildcard ("**") path variables can
	// be anywhere in the path (but not in partial segments). A single named wildcard
	// is declared as either {name} alone or {name=*}, a double named wildcard is declared
	// as {name=**}. For example:
	// `path_template: /v1/{single-segment=*}/{multi-segment=**}`
	// Once defined, these variables may be used to populate transformations.
	PathTemplate string `yaml:"path_template" mapstructure:"path_template"`

	// HTTP method
	// Discrete values: "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"
	// "" matches any request method
	Method string `yaml:"method,omitempty" mapstructure:"method,omitempty"`
}

// APIOperationParameter describes an input value to an API Operation.
type APIOperationParameter struct {
	// One of Query, Header, or JWTClaim.
	Match ParamMatch `yaml:"-"`

	// Optional transformation of the parameter value (e.g. "Bearer " for Authorization tokens).
	Transformation StringTransformation `yaml:"transformation,omitempty" mapstructure:"transformation,omitempty"`
}

type apiOperationParameterWrapper struct {
	Header         *Header              `yaml:"header,omitempty" mapstructure:"header,omitempty"`
	Query          *Query               `yaml:"query,omitempty" mapstructure:"query,omitempty"`
	JWTClaim       *JWTClaim            `yaml:"jwt_claim,omitempty" mapstructure:"jwt_claim,omitempty"`
	Transformation StringTransformation `yaml:"transformation,omitempty" mapstructure:"transformation,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
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
		ctr++
		p.Match = *w.Header
	}
	if w.Query != nil {
		ctr++
		p.Match = *w.Query
	}
	if w.JWTClaim != nil {
		ctr++
		p.Match = *w.JWTClaim
	}
	if ctr != 1 {
		return fmt.Errorf("precisely one header, query or jwt_claim should be set, got %d", ctr)
	}

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (p APIOperationParameter) MarshalYAML() (interface{}, error) {
	w := apiOperationParameterWrapper{}

	switch v := p.Match.(type) {
	case Header:
		w.Header = &v
	case Query:
		w.Query = &v
	case JWTClaim:
		w.JWTClaim = &v
	default:
		return nil, fmt.Errorf("unsupported match type")
	}

	w.Transformation = p.Transformation
	return w, nil
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
	Requirement string `yaml:"requirement" mapstructure:"requirement"`

	// Name of the claim.
	Name string `yaml:"name" mapstructure:"name"`
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
	Template string `yaml:"template,omitempty" mapstructure:"template,omitempty"`

	// Substitution string, optionally using variables declared in the template.
	Substitution string `yaml:"substitution,omitempty" mapstructure:"substitution,omitempty"`
}

// CorsPolicy defines CORS behavior and headers.
type CorsPolicy struct {
	// Specifies the list of origins that will be allowed to do CORS requests. An
	// origin is allowed if it exactly matches any value in the list.
	// This translates to the `Access-Control-Allow-Origin` header.
	// If AllowOrigins includes "*", it will be sent as a last resort.
	AllowOrigins []string `yaml:"allow_origins,omitempty" mapstructure:"allow_origins,omitempty"`

	// Specifies the regular expression patterns that match allowed origins. For
	// regular expression grammar please see github.com/google/re2/wiki/Syntax. An
	// origin is allowed if it matches any pattern in the list.
	// This translates to the `Access-Control-Allow-Origin` header.
	AllowOriginsRegexes []string `yaml:"allow_origins_regexes,omitempty" mapstructure:"allow_origins_regexes,omitempty"`

	// Specifies the content for the `Access-Control-Allow-Headers` header.
	AllowHeaders []string `yaml:"allow_headers,omitempty" mapstructure:"allow_headers,omitempty"`

	// Specifies the content for the `Access-Control-Allow-Methods` header.
	AllowMethods []string `yaml:"allow_methods,omitempty" mapstructure:"allow_methods,omitempty"`

	// Specifies the content for the `Access-Control-Expose-Headers` header.
	ExposeHeaders []string `yaml:"expose_headers,omitempty" mapstructure:"expose_headers,omitempty"`

	// Specifies how long results of a preflight request can be cached in seconds.
	// This translates to the `Access-Control-Max-Age` header.
	MaxAge int `yaml:"max_age,omitempty" mapstructure:"max_age,omitempty"`

	// In response to a preflight request, setting this to true indicates that the
	// actual request can include user credentials. This translates to the
	// `Access-Control-Allow-Credentials` header.
	// If Access-Control-Allow-Origin header is set to "*", this is forced to false.
	AllowCredentials bool `yaml:"allow_credentials,omitempty" mapstructure:"allow_credentials,omitempty"`
}

// IsEmpty returns true if there is no valid CORS policy to apply.
func (c CorsPolicy) IsEmpty() bool {
	return len(c.AllowOrigins) == 0 && len(c.AllowOriginsRegexes) == 0
}

// TargetAuthentication configures how to authenticate the request to the backend.
type TargetAuthentication struct {
	// The time between two adjacent token refreshments.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" mapstructure:"refresh_interval,omitempty"`

	// OAuthProvider contains information for getting the OAuth tokens.
	// Currently supports GoogleOAuth.
	OAuthProvider OAuthProvider `yaml:"-" mapstructure:"-"`
}

type targetAuthenticationWrapper struct {
	// The time between two adjacent token refreshments.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" mapstructure:"refresh_interval,omitempty"`

	// GoogleOAuth configures how to authenticate the request to the backend with Google OAuth tokens.
	GoogleOAuth *GoogleOAuth `yaml:"google_oauth,omitempty" mapstructure:"google_oauth,omitempty"`
}

func (t *TargetAuthentication) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh TargetAuthentication
	if err := node.Decode((*Unmarsh)(t)); err != nil {
		return err
	}

	w := &targetAuthenticationWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}
	if w.GoogleOAuth != nil {
		t.OAuthProvider = *w.GoogleOAuth
	}

	return nil
}

func (t TargetAuthentication) MarshalYAML() (interface{}, error) {
	w := &targetAuthenticationWrapper{
		RefreshInterval: t.RefreshInterval,
	}

	switch v := t.OAuthProvider.(type) {
	case GoogleOAuth:
		w.GoogleOAuth = &v
	}

	return w, nil
}

type OAuthProvider interface {
	oauthProvider()
}

type GoogleOAuth struct {
	// Service account that will be impersonated for backend access.
	ServiceAccountEmail string `yaml:"service_account_email,omitempty" mapstructure:"service_account_email,omitempty"`

	// TokenInfo contains information about the ID or access token.
	TokenInfo TokenInfo `yaml:"-" mapstructure:"-"`
}

func (g GoogleOAuth) oauthProvider() {}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (g *GoogleOAuth) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh GoogleOAuth
	if err := node.Decode((*Unmarsh)(g)); err != nil {
		return err
	}

	w := &googleOAuthWrapper{}
	if err := node.Decode(w); err != nil {
		return err
	}
	ctr := 0
	if w.AccessTokenInfo != nil {
		ctr++
		g.TokenInfo = *w.AccessTokenInfo
	}
	if w.IdentityTokenInfo != nil {
		ctr++
		g.TokenInfo = *w.IdentityTokenInfo
	}
	if ctr > 1 {
		return fmt.Errorf("at most one of access_token or id_token can be present")
	}

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (g GoogleOAuth) MarshalYAML() (interface{}, error) {
	w := &googleOAuthWrapper{
		ServiceAccountEmail: g.ServiceAccountEmail,
	}

	switch v := g.TokenInfo.(type) {
	case AccessTokenInfo:
		w.AccessTokenInfo = &v
	case IdentityTokenInfo:
		w.IdentityTokenInfo = &v
	}

	return w, nil
}

type googleOAuthWrapper struct {
	ServiceAccountEmail string             `yaml:"service_account_email,omitempty"`
	AccessTokenInfo     *AccessTokenInfo   `yaml:"access_token,omitempty"`
	IdentityTokenInfo   *IdentityTokenInfo `yaml:"id_token,omitempty"`
}

// TokenInfo contains information about the ID or access token.
type TokenInfo interface {
	tokenInfo()
}

// AccessTokenInfo contains information about the access token.
type AccessTokenInfo struct {
	// Code to identify the scopes to be included in the OAuth 2.0 access token.
	// See https://developers.google.com/identity/protocols/googlescopes for more
	// information.
	Scopes []string `yaml:"scopes,omitempty"`
}

func (i AccessTokenInfo) tokenInfo() {}

// IdentityTokenInfo contains information about the ID token.
type IdentityTokenInfo struct {
	// The audience for the token, such as the API or account that this token
	// grants access to.
	Audience string `yaml:"audience" mapstructure:"audience"`

	// Include the service account email in the token. If set to `true`, the
	// token will contain `email` and `email_verified` claims.
	IncludeEmail bool `yaml:"include_email,omitempty" mapstructure:"include_email,omitempty"`
}

func (i IdentityTokenInfo) tokenInfo() {}
