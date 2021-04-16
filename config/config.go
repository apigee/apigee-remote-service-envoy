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
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

const (
	// LegacySaaSInternalBase is the internal API used for auth and analytics
	LegacySaaSInternalBase = "https://istioservices.apigee.net/edgemicro"

	// GCPExperienceBase is the default management API URL for GCP Experience
	GCPExperienceBase = "https://apigee.googleapis.com"

	// ServiceAccount is the json file with application credentials
	ServiceAccount = "client_secret.json"

	// DefaultAnalyticsSecretPath is the default path the analytics credentials directory
	DefaultAnalyticsSecretPath = "/analytics-secret"

	// ApigeeAPIScope specifies the scope Apigee API needs
	ApigeeAPIScope = "https://www.googleapis.com/auth/cloud-platform"

	// EnvironmentVairiablePrefix is the prefix of the env vars that can override given config
	EnvironmentVariablePrefix = "APIGEE"

	RemoteServiceKey     = "APIGEE.TENANT.PRIVATE_KEY"
	RemoteServiceKeyID   = "APIGEE.TENANT.PRIVATE_KEY_ID"
	RemoteServiceJWKS    = "APIGEE.TENANT.JWKS"
	AnalyticsCredentials = "APIGEE.ANALYTICS.CREDENTIALS_JSON"
)

func init() {
	// Enable automatic environment variable check
	viper.AutomaticEnv()

	// Set config to yaml
	viper.SetConfigType("yaml")

	// Bind environment variables to those derived from the config struct.
	// This is needed because viper.Unmarshall() does not automatically
	// check environment variables for the keys corresponding to the struct
	// fields.
	bindEnvs(Config{}, "")
}

// bindEnvs extracts mapstructure annotations of any struct into a key
// with delimiter "." and bind the key with environment variable with
// prefix "APIGEE." and all upper cases.
func bindEnvs(raw interface{}, prefix string) {
	rv := reflect.ValueOf(raw)
	rt := reflect.TypeOf(raw)
	if prefix != "" {
		prefix = prefix + "."
	}
	for i := 0; i < rt.NumField(); i++ {
		v := rv.Field(i)
		t := rt.Field(i)
		tv, ok := t.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		tv = strings.Split(tv, ",")[0]
		k := prefix + tv
		switch v.Kind() {
		case reflect.Struct:
			bindEnvs(v.Interface(), k)
		default:
			_ = viper.BindEnv(k, envVarKey(k))
		}
	}
}

func envVarKey(key string) string {
	return fmt.Sprintf("%s.%s", EnvironmentVariablePrefix, strings.ToUpper(key))
}

// DefaultConfig returns a config with defaults set
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			TempDir:                   "/tmp/apigee-istio",
			KeepAliveMaxConnectionAge: time.Minute,
			APIAddress:                ":5000",
			MetricsAddress:            ":5001",
		},
		Tenant: TenantConfig{
			ClientTimeout:       30 * time.Second,
			InternalJWTDuration: 10 * time.Minute,
			InternalJWTRefresh:  30 * time.Second,
		},
		Products: ProductsConfig{
			RefreshRate: 2 * time.Minute,
		},
		Analytics: AnalyticsConfig{
			FileLimit:          1024,
			SendChannelSize:    10,
			CollectionInterval: 2 * time.Minute,
		},
		Auth: AuthConfig{
			APIKeyCacheDuration: 30 * time.Minute,
			APIKeyHeader:        "x-api-key",
			APIHeader:           ":authority",
		},
	}
}

// Config is all config
type Config struct {
	Global    GlobalConfig    `yaml:"global,omitempty" json:"global,omitempty" mapstructure:"global,omitempty"`
	Tenant    TenantConfig    `yaml:"tenant,omitempty" json:"tenant,omitempty" mapstructure:"tenant,omitempty"`
	Products  ProductsConfig  `yaml:"products,omitempty" json:"products,omitempty" mapstructure:"products,omitempty"`
	Analytics AnalyticsConfig `yaml:"analytics,omitempty" json:"analytics,omitempty" mapstructure:"analytics,omitempty"`
	// If EnvConfigs is specified, APIKeyHeader, APIKeyClaim, JWTProviderKey in AuthConfig will be ineffectual.
	Auth       AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty" mapstructure:"auth,omitempty"`
	EnvConfigs EnvConfigs `yaml:"env_configs,omitempty" json:"env_configs,omitempty" mapstructure:"env_configs,omitempty"`
}

// GlobalConfig is global configuration for the server
type GlobalConfig struct {
	APIAddress                string            `yaml:"api_address,omitempty" json:"api_address,omitempty" mapstructure:"api_address,omitempty"`
	MetricsAddress            string            `yaml:"metrics_address,omitempty" json:"metrics_address,omitempty" mapstructure:"metrics_address,omitempty"`
	TempDir                   string            `yaml:"temp_dir,omitempty" json:"temp_dir,omitempty" mapstructure:"temp_dir,omitempty"`
	KeepAliveMaxConnectionAge time.Duration     `yaml:"keep_alive_max_connection_age,omitempty" json:"keep_alive_max_connection_age,omitempty" mapstructure:"keep_alive_max_connection_age,omitempty"`
	TLS                       TLSListenerConfig `yaml:"tls,omitempty" json:"tls,omitempty" mapstructure:"tls,omitempty"`
	Namespace                 string            `yaml:"-" json:"-" mapstructure:"namespace,omitempty"`
}

// TLSListenerConfig is tls configuration
type TLSListenerConfig struct {
	KeyFile  string `yaml:"key_file,omitempty" json:"key_file,omitempty" mapstructure:"key_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty" mapstructure:"cert_file,omitempty"`
}

// TLSClientConfig is mtls configuration
type TLSClientConfig struct {
	CAFile                 string `yaml:"ca_file,omitempty" json:"ca_file,omitempty" mapstructure:"ca_file,omitempty"`
	KeyFile                string `yaml:"key_file,omitempty" json:"key_file,omitempty" mapstructure:"key_file,omitempty"`
	CertFile               string `yaml:"cert_file,omitempty" json:"cert_file,omitempty" mapstructure:"cert_file,omitempty"`
	AllowUnverifiedSSLCert bool   `yaml:"allow_unverified_ssl_cert,omitempty" json:"allow_unverified_ssl_cert,omitempty" mapstructure:"allow_unverified_ssl_cert,omitempty"`
}

// TenantConfig is config relating to an Apigee tentant
type TenantConfig struct {
	InternalAPI         string          `yaml:"internal_api,omitempty" json:"internal_api,omitempty" mapstructure:"internal_api,omitempty"`
	RemoteServiceAPI    string          `yaml:"remote_service_api" json:"remote_service_api" mapstructure:"remote_service_api"`
	OrgName             string          `yaml:"org_name" json:"org_name" mapstructure:"org_name"`
	EnvName             string          `yaml:"env_name" json:"env_name" mapstructure:"env_name"`
	Key                 string          `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key,omitempty"`
	Secret              string          `yaml:"secret,omitempty" json:"secret,omitempty" mapstructure:"secret,omitempty"`
	ClientTimeout       time.Duration   `yaml:"client_timeout,omitempty" json:"client_timeout,omitempty" mapstructure:"client_timeout,omitempty"`
	TLS                 TLSClientConfig `yaml:"tls,omitempty" json:"tls,omitempty" mapstructure:"tls,omitempty"`
	PrivateKey          *rsa.PrivateKey `yaml:"-" json:"-"`
	PrivateKeyID        string          `yaml:"-" json:"-"`
	JWKS                jwk.Set         `yaml:"-" json:"-"`
	InternalJWTDuration time.Duration   `yaml:"-" json:"-"`
	InternalJWTRefresh  time.Duration   `yaml:"-" json:"-"`
}

func (t *TenantConfig) IsMultitenant() bool {
	return t.EnvName == "*"
}

// ProductsConfig is products-related config
type ProductsConfig struct {
	RefreshRate time.Duration `yaml:"refresh_rate,omitempty" json:"refresh_rate,omitempty" mapstructure:"refresh_rate,omitempty"`
}

// AnalyticsConfig is analytics-related config
type AnalyticsConfig struct {
	LegacyEndpoint     bool                `yaml:"legacy_endpoint,omitempty" json:"legacy_endpoint,omitempty" mapstructure:"legacy_endpoint,omitempty"`
	FileLimit          int                 `yaml:"file_limit,omitempty" json:"file_limit,omitempty" mapstructure:"file_limit,omitempty"`
	SendChannelSize    int                 `yaml:"send_channel_size,omitempty" json:"send_channel_size,omitempty" mapstructure:"send_channel_size,omitempty"`
	CollectionInterval time.Duration       `yaml:"collection_interval,omitempty" json:"collection_interval,omitempty" mapstructure:"collection_interval,omitempty"`
	CredentialsJSON    []byte              `yaml:"-" json:"-"`
	Credentials        *google.Credentials `yaml:"-" json:"-"`
}

// AuthConfig is auth-related config
type AuthConfig struct {
	APIKeyClaim           string        `yaml:"api_key_claim,omitempty" json:"api_key_claim,omitempty" mapstructure:"api_key_claim,omitempty"`
	APIKeyCacheDuration   time.Duration `yaml:"api_key_cache_duration,omitempty" json:"api_key_cache_duration,omitempty" mapstructure:"api_key_cache_duration,omitempty"`
	APIKeyHeader          string        `yaml:"api_key_header,omitempty" json:"api_key_header,omitempty" mapstructure:"api_key_header,omitempty"`
	APIHeader             string        `yaml:"api_header,omitempty" json:"api_header,omitempty" mapstructure:"api_header,omitempty"`
	AllowUnauthorized     bool          `yaml:"allow_unauthorized,omitempty" json:"allow_unauthorized,omitempty" mapstructure:"allow_unauthorized,omitempty"`
	JWTProviderKey        string        `yaml:"jwt_provider_key,omitempty" json:"jwt_provider_key,omitempty" mapstructure:"jwt_provider_key,omitempty"`
	AppendMetadataHeaders bool          `yaml:"append_metadata_headers,omitempty" json:"append_metadata_headers,omitempty" mapstructure:"append_metadata_headers,omitempty"`
}

// EnvConfigs contains environment configs or URIs to them.
type EnvConfigs struct {
	// A list of strings containing environment config URIs
	// Only the local file system is supported currently, e.g., file://path/to/config.yaml
	ConfigURIs []string `yaml:"config_uris,omitempty" json:"config_uris,omitempty"`

	// A list of environment configs
	Inline []EnvironmentConfig `yaml:"inline,omitempty" json:"inline,omitempty"`
}

// EnvironmentConfig is an Apigee Environment-level config for
// Envoy Adapter. It contains a list of operations for the adapter to
// perform request authentication and authorization.
type EnvironmentConfig struct {
	// Unique ID of the environment config
	ID string `yaml:"id" json:"id"`

	// A list of proxy configs
	ProxyConfigs []ProxyConfig `yaml:"proxy_configs" json:"proxy_configs"`
}

// ProxyConfig has the proxy configuration.
type ProxyConfig struct {
	// Top-level basepath for the proxy config
	Basepath string `yaml:"basepath,omitempty" json:"basepath,omitempty"`

	// Authentication defines the proxy-level authentication requirement
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// ConsumerAuthorization defines the proxy-level consumer authorization
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" json:"consumer_authorization,omitempty"`

	// Name of the target server for this proxy.
	Target string `yaml:"target" json:"target"`

	// A list of Operations, names of which must be unique within the proxy config.
	Operations []APIOperation `yaml:"operations,omitempty" json:"operations,omitempty"`
}

// An APIOperation associates a set of rules with a set of request matching
// settings.
type APIOperation struct {
	// Name of the operation. Unique within a proxy config.
	Name string `yaml:"name" json:"name"`

	// Authentication defines the operation-level authentication requirement and overrides whatever in the proxy level
	Authentication AuthenticationRequirement `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// ConsumerAuthorization defines the operation-level consumer authorization and overrides whatever in the proxy level
	ConsumerAuthorization ConsumerAuthorization `yaml:"consumer_authorization,omitempty" json:"consumer_authorization,omitempty"`

	// HTTP matching rules for this operation. If omitted, this will match all requests.
	HTTPMatches []HTTPMatch `yaml:"http_match,omitempty" json:"http_match,omitempty"`

	// Name of the target server for this operation.
	Target string `yaml:"target" json:"target"`
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

// JWTAuthentication defines the JWT authentication.
type JWTAuthentication struct {
	// Name of this JWT requirement, unique within the Proxy.
	Name string `yaml:"name" json:"name"`

	// JWT issuer ("iss" claim)
	Issuer string `yaml:"issuer" json:"issuer"`

	// The JWKS source
	JWKSSource JWKSSource `yaml:"-" json:"-"`

	// Audiences contains a list of audiences
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`

	// Header name that will contain decoded JWT payload in requests forwarded to
	// target.
	ForwardPayloadHeader string `yaml:"forward_payload_header,omitempty" json:"forward_payload_header,omitempty"`

	// Locations where JWT may be found. First match wins.
	In []HTTPParameter `yaml:"in" json:"in"`
}

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

func (JWTAuthentication) authenticationRequirements() {}

// JWKSSource is the JWKS source.
type JWKSSource interface {
	jwksSource()
}

// RemoteJWKS contains information for remote JWKS.
type RemoteJWKS struct {
	// URL of the JWKS
	URL string `yaml:"url" json:"url"`

	// CacheDuration of the JWKS
	CacheDuration time.Duration `yaml:"cache_duration,omitempty" json:"cache_duration,omitempty"`
}

func (RemoteJWKS) jwksSource() {}

// ConsumerAuthorization is the configuration of API consumer authorization.
type ConsumerAuthorization struct {
	// Allow requests to be forwarded even if the consumer credential cannot be
	// verified by the API Key provider due to service unavailability.
	FailOpen bool `yaml:"fail_open,omitempty" json:"fail_open,omitempty"`

	// Locations of API consumer credential (API Key). First match wins.
	In []HTTPParameter `yaml:"in" json:"in"`
}

// HTTPMatch is an HTTP request matching rule.
type HTTPMatch struct {
	// URL path template using to match incoming requests and optionally identify
	// path variables.
	PathTemplate string `yaml:"path_template" json:"path_template"`

	// HTTP method (e.g. GET, POST, PUT, etc.)
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
}

// HTTPParameter defines an HTTP paramter.
type HTTPParameter struct {
	// Query, Header and JWTClaim are supported.
	Match ParamMatch `yaml:"-" json:"-"`

	// Optional transformation of the parameter value (e.g. "Bearer " for Authorization tokens).
	Transformation StringTransformation `yaml:"transformation,omitempty" json:"transformation,omitempty"`
}

type httpParameterWrapper struct {
	Header   *Header   `yaml:"header,omitempty" json:"header,omitempty"`
	Query    *Query    `yaml:"query,omitempty" json:"query,omitempty"`
	JWTClaim *JWTClaim `yaml:"jwt_claim,omitempty" json:"jwt_claim,omitempty"`
}

// UnmarshalYAML implements the custom unmarshal method
// for HTTPParamter with input yaml bytes
func (p *HTTPParameter) UnmarshalYAML(node *yaml.Node) error {
	type Unmarsh HTTPParameter
	if err := node.Decode((*Unmarsh)(p)); err != nil {
		return err
	}

	h := &httpParameterWrapper{}
	if err := node.Decode(h); err != nil {
		return err
	}
	ctr := 0
	if h.Header != nil {
		ctr += 1
		p.Match = *h.Header
	}
	if h.Query != nil {
		ctr += 1
		p.Match = *h.Query
	}
	if h.JWTClaim != nil {
		ctr += 1
		p.Match = *h.JWTClaim
	}
	if ctr != 1 {
		return fmt.Errorf("precisely one header, query or jwt_claim should be set")
	}

	return nil
}

// UnmarshalJSON implements the custom unmarshal method
// for HTTPParamter with input json bytes
func (p *HTTPParameter) UnmarshalJSON(b []byte) error {
	type Unmarsh HTTPParameter
	if err := json.Unmarshal(b, (*Unmarsh)(p)); err != nil {
		return err
	}

	h := &httpParameterWrapper{}
	if err := json.Unmarshal(b, h); err != nil {
		return err
	}
	ctr := 0
	if h.Header != nil {
		ctr += 1
		p.Match = *h.Header
	}
	if h.Query != nil {
		ctr += 1
		p.Match = *h.Query
	}
	if h.JWTClaim != nil {
		ctr += 1
		p.Match = *h.JWTClaim
	}
	if ctr != 1 {
		return fmt.Errorf("precisely one header, query or jwt_claim should be set")
	}

	return nil
}

// ParamMatch tells the location of the HTTP paramter.
type ParamMatch interface {
	paramMatch()
}

// Name of a query paramter
type Query string

func (Query) paramMatch() {}

// Name of a header
type Header string

func (Header) paramMatch() {}

// JWTClaim is reference to a JWT claim.
type JWTClaim struct {
	// Name of the JWT requirement
	Requirement string `yaml:"requirement" json:"requirement"`

	// Name of the claim
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

// Load config with the given config file, secret paths and a flag specifying whether analytics credentials must be present.
// Fields with mapstructure annotations will support loading from the following sources with descending precedence:
//   * Environment variables - all upper cases with prefix "APIGEE." and annotations in different structs are delimited with ".",
//     e.g., APIGEE.GLOBAL.API_ADDRESS=<addr> will assign Global.APIAddress to <addr>
//   * Config file in yaml format, e.g., the config below
//     global:
//       api_address: <addr>
//     will assign Global.APIAddress to <addr>
// The following fields do not have mapstructure annotations but support similar ways of loading as described below:
//   * Tenant.JWKS will be unmarshalled from APIGEE.TENANT.JWKS if such an environment variable exists. If not and policySecretPath is
//     given, it will unmarshalled from the content of file {{policySecretPath}}/remote-service.crt. Lastly, if the given config file
//     is multiple yaml files with secret CRD named "policy", the secret data with key "remote-service.crt" will be looked for and unmarshalled.
//   * Tenant.PrivateKey will be unmarshalled from APIGEE.TENANT.PRIVATE_KEY if such an environment variable exists. If not and policySecretPath is
//     given, it will unmarshalled from the content of file {{policySecretPath}}/remote-service.key. Lastly, if the given config file
//     is multiple yaml files with secret CRDs named "policy", the secret data with key "remote-service.key" will be looked for and unmarshalled.
//   * Tenant.PrivateKeyID will be given by APIGEE.TENANT.PRIVATE_KEY_ID if such an environment variable exists. If not and policySecretPath is
//     given, the value of the key "kid" will be looked for from the property maps in {{policySecretPath}}/remote-service.properties.
//     Lastly, if the given config file is multiple yaml files with secret CRDs named "policy", the secret data with key "remote-service.props"
//     will be looked for and unmarshalled into a map where the value of the key "kid" will be looked for and used.
//   * Analytics.CredentialsJSON will be given by APIGEE.ANALYTICS.CREDENTIALS_JSON if such an environment variable exists. If not and
//     analyticsSecretPath is given, the file content of {{analyticsSecretPath}}/client_secret.json will be used. If such file does not
//     exist but analyticsSecretPath is equal to DefaultAnalyticsSecretPath, the secret CRD named "analytics" in the config file will be looked
//     for, in which the data with key "client_secret.json" will be used.
func (c *Config) Load(configFile, policySecretPath, analyticsSecretPath string, requireAnalyticsCredentials bool, envConfigFiles ...string) error {
	log.Debugf("reading config from: %s", configFile)
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	// attempt load from CRD
	var key, kidProps, jwksBytes []byte
	var configBytes []byte
	decoder := yaml.NewDecoder(bytes.NewReader(yamlFile))

	crd := &ConfigMapCRD{}
	for decoder.Decode(crd) != io.EOF {
		if crd.Kind == "ConfigMap" {
			configBytes = []byte(crd.Data["config.yaml"])
			if configBytes != nil {
				c.Global.Namespace = crd.Metadata.Namespace
				if err = c.unmarshalWithConfig(configBytes); err != nil {
					return errors.Wrap(err, "bad config file format")
				}
			}
		} else if crd.Kind == "Secret" {
			if strings.Contains(crd.Metadata.Name, "policy") {
				key, _ = base64.StdEncoding.DecodeString(crd.Data[SecretPrivateKey])
				kidProps, _ = base64.StdEncoding.DecodeString(crd.Data[SecretPropsKey])
				jwksBytes, _ = base64.StdEncoding.DecodeString(crd.Data[SecretJWKSKey])

				// check the lengths as DecodeString() only returns empty bytes
				if len(key) == 0 || len(kidProps) == 0 || len(jwksBytes) == 0 { // all or nothing
					key = nil
					kidProps = nil
					jwksBytes = nil
				}
			} else if strings.Contains(crd.Metadata.Name, "analytics") {
				c.Analytics.CredentialsJSON, _ = base64.StdEncoding.DecodeString(crd.Data[ServiceAccount])
				c.Analytics.Credentials, err = google.CredentialsFromJSON(context.Background(), c.Analytics.CredentialsJSON, ApigeeAPIScope)
				if err != nil {
					return err
				}
			}
		}
	}

	// didn't load, try as simple config file
	if configBytes == nil {
		if err = c.unmarshalWithConfig(yamlFile); err != nil {
			return errors.Wrap(err, "bad config file format")
		}
	}

	// if no Secret, try files in policySecretPath
	if c.IsGCPManaged() {

		if policySecretPath != "" && key == nil {
			if key, err = os.ReadFile(path.Join(policySecretPath, SecretPrivateKey)); err == nil {
				if kidProps, err = os.ReadFile(path.Join(policySecretPath, SecretPropsKey)); err == nil {
					jwksBytes, err = os.ReadFile(path.Join(policySecretPath, SecretJWKSKey))
				}
			}
		}
		if err != nil {
			return err
		}

		props, err := util.ReadProperties(bytes.NewReader(kidProps))
		if err != nil {
			return err
		}

		c.Tenant.PrivateKeyID = props[SecretPropsKIDKey]
		jwks := jwk.NewSet()
		if err = json.Unmarshal(jwksBytes, jwks); err == nil {
			c.Tenant.JWKS = jwks
			if c.Tenant.PrivateKey, err = util.LoadPrivateKey(key); err != nil {
				return err
			}
		}

		if err = c.secretsFromEnv(); err != nil {
			return err
		}

		// attempts to load the service account credentials if a path is given
		if analyticsSecretPath != "" {
			svc := path.Join(analyticsSecretPath, ServiceAccount)
			log.Debugf("using analytics service account credentials from: %s", svc)
			sa, err := os.ReadFile(svc)
			if err != nil {
				if analyticsSecretPath == DefaultAnalyticsSecretPath {
					// allows fall back to default credentials if the path is the default one
					log.Warnf("analytics service account credentials not found on default path, falling back to credentials from config file")
				} else {
					// returns error if the invalid path is explicitly specified
					return err
				}
			} else {
				// overwrites the credentials if read from the config
				if err = c.analyticsCredentialsFromBytes(sa); err != nil {
					return err
				}
			}
		}

		if val := viper.GetString(AnalyticsCredentials); val != "" {
			if err = c.analyticsCredentialsFromBytes([]byte(val)); err != nil {
				return err
			}
		}
	}

	return c.Validate(requireAnalyticsCredentials)
}

// unmarshalWithConfig uses viper to read the config bytes and unmarshal values into the config struct
// such that environment variables take precedence over what's in the config bytes
func (c *Config) unmarshalWithConfig(b []byte) error {
	if err := viper.ReadConfig(bytes.NewBuffer(b)); err != nil {
		return err
	}
	return viper.Unmarshal(c)
}

func (c *Config) secretsFromEnv() error {
	var err error
	if val := viper.GetString(RemoteServiceKeyID); val != "" {
		c.Tenant.PrivateKeyID = val
	}
	if val := viper.GetString(RemoteServiceJWKS); val != "" {
		jwks := jwk.NewSet()
		if err = json.Unmarshal([]byte(val), jwks); err != nil {
			return err
		}
		c.Tenant.JWKS = jwks
	}
	if val := viper.GetString(RemoteServiceKey); val != "" {
		if c.Tenant.PrivateKey, err = util.LoadPrivateKey([]byte(val)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) analyticsCredentialsFromBytes(b []byte) error {
	var err error
	c.Analytics.CredentialsJSON = b
	c.Analytics.Credentials, err = google.CredentialsFromJSON(context.Background(), b, ApigeeAPIScope)
	return err
}

// IsGCPManaged is true for hybrid and NG SaaS
func (c *Config) IsGCPManaged() bool {
	return c.Tenant.InternalAPI == ""
}

// IsApigeeManaged is true for legacy SaaS
func (c *Config) IsApigeeManaged() bool {
	return c.Tenant.InternalAPI == LegacySaaSInternalBase
}

// IsOPDK is true for OPDK installs
func (c *Config) IsOPDK() bool {
	return !c.IsGCPManaged() && !c.IsApigeeManaged()
}

// Validate validates the config
func (c *Config) Validate(requireAnalyticsCredentials bool) error {
	var errs error
	if c.Tenant.RemoteServiceAPI == "" {
		errs = errorset.Append(errs, fmt.Errorf("tenant.remote_service_api is required"))
	}
	if len(c.Analytics.CredentialsJSON) == 0 {
		if c.Tenant.InternalAPI == "" && requireAnalyticsCredentials {
			cred, err := google.FindDefaultCredentials(context.Background(), ApigeeAPIScope)
			if err != nil {
				errs = errorset.Append(errs, fmt.Errorf("tenant.internal_api is required if analytics credentials not given"))
			} else { // to avoid the non-name error
				c.Analytics.Credentials = cred
			}
		}
	} else {
		if c.Tenant.InternalAPI != "" {
			errs = errorset.Append(errs, fmt.Errorf("tenant.internal_api and analytics credentials are mutually exclusive"))
		}
	}
	if c.Tenant.OrgName == "" {
		errs = errorset.Append(errs, fmt.Errorf("tenant.org_name is required"))
	}
	if c.Tenant.EnvName == "" {
		errs = errorset.Append(errs, fmt.Errorf("tenant.env_name is required"))
	}
	if (c.Global.TLS.CertFile != "" || c.Global.TLS.KeyFile != "") &&
		(c.Global.TLS.CertFile == "" || c.Global.TLS.KeyFile == "") {
		errs = errorset.Append(errs, fmt.Errorf("global.tls.cert_file and global.tls.key_file are both required if either are present"))
	}
	if (c.Tenant.TLS.CAFile != "" || c.Tenant.TLS.CertFile != "" || c.Tenant.TLS.KeyFile != "") &&
		(c.Tenant.TLS.CAFile == "" || c.Tenant.TLS.CertFile == "" || c.Tenant.TLS.KeyFile == "") {
		errs = errorset.Append(errs, fmt.Errorf("all tenant.tls options are required if any are present"))
	}
	return errs
}

// ConfigMapCRD is a CRD for ConfigMap
type ConfigMapCRD struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

// SecretCRD is a CRD for Secret
type SecretCRD struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Type       string            `yaml:"type,omitempty"`
	Data       map[string]string `yaml:"data"`
}

// Metadata is for Kubernetes CRD generation
type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// note: hybrid forces these specific file extensions! https://docs.apigee.com/hybrid/v1.2/k8s-secrets
const (
	SecretJWKSKey     = "remote-service.crt"        // hybrid treats .crt as blob
	SecretPrivateKey  = "remote-service.key"        // private key
	SecretPropsKey    = "remote-service.properties" // java properties format: %s=%s
	SecretPropsKIDKey = "kid"
)
