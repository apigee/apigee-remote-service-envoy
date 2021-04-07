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
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
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

	ApigeeAPIScope = "https://www.googleapis.com/auth/cloud-platform" // scope Apigee API needs
)

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
// Auth and EnvConfigs are mutually exclusive
type Config struct {
	Global     GlobalConfig    `yaml:"global,omitempty" json:"global,omitempty"`
	Tenant     TenantConfig    `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	Products   ProductsConfig  `yaml:"products,omitempty" json:"products,omitempty"`
	Analytics  AnalyticsConfig `yaml:"analytics,omitempty" json:"analytics,omitempty"`
	Auth       AuthConfig      `yaml:"auth,omitempty" json:"auth,omitempty"`
	EnvConfigs EnvConfigs      `yaml:"env_configs,omitempty" json:"env_configs,omitempty"`
}

// GlobalConfig is global configuration for the server
type GlobalConfig struct {
	APIAddress                string            `yaml:"api_address,omitempty" json:"api_address,omitempty"`
	MetricsAddress            string            `yaml:"metrics_address,omitempty" json:"metrics_address,omitempty"`
	TempDir                   string            `yaml:"temp_dir,omitempty" json:"temp_dir,omitempty"`
	KeepAliveMaxConnectionAge time.Duration     `yaml:"keep_alive_max_connection_age,omitempty" json:"keep_alive_max_connection_age,omitempty"`
	TLS                       TLSListenerConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
	Namespace                 string            `yaml:"-" json:"-"`
}

// TLSListenerConfig is tls configuration
type TLSListenerConfig struct {
	KeyFile  string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
}

// TLSClientConfig is mtls configuration
type TLSClientConfig struct {
	CAFile                 string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	KeyFile                string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CertFile               string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	AllowUnverifiedSSLCert bool   `yaml:"allow_unverified_ssl_cert,omitempty" json:"allow_unverified_ssl_cert,omitempty"`
}

// TenantConfig is config relating to an Apigee tentant
type TenantConfig struct {
	InternalAPI         string          `yaml:"internal_api,omitempty" json:"internal_api,omitempty"`
	RemoteServiceAPI    string          `yaml:"remote_service_api" json:"remote_service_api"`
	OrgName             string          `yaml:"org_name" json:"org_name"`
	EnvName             string          `yaml:"env_name" json:"env_name"`
	Key                 string          `yaml:"key,omitempty" json:"key,omitempty"`
	Secret              string          `yaml:"secret,omitempty" json:"secret,omitempty"`
	ClientTimeout       time.Duration   `yaml:"client_timeout,omitempty" json:"client_timeout,omitempty"`
	TLS                 TLSClientConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
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
	RefreshRate time.Duration `yaml:"refresh_rate,omitempty" json:"refresh_rate,omitempty"`
}

// AnalyticsConfig is analytics-related config
type AnalyticsConfig struct {
	LegacyEndpoint     bool                `yaml:"legacy_endpoint,omitempty" json:"legacy_endpoint,omitempty"`
	FileLimit          int                 `yaml:"file_limit,omitempty" json:"file_limit,omitempty"`
	SendChannelSize    int                 `yaml:"send_channel_size,omitempty" json:"send_channel_size,omitempty"`
	CollectionInterval time.Duration       `yaml:"collection_interval,omitempty" json:"collection_interval,omitempty"`
	CredentialsJSON    []byte              `yaml:"-" json:"-"`
	Credentials        *google.Credentials `yaml:"-" json:"-"`
}

// AuthConfig is auth-related config
type AuthConfig struct {
	APIKeyClaim           string        `yaml:"api_key_claim,omitempty" json:"api_key_claim,omitempty"`
	APIKeyCacheDuration   time.Duration `yaml:"api_key_cache_duration,omitempty" json:"api_key_cache_duration,omitempty"`
	APIKeyHeader          string        `yaml:"api_key_header,omitempty" json:"api_key_header,omitempty"`
	APIHeader             string        `yaml:"api_header,omitempty" json:"api_header,omitempty"`
	AllowUnauthorized     bool          `yaml:"allow_unauthorized,omitempty" json:"allow_unauthorized,omitempty"`
	JWTProviderKey        string        `yaml:"jwt_provider_key,omitempty" json:"jwt_provider_key,omitempty"`
	AppendMetadataHeaders bool          `yaml:"append_metadata_headers,omitempty" json:"append_metadata_headers,omitempty"`
}

// EnvConfigs
type EnvConfigs struct {
	// A list of files containing environment config
	ConfigFiles []string `yaml:"config_files,omitempty" json:"config_files,omitempty"`

	// A list of environment configs
	InlineConfigs []EnvironmentConfig `yaml:"inline_configs,omitempty" json:"inline_configs,omitempty"`
}

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

	// String modification to strip off matched value (e.g. "Bearer " for Authorization
	// tokens).
	Modification StringModification `yaml:"modification,omitempty" json:"modification,omitempty"`
}

// StringModification uses simple template syntax
// e.g. template: "prefix-{foo}-{bar}-suffix"
//      substitution: "{foo}_{bar}"
//      -->
//      input: "prefix-hello-world-suffix"
//      output: "hello_world"
type StringModification struct {
	// String template, optionally containing variable declarations.
	Template string `yaml:"template,omitempty" json:"template,omitempty"`

	// Substitution string, optionally using variables declared in the template.
	Substitution string `yaml:"substitution,omitempty" json:"substitution,omitempty"`
}

// JWTClaim is reference to a JWT claim.
type JWTClaim struct {
	// Name of the JWT provider
	Provider string `yaml:"provider" json:"provider"`

	// Name of the claim
	Name string `yaml:"name" json:"name"`
}

// Load config
func (c *Config) Load(configFile, policySecretPath, analyticsSecretPath string, requireAnalyticsCredentials bool) error {
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
				if err = yaml.Unmarshal(configBytes, c); err != nil {
					return errors.Wrap(err, "bad config file format")
				}
				c.Global.Namespace = crd.Metadata.Namespace
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
		if err = yaml.Unmarshal(yamlFile, c); err != nil {
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
				c.Analytics.CredentialsJSON = sa
				c.Analytics.Credentials, err = google.CredentialsFromJSON(context.Background(), sa, ApigeeAPIScope)
				if err != nil {
					return err
				}
			}
		}
	}

	return c.Validate(requireAnalyticsCredentials)
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
