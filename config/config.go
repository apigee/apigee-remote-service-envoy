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

	EnvConfigsURIs = "ENVIRONMENT_CONFIGS.REFERENCES"
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

// Default returns a config with defaults set
func Default() *Config {
	return &Config{
		Global: Global{
			TempDir:                   "/tmp/apigee-istio",
			KeepAliveMaxConnectionAge: time.Minute,
			APIAddress:                ":5000",
			MetricsAddress:            ":5001",
		},
		Tenant: Tenant{
			ClientTimeout:       30 * time.Second,
			InternalJWTDuration: 10 * time.Minute,
			InternalJWTRefresh:  30 * time.Second,
		},
		Products: Products{
			RefreshRate: 2 * time.Minute,
		},
		Analytics: Analytics{
			FileLimit:          1024,
			SendChannelSize:    10,
			CollectionInterval: 2 * time.Minute,
		},
		Auth: Auth{
			APIKeyCacheDuration: 30 * time.Minute,
			APIKeyHeader:        "x-api-key",
			APIHeader:           ":authority",
		},
	}
}

// Config is all config
type Config struct {
	Global    Global    `yaml:"global,omitempty" mapstructure:"global,omitempty"`
	Tenant    Tenant    `yaml:"tenant,omitempty" mapstructure:"tenant,omitempty"`
	Products  Products  `yaml:"products,omitempty" mapstructure:"products,omitempty"`
	Analytics Analytics `yaml:"analytics,omitempty" mapstructure:"analytics,omitempty"`
	// If EnvironmentConfigs is specified, APIKeyHeader, APIKeyClaim, JWTProviderKey in AuthConfig will be ineffectual.
	Auth Auth `yaml:"auth,omitempty" mapstructure:"auth,omitempty"`
	// Apigee Environment configurations.
	EnvironmentSpecs EnvironmentSpecs `yaml:"environment_specs,omitempty" mapstructure:"environment_specs,omitempty"`
}

// Global is global configuration for the server
type Global struct {
	APIAddress                string          `yaml:"api_address,omitempty" mapstructure:"api_address,omitempty"`
	MetricsAddress            string          `yaml:"metrics_address,omitempty" mapstructure:"metrics_address,omitempty"`
	TempDir                   string          `yaml:"temp_dir,omitempty" mapstructure:"temp_dir,omitempty"`
	KeepAliveMaxConnectionAge time.Duration   `yaml:"keep_alive_max_connection_age,omitempty" mapstructure:"keep_alive_max_connection_age,omitempty"`
	TLS                       TLSListenerSpec `yaml:"tls,omitempty" mapstructure:"tls,omitempty"`
	Namespace                 string          `yaml:"-" mapstructure:"namespace,omitempty"`
}

// TLSListenerSpec is tls configuration
type TLSListenerSpec struct {
	KeyFile  string `yaml:"key_file,omitempty" mapstructure:"key_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty" mapstructure:"cert_file,omitempty"`
}

// TLSClientSpec is mtls configuration
type TLSClientSpec struct {
	CAFile                 string `yaml:"ca_file,omitempty" mapstructure:"ca_file,omitempty"`
	KeyFile                string `yaml:"key_file,omitempty" mapstructure:"key_file,omitempty"`
	CertFile               string `yaml:"cert_file,omitempty" mapstructure:"cert_file,omitempty"`
	AllowUnverifiedSSLCert bool   `yaml:"allow_unverified_ssl_cert,omitempty" mapstructure:"allow_unverified_ssl_cert,omitempty"`
}

// Tenant is config relating to an Apigee tentant
type Tenant struct {
	InternalAPI         string          `yaml:"internal_api,omitempty" mapstructure:"internal_api,omitempty"`
	RemoteServiceAPI    string          `yaml:"remote_service_api" mapstructure:"remote_service_api"`
	OrgName             string          `yaml:"org_name" mapstructure:"org_name"`
	EnvName             string          `yaml:"env_name" mapstructure:"env_name"`
	Key                 string          `yaml:"key,omitempty" mapstructure:"key,omitempty"`
	Secret              string          `yaml:"secret,omitempty" mapstructure:"secret,omitempty"`
	ClientTimeout       time.Duration   `yaml:"client_timeout,omitempty" mapstructure:"client_timeout,omitempty"`
	TLS                 TLSClientSpec   `yaml:"tls,omitempty" mapstructure:"tls,omitempty"`
	PrivateKey          *rsa.PrivateKey `yaml:"-"`
	PrivateKeyID        string          `yaml:"-"`
	JWKS                jwk.Set         `yaml:"-"`
	InternalJWTDuration time.Duration   `yaml:"-"`
	InternalJWTRefresh  time.Duration   `yaml:"-"`
}

func (t *Tenant) IsMultitenant() bool {
	return t.EnvName == "*"
}

// Products is products-related config
type Products struct {
	RefreshRate time.Duration `yaml:"refresh_rate,omitempty" json:"refresh_rate,omitempty" mapstructure:"refresh_rate,omitempty"`
}

// Analytics is analytics-related config
type Analytics struct {
	LegacyEndpoint     bool                `yaml:"legacy_endpoint,omitempty" mapstructure:"legacy_endpoint,omitempty"`
	FileLimit          int                 `yaml:"file_limit,omitempty" mapstructure:"file_limit,omitempty"`
	SendChannelSize    int                 `yaml:"send_channel_size,omitempty" mapstructure:"send_channel_size,omitempty"`
	CollectionInterval time.Duration       `yaml:"collection_interval,omitempty" mapstructure:"collection_interval,omitempty"`
	CredentialsJSON    []byte              `yaml:"-"`
	Credentials        *google.Credentials `yaml:"-"`
}

// Auth is auth-related config
type Auth struct {
	APIKeyClaim           string        `yaml:"api_key_claim,omitempty" mapstructure:"api_key_claim,omitempty"`
	APIKeyCacheDuration   time.Duration `yaml:"api_key_cache_duration,omitempty" mapstructure:"api_key_cache_duration,omitempty"`
	APIKeyHeader          string        `yaml:"api_key_header,omitempty" mapstructure:"api_key_header,omitempty"`
	APIHeader             string        `yaml:"api_header,omitempty" mapstructure:"api_header,omitempty"`
	AllowUnauthorized     bool          `yaml:"allow_unauthorized,omitempty" mapstructure:"allow_unauthorized,omitempty"`
	JWTProviderKey        string        `yaml:"jwt_provider_key,omitempty" mapstructure:"jwt_provider_key,omitempty"`
	AppendMetadataHeaders bool          `yaml:"append_metadata_headers,omitempty" mapstructure:"append_metadata_headers,omitempty"`
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

	for _, f := range c.EnvironmentSpecs.References {
		if err := c.loadEnvironmentSpec(f); err != nil {
			return err
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

// loadEnvironmentSpec unmarshals the given file content into an EnvironmentSpec
// and appends it to c.EnvironmentSpecs.Inline
func (c *Config) loadEnvironmentSpec(f string) error {
	log.Debugf("reading environment config from: %s", f)
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	ec := EnvironmentSpec{}
	if err := yaml.Unmarshal(data, &ec); err != nil {
		return err
	}
	c.EnvironmentSpecs.Inline = append(c.EnvironmentSpecs.Inline, ec)

	return nil
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
	return errorset.Append(errs, ValidateEnvironmentSpecs(c.EnvironmentSpecs.Inline))
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
