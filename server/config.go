// Copyright 2020 Google LLC
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

package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v3"
)

const (
	// LegacySaaSInternalBase is the internal API used for auth and analytics
	LegacySaaSInternalBase = "https://istioservices.apigee.net/edgemicro"

	// ServiceAccount is the json file with application credentials
	ServiceAccount = "client_secret.json"
)

// DefaultConfig returns a config with defaults set
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			TempDir:                   "/tmp/apigee-istio",
			KeepAliveMaxConnectionAge: 10 * time.Minute,
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
			TargetHeader:        ":authority",
			RejectUnauthorized:  false,
			JWTProviderKey:      "apigee",
		},
	}
}

// Config is all config
type Config struct {
	Global    GlobalConfig    `yaml:"global,omitempty"`
	Tenant    TenantConfig    `yaml:"tenant,omitempty"`
	Products  ProductsConfig  `yaml:"products,omitempty"`
	Analytics AnalyticsConfig `yaml:"analytics,omitempty"`
	Auth      AuthConfig      `yaml:"auth,omitempty"`
}

// GlobalConfig is global configuration for the server
type GlobalConfig struct {
	APIAddress                string            `yaml:"api_address,omitempty"`
	MetricsAddress            string            `yaml:"metrics_address,omitempty"`
	TempDir                   string            `yaml:"temp_dir,omitempty"`
	KeepAliveMaxConnectionAge time.Duration     `yaml:"keep_alive_max_connection_age,omitempty"`
	TLS                       TLSListenerConfig `yaml:"tls,omitempty"`
	Namespace                 string            `yaml:"-"`
}

// TLSListenerConfig is tls configuration
type TLSListenerConfig struct {
	KeyFile  string `yaml:"key_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty"`
}

// TLSClientConfig is mtls configuration
type TLSClientConfig struct {
	CAFile                 string `yaml:"ca_file,omitempty"`
	KeyFile                string `yaml:"key_file,omitempty"`
	CertFile               string `yaml:"cert_file,omitempty"`
	AllowUnverifiedSSLCert bool   `yaml:"allow_unverified_ssl_cert,omitempty"`
}

// TenantConfig is config relating to an Apigee tentant
type TenantConfig struct {
	InternalAPI            string          `yaml:"internal_api,omitempty"`
	RemoteServiceAPI       string          `yaml:"remote_service_api"`
	OrgName                string          `yaml:"org_name"`
	EnvName                string          `yaml:"env_name"`
	Key                    string          `yaml:"key,omitempty"`
	Secret                 string          `yaml:"secret,omitempty"`
	ClientTimeout          time.Duration   `yaml:"client_timeout,omitempty"`
	AllowUnverifiedSSLCert bool            `yaml:"allow_unverified_ssl_cert,omitempty"`
	PrivateKey             *rsa.PrivateKey `yaml:"-"`
	PrivateKeyID           string          `yaml:"-"`
	JWKS                   *jwk.Set        `yaml:"-"`
	InternalJWTDuration    time.Duration   `yaml:"-"`
	InternalJWTRefresh     time.Duration   `yaml:"-"`
}

// ProductsConfig is products-related config
type ProductsConfig struct {
	RefreshRate time.Duration `yaml:"refresh_rate,omitempty"`
}

// AnalyticsConfig is analytics-related config
type AnalyticsConfig struct {
	LegacyEndpoint     bool            `yaml:"legacy_endpoint,omitempty"`
	FileLimit          int             `yaml:"file_limit,omitempty"`
	SendChannelSize    int             `yaml:"send_channel_size,omitempty"`
	CollectionInterval time.Duration   `yaml:"collection_interval,omitempty"`
	FluentdEndpoint    string          `yaml:"fluentd_endpoint,omitempty"`
	TLS                TLSClientConfig `yaml:"tls,omitempty"`
	CredentialsJSON    []byte          `yaml:"-"`
}

// AuthConfig is auth-related config
type AuthConfig struct {
	APIKeyClaim         string        `yaml:"api_key_claim,omitempty"`
	APIKeyCacheDuration time.Duration `yaml:"api_key_cache_duration,omitempty"`
	JWKSPollInterval    time.Duration `yaml:"jwks_poll_interval,omitempty"`
	APIKeyHeader        string        `yaml:"api_key_header,omitempty"`
	TargetHeader        string        `yaml:"target_header,omitempty"`
	RejectUnauthorized  bool          `yaml:"reject_unauthorized,omitempty"`
	JWTProviderKey      string        `yaml:"-"`
}

// Load config
func (c *Config) Load(configFile, policySecretPath, analyticsSecretPath string) error {
	log.Debugf("reading config from: %s", configFile)
	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}

	// attempt load from CRD
	var key, kidProps, jwksBytes []byte
	configMap := &ConfigMapCRD{}
	secret := &SecretCRD{}
	var configBytes []byte
	decoder := yaml.NewDecoder(bytes.NewReader(yamlFile))
	if decoder.Decode(configMap) == nil && configMap.Kind == "ConfigMap" {
		configBytes = []byte(configMap.Data["config.yaml"])
		if configBytes != nil {
			if err = yaml.Unmarshal(configBytes, c); err != nil {
				return errors.Wrap(err, "bad config file format")
			}
			c.Global.Namespace = configMap.Metadata.Namespace
		}

		if decoder.Decode(secret) == nil && secret.Kind == "Secret" {
			key, _ = base64.StdEncoding.DecodeString(secret.Data[SecretPrivateKey])
			kidProps, _ = base64.StdEncoding.DecodeString(secret.Data[SecretPropsKey])
			jwksBytes, _ = base64.StdEncoding.DecodeString(secret.Data[SecretJKWSKey])

			// TODO: DecodeString() never returns nil even on error
			// the above check is not effective
			if key == nil || kidProps == nil || jwksBytes == nil { // all or nothing
				key = nil
				kidProps = nil
				jwksBytes = nil
			}
		}

		if decoder.Decode(secret) == nil && secret.Kind == "Secret" {
			c.Analytics.CredentialsJSON, _ = base64.StdEncoding.DecodeString(secret.Data[ServiceAccount])
		}
	}

	// didn't load, try as simple config file
	if configBytes == nil {
		if err = yaml.Unmarshal(yamlFile, c); err != nil {
			return errors.Wrap(err, "bad config file format")
		}
	}

	if err = c.Validate(); err != nil {
		return err
	}

	// if no Secret, try files in policySecretPath
	if c.IsGCPManaged() {

		if policySecretPath != "" && key == nil {
			if key, err = ioutil.ReadFile(path.Join(policySecretPath, SecretPrivateKey)); err == nil {
				if kidProps, err = ioutil.ReadFile(path.Join(policySecretPath, SecretPropsKey)); err == nil {
					jwksBytes, err = ioutil.ReadFile(path.Join(policySecretPath, SecretJKWSKey))
				}
			}
		}
		if err != nil {
			return err
		}

		props, err := ReadProperties(bytes.NewReader(kidProps))
		if err != nil {
			return err
		}

		c.Tenant.PrivateKeyID = props[SecretPropsKIDKey]
		jwks := &jwk.Set{}
		if err = json.Unmarshal(jwksBytes, jwks); err == nil {
			c.Tenant.JWKS = jwks
			if c.Tenant.PrivateKey, err = loadPrivateKey(key, ""); err != nil {
				return err
			}
		}

		if analyticsSecretPath != "" && c.Analytics.CredentialsJSON == nil {
			if c.Analytics.CredentialsJSON, err = ioutil.ReadFile(path.Join(analyticsSecretPath, ServiceAccount)); err != nil {
				return err
			}
		}
	}

	return c.Validate()
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
func (c *Config) Validate() error {
	var errs error
	if c.Tenant.RemoteServiceAPI == "" {
		errs = multierror.Append(errs, fmt.Errorf("tenant.remote_service_api is required"))
	}
	if c.Tenant.InternalAPI == "" && c.Analytics.FluentdEndpoint == "" && c.Analytics.CredentialsJSON == nil {
		errs = multierror.Append(errs, fmt.Errorf("tenant.internal_api or tenant.analytics.fluentd_endpoint is required if no service account"))
	}
	if c.Tenant.OrgName == "" {
		errs = multierror.Append(errs, fmt.Errorf("tenant.org_name is required"))
	}
	if c.Tenant.EnvName == "" {
		errs = multierror.Append(errs, fmt.Errorf("tenant.env_name is required"))
	}
	if (c.Global.TLS.CertFile != "" || c.Global.TLS.KeyFile != "") &&
		(c.Global.TLS.CertFile == "" || c.Global.TLS.KeyFile == "") {
		errs = multierror.Append(errs, fmt.Errorf("global.tls.cert_file and global.tls.key_file are both required if either are present"))
	}
	if (c.Analytics.TLS.CAFile != "" || c.Analytics.TLS.CertFile != "" || c.Analytics.TLS.KeyFile != "") &&
		(c.Analytics.TLS.CAFile == "" || c.Analytics.TLS.CertFile == "" || c.Analytics.TLS.KeyFile == "") {
		errs = multierror.Append(errs, fmt.Errorf("all analytics.tls options are required if any are present"))
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
	SecretJKWSKey     = "remote-service.crt"        // hybrid treats .crt as blob
	SecretPrivateKey  = "remote-service.key"        // private key
	SecretPropsKey    = "remote-service.properties" // java properties format: %s=%s
	SecretPropsKIDKey = "kid"
)
