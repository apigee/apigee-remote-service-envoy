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
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfig returns a config with defaults set
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			TempDir:                   "/tmp/apigee-istio",
			KeepAliveMaxConnectionAge: 10 * time.Minute,
		},
		Tenant: TenantConfig{
			ClientTimeout: 30 * time.Second,
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
	TempDir                   string        `yaml:"temp_dir,omitempty"`
	KeepAliveMaxConnectionAge time.Duration `yaml:"keep_alive_max_connection_age,omitempty"`
}

// TenantConfig is config relating to an Apigee tentant
type TenantConfig struct {
	ManagementAPI          string        `yaml:"management_api,omitempty"`
	RemoteServiceAPI       string        `yaml:"remote_service_api"`
	FluentdConfigFile      string        `yaml:"fluentd_config_file,omitempty"`
	OrgName                string        `yaml:"org_name"`
	EnvName                string        `yaml:"env_name"`
	Key                    string        `yaml:"key"`
	Secret                 string        `yaml:"secret"`
	ClientTimeout          time.Duration `yaml:"client_timeout,omitempty"`
	AllowUnverifiedSSLCert bool          `yaml:"allow_unverified_ssl_cert,omitempty"`
}

// ProductsConfig is products-related config
type ProductsConfig struct {
	RefreshRate time.Duration `yaml:"refresh_rate,omitempty"`
}

// AnalyticsConfig is analytics-related config
type AnalyticsConfig struct {
	LegacyEndpoint     bool          `yaml:"legacy_endpoint,omitempty"`
	FileLimit          int           `yaml:"file_limit,omitempty"`
	SendChannelSize    int           `yaml:"send_channel_size,omitempty"`
	CollectionInterval time.Duration `yaml:"collection_interval,omitempty"`
}

// AuthConfig is auth-related config
type AuthConfig struct {
	APIKeyClaim         string        `yaml:"api_key_claim,omitempty"`
	APIKeyCacheDuration time.Duration `yaml:"api_key_cache_duration,omitempty"`
	JWKSPollInterval    time.Duration `yaml:"jwks_poll_interval,omitempty"`
}

// Load config
func (c *Config) Load(file string) error {
	yamlFile, err := ioutil.ReadFile(file)
	if err == nil {
		err = yaml.Unmarshal(yamlFile, c)
	}
	return err
}

// # Example Config file
// global:
// 	 temp_dir: /tmp/apigee-istio
//   keep_alive_max_connection_age: 10m
// tenant:
//   management_api: https://istioservices.apigee.net/edgemicro
//   remote_service_api: https://myorg-test.apigee.net/istio-auth
//   fluentd_config_file: /opt/apigee/customer/default.properties
//   org_name: myorg
//   env_name: test
//   key: mykey
//   secret: mysecret
//   client_timeout: 30s
//   allow_Unverified_ssl_cert: false
// products:
//   refresh_rate: 2m
// analytics:
//   legacy_endpoint: false
//   file_limit: 1024
// auth:
//   api_key_claim:
//   api_key_cache_duration: 30m
