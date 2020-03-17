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

	"gopkg.in/yaml.v2"
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
	Global    GlobalConfig    `yaml:"global"`
	Tenant    TenantConfig    `yaml:"tenant"`
	Products  ProductsConfig  `yaml:"products"`
	Analytics AnalyticsConfig `yaml:"analytics"`
	Auth      AuthConfig      `yaml:"auth"`
}

// GlobalConfig is global configuration for the server
type GlobalConfig struct {
	TempDir                   string        `yaml:"temp_dir"`
	KeepAliveMaxConnectionAge time.Duration `yaml:"keep_alive_max_connection_age"`
}

// TenantConfig is config relating to an Apigee tentant
type TenantConfig struct {
	ApigeeBase             string        `yaml:"apigee_base"`
	CustomerBase           string        `yaml:"customer_base"`
	HybridConfigFile       string        `yaml:"hybrid_config"`
	OrgName                string        `yaml:"org_name"`
	EnvName                string        `yaml:"env_name"`
	Key                    string        `yaml:"key"`
	Secret                 string        `yaml:"secret"`
	ClientTimeout          time.Duration `yaml:"client_timeout"`
	AllowUnverifiedSSLCert bool          `yaml:"allow_unverified_ssl_cert"`
}

// ProductsConfig is products-related config
type ProductsConfig struct {
	RefreshRate time.Duration `yaml:"refresh_rate"`
}

// AnalyticsConfig is analytics-related config
type AnalyticsConfig struct {
	LegacyEndpoint     bool          `yaml:"legacy_endpoint"`
	FileLimit          int           `yaml:"file_limit"`
	SendChannelSize    int           `yaml:"send_channel_size"`
	CollectionInterval time.Duration `yaml:"collection_interval"`
}

// AuthConfig is auth-related config
type AuthConfig struct {
	APIKeyClaim         string        `yaml:"api_key_claim"`
	APIKeyCacheDuration time.Duration `yaml:"api_key_cache_duration"`
	JWKSPollInterval    time.Duration `yaml:"jwks_poll_interval"`
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
//   apigee_base: https://istioservices.apigee.net/edgemicro
//   customer_base: https://myorg-test.apigee.net/istio-auth
//   hybrid_config: /opt/apigee/customer/default.properties
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
