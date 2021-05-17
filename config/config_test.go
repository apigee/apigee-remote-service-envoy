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

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

const (
	allConfigOptions = `
global:
  temp_dir: /tmp/apigee-istio
  keep_alive_max_connection_age: 10m
  api_address: :5000
  metrics_address: :5001
  tls:
    cert_file: tls.crt
    key_file: tls.key
tenant:
  internal_api: https://istioservices.apigee.net/edgemicro
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env
  key: mykey
  secret: mysecret
  client_timeout: 30s
  tls:
    ca_file: /opt/apigee/tls/ca.crt
    cert_file: /opt/apigee/tls/tls.crt
    key_file: /opt/apigee/tls/tls.key
    allow_unverified_ssl_cert: false
products:
  refresh_rate: 2m
analytics:
  legacy_endpoint: false
  file_limit: 1024
  send_channel_size: 10
  collection_interval: 10s
auth:
  api_key_claim: claim
  api_key_cache_duration: 30m
  api_key_header: x-api-key
  api_header: :authority
  allow_unauthorized: false
  jwt_provider_key: apigee
  append_metadata_headers: true`

	configMapConfigKey = "config.yaml"
)

func TestPlatformDetect(t *testing.T) {
	// OPDK
	config := &Config{
		Tenant: Tenant{
			InternalAPI: "x",
		},
	}
	if config.IsGCPManaged() {
		t.Fatalf("expected !config.isGCPExperience")
	}
	if config.IsApigeeManaged() {
		t.Fatalf("expected !config.IsApigeeManaged")
	}
	if !config.IsOPDK() {
		t.Fatalf("expected config.IsOPDK")
	}

	// Legacy SaaS
	config.Tenant.InternalAPI = LegacySaaSInternalBase
	if config.IsGCPManaged() {
		t.Fatalf("expected !config.isGCPExperience")
	}
	if !config.IsApigeeManaged() {
		t.Fatalf("expected config.IsApigeeManaged")
	}
	if config.IsOPDK() {
		t.Fatalf("expected !config.IsOPDK")
	}

	// Legacy SaaS
	config.Tenant.InternalAPI = LegacySaaSInternalBase
	if config.IsGCPManaged() {
		t.Fatalf("expected !config.isGCPExperience")
	}
	if !config.IsApigeeManaged() {
		t.Fatalf("expected config.IsApigeeManaged")
	}
	if config.IsOPDK() {
		t.Fatalf("expected !config.IsOPDK")
	}

	// GCP
	config.Tenant.InternalAPI = ""
	if !config.IsGCPManaged() {
		t.Fatalf("expected config.isGCPExperience")
	}
	if config.IsApigeeManaged() {
		t.Fatalf("expected !config.IsApigeeManaged")
	}
	if config.IsOPDK() {
		t.Fatalf("expected !config.IsOPDK")
	}

}

func TestHybridSingleFile(t *testing.T) {
	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	const config = `
    tenant:
      remote_service_api: https://org-test.apigee.net/remote-service
      org_name: org
      env_name: env`
	configCRD := makeConfigCRD(config)
	policySecretCRD, err := makePolicySecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	analyticsSecretCRD, err := makeAnalyaticsSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err := makeYAML(configCRD, policySecretCRD, analyticsSecretCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.Load(tf.Name(), "xxx", DefaultAnalyticsSecretPath, true); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "my kid")
}

func TestMultifileConfig(t *testing.T) {
	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	configCRD, secretCRD, _, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tf.WriteString(configCRD.Data[configMapConfigKey]); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	secretDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(secretDir)

	for k, v := range secretCRD.Data {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path.Join(secretDir, k), data, os.ModePerm); err != nil {
			t.Fatal(err)
		}
	}

	c := Default()
	if err := c.Load(tf.Name(), secretDir, "", false); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "my kid")
}

func TestIncompletePolicySecret(t *testing.T) {
	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	configCRD, policySecretCRD, _, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

	// remove the JWKS
	delete(policySecretCRD.Data, SecretJWKSKey)

	configMapYAML, err := makeYAML(configCRD, policySecretCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.Load(tf.Name(), "", "", false); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "")
}

func TestLoadOrders(t *testing.T) {
	configCRD, policySecretCRD, analyticsSecretCRD, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// put ConfigMap in the end
	configMapYAML, err := makeYAML(policySecretCRD, analyticsSecretCRD, configCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.Load(tf.Name(), "", "", true); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "my kid")

	tf, err = os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// put ConfigMap in the middle
	configMapYAML, err = makeYAML(policySecretCRD, configCRD, analyticsSecretCRD)
	if err != nil {
		t.Fatal(err)
	}

	err = tf.Truncate(0) // re-create the yaml file
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c = Default()
	if err := c.Load(tf.Name(), "", "", true); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "my kid")
}

func TestIgnoreIrrelevantConfig(t *testing.T) {
	configCRD, policySecretCRD, analyticsSecretCRD, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	otherCRD := &ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
		Metadata: Metadata{
			Name:      "apigee-service-account",
			Namespace: "apigee",
		},
	}

	// put ConfigMap in the end
	configMapYAML, err := makeYAML(configCRD, policySecretCRD, analyticsSecretCRD, otherCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	if err := c.Load(tf.Name(), "xxx", "", true); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLegacyConfig(t *testing.T) {
	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	configCRD := makeConfigCRD(allConfigOptions)
	secretCRD, err := makePolicySecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err := makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	if err := c.Load(tf.Name(), "xxx", "", true); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Global.Namespace, "apigee")
	equal(t, c.Global.TempDir, "/tmp/apigee-istio")
}

func TestLoadAnalytics(t *testing.T) {
	const config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env`

	configCRD := makeConfigCRD(config)

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// put ConfigMap in the end
	configMapYAML, err := makeYAML(configCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	credDir, err := os.MkdirTemp("", "analytics-secret")
	if err != nil {
		t.Fatalf("%v", err)
	}
	credFile := path.Join(credDir, ServiceAccount)
	if err := os.WriteFile(credFile, testutil.FakeServiceAccount(), 0644); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.RemoveAll(credDir)

	// valid path to analytics credentials
	c := Default()
	if err := c.Load(tf.Name(), "", credDir, true); err != nil {
		t.Error(err)
	}

	// cache original GOOGLE_APPLICATION_CREDENTIALS for recoverage
	oldEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", oldEnv)

	// set valid GOOGLE_APPLICATION_CREDENTIALS
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credFile)
	c = Default()
	if err := c.Load(tf.Name(), "", "", true); err != nil {
		t.Error(err)
	}

	// no analytics credentials given and invalid config
	// explicitly set invalid GOOGLE_APPLICATION_CREDENTIALS to avoid
	// any interference from the test environment
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "not valid")
	c = Default()
	err = c.Load(tf.Name(), "", "", true)
	if err == nil {
		t.Fatal("want error got none")
	}

	wantErrs := []string{
		"tenant.internal_api is required if analytics credentials not given",
	}
	merr := err.(*errorset.Error)
	if merr.Len() != len(wantErrs) {
		t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
	}

	errs := merr.Errors
	for i, e := range errs {
		equal(t, e.Error(), wantErrs[i])
	}
}

func TestAnalyticsRollback(t *testing.T) {
	configCRD, policySecretCRD, analyticsSecretCRD, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// put ConfigMap in the end
	configMapYAML, err := makeYAML(policySecretCRD, analyticsSecretCRD, configCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	var c *Config

	// analytics to be rolled back to that from config file
	c = Default()
	err = c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
	if string(c.Analytics.CredentialsJSON) != `{"type": "service_account"}` {
		t.Errorf("want the analytics credentials to be rolled back")
	}

	// invalid path to analytics credentials
	c = Default()
	err = c.Load(tf.Name(), "", "no such path", true)
	if err == nil {
		t.Error("want error got none")
	} else {
		equal(t, err.Error(), "open no such path/client_secret.json: no such file or directory")
	}
}

func TestInvalidConfig(t *testing.T) {
	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// a bad simple config
	if _, err := tf.WriteString("not a good yaml"); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	if err := c.Load(tf.Name(), "", "", true); err == nil {
		t.Error("should have gotten error")
	}

	tf, err = os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	configCRD := makeConfigCRD("not a good yaml")
	configMapYAML, err := makeYAML(configCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c = &Config{}
	if err := c.Load(tf.Name(), "", "", true); err == nil {
		t.Error("should have gotten error")
	}
}

func TestLoadFromEnvironmentVariables(t *testing.T) {
	kid := "another kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{Type: util.PEMKeyType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	os.Setenv(RemoteServiceKey, string(pkBytes))
	defer os.Setenv(RemoteServiceKey, "")

	os.Setenv(RemoteServiceJWKS, string(jwksBuf))
	defer os.Setenv(RemoteServiceJWKS, "")

	os.Setenv(RemoteServiceKeyID, kid)
	defer os.Setenv(RemoteServiceKeyID, "")

	fakeSA := string(testutil.FakeServiceAccount())
	os.Setenv(AnalyticsCredentials, fakeSA)
	defer os.Setenv(AnalyticsCredentials, "")

	os.Setenv(envVarKey("GLOBAL.NAMESPACE"), "test-namespace")
	defer os.Setenv(envVarKey("GLOBAL.NAMESPACE"), "")

	os.Setenv(envVarKey("TENANT.ORG_NAME"), "test-org")
	defer os.Setenv(envVarKey("TENANT.ORG_NAME"), "")

	configCRD, policySecretCRD, _, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// put ConfigMap in the end
	configMapYAML, err := makeYAML(configCRD, policySecretCRD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
	// should be from the environment variables
	if c.Tenant.PrivateKeyID != kid {
		t.Errorf("c.Tenant.PrivateKeyID = %s, want %s", c.Tenant.PrivateKeyID, kid)
	}
	if c.Tenant.OrgName != "test-org" {
		t.Errorf("c.Tenant.OrgName = %s, want %s", c.Tenant.OrgName, "test-org")
	}
	if c.Global.Namespace != "test-namespace" {
		t.Errorf("c.Global.Namespace = %s, want %s", c.Global.Namespace, "test-namespace")
	}

	if s := string(c.Analytics.CredentialsJSON); s != fakeSA {
		t.Errorf("string(c.Analytics.CredentialsJSON) = %s, want %s", s, fakeSA)
	}

	os.Setenv(RemoteServiceKey, "not a private key")
	c = Default()
	if err := c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true); err == nil {
		t.Errorf("c.Load() should have given error on bad private key")
	}

	os.Setenv(RemoteServiceKey, string(pkBytes))
	os.Setenv(RemoteServiceJWKS, "not a jwks")
	c = Default()
	if err := c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true); err == nil {
		t.Errorf("c.Load() should have given error on bad jwks")
	}
}

func TestLoadEnvironmentSpecs(t *testing.T) {
	tests := []struct {
		desc        string
		filename    string
		wantEnvSpec EnvironmentSpec
	}{
		{
			desc:     "good config file with references to env config files",
			filename: "./testdata/good_config.yaml",
			wantEnvSpec: EnvironmentSpec{
				ID: "good-env-config",
				APIs: []APISpec{
					{
						ID:       "api-1",
						BasePath: "/v1",
						Authentication: AuthenticationRequirement{
							Requirements: JWTAuthentication{
								Name:       "foo",
								Issuer:     "bar",
								JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
								In:         []APIOperationParameter{{Match: Header("header")}},
							},
						},
						ConsumerAuthorization: ConsumerAuthorization{
							In: []APIOperationParameter{{Match: Header("x-api-key")}},
						},
						Operations: []APIOperation{
							{
								Name: "op-1",
								HTTPMatches: []HTTPMatch{
									{
										PathTemplate: "/petstore",
										Method:       "GET",
									},
								},
							},
							{
								Name: "op-2",
								HTTPMatches: []HTTPMatch{
									{
										PathTemplate: "/bookshop",
										Method:       "POST",
									},
								},
							},
						},
						HTTPRequestTransforms: HTTPRequestTransformations{
							SetHeaders: map[string]string{
								"x-apigee-route": "route",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			c := &Config{}
			if err := c.Load(test.filename, "", "", false); err != nil {
				t.Errorf("c.Load() returns unexpected: %v", err)
			}
			if l := len(c.EnvironmentSpecs.Inline); l != 1 {
				t.Fatalf("c.Load() results in %d EnvironmentSpec, wanted 1", l)
			}
			if diff := cmp.Diff(test.wantEnvSpec, c.EnvironmentSpecs.Inline[0]); diff != "" {
				t.Errorf("c.Load() results in unexpected EnvironmentSpec diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadEnvironmentSpecsError(t *testing.T) {
	tests := []struct {
		desc     string
		filename string
	}{
		{
			desc:     "bad env config files",
			filename: "./testdata/bad_config_1.yaml",
		},
		{
			desc:     "non-existent env config files",
			filename: "./testdata/bad_config_2.yaml",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			c := &Config{}
			if err := c.Load(test.filename, "", "", false); err == nil {
				t.Errorf("c.Load() returns no error, should have got error")
			}
		})
	}
}

func TestValidate(t *testing.T) {
	// cache original GOOGLE_APPLICATION_CREDENTIALS for recoverage
	oldEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", oldEnv)

	// explicitly set invalid GOOGLE_APPLICATION_CREDENTIALS to avoid
	// any interference from the test environment
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "invalid path")

	c := &Config{}
	var wantErrs []string
	var merr *errorset.Error

	err := c.Validate(true)
	if err == nil {
		t.Fatal("should have gotten errors")
	}

	wantErrs = []string{
		"tenant.remote_service_api is required",
		"tenant.internal_api is required if analytics credentials not given",
		"tenant.org_name is required",
		"tenant.env_name is required",
	}
	merr = err.(*errorset.Error)
	if merr.Len() != len(wantErrs) {
		t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
	}

	for i, e := range merr.Errors {
		equal(t, e.Error(), wantErrs[i])
	}

	err = c.Validate(false)
	if err == nil {
		t.Fatal("should have gotten errors")
	}

	wantErrs = []string{
		"tenant.remote_service_api is required",
		"tenant.org_name is required",
		"tenant.env_name is required",
	}
	merr = err.(*errorset.Error)
	if merr.Len() != len(wantErrs) {
		t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
	}

	for i, e := range merr.Errors {
		equal(t, e.Error(), wantErrs[i])
	}
}

func TestValidateTLS(t *testing.T) {
	config := Default()
	config.Tenant = Tenant{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "env",
		Key:              "key",
		Secret:           "secret",
	}

	opts := [][]string{
		{"x", "", "x", "", ""},
		{"", "x", "", "x", ""},
		{"", "x", "", "", "x"},
		{"", "x", "x", "", "x"},
		{"", "x", "", "x", "x"},
		{"", "x", "x", "x", ""},
	}

	for i, o := range opts {
		t.Logf("round %d", i)
		config.Global.TLS.CertFile = o[0]
		config.Global.TLS.KeyFile = o[1]
		config.Tenant.TLS.CAFile = o[2]
		config.Tenant.TLS.CertFile = o[3]
		config.Tenant.TLS.KeyFile = o[4]

		err := config.Validate(true)
		if err == nil {
			t.Fatal("should have gotten errors")
		}
		wantErrs := []string{
			"global.tls.cert_file and global.tls.key_file are both required if either are present",
			"all tenant.tls options are required if any are present",
		}
		merr := err.(*errorset.Error)
		if merr.Len() != len(wantErrs) {
			t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
		}

		errs := merr.Errors
		for i, e := range errs {
			equal(t, e.Error(), wantErrs[i])
		}
	}
}

func TestMultitenant(t *testing.T) {
	tests := []struct {
		desc string
		tc   Tenant
		want bool
	}{
		{
			desc: "multitenant",
			tc: Tenant{
				EnvName: "*",
			},
			want: true,
		},
		{
			desc: "not multitenant",
			tc: Tenant{
				EnvName: "env",
			},
			want: false,
		},
	}

	for _, test := range tests {
		if got := test.tc.IsMultitenant(); got != test.want {
			t.Errorf("tc.IsMultitenant() = %v, want = %v", got, test.want)
		}
	}
}

func makeConfigCRD(config string) *ConfigMapCRD {
	data := map[string]string{configMapConfigKey: config}
	return &ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: data,
	}
}

func makePolicySecretCRD() (*SecretCRD, error) {
	kid := "my kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		return nil, err
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{Type: util.PEMKeyType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	props := map[string]string{SecretPropsKIDKey: kid}
	propsBuf := new(bytes.Buffer)
	if err := util.WriteProperties(propsBuf, props); err != nil {
		return nil, err
	}

	data := map[string]string{
		SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBuf),
		SecretPrivateKey: base64.StdEncoding.EncodeToString(pkBytes),
		SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
	}

	return &SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "Opaque",
		Metadata: Metadata{
			Name:      "org-env-policy-secret",
			Namespace: "apigee",
		},
		Data: data,
	}, nil
}

func makeAnalyaticsSecretCRD() (*SecretCRD, error) {
	data := map[string]string{
		ServiceAccount: base64.StdEncoding.EncodeToString([]byte(`{"type": "service_account"}`)),
	}

	return &SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "Opaque",
		Metadata: Metadata{
			Name:      "org-env-analytics-secret",
			Namespace: "apigee",
		},
		Data: data,
	}, nil
}

func makeCRDs() (configCRD *ConfigMapCRD, policySecretCRD, analyticsSecretCRD *SecretCRD, err error) {
	const config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env`
	configCRD = makeConfigCRD(config)
	policySecretCRD, err = makePolicySecretCRD()
	if err != nil {
		return nil, nil, nil, err
	}
	analyticsSecretCRD, err = makeAnalyaticsSecretCRD()
	if err != nil {
		return nil, nil, nil, err
	}
	return configCRD, policySecretCRD, analyticsSecretCRD, nil
}

func makeYAML(crds ...interface{}) (string, error) {
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	for _, crd := range crds {
		if err := yamlEncoder.Encode(crd); err != nil {
			return "", err
		}
	}
	return yamlBuffer.String(), nil
}

func equal(t *testing.T, got, want string) {
	if got != want {
		t.Errorf("got: '%s', want: '%s'", got, want)
	}
}
