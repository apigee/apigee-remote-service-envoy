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
		Tenant: TenantConfig{
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

	c := DefaultConfig()
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

	c := DefaultConfig()
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

	c := DefaultConfig()
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

	c := DefaultConfig()
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

	c = DefaultConfig()
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
	c := DefaultConfig()
	if err := c.Load(tf.Name(), "", credDir, true); err != nil {
		t.Error(err)
	}

	// cache original GOOGLE_APPLICATION_CREDENTIALS for recoverage
	oldEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", oldEnv)

	// set valid GOOGLE_APPLICATION_CREDENTIALS
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credFile)
	c = DefaultConfig()
	if err := c.Load(tf.Name(), "", "", true); err != nil {
		t.Error(err)
	}

	// no analytics credentials given and invalid config
	// explicitly set invalid GOOGLE_APPLICATION_CREDENTIALS to avoid
	// any interference from the test environment
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "not valid")
	c = DefaultConfig()
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
	c = DefaultConfig()
	err = c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
	if string(c.Analytics.CredentialsJSON) != `{"type": "service_account"}` {
		t.Errorf("want the analytics credentials to be rolled back")
	}

	// invalid path to analytics credentials
	c = DefaultConfig()
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

	c := DefaultConfig()
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
	c = DefaultConfig()
	if err := c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true); err == nil {
		t.Errorf("c.Load() should have given error on bad private key")
	}

	os.Setenv(RemoteServiceKey, string(pkBytes))
	os.Setenv(RemoteServiceJWKS, "not a jwks")
	c = DefaultConfig()
	if err := c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true); err == nil {
		t.Errorf("c.Load() should have given error on bad jwks")
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
	config := DefaultConfig()
	config.Tenant = TenantConfig{
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

func TestUnmarshalAuthenticationRequirementYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *AuthenticationRequirement
	}{
		{
			desc: "valid jwt",
			data: []byte(`
jwt:
  name: foo
  issuer: bar
  in:
  - header: header
  remote_jwks:
    url: url
    cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: JWTAuthentication{
					Name:       "foo",
					Issuer:     "bar",
					In:         []HTTPParameter{{Match: Header("header")}},
					JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
				},
			},
		},
		{
			desc: "valid any enclosing jwt",
			data: []byte(`
any:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
- jwt:
    name: bar
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url2
      cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []HTTPParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid all enclosing jwt",
			data: []byte(`
all:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
- jwt:
    name: bar
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url2
      cache_duration: 1h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "foo",
							Issuer:     "bar",
							In:         []HTTPParameter{{Match: Header("header")}},
							JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
						},
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bar",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
						},
					},
				}),
			},
		},
		{
			desc: "valid any enclosing all and jwt",
			data: []byte(`
any:
- all:
  - jwt:
      name: foo
      issuer: bar
      in:
      - header: header
      remote_jwks:
        url: url1
        cache_duration: 1h
  - jwt:
      name: bar
      issuer: foo
      in:
      - query: query
      remote_jwks:
        url: url2
        cache_duration: 1h
- jwt:
    name: bac
    issuer: foo
    in:
    - query: query
    remote_jwks:
      url: url3
      cache_duration: 2h
`),
			want: &AuthenticationRequirement{
				AuthenticationRequirements: AnyAuthenticationRequirements([]AuthenticationRequirement{
					{
						AuthenticationRequirements: AllAuthenticationRequirements([]AuthenticationRequirement{
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "foo",
									Issuer:     "bar",
									In:         []HTTPParameter{{Match: Header("header")}},
									JWKSSource: RemoteJWKS{URL: "url1", CacheDuration: time.Hour},
								},
							},
							{
								AuthenticationRequirements: JWTAuthentication{
									Name:       "bar",
									Issuer:     "foo",
									In:         []HTTPParameter{{Match: Query("query")}},
									JWKSSource: RemoteJWKS{URL: "url2", CacheDuration: time.Hour},
								},
							},
						}),
					},
					{
						AuthenticationRequirements: JWTAuthentication{
							Name:       "bac",
							Issuer:     "foo",
							In:         []HTTPParameter{{Match: Query("query")}},
							JWKSSource: RemoteJWKS{URL: "url3", CacheDuration: 2 * time.Hour},
						},
					},
				}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			a := &AuthenticationRequirement{}
			if err := yaml.Unmarshal(test.data, a); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, a); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected AuthenticationRequirement diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalAuthenticationRequirementYAMLError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc: "any and jwt coexist",
			data: []byte(`
any:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
jwt:
  name: bar
  issuer: foo
  in:
  - query: query
  remote_jwks:
    url: url2
    cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
		{
			desc: "all and jwt coexist",
			data: []byte(`
all:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
jwt:
  name: bar
  issuer: foo
  in:
  - query: query
  remote_jwks:
    url: url2
    cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
		{
			desc: "all and any coexist",
			data: []byte(`
all:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
any:
- jwt:
    name: foo
    issuer: bar
    in:
    - header: header
    remote_jwks:
      url: url1
      cache_duration: 1h
`),
			wantErr: "precisely one of jwt, any or all should be set",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			a := &AuthenticationRequirement{}
			if err := yaml.Unmarshal(test.data, a); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, want %s", test.wantErr)
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestUnmarshalJWTAuthenticationYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *JWTAuthentication
	}{
		{
			desc: "valid remote_jwks",
			data: []byte(`
name: foo
issuer: bar
in:
- header: header
remote_jwks:
  url: url
  cache_duration: 1h
`),
			want: &JWTAuthentication{
				Name:   "foo",
				Issuer: "bar",
				In: []HTTPParameter{
					{
						Match: Header("header"),
					},
				},
				JWKSSource: RemoteJWKS{
					URL:           "url",
					CacheDuration: time.Hour,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			j := &JWTAuthentication{}
			if err := yaml.Unmarshal(test.data, j); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, j); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected JWTAuthentication diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalHTTPParameterYAML(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *HTTPParameter
	}{
		{
			desc: "valid http parameter with header",
			data: []byte(`header: header`),
			want: &HTTPParameter{
				Match: Header("header"),
			},
		},
		{
			desc: "valid http parameter with query",
			data: []byte(`query: query`),
			want: &HTTPParameter{
				Match: Query("query"),
			},
		},
		{
			desc: "valid http parameter with jwt claim",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
`),
			want: &HTTPParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        "bar",
				},
			},
		},
		{
			desc: "valid http parameter with jwt claim and transformation",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
transformation:
  template: temp
  substitution: sub
`),
			want: &HTTPParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        "bar",
				},
				Transformation: StringTransformation{
					Template:     "temp",
					Substitution: "sub",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := yaml.Unmarshal(test.data, p); err != nil {
				t.Errorf("yaml.Unmarshal() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, p); diff != "" {
				t.Errorf("yaml.Unmarshal() results in unexpected HTTPParamter diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalHTTPParameterJSON(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want *HTTPParameter
	}{
		{
			desc: "valid http parameter with header",
			data: []byte(`{"header": "header"}`),
			want: &HTTPParameter{
				Match: Header("header"),
			},
		},
		{
			desc: "valid http parameter with query",
			data: []byte(`{"query": "query"}`),
			want: &HTTPParameter{
				Match: Query("query"),
			},
		},
		{
			desc: "valid http parameter with jwt claim",
			data: []byte(`
{
	"jwt_claim": {
		"requirement": "foo",
		"name": "bar"
	}
}
`),
			want: &HTTPParameter{
				Match: JWTClaim{
					Requirement: "foo",
					Name:        "bar",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := p.UnmarshalJSON(test.data); err != nil {
				t.Errorf("p.UnmarshalJSON() returns unexpected: %v", err)
			}
			if diff := cmp.Diff(test.want, p); diff != "" {
				t.Errorf("p.UnmarshalJSON() results in unexpected HTTPParamter diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalHTTPParameterYAMLError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc: "transformation in bad format",
			data: []byte(`
header: header
transformation: bad
`),
		},
		{
			desc: "jwt_claim in bad format",
			data: []byte(`
jwt_claim: bad
`),
		},
		{
			desc: "jwt claim and header coexist",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
header: header
`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "jwt claim and query coexist",
			data: []byte(`
jwt_claim:
  requirement: foo
  name: bar
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "header and query coexist",
			data: []byte(`
header: header
query: query
`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := yaml.Unmarshal(test.data, p); err == nil {
				t.Errorf("yaml.Unmarshal() returns no error, want %s", test.wantErr)
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("yaml.Unmarshal() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestUnmarshalHTTPParameterJSONError(t *testing.T) {
	tests := []struct {
		desc    string
		data    []byte
		wantErr string
	}{
		{
			desc:    "no match",
			data:    []byte(`{}`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "transformation in bad format",
			data: []byte(`
{
	"header": "header",
	"transformation": "bad"
}`),
		},
		{
			desc: "jwt_claim in bad format",
			data: []byte(`
{
	"jwt_claim": "bad"
}`),
		},
		{
			desc: "jwt claim and header coexist",
			data: []byte(`
{
	"jwt_claim": {
		"requirement": "foo",
		"name": "bar"
	},
	"header": "header"
}`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "jwt claim and query coexist",
			data: []byte(`
{
	"jwt_claim": {
		"requirement": "foo",
		"name": "bar"
	},
	"query": "query"
}`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
		{
			desc: "header and query coexist",
			data: []byte(`
{
	"header": "header",
	"query": "query"
}`),
			wantErr: "precisely one header, query or jwt_claim should be set",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			p := &HTTPParameter{}
			if err := p.UnmarshalJSON(test.data); err == nil {
				t.Errorf("p.UnmarshalJSON() returns no error, want %s", test.wantErr)
			} else if test.wantErr != "" && err.Error() != test.wantErr {
				t.Errorf("p.UnmarshalJSON() returns error %v, want %s", err, test.wantErr)
			}
		})
	}
}

func TestAuthenticationRequirementTypes(t *testing.T) {
	j := JWTAuthentication{}
	j.authenticationRequirements()

	any := AnyAuthenticationRequirements{}
	any.authenticationRequirements()

	all := AllAuthenticationRequirements{}
	all.authenticationRequirements()
}

func TestJWKSSourceTypes(t *testing.T) {
	j := RemoteJWKS{}
	j.jwksSource()
}

func TestParamMatchTypes(t *testing.T) {
	h := Header("header")
	h.paramMatch()

	q := Query("query")
	q.paramMatch()

	j := JWTClaim{}
	j.paramMatch()
}

func TestMultitenant(t *testing.T) {
	tests := []struct {
		desc string
		tc   TenantConfig
		want bool
	}{
		{
			desc: "multitenant",
			tc: TenantConfig{
				EnvName: "*",
			},
			want: true,
		},
		{
			desc: "not multitenant",
			tc: TenantConfig{
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
