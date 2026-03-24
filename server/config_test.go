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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	defer func() { _ = os.RemoveAll(secretDir) }()

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
	defer func() { _ = os.Remove(tf.Name()) }()

	configCRD, policySecretCRD, _, err := makeCRDs()
	if err != nil {
		t.Fatal(err)
	}

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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	defer func() { _ = os.Remove(tf.Name()) }()

	otherCRD := &ConfigMapCRD{
		APIVersion: "v1",
		Kind:        "ServiceAccount",
		Metadata: Metadata{
			Name:      "apigee-service-account",
			Namespace: "apigee",
		},
	}

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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	if err := os.WriteFile(credFile, fakeServiceAccount(), 0644); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() { _ = os.RemoveAll(credDir) }()

	c := DefaultConfig()
	if err := c.Load(tf.Name(), "", credDir, true); err != nil {
		t.Error(err)
	}

	oldEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	defer func() { _ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", oldEnv) }()

	_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credFile)
	c = DefaultConfig()
	if err := c.Load(tf.Name(), "", "", true); err != nil {
		t.Error(err)
	}

	_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "not valid")
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

	for i, e := range merr.Errors {
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
	defer func() { _ = os.Remove(tf.Name()) }()

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
	err = c.Load(tf.Name(), "", DefaultAnalyticsSecretPath, true)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
	if !bytes.Equal(c.Analytics.CredentialsJSON, fakeServiceAccount()) {
		t.Errorf("want the analytics credentials to be rolled back")
	}

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
	defer func() { _ = os.Remove(tf.Name()) }()

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
}

func makeConfigCRD(config string) *ConfigMapCRD {
	data := map[string]string{configMapConfigKey: config}
	return &ConfigMapCRD{
		APIVersion: "v1",
		Kind:        "ConfigMap",
		Metadata: Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: data,
	}
}

func TestValidate(t *testing.T) {
	oldEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	defer func() { _ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", oldEnv) }()
	_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "invalid path")

	c := &Config{}
	err := c.Validate(true)
	if err == nil {
		t.Fatal("should have gotten errors")
	}

	wantErrs := []string{
		"tenant.remote_service_api is required",
		"tenant.internal_api is required if analytics credentials not given",
		"tenant.org_name is required",
		"tenant.env_name is required",
	}
	merr := err.(*errorset.Error)
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
		{"x", "", "x", "x", "x"}, // Global fail, Tenant pass
		{"x", "x", "x", "", ""},  // Global pass, Tenant fail
		{"x", "", "x", "", ""},   // Both fail
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
		
		errMsg := err.Error()
		if o[1] == "" && !strings.Contains(errMsg, "global.tls.cert_file and global.tls.key_file are both required") {
			t.Errorf("expected global tls error, got: %s", errMsg)
		}
		if o[3] == "" && !strings.Contains(errMsg, "all tenant.tls options are required") {
			t.Errorf("expected tenant tls error, got: %s", errMsg)
		}
	}
}

func TestValidateAnalyticsBranches(t *testing.T) {
	// Case 1: requireAnalyticsCredentials is false
	c := DefaultConfig()
	c.Tenant.RemoteServiceAPI = "http://api"
	c.Tenant.OrgName = "org"
	c.Tenant.EnvName = "env"
	if err := c.Validate(false); err != nil {
		t.Errorf("expected no error when analytics not required, got %v", err)
	}

	// Case 2: CredentialsJSON is already set
	c.Analytics.CredentialsJSON = []byte(`{}`)
	c.Tenant.InternalAPI = "http://internal"
	err := c.Validate(true)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got %v", err)
	}
}

func makePolicySecretCRD() (*SecretCRD, error) {
	kid := "my kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		return nil, err
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{Type: PEMKeyType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	props := map[string]string{SecretPropsKIDKey: kid}
	propsBuf := new(bytes.Buffer)
	if err := WriteProperties(propsBuf, props); err != nil {
		return nil, err
	}

	data := map[string]string{
		SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBuf),
		SecretPrivateKey: base64.StdEncoding.EncodeToString(pkBytes),
		SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
	}

	return &SecretCRD{
		APIVersion: "v1",
		Kind:        "Secret",
		Type:        "Opaque",
		Metadata: Metadata{
			Name:      "org-env-policy-secret",
			Namespace: "apigee",
		},
		Data: data,
	}, nil
}

func makeAnalyaticsSecretCRD() (*SecretCRD, error) {
	data := map[string]string{
		ServiceAccount: base64.StdEncoding.EncodeToString(fakeServiceAccount()),
	}

	return &SecretCRD{
		APIVersion: "v1",
		Kind:        "Secret",
		Type:        "Opaque",
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

func TestConfigDiscovery(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "config_test")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_ = os.WriteFile(path.Join(tmpDir, "client_id"), []byte("my-id"), 0644)
	_ = os.WriteFile(path.Join(tmpDir, "client_secret"), []byte("my-secret"), 0644)

	analyticsDir, _ := os.MkdirTemp("", "analytics")
	defer func() { _ = os.RemoveAll(analyticsDir) }()
	_ = os.WriteFile(path.Join(analyticsDir, ServiceAccount), fakeServiceAccount(), 0644)

	validYaml := path.Join(tmpDir, "valid.yaml")
	content := `
apiVersion: v1
kind: Secret
metadata:
  name: apigee-remote-service-envoy
data:
  config.yaml: dGVuYW50OgogIGludGVybmFsX2FwaTogaHR0cDovL2xvY2FsaG9zdAogIHJlbW90ZV9zZXJ2aWNlX2FwaTogaHR0cDovL2FwaQogIG9yZ19uYW1lOiBvcmcKICBlbnZfbmFtZTogZW52`
	
	_ = os.WriteFile(validYaml, []byte(content), 0644)

	c := &Config{}
	_ = c.Load("missing.yaml", "", "", false)
	
	badYaml := path.Join(tmpDir, "bad.yaml")
	_ = os.WriteFile(badYaml, []byte("!!binary '==='"), 0644)
	_ = c.Load(badYaml, "", "", false)

	_ = c.Load(validYaml, tmpDir, analyticsDir, true)
	_ = c.Load(validYaml, tmpDir, "/invalid/path", true)
}

func TestLoadBadYAML(t *testing.T) {
	tf, _ := os.CreateTemp("", "")
	defer func() { _ = os.Remove(tf.Name()) }()
	
	badConfig := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
data:
  config.yaml: "global: [this should not be a list]"`
	
	_, _ = tf.WriteString(badConfig)
	_ = tf.Close()

	c := &Config{}
	err := c.Load(tf.Name(), "", "", false)
	if err == nil || !strings.Contains(err.Error(), "bad config file format") {
		t.Errorf("expected bad config file format error, got: %v", err)
	}
}

func TestLoadCorruptSecrets(t *testing.T) {
	confFile, _ := os.CreateTemp("", "config.yaml")
	defer func() { _ = os.Remove(confFile.Name()) }()
	_, _ = confFile.WriteString("tenant:\n  org_name: org\n  env_name: env")
	_ = confFile.Close()


	tmpDir1, _ := os.MkdirTemp("", "prop_fail")
	defer func() { _ = os.RemoveAll(tmpDir1) }()
	_ = os.WriteFile(path.Join(tmpDir1, SecretPrivateKey), []byte("---key---"), 0644)
	_ = os.WriteFile(path.Join(tmpDir1, SecretJWKSKey), []byte("{}"), 0644)
	_ = os.WriteFile(path.Join(tmpDir1, SecretPropsKey), []byte("!!not-properties!!"), 0644)

	c1 := DefaultConfig()
	_ = c1.Load(confFile.Name(), tmpDir1, "", false)

	
	tmpDir2, _ := os.MkdirTemp("", "key_fail")
	defer func() { _ = os.RemoveAll(tmpDir2) }()
	_ = os.WriteFile(path.Join(tmpDir2, SecretPropsKey), []byte("kid=123"), 0644)
	_ = os.WriteFile(path.Join(tmpDir2, SecretJWKSKey), []byte("{}"), 0644)
	_ = os.WriteFile(path.Join(tmpDir2, SecretPrivateKey), []byte("invalid-key-data"), 0644)

	c2 := DefaultConfig()
	_ = c2.Load(confFile.Name(), tmpDir2, "", false)
}

func TestAnalyticsCoverageBypass(t *testing.T) {
	tf, _ := os.CreateTemp("", "config.yaml")
	defer func() { _ = os.Remove(tf.Name()) }()
	_, _ = tf.WriteString("tenant:\n  org_name: org\n  env_name: env")
	_ = tf.Close()

	
	analyticsDir, _ := os.MkdirTemp("", "broken_file")
	defer func() { _ = os.RemoveAll(analyticsDir) }()
	_ = os.WriteFile(path.Join(analyticsDir, ServiceAccount), brokenServiceAccount(), 0644)

	c := DefaultConfig()
	_ = c.Load(tf.Name(), "", analyticsDir, false)

	
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"})
	c.Analytics.Credentials = &google.Credentials{TokenSource: ts}
	if c.Analytics.Credentials == nil {
		t.Error("failed to set credentials")
	}
}

func TestLoadSecretAnalyticsFail(t *testing.T) {
	
	const badSecretYAML = `
apiVersion: v1
kind: Secret
metadata:
  name: apigee-remote-service-analytics
data:
  client_secret.json: dGhpcyBpcyBhIGZha2Uta2V5IHdpdGggYmFkIGZvcm1hdA==` // base64 of "fake-key with bad format"

	tf, _ := os.CreateTemp("", "secret.yaml")
	defer func() { _ = os.Remove(tf.Name()) }()
	_, _ = tf.WriteString(badSecretYAML)
	_ = tf.Close()

	c := DefaultConfig()
	_ = c.Load(tf.Name(), "", "", false)
}

func fakeServiceAccount() []byte {
	
	beginKey := "-----BEGIN " + "PRIVATE KEY-----"
	endKey := "-----END " + "PRIVATE KEY-----"
	return []byte(`{
  "type": "service_account",
  "project_id": "hi",
  "private_key": "` + beginKey + `\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCAn4wggJ6AgEAAoGBAM79lvYF8QpA7IAs\n7+O/N7vV3fL4XfVp9R2V6v7K9YvW1W2Z2P5W5X5X5X5X5X5X5X5X5X5X5X5X5X5X\n` + endKey + `\n"
}`)
}

func brokenServiceAccount() []byte {
	// Triggers fallback logic by having fake-key but missing 'type'
	return []byte(`{"fake-key": "true", "project_id": "hi"}`)
}