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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/testutil"
	"github.com/hashicorp/go-multierror"
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
  allow_unverified_ssl_cert: false
products:
  refresh_rate: 2m
analytics:
  legacy_endpoint: false
  file_limit: 1024
  send_channel_size: 10
  collection_interval: 10s
  fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001
  tls:
    ca_file: /opt/apigee/tls/ca.crt
    cert_file: /opt/apigee/tls/tls.crt
    key_file: /opt/apigee/tls/tls.key
    allow_unverified_ssl_cert: false
auth:
  api_key_claim: claim
  api_key_cache_duration: 30m
  api_key_header: x-api-key
  api_target_header: :authority
  reject_unauthorized: true
  jwks_poll_interval: 0s`
)

// TODO: Test multi-file (as in Kubernetes)

func TestHybridConfig(t *testing.T) {
	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	const minConfig = `
    tenant:
      remote_service_api: https://org-test.apigee.net/remote-service
      org_name: org
      env_name: env
    analytics:
      fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001`
	configCRD := makeConfigCRD(minConfig)
	secretCRD, err := makeSecretCRD()
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

	// TODO: remove
	bytes, err := ioutil.ReadFile(tf.Name())
	t.Logf("contents:\n%s", bytes)

	c := DefaultConfig()
	if err := c.Load(tf.Name(), "xxx"); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Tenant.PrivateKeyID, "kid")
}

func TestLoadUnifiedConfig(t *testing.T) {
	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	configCRD := makeConfigCRD(allConfigOptions) // TODO: fix this, having `internal_api` will skip loading secret
	secretCRD, err := makeSecretCRD()
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

	// TODO: remove
	bytes, err := ioutil.ReadFile(tf.Name())
	t.Logf("contents:\n%s", bytes)

	c := &Config{}
	if err := c.Load(tf.Name(), "xxx"); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Global.Namespace, "apigee")
	equal(t, c.Global.TempDir, "/tmp/apigee-istio")
}

func makeConfigCRD(config string) *ConfigMapCRD {
	data := map[string]string{"config.yaml": config}
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

func TestValidate(t *testing.T) {
	c := &Config{}
	err := c.Validate()
	if err == nil {
		t.Fatal("should have gotten errors")
	}

	wantErrs := []string{
		"tenant.remote_service_api is required",
		"tenant.internal_api or tenant.analytics.fluentd_endpoint is required",
		"tenant.org_name is required",
		"tenant.env_name is required",
	}
	merr := err.(*multierror.Error)
	if merr.Len() != len(wantErrs) {
		t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
	}

	errs := merr.Errors
	for i, e := range errs {
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
		config.Analytics.TLS.CAFile = o[2]
		config.Analytics.TLS.CertFile = o[3]
		config.Analytics.TLS.KeyFile = o[4]

		err := config.Validate()
		if err == nil {
			t.Fatal("should have gotten errors")
		}
		wantErrs := []string{
			"global.tls.cert_file and global.tls.key_file are both required if either are present",
			"all analytics.tls options are required if any are present",
		}
		merr := err.(*multierror.Error)
		if merr.Len() != len(wantErrs) {
			t.Fatalf("got %d errors, want: %d, errors: %s", merr.Len(), len(wantErrs), merr)
		}

		errs := merr.Errors
		for i, e := range errs {
			equal(t, e.Error(), wantErrs[i])
		}
	}
}

func makeSecretCRD() (*SecretCRD, error) {
	kid := "kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		return nil, err
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{Type: PEMKeyType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	data := map[string]string{
		SecretJKWSKey:    base64.StdEncoding.EncodeToString(jwksBuf),
		SecretPrivateKey: base64.StdEncoding.EncodeToString(pkBytes),
		SecretKIDKey:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(SecretKIDFormat, kid))),
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
