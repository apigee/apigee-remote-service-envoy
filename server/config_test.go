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
	"os"
	"testing"

	"github.com/hashicorp/go-multierror"
)

const allConfigOptions = `
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
  remote_service_api: https://myorg-test.apigee.net/remote-service
  org_name: myorg
  env_name: test
  key: mykey
  secret: mysecret
  client_timeout: 30s
  allow_Unverified_ssl_cert: false
products:
  refresh_rate: 2m
analytics:
  legacy_endpoint: false
  file_limit: 1024
  send_channel_size: 10
  collection_interval: 10s
  fluentd_endpoint: apigee-udca-theganyo-apigee-test.apigee.svc.cluster.local:20001
  tls:
    ca_file: /opt/apigee/tls/ca.crt
    cert_file: /opt/apigee/tls/tls.crt
    key_file: /opt/apigee/tls/tls.key
auth:
  api_key_claim: claim
  api_key_cache_duration: 30m
  api_key_header: x-api-key
  api_target_header: :authority
  reject_unauthorized: true
  jwks_poll_interval: 0s
`

func TestDefaultConfig(t *testing.T) {
	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	const minConfig = `
    tenant:
      internal_api: https://istioservices.apigee.net/edgemicro
      remote_service_api: https://myorg-test.apigee.net/remote-service
      org_name: myorg
      env_name: test
      key: mykey
      secret: mysecret
  `
	if _, err := tf.WriteString(minConfig); err != nil {
		t.Fatal(err)
	}

	c := DefaultConfig()
	if err := c.Load(tf.Name()); err != nil {
		t.Fatal(err)
	}

	if err := c.Validate(); err != nil {
		t.Fatalf("config should be valid, got: %s", err)
	}
}

func TestLoad(t *testing.T) {
	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	if _, err := tf.WriteString(allConfigOptions); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}

	bytes, err := ioutil.ReadFile(tf.Name())
	t.Logf("contents:\n%s", bytes)

	c := &Config{}
	if err := c.Load(tf.Name()); err != nil {
		t.Fatal(err)
	}

	equal(t, c.Global.TempDir, "/tmp/apigee-istio")
}

func equal(t *testing.T, got, want string) {
	if got != want {
		t.Errorf("got: '%s', want: '%s'", got, want)
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
		"tenant.key is required",
		"tenant.secret is required",
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
