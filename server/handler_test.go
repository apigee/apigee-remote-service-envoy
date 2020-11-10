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

// Package protostruct supports operations on the protocol buffer Struct message.
package server

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/testutil"
)

func TestNewHandler(t *testing.T) {

	kid := "kid"
	privateKey, _, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	config := DefaultConfig()
	config.Tenant = TenantConfig{
		InternalAPI:            "http://localhost/remote-service",
		RemoteServiceAPI:       "http://localhost/remote-service",
		OrgName:                "org",
		EnvName:                "env",
		AllowUnverifiedSSLCert: true,
		PrivateKeyID:           kid,
		PrivateKey:             privateKey,
	}
	config.Auth = AuthConfig{
		APIKeyClaim:        "claim",
		APIKeyHeader:       "header",
		TargetHeader:       "target",
		RejectUnauthorized: false,
	}

	h, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}

	if h.InternalAPI().String() != config.Tenant.InternalAPI {
		t.Errorf("got: %s, want: %s", h.internalAPI, config.Tenant.InternalAPI)
	}
	if h.RemoteServiceAPI().String() != config.Tenant.RemoteServiceAPI {
		t.Errorf("got: %s, want: %s", h.remoteServiceAPI, config.Tenant.RemoteServiceAPI)
	}
	if h.Organization() != config.Tenant.OrgName {
		t.Errorf("got: %s, want: %s", h.Organization(), config.Tenant.OrgName)
	}
	if h.Environment() != config.Tenant.EnvName {
		t.Errorf("got: %s, want: %s", h.Environment(), config.Tenant.EnvName)
	}

	if h.productMan == nil {
		t.Errorf("productMan must be populated")
	}
	if h.authMan == nil {
		t.Errorf("authMan must be populated")
	}
	if h.analyticsMan == nil {
		t.Errorf("analyticsMan must be populated")
	}
	if h.quotaMan == nil {
		t.Errorf("quotaMan must be populated")
	}

	if h.apiKeyClaim != config.Auth.APIKeyClaim {
		t.Errorf("got: %s, want: %s", h.apiKeyClaim, config.Auth.APIKeyClaim)
	}
	if h.apiKeyHeader != config.Auth.APIKeyHeader {
		t.Errorf("got: %s, want: %s", h.apiKeyHeader, config.Auth.APIKeyHeader)
	}
	if h.targetHeader != config.Auth.TargetHeader {
		t.Errorf("got: %s, want: %s", h.targetHeader, config.Auth.TargetHeader)
	}
	if h.rejectUnauthorized != config.Auth.RejectUnauthorized {
		t.Errorf("got: %t, want: %t", h.rejectUnauthorized, config.Auth.RejectUnauthorized)
	}

	config.Tenant.InternalAPI = "not an url"
	_, err = NewHandler(config)
	if err == nil {
		t.Error("should get error")
	}

	config.Tenant.InternalAPI = config.Tenant.RemoteServiceAPI
	config.Tenant.RemoteServiceAPI = "not an url"
	_, err = NewHandler(config)
	if err == nil {
		t.Error("should get error")
	}

	// valid credentials given in config; internalAPI set to GCP managed URL
	config.Tenant.RemoteServiceAPI = config.Tenant.InternalAPI
	config.Tenant.InternalAPI = ""
	config.Analytics.CredentialsJSON = fakeServiceAccount()
	h, err = NewHandler(config)
	if err != nil {
		t.Error(err)
	}
	if h.internalAPI.Host != "apigee.googleapis.com" {
		t.Errorf("internalAPI error: want %s got %s", "apigee.googleapis.com", h.internalAPI.Host)
	}

	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	// write credentials to file and set GOOGLE_APPLICATION_CREDENTIALS to its path
	if _, err := tf.Write(config.Analytics.CredentialsJSON); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tf.Name())
	// remove credentials in config
	// valid default application credentials given by GOOGLE_APPLICATION_CREDENTIALS
	config.Analytics.CredentialsJSON = nil
	_, err = NewHandler(config)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	// no valid default application credentials; fall back to client without auth
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "invalid path")
	_, err = NewHandler(config)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	// invalid credentials given in config; returns error and no fall back
	config.Analytics.CredentialsJSON = []byte("invalid sa")
	_, err = NewHandler(config)
	if err == nil {
		t.Error("should get error")
	}

	h.Close()
}

func fakeServiceAccount() []byte {
	sa := []byte(`{
	"type": "service_account",
	"project_id": "hi",
	"private_key_id": "5a0ef8b44fe312a005ac6e6fe59e2e559b40bff3",
	"private_key": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
	"client_email": "client@hi.iam.gserviceaccount.com",
	"client_id": "111111111111111111",
	"auth_uri": "https://mock.com/o/oauth2/auth",
	"token_uri": "https://mock.com/token",
	"auth_provider_x509_cert_url": "https://mock.com/oauth2/v1/certs",
	"client_x509_cert_url": "https://mock.com/robot/v1/metadata/x509/client%40hi.iam.gserviceaccount.com"
}`)
	return sa
}
