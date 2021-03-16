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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/testutil"
	"golang.org/x/oauth2/google"
)

func TestNewHandler(t *testing.T) {

	kid := "kid"
	privateKey, _, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	config := DefaultConfig()
	config.Tenant = TenantConfig{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "*",
		PrivateKeyID:     kid,
		PrivateKey:       privateKey,
	}
	config.Auth = AuthConfig{
		APIKeyClaim:       "claim",
		APIKeyHeader:      "header",
		APIHeader:         "api",
		AllowUnauthorized: true,
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
	if h.apiHeader != config.Auth.APIHeader {
		t.Errorf("got: %s, want: %s", h.apiHeader, config.Auth.APIHeader)
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
	cred, err := google.CredentialsFromJSON(context.Background(), fakeServiceAccount(), ApigeeAPIScope)
	if err != nil {
		t.Fatal(err)
	}
	config.Analytics.Credentials = cred
	h, err = NewHandler(config)
	if err != nil {
		t.Error(err)
	}
	if h.internalAPI.Host != "apigee.googleapis.com" {
		t.Errorf("internalAPI error: want %s got %s", "apigee.googleapis.com", h.internalAPI.Host)
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

func TestNewHandlerWithTLS(t *testing.T) {
	kid := "kid"
	privateKey, _, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	pemKey, pemCert, err := generateCert()
	if err != nil {
		t.Fatal(err)
	}

	tempDir, err := os.MkdirTemp("", "tls")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tempDir)

	keyFile := path.Join(tempDir, "key.pem")
	certFile := path.Join(tempDir, "cert.pem")

	if err := os.WriteFile(keyFile, pemKey, os.FileMode(0755)); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certFile, pemCert, os.FileMode(0755)); err != nil {
		t.Fatal(err)
	}

	config := DefaultConfig()
	config.Tenant = TenantConfig{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "*",
		PrivateKeyID:     kid,
		PrivateKey:       privateKey,
		TLS: TLSClientConfig{
			CAFile:                 certFile,
			CertFile:               certFile,
			KeyFile:                keyFile,
			AllowUnverifiedSSLCert: true,
		},
	}
	config.Analytics = AnalyticsConfig{
		FileLimit:          1024,
		SendChannelSize:    10,
		CollectionInterval: 2 * time.Minute,
		LegacyEndpoint:     true,
		TLS: TLSClientConfig{
			CAFile:                 certFile,
			CertFile:               certFile,
			KeyFile:                keyFile,
			AllowUnverifiedSSLCert: true,
		},
	}
	config.Auth = AuthConfig{
		APIKeyClaim:  "claim",
		APIKeyHeader: "header",
		APIHeader:    "api",
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
}

func generateCert() ([]byte, []byte, error) {
	certKeyLength := 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, certKeyLength)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Apigee"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, nil, err
	}
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, err
	}

	return keyBuf.Bytes(), certBuf.Bytes(), nil
}
