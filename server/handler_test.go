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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"golang.org/x/oauth2/google"
)

func TestNewHandler(t *testing.T) {

	kid := "kid"
	privateKey, _, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Tenant = config.Tenant{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "*",
		PrivateKeyID:     kid,
		PrivateKey:       privateKey,
	}
	cfg.Auth = config.Auth{
		APIKeyClaim:       "claim",
		APIKeyHeader:      "header",
		APIHeader:         "api",
		AllowUnauthorized: true,
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if h.InternalAPI().String() != cfg.Tenant.InternalAPI {
		t.Errorf("got: %s, want: %s", h.internalAPI, cfg.Tenant.InternalAPI)
	}
	if h.RemoteServiceAPI().String() != cfg.Tenant.RemoteServiceAPI {
		t.Errorf("got: %s, want: %s", h.remoteServiceAPI, cfg.Tenant.RemoteServiceAPI)
	}
	if h.Organization() != cfg.Tenant.OrgName {
		t.Errorf("got: %s, want: %s", h.Organization(), cfg.Tenant.OrgName)
	}
	if h.Environment() != cfg.Tenant.EnvName {
		t.Errorf("got: %s, want: %s", h.Environment(), cfg.Tenant.EnvName)
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

	if h.apiKeyClaim != cfg.Auth.APIKeyClaim {
		t.Errorf("got: %s, want: %s", h.apiKeyClaim, cfg.Auth.APIKeyClaim)
	}
	if h.apiKeyHeader != cfg.Auth.APIKeyHeader {
		t.Errorf("got: %s, want: %s", h.apiKeyHeader, cfg.Auth.APIKeyHeader)
	}
	if h.apiHeader != cfg.Auth.APIHeader {
		t.Errorf("got: %s, want: %s", h.apiHeader, cfg.Auth.APIHeader)
	}

	cfg.Tenant.InternalAPI = "not an url"
	_, err = NewHandler(cfg)
	if err == nil {
		t.Error("should get error")
	}

	cfg.Tenant.InternalAPI = cfg.Tenant.RemoteServiceAPI
	cfg.Tenant.RemoteServiceAPI = "not an url"
	_, err = NewHandler(cfg)
	if err == nil {
		t.Error("should get error")
	}

	// valid credentials given in cfg; internalAPI set to GCP managed URL
	cfg.Tenant.RemoteServiceAPI = cfg.Tenant.InternalAPI
	cfg.Tenant.InternalAPI = ""
	cred, err := google.CredentialsFromJSON(context.Background(), testutil.FakeServiceAccount(), config.ApigeeAPIScope)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Analytics.Credentials = cred
	h, err = NewHandler(cfg)
	if err != nil {
		t.Error(err)
	}
	if h.internalAPI.Host != "apigee.googleapis.com" {
		t.Errorf("internalAPI error: want %s got %s", "apigee.googleapis.com", h.internalAPI.Host)
	}

	h.Close()
}

func TestNewHandlerWithEnvSpec(t *testing.T) {

	kid := "kid"
	privateKey, _, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.EnvironmentSpecs = config.EnvironmentSpecs{
		Inline: []config.EnvironmentSpec{createAuthEnvSpec()},
	}

	cfg.Tenant = config.Tenant{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "*",
		PrivateKeyID:     kid,
		PrivateKey:       privateKey,
	}

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "no such file")
	_, err = NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() should return error for bad application default credentials")
	}

	tf, err := os.CreateTemp("", "creds.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	_, err = tf.Write(testutil.FakeServiceAccount())
	if err != nil {
		t.Fatal(err)
	}
	tf.Close()

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tf.Name())
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(h.envSpecsByID) < 1 {
		t.Errorf("envSpecsByID was not populated")
	}
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

	cfg := config.Default()
	cfg.Tenant = config.Tenant{
		InternalAPI:      "http://localhost/remote-service",
		RemoteServiceAPI: "http://localhost/remote-service",
		OrgName:          "org",
		EnvName:          "*",
		PrivateKeyID:     kid,
		PrivateKey:       privateKey,
		TLS: config.TLSClientSpec{
			CAFile:                 certFile,
			CertFile:               certFile,
			KeyFile:                keyFile,
			AllowUnverifiedSSLCert: true,
		},
	}
	cfg.Analytics = config.Analytics{
		FileLimit:          1024,
		SendChannelSize:    10,
		CollectionInterval: 2 * time.Minute,
		LegacyEndpoint:     true,
	}
	cfg.Auth = config.Auth{
		APIKeyClaim:  "claim",
		APIKeyHeader: "header",
		APIHeader:    "api",
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if h.InternalAPI().String() != cfg.Tenant.InternalAPI {
		t.Errorf("got: %s, want: %s", h.internalAPI, cfg.Tenant.InternalAPI)
	}
	if h.RemoteServiceAPI().String() != cfg.Tenant.RemoteServiceAPI {
		t.Errorf("got: %s, want: %s", h.remoteServiceAPI, cfg.Tenant.RemoteServiceAPI)
	}
	if h.Organization() != cfg.Tenant.OrgName {
		t.Errorf("got: %s, want: %s", h.Organization(), cfg.Tenant.OrgName)
	}
	if h.Environment() != cfg.Tenant.EnvName {
		t.Errorf("got: %s, want: %s", h.Environment(), cfg.Tenant.EnvName)
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

	cfg.Tenant.TLS.CAFile = "bad-ca-path"
	_, err = NewHandler(cfg)
	if err == nil {
		t.Error("should get error")
	}

	cfg.Tenant.TLS.CAFile = certFile
	cfg.Tenant.TLS.CertFile = "bad-cert-path"
	_, err = NewHandler(cfg)
	if err == nil {
		t.Error("should get error")
	}
}

func TestMutualTLSRoundTripper(t *testing.T) {
	ts := newMutualTLSServer()
	defer ts.Close()

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

	var c *http.Client

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig.InsecureSkipVerify = true
	c = &http.Client{
		Transport: tr,
	}
	_, err = c.Do(req)
	if err == nil { // should have not error about no client cert
		t.Error("should get error")
	}

	tlsConfig := config.TLSClientSpec{
		CAFile:                 certFile,
		CertFile:               certFile,
		KeyFile:                keyFile,
		AllowUnverifiedSSLCert: true,
	}

	rt, err := roundTripperWithTLS(tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	c = &http.Client{
		Transport: rt,
	}
	_, err = c.Do(req)
	if err != nil {
		t.Error(err)
	}
}

func newMutualTLSServer() *httptest.Server {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	// require client cert but skip verification
	ts.TLS = &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ClientAuth: tls.RequireAnyClientCert,
	}
	ts.StartTLS()

	return ts
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
