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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/testutil"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func TestStaticAuthManager(t *testing.T) {
	config := &Config{
		Tenant: TenantConfig{
			InternalAPI: "x",
		},
	}
	m, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("expected nil error, got: %s", err)
	}
	if _, ok := m.(*StaticAuthManager); !ok {
		t.Fatalf("expected StaticAuthManager, got: %s", m)
	}

	auth := fmt.Sprintf("%s:%s", config.Tenant.Key, config.Tenant.Secret)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	want := fmt.Sprintf("Basic %s", encodedAuth)

	got := m.getAuthorizationHeader()
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestJWTAuthManager(t *testing.T) {
	kid := "kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		Tenant: TenantConfig{
			PrivateKeyID:        kid,
			PrivateKey:          privateKey,
			InternalJWTDuration: time.Second,
			InternalJWTRefresh:  0,
		},
	}
	if !config.IsGCPManaged() {
		t.Fatalf("expected config.isGCPExperience")
	}
	m, err := NewAuthManager(config)
	if err != nil {
		t.Fatal(err)
	}
	jam, ok := m.(*JWTAuthManager)
	if !ok {
		t.Fatalf("want JWTAuthManager, got: %s", m)
	}

	verifyHdr := func(hdr string) {
		token := strings.TrimPrefix(hdr, "Bearer ")

		jwkSet, err := jwk.Parse(jwksBuf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = jws.VerifySet([]byte(token), jwkSet); err != nil {
			t.Fatal(err)
		}
	}

	token := jam.getToken()
	hdr := m.getAuthorizationHeader()
	verifyHdr(hdr)
	time.Sleep(5 * time.Millisecond)

	token2 := jam.getToken()
	hdr2 := m.getAuthorizationHeader()
	verifyHdr(hdr2)

	if token == token2 {
		t.Errorf("should be new token")
	}

	jam.stop()
}

func TestNoAuthPUTRoundTripper(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			if auth := r.Header.Get("Authorization"); auth != "" {
				t.Errorf("want no auth header in PUT request, got %s", auth)
			}
		default:
			if u, p, ok := r.BasicAuth(); !ok || u != "key" || p != "secret" {
				t.Errorf("want basic auth header key:secret, got %s:%s", u, p)
			}
		}
	}))
	defer ts.Close()

	client := http.DefaultClient
	client.Transport = NoAuthPUTRoundTripper()

	var req *http.Request
	var err error

	req, err = http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("key", "secret")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}

	req, err = http.NewRequest(http.MethodPut, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("key", "secret")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
}
