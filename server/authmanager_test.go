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

		jwkSet, err := jwk.ParseBytes(jwksBuf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = jws.VerifyWithJWKSet([]byte(token), jwkSet, nil); err != nil {
			t.Fatal(err)
		}
	}

	token := jam.getToken()
	hdr := m.getAuthorizationHeader()
	verifyHdr(hdr)

	token2 := jam.getToken()
	hdr2 := m.getAuthorizationHeader()
	verifyHdr(hdr2)

	if token == token2 {
		fmt.Errorf("should be new token")
	}

	jam.stop()
}
