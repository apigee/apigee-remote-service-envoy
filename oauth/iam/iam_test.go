// Copyright 2021 Google LLC
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

package iam

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iamv1 "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

func TestAccessTokenRefreshBackoff(t *testing.T) {
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.Error(w, "server not ready", http.StatusInternalServerError)
			return
		}
		req := &iamv1.GenerateAccessTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := &iamv1.GenerateAccessTokenResponse{
			AccessToken: "token",
			ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}
	s, err := NewIAMService(opts...)
	if err != nil {
		t.Fatalf("NewIAMService() err = %v, wanted no error", err)
	}
	defer s.Close()

	if _, err := s.AccessTokenSource("", nil, 0); err == nil {
		t.Errorf("AccessTokenSource() err = nil, wanted error for empty service account")
	}

	saEmail := "foo@bar.iam.gserviceaccount.com"

	if _, err := s.AccessTokenSource(saEmail, nil, 0); err == nil {
		t.Errorf("AccessTokenSource() err = nil, wanted error for empty scopes")
	}

	scope := "https://www.googleapis.com/auth/cloud-platform"
	if _, err := s.AccessTokenSource(saEmail, []string{scope}, 0); err != nil {
		t.Fatalf("AccessTokenSource() err = %v, wanted no error", err)
	}

	ts, err := s.AccessTokenSource(saEmail, []string{scope}, time.Hour)
	if err != nil {
		t.Fatalf("AccessTokenSource() err = %v, wanted no error", err)
	}

	// The first refresh should have not yet happened.
	if _, err := ts.Value(); err == nil {
		t.Fatalf("ts.Token() err = nil, wanted error")
	}
	time.Sleep(10 * time.Millisecond)
	// The error should be cached at this point.
	if _, err := ts.Value(); err == nil {
		t.Fatalf("ts.Token() err = nil, wanted error")
	}

	ready = true
	// One retry should happen within 200ms.
	time.Sleep(210 * time.Millisecond)
	val, err := ts.Value()
	if err != nil {
		t.Fatalf("ts.Value() err = %v, wanted no error", err)
	}
	if val != "Bearer token" {
		t.Errorf("ts.Value() returned %q, wanted %q", val, "token-1")
	}
}

func TestAccessTokenRefreshAfterTokenExpiration(t *testing.T) {
	ctr := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &iamv1.GenerateAccessTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp *iamv1.GenerateAccessTokenResponse
		if ctr == 0 {
			resp = &iamv1.GenerateAccessTokenResponse{
				AccessToken: "token-1",
				ExpireTime:  time.Now().Add(10 * time.Millisecond).Format(time.RFC3339),
			}
		} else {
			resp = &iamv1.GenerateAccessTokenResponse{
				AccessToken: "token-2",
				ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
			}
		}
		ctr++
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}
	s, err := NewIAMService(opts...)
	if err != nil {
		t.Fatalf("NewIAMService() err = %v, wanted no error", err)
	}
	defer s.Close()

	saEmail := "foo@bar.iam.gserviceaccount.com"
	scope := "https://www.googleapis.com/auth/cloud-platform"
	ts, err := s.AccessTokenSource(saEmail, []string{scope}, time.Hour)
	if err != nil {
		t.Fatalf("AccessTokenSource() err = %v, wanted no error", err)
	}

	val, err := ts.Value()
	if err != nil {
		t.Fatalf("ts.Value() err = %v, wanted no error", err)
	}
	if val != "Bearer token-1" {
		t.Errorf("ts.Value() returned %q, wanted %q", val, "token-1")
	}

	// The first token should have expired and lead to another fetch.
	time.Sleep(10 * time.Millisecond)
	val, err = ts.Value()
	if err != nil {
		t.Fatalf("ts.Value() err = %v, wanted no error", err)
	}
	if val != "Bearer token-2" {
		t.Errorf("ts.Value() returned %q, wanted %q", val, "token-2")
	}
}

func TestIdentityTokenRefreshBackoff(t *testing.T) {
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.Error(w, "server not ready", http.StatusInternalServerError)
			return
		}
		req := &iamv1.GenerateIdTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := &iamv1.GenerateIdTokenResponse{
			Token: "token",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}
	s, err := NewIAMService(opts...)
	if err != nil {
		t.Fatalf("NewIAMService() err = %v, wanted no error", err)
	}
	defer s.Close()

	if _, err := s.IdentityTokenSource("", "aud", false, 0); err == nil {
		t.Errorf("IdentityTokenSource() err = nil, wanted error for empty service account")
	}

	saEmail := "foo@bar.iam.gserviceaccount.com"
	if _, err := s.IdentityTokenSource(saEmail, "", false, 0); err == nil {
		t.Errorf("IdentityTokenSource() err = nil, wanted error for empty audience")
	}

	if _, err := s.IdentityTokenSource(saEmail, "aud", true, 0); err != nil {
		t.Fatalf("IdentityTokenSource() err = %v, wanted no error", err)
	}

	ts, err := s.IdentityTokenSource(saEmail, "aud", true, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("IdentityTokenSource() err = %v, wanted no error", err)
	}

	// The first refresh should have not yet happened.
	if _, err := ts.Value(); err == nil {
		t.Fatalf("ts.Value() err = nil, wanted error")
	}
	time.Sleep(10 * time.Millisecond)
	// The error should be cached at this point.
	if _, err := ts.Value(); err == nil {
		t.Fatalf("ts.Token() err = nil, wanted error")
	}
	ready = true

	// One retry should happen within 200ms.
	time.Sleep(210 * time.Millisecond)
	val, err := ts.Value()
	if err != nil {
		t.Fatalf("ts.Value() err = %v, wanted no error", err)
	}
	if val != "Bearer token" {
		t.Errorf("ts.Value() returned %q, wanted %q", val, "token")
	}
}
