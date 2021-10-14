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

func TestAccessTokenRefresh(t *testing.T) {
	ctr := 0
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
		var resp *iamv1.GenerateAccessTokenResponse
		if ctr == 0 {
			resp = &iamv1.GenerateAccessTokenResponse{
				AccessToken: "token-1",
				ExpireTime:  time.Now().Add(time.Millisecond).Format(time.RFC3339),
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

	ts, err := s.AccessTokenSource(saEmail, []string{scope}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("AccessTokenSource() err = %v, wanted no error", err)
	}

	if _, err := ts.Token(); err == nil {
		t.Fatalf("ts.Token() err = nil, wanted error")
	}
	// One refresh should happen with error.
	time.Sleep(60 * time.Millisecond)
	ready = true
	tk, err := ts.Token()
	if err != nil {
		t.Fatalf("ts.Token() err = %v, wanted no error", err)
	}
	if tk.AccessToken != "token-1" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-1")
	}

	time.Sleep(10 * time.Millisecond)
	// The token should be refreshed because the previous one expired.
	tk, err = ts.Token()
	if err != nil {
		t.Fatalf("ts.Token() err = %v, wanted no error", err)
	}
	if tk.AccessToken != "token-2" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-2")
	}
}

func TestIdentityTokenRefresh(t *testing.T) {
	ctr := 0
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
		var resp *iamv1.GenerateIdTokenResponse
		if ctr == 0 {
			resp = &iamv1.GenerateIdTokenResponse{
				Token: "token-1",
			}
		} else {
			resp = &iamv1.GenerateIdTokenResponse{
				Token: "token-2",
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

	if _, err := ts.Token(); err == nil {
		t.Fatalf("ts.Token() err = nil, wanted error")
	}
	// One refresh should happen with error.
	time.Sleep(60 * time.Millisecond)
	ready = true
	tk, err := ts.Token()
	if err != nil {
		t.Fatalf("ts.Token() err = %v, wanted no error", err)
	}
	if tk.AccessToken != "token-1" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-1")
	}

	time.Sleep(60 * time.Millisecond)
	// The token should be refreshed because of the refresh interval.
	tk, err = ts.Token()
	if err != nil {
		t.Fatalf("ts.Token() err = %v, wanted no error", err)
	}
	if tk.AccessToken != "token-2" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-2")
	}
}
