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

package google

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iam "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

func TestNewIAMServiceError(t *testing.T) {
	tests := []struct {
		desc    string
		saEmail string
		opts    []option.ClientOption
	}{
		{
			desc: "missing service account",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := NewIAMService(context.Background(), test.saEmail, test.opts...)
			if err == nil {
				t.Errorf("NewIAMService(...) err = nil, wanted error")
			}
		})
	}
}

func TestAccessTokenRefresh(t *testing.T) {
	ctr := 0
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.Error(w, "server not ready", http.StatusInternalServerError)
			return
		}
		req := &iam.GenerateAccessTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp *iam.GenerateAccessTokenResponse
		if ctr == 0 {
			resp = &iam.GenerateAccessTokenResponse{
				AccessToken: "token-1",
				ExpireTime:  time.Now().Add(time.Millisecond).Format(time.RFC3339),
			}
		} else {
			resp = &iam.GenerateAccessTokenResponse{
				AccessToken: "token-2",
				ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
			}
		}
		ctr++
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		}
	}))

	ctxWithCancel, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}
	s, err := NewIAMService(ctxWithCancel, "foo@bar.iam.gserviceaccount.com", opts...)
	if err != nil {
		t.Fatalf("NewIAMService() err = %v, wanted no error", err)
	}

	if _, err := s.AccessTokenSource(nil, 0); err == nil {
		t.Errorf("AccessTokenSource() err = nil, wanted error for empty scopes")
	}

	scope := "https://www.googleapis.com/auth/cloud-platform"
	if _, err := s.AccessTokenSource([]string{scope}, 0); err != nil {
		t.Fatalf("AccessTokenSource() err = %v, wanted no error", err)
	}

	ts, err := s.AccessTokenSource([]string{scope}, 50*time.Millisecond)
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
		req := &iam.GenerateIdTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp *iam.GenerateIdTokenResponse
		if ctr == 0 {
			resp = &iam.GenerateIdTokenResponse{
				Token: "token-1",
			}
		} else {
			resp = &iam.GenerateIdTokenResponse{
				Token: "token-2",
			}
		}
		ctr++
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		}
	}))

	ctxWithCancel, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}
	s, err := NewIAMService(ctxWithCancel, "foo@bar.iam.gserviceaccount.com", opts...)
	if err != nil {
		t.Fatalf("NewIAMService() err = %v, wanted no error", err)
	}

	if _, err := s.IdentityTokenSource("", false, 0); err == nil {
		t.Errorf("IdentityTokenSource() err = nil, wanted error for empty audience")
	}

	if _, err := s.IdentityTokenSource("aud", true, 0); err != nil {
		t.Fatalf("IdentityTokenSource() err = %v, wanted no error", err)
	}

	ts, err := s.IdentityTokenSource("aud", true, 50*time.Millisecond)
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
