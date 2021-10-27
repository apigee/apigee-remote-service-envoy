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

package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/iam/google"
	iamv1 "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// IAMServer returns a test IAM server.
func IAMServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "generateAccessToken") {
			if err := json.NewEncoder(w).Encode(&iamv1.GenerateAccessTokenResponse{
				AccessToken: "access-token",
				ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
			}); err != nil {
				http.Error(w, "failed to marshal response", http.StatusInternalServerError)
			}
		} else if strings.Contains(r.URL.Path, "generateIdToken") {
			if err := json.NewEncoder(w).Encode(&iamv1.GenerateIdTokenResponse{
				Token: "id-token",
			}); err != nil {
				http.Error(w, "failed to marshal response", http.StatusInternalServerError)
			}
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
	}))
}

// IAMService returns a test iam service client.
func IAMService(srv *httptest.Server) (*google.IAMService, error) {
	opts := []option.ClientOption{
		option.WithHTTPClient(http.DefaultClient),
		option.WithEndpoint(srv.URL),
	}

	s, err := google.NewIAMService(opts...)
	if err != nil {
		return nil, err
	}
	return s, nil
}
