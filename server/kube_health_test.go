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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync" // Added
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestKubeHealth(t *testing.T) {
	var mu sync.Mutex // Added to protect 'fail'
	var fail bool
	
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()         // Added lock
		shouldFail := fail
		mu.Unlock()       // Added unlock

		if shouldFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var result = product.APIResponse{
			APIProducts: []product.APIProduct{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer ts.Close()

	serverURL, _ := url.Parse(ts.URL)
	opts := product.Options{
		Client:      http.DefaultClient,
		BaseURL:     serverURL,
		RefreshRate: time.Minute,
		Org:         "org",
		Env:         "env",
	}

	// 1. Start with failure
	mu.Lock()
	fail = true
	mu.Unlock()

	productMan, err := product.NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer productMan.Close()

	grpcHealth := health.NewServer()
	handler := &Handler{productMan: productMan}
	kubeHealth := NewKubeHealth(handler, grpcHealth)

	if err := kubeHealth.error(); err == nil || !strings.Contains(strings.ToLower(err.Error()), "products not loaded") {
		t.Errorf("expected products not loaded, got: %v", err)
	}

	// 2. Allow success
	mu.Lock()
	fail = false
	mu.Unlock()

	ready := false
	for i := 0; i < 50; i++ {
		if err := kubeHealth.error(); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ready {
		t.Fatalf("kubeHealth never became ready; last error: %v", kubeHealth.error())
	}

	// 3. Test HTTP Handler (Success Case)
	req := httptest.NewRequest("GET", "/", nil)
	res := httptest.NewRecorder()
	kubeHealth.HandlerFunc()(res, req)
	if res.Code != 200 {
		t.Errorf("expected 200, got: %d", res.Code)
	}

	// 4. Force gRPC NOT_SERVING state
	grpcHealth.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	err = kubeHealth.error()
	
	// Case-insensitive check for NOT_SERVING
	if err == nil || !strings.Contains(strings.ToUpper(err.Error()), "NOT_SERVING") {
		t.Errorf("expected error containing 'NOT_SERVING', got: %v", err)
	}

	// 5. Verify HTTP Handler reflects the gRPC NOT_SERVING state (returns 500)
	res = httptest.NewRecorder()
	kubeHealth.HandlerFunc()(res, req)
	if res.Code != 500 {
		t.Errorf("expected 500, got: %d", res.Code)
	}
}