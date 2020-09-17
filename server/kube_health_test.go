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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/product"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestKubeHealth(t *testing.T) {
	fail := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result = product.APIResponse{
			APIProducts: []product.APIProduct{},
		}
		if fail {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	productMan, err := product.NewManager(product.Options{
		Client:      http.DefaultClient,
		BaseURL:     serverURL,
		RefreshRate: time.Minute,
		Org:         "org",
		Env:         "env",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer productMan.Close()

	grpcHealth := health.NewServer()
	handler := &Handler{
		productMan: productMan,
	}

	kubeHealth := NewKubeHealth(handler, grpcHealth)
	err = kubeHealth.error()
	exp := "products not loaded"
	if err.Error() != exp {
		t.Errorf("expected %s, got: %s", exp, err)
	}

	fail = false
	// give it a moment to load
	time.Sleep(5 * time.Millisecond)
	err = kubeHealth.error()
	if err != nil {
		t.Errorf("expected no error, got: %s", err)
	}

	// handler
	req := httptest.NewRequest("GET", "/", nil)
	res := httptest.NewRecorder()
	kubeHealth.HandlerFunc()(res, req)
	if res.Code != 200 {
		t.Errorf("expected 200, got: %d, body: %s", res.Code, res.Body)
	}

	// grpc err
	grpcHealth.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	err = kubeHealth.error()
	if err.Error() != grpc_health_v1.HealthCheckResponse_NOT_SERVING.String() {
		t.Errorf("expected %s, got: %s", exp, err)
	}

	// handler err
	res = httptest.NewRecorder()
	kubeHealth.HandlerFunc()(res, req)
	if res.Code != 500 {
		t.Errorf("expected 500, got: %d, body: %s", res.Code, res.Body)
	}
}
