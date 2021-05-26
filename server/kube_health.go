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
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func NewKubeHealth(handler *Handler, health *health.Server) *KubeHealth {
	kubeHealth := &KubeHealth{
		Handler: handler,
		Health:  health,
	}
	go func() {
		_ = handler.productMan.Products() // blocks until ready
		kubeHealth.Lock()
		kubeHealth.ready = true
		kubeHealth.Unlock()
	}()
	return kubeHealth
}

type KubeHealth struct {
	sync.Mutex
	Handler *Handler
	Health  *health.Server
	ready   bool
}

// nil if ok, error with message if not
func (h *KubeHealth) error() error {
	h.Lock()
	defer h.Unlock()
	if !h.ready {
		return fmt.Errorf("products not loaded")
	}
	in := &grpc_health_v1.HealthCheckRequest{}
	response, err := h.Health.Check(context.Background(), in)
	if err != nil {
		return err
	}
	if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf(response.Status.String())
	}
	return nil
}

// KubeHealth returns http.HandlerFunc for endpoint
func (h *KubeHealth) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h.error(); err != nil {
			w.WriteHeader(500)
			if _, err := w.Write([]byte(err.Error())); err != nil {
				log.Warnf("healthz unable to respond: %s", err)
			}
			return
		}
		w.WriteHeader(200)
	}
}
