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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/apigee/apigee-remote-service-golib/analytics"
	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/apigee/apigee-remote-service-golib/quota"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// A Handler is the main entry
type Handler struct {
	internalAPI        *url.URL
	remoteServiceAPI   *url.URL
	orgName            string
	envName            string
	apiKeyClaim        string
	apiKeyHeader       string
	targetHeader       string
	rejectUnauthorized bool

	productMan   product.Manager
	authMan      auth.Manager
	analyticsMan analytics.Manager
	quotaMan     quota.Manager
}

// InternalAPI is the internal api base (legacy)
func (h *Handler) InternalAPI() *url.URL {
	return h.internalAPI
}

// RemoteServiceAPI is the remote service base
func (h *Handler) RemoteServiceAPI() *url.URL {
	return h.remoteServiceAPI
}

// Organization is the tenant organization
func (h *Handler) Organization() string {
	return h.orgName
}

// Environment is the tenant environment
func (h *Handler) Environment() string {
	return h.envName
}

// NewHandler creates a handler
func NewHandler(config *Config) (*Handler, error) {

	var internalAPI, remoteServiceAPI *url.URL
	var err error
	if config.Tenant.InternalAPI != "" {
		internalAPI, err = url.Parse(config.Tenant.InternalAPI)
		if err != nil {
			return nil, err
		}
		if internalAPI.Scheme == "" {
			return nil, fmt.Errorf("invalid URL: %s", config.Tenant.InternalAPI)
		}
	}
	if config.Tenant.RemoteServiceAPI != "" {
		remoteServiceAPI, err = url.Parse(config.Tenant.RemoteServiceAPI)
		if err != nil {
			return nil, err
		}
		if remoteServiceAPI.Scheme == "" {
			return nil, fmt.Errorf("invalid URL: %s", config.Tenant.RemoteServiceAPI)
		}
	}

	tr := http.DefaultTransport
	if config.Tenant.AllowUnverifiedSSLCert {
		tr = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		}
	}

	// add authorization to transport
	tr, err = AuthorizationRoundTripper(config, tr)
	if err != nil {
		return nil, err
	}

	productMan, err := product.NewManager(product.Options{
		Client:      instrumentedClientFor(config, "products", tr),
		BaseURL:     remoteServiceAPI,
		RefreshRate: config.Products.RefreshRate,
		Org:         config.Tenant.OrgName,
		Env:         config.Tenant.EnvName,
	})
	if err != nil {
		return nil, err
	}

	authMan, err := auth.NewManager(auth.Options{
		PollInterval:        config.Auth.JWKSPollInterval,
		Client:              instrumentedClientFor(config, "auth", tr),
		APIKeyCacheDuration: config.Auth.APIKeyCacheDuration,
		Org:                 config.Tenant.OrgName,
		Env:                 config.Tenant.EnvName,
	})
	if err != nil {
		return nil, err
	}

	quotaMan, err := quota.NewManager(quota.Options{
		BaseURL: remoteServiceAPI,
		Client:  instrumentedClientFor(config, "quotas", tr),
		Org:     config.Tenant.OrgName,
		Env:     config.Tenant.EnvName,
	})
	if err != nil {
		return nil, err
	}

	tempDirMode := os.FileMode(0700)
	tempDir := config.Global.TempDir
	analyticsDir := filepath.Join(tempDir, "analytics")
	if err := os.MkdirAll(analyticsDir, tempDirMode); err != nil {
		return nil, err
	}

	analyticsMan, err := analytics.NewManager(analytics.Options{
		LegacyEndpoint:     config.Analytics.LegacyEndpoint,
		BufferPath:         analyticsDir,
		StagingFileLimit:   config.Analytics.FileLimit,
		BaseURL:            internalAPI,
		Client:             instrumentedClientFor(config, "analytics", tr),
		SendChannelSize:    config.Analytics.SendChannelSize,
		CollectionInterval: time.Minute,
		FluentdEndpoint:    config.Analytics.FluentdEndpoint,
		TLSCAFile:          config.Analytics.TLS.CAFile,
		TLSCertFile:        config.Analytics.TLS.CertFile,
		TLSKeyFile:         config.Analytics.TLS.KeyFile,
		TLSSkipVerify:      config.Analytics.TLS.AllowUnverifiedSSLCert,
	})
	if err != nil {
		return nil, err
	}

	h := &Handler{
		remoteServiceAPI:   remoteServiceAPI,
		internalAPI:        internalAPI,
		orgName:            config.Tenant.OrgName,
		envName:            config.Tenant.EnvName,
		productMan:         productMan,
		authMan:            authMan,
		analyticsMan:       analyticsMan,
		quotaMan:           quotaMan,
		apiKeyClaim:        config.Auth.APIKeyClaim,
		apiKeyHeader:       config.Auth.APIKeyHeader,
		targetHeader:       config.Auth.TargetHeader,
		rejectUnauthorized: config.Auth.RejectUnauthorized,
	}

	return h, nil
}

func instrumentedClientFor(config *Config, api string, rt http.RoundTripper) *http.Client {
	promLabels := prometheus.Labels{"org": config.Tenant.OrgName, "env": config.Tenant.EnvName, "api": api}
	observer := prometheusApigeeRequests.MustCurryWith(promLabels)
	rt = promhttp.InstrumentRoundTripperDuration(observer, rt)
	return &http.Client{
		Timeout:   config.Tenant.ClientTimeout,
		Transport: rt,
	}
}

var (
	prometheusApigeeRequests = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "apigee",
		Name:      "requests_seconds",
		Help:      "Time taken to make apigee requests by code",
		Buckets:   prometheus.DefBuckets,
	}, []string{"org", "env", "api", "code", "method"})
)
