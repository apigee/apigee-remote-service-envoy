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
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	jwtProviderKey     string

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
		trans := tr.(*http.Transport).Clone()
		trans.TLSClientConfig.InsecureSkipVerify = true
		tr = trans
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

	var analyticsClient *http.Client
	// It tries to get a credentials authorized client if the credentials json is not empty.
	// Otherwise it uses the same setting as the other managers do.
	if config.Analytics.CredentialsJSON != nil {
		analyticsClient, err = clientAuthorizedByCredentials(config, "analytics", config.Analytics.CredentialsJSON)
		if err != nil {
			return nil, err
		}
		// overwrites internalAPI to the GCP managed base
		// no need to check error since it's a well-defined const
		internalAPI, _ = url.Parse(GCPExperienceBase)
	} else {
		analyticsClient = instrumentedClientFor(config, "analytics", tr)
	}

	analyticsMan, err := analytics.NewManager(analytics.Options{
		LegacyEndpoint:     config.Analytics.LegacyEndpoint,
		BufferPath:         analyticsDir,
		StagingFileLimit:   config.Analytics.FileLimit,
		BaseURL:            internalAPI,
		Client:             analyticsClient,
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
		jwtProviderKey:     config.Auth.JWTProviderKey,
	}

	return h, nil
}

// instrumentedClientFor returns a http.Client with a given RoundTripper
func instrumentedClientFor(config *Config, api string, rt http.RoundTripper) *http.Client {
	rt = roundTripperWithPrometheus(config, api, rt)
	return &http.Client{
		Timeout:   config.Tenant.ClientTimeout,
		Transport: rt,
	}
}

// roundTripperWithPrometheus returns a http.RoundTripper with prometheus labels configured
func roundTripperWithPrometheus(config *Config, api string, rt http.RoundTripper) http.RoundTripper {
	promLabels := prometheus.Labels{"org": config.Tenant.OrgName, "env": config.Tenant.EnvName, "api": api}
	observer := prometheusApigeeRequests.MustCurryWith(promLabels)
	return promhttp.InstrumentRoundTripperDuration(observer, rt)
}

// clientAuthorizedByServiceAccount returns a http client authorized with the
// service account credentials provided as json data
func clientAuthorizedByCredentials(config *Config, api string, jsonData []byte) (*http.Client, error) {
	const scope = "https://www.googleapis.com/auth/cloud-platform" // scope Apigee API needs
	ctx := context.Background()
	cred, err := google.CredentialsFromJSON(ctx, jsonData, scope)
	if err != nil {
		return nil, err
	}
	client := oauth2.NewClient(ctx, cred.TokenSource)
	rt := client.Transport
	// modify base roundtripper to strip auth header on PUT requests
	if rt, ok := rt.(*oauth2.Transport); ok {
		rt.Base = NoAuthPUTRoundTripper()
	} else {
		return nil, fmt.Errorf("unable to modify oauth2 client base transport")
	}
	client.Transport = roundTripperWithPrometheus(config, api, rt)
	client.Timeout = config.Tenant.ClientTimeout
	return client, nil
}

var (
	prometheusApigeeRequests = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "apigee",
		Name:      "requests_seconds",
		Help:      "Time taken to make apigee requests by code",
		Buckets:   prometheus.DefBuckets,
	}, []string{"org", "env", "api", "code", "method"})
)
