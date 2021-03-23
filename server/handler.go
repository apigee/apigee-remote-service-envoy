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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// A Handler is the main entry
type Handler struct {
	internalAPI           *url.URL
	remoteServiceAPI      *url.URL
	orgName               string
	envName               string
	apiKeyClaim           string
	apiKeyHeader          string
	apiHeader             string
	allowUnauthorized     bool
	appendMetadataHeaders bool
	jwtProviderKey        string
	isMultitenant         bool

	productMan   product.Manager
	authMan      auth.Manager
	analyticsMan analytics.Manager
	quotaMan     quota.Manager
}

// Close waits for all managers to close
func (h *Handler) Close() {
	wg := sync.WaitGroup{}
	wg.Add(4)
	type Closable interface {
		Close()
	}
	close := func(c Closable) {
		c.Close()
		wg.Done()
	}
	go close(h.productMan)
	go close(h.authMan)
	go close(h.analyticsMan)
	go close(h.quotaMan)
	wg.Wait()
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

// Environment is the tenant environment (or "*" for multitenant)
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

	// get a roundtripper with client TLS config
	tr, err := roundTripperWithTLS(config.Tenant.TLS)
	if err != nil {
		return nil, err
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
		Client:              instrumentedClientFor(config, "auth", tr),
		APIKeyCacheDuration: config.Auth.APIKeyCacheDuration,
		Org:                 config.Tenant.OrgName,
	})
	if err != nil {
		return nil, err
	}

	quotaMan, err := quota.NewManager(quota.Options{
		BaseURL: remoteServiceAPI,
		Client:  instrumentedClientFor(config, "quotas", tr),
		Org:     config.Tenant.OrgName,
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
	if config.Analytics.Credentials != nil {
		// Attempts to get an authorized http client with given analytics credentials
		analyticsClient = clientAuthorizedByCredentials(config, "analytics", config.Analytics.Credentials)
		// overwrite the internalAPI to the GCP managed host
		internalAPI, _ = url.Parse(GCPExperienceBase)
	} else {
		log.Debugf("analytics http client not using GCP authorization")
		tlsConfig := TLSClientConfig{ // only use AllowUnverifiedSSLCert first
			AllowUnverifiedSSLCert: config.Tenant.TLS.AllowUnverifiedSSLCert,
		}
		if config.Analytics.LegacyEndpoint { // allow mTLS config for OPDK
			tlsConfig = config.Tenant.TLS
		}
		tr, err := roundTripperWithTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		// the same method is called previously with same inputs, no need to check error again
		tr, _ = AuthorizationRoundTripper(config, tr)
		analyticsClient = instrumentedClientFor(config, "analytics", tr)
	}

	analyticsMan, err := analytics.NewManager(analytics.Options{
		LegacyEndpoint:     config.Analytics.LegacyEndpoint,
		BufferPath:         analyticsDir,
		StagingFileLimit:   config.Analytics.FileLimit,
		BaseURL:            internalAPI,
		Client:             analyticsClient,
		SendChannelSize:    config.Analytics.SendChannelSize,
		CollectionInterval: config.Analytics.CollectionInterval,
	})
	if err != nil {
		return nil, err
	}

	h := &Handler{
		remoteServiceAPI:      remoteServiceAPI,
		internalAPI:           internalAPI,
		orgName:               config.Tenant.OrgName,
		envName:               config.Tenant.EnvName,
		productMan:            productMan,
		authMan:               authMan,
		analyticsMan:          analyticsMan,
		quotaMan:              quotaMan,
		apiKeyClaim:           config.Auth.APIKeyClaim,
		apiKeyHeader:          config.Auth.APIKeyHeader,
		apiHeader:             config.Auth.APIHeader,
		allowUnauthorized:     config.Auth.AllowUnauthorized,
		jwtProviderKey:        config.Auth.JWTProviderKey,
		appendMetadataHeaders: config.Auth.AppendMetadataHeaders,
		isMultitenant:         config.Tenant.IsMultitenant(),
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
// service account credentials provided as json data or application default credentials
func clientAuthorizedByCredentials(config *Config, api string, cred *google.Credentials) *http.Client {
	ctx := context.Background()

	client := oauth2.NewClient(ctx, cred.TokenSource)

	// modify base roundtripper to strip auth header on PUT requests
	rt := client.Transport.(*oauth2.Transport)
	rt.Base = NoAuthPUTRoundTripper()

	client.Transport = roundTripperWithPrometheus(config, api, rt)
	client.Timeout = config.Tenant.ClientTimeout
	return client
}

// roundTripperWithTLS returns a http.RoundTripper with given TLSClientConfig
// and the default http.Transport will be used given a default TLSClientConfig
func roundTripperWithTLS(config TLSClientConfig) (http.RoundTripper, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if config.AllowUnverifiedSSLCert {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	// add given CA to the RootCAs
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("error appending CA to cert pool")
		}
		tr.TLSClientConfig.RootCAs = caCertPool
	}

	// use given certs to configure client-side TLS
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return tr, nil
}

var (
	prometheusApigeeRequests = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "apigee",
		Name:      "requests_seconds",
		Help:      "Time taken to make apigee requests by code",
		Buckets:   prometheus.DefBuckets,
	}, []string{"org", "env", "api", "code", "method"})
)
