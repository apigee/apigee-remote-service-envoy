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

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/oauth/iam"
	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
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
	envSpecsByID          map[string]*config.EnvironmentSpecExt
	operationConfigType   string
	ready                 *util.AtomicBool

	productMan   product.Manager
	authMan      auth.Manager
	analyticsMan analytics.Manager
	quotaMan     quota.Manager

	iamService *iam.IAMService
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
	if h.iamService != nil {
		go close(h.iamService)
	}
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

// Ready returns true if the handler is ready to process requests
func (h *Handler) Ready() bool {
	return h.ready.IsTrue()
}

// NewHandler creates a handler
func NewHandler(cfg *config.Config) (*Handler, error) {

	var internalAPI, remoteServiceAPI *url.URL
	var err error
	if cfg.Tenant.InternalAPI != "" {
		internalAPI, err = url.Parse(cfg.Tenant.InternalAPI)
		if err != nil {
			return nil, err
		}
		if internalAPI.Scheme == "" {
			return nil, fmt.Errorf("invalid URL: %s", cfg.Tenant.InternalAPI)
		}
	}
	if cfg.Tenant.RemoteServiceAPI != "" {
		remoteServiceAPI, err = url.Parse(cfg.Tenant.RemoteServiceAPI)
		if err != nil {
			return nil, err
		}
		if remoteServiceAPI.Scheme == "" {
			return nil, fmt.Errorf("invalid URL: %s", cfg.Tenant.RemoteServiceAPI)
		}
	}

	// get a roundtripper with client TLS config
	tr, err := roundTripperWithTLS(cfg.Tenant.TLS)
	if err != nil {
		return nil, err
	}

	// add authorization to transport
	tr, err = AuthorizationRoundTripper(cfg, tr)
	if err != nil {
		return nil, err
	}

	var opConfigTypes []string
	if cfg.Tenant.OperationConfigType != "" {
		opConfigTypes = append(opConfigTypes, cfg.Tenant.OperationConfigType)
	}
	productMan, err := product.NewManager(product.Options{
		Client:               instrumentedClientFor(cfg, "products", tr),
		BaseURL:              remoteServiceAPI,
		RefreshRate:          cfg.Products.RefreshRate,
		Org:                  cfg.Tenant.OrgName,
		Env:                  cfg.Tenant.EnvName,
		OperationConfigTypes: opConfigTypes,
	})
	if err != nil {
		return nil, err
	}

	environmentSpecsByID := make(map[string]*config.EnvironmentSpecExt, len(cfg.EnvironmentSpecs.Inline))
	var jwtProviders []jwt.Provider
	var iamsvc *iam.IAMService
	if len(cfg.EnvironmentSpecs.Inline) != 0 {
		if creds, err := google.FindDefaultCredentials(context.Background(), config.ApigeeAPIScope); err != nil {
			log.Warnf("failed to find application default credentials for google oauth: %v", err)
		} else {
			client := clientAuthorizedByCredentials(cfg, "google-oauth", creds)
			svc, err := iam.NewIAMService(option.WithHTTPClient(client))
			if err != nil {
				log.Warnf("failed to create iam service: %v", err)
			} else {
				iamsvc = svc
			}
		}
	}
	for i := range cfg.EnvironmentSpecs.Inline {
		// make EnvironmentSpecExt lookup table
		spec := cfg.EnvironmentSpecs.Inline[i]
		envSpec, err := config.NewEnvironmentSpecExt(&spec, config.WithIAMService(iamsvc))
		if err != nil {
			return nil, err
		}
		environmentSpecsByID[spec.ID] = envSpec

		// make providers array
		for _, jwtAuth := range envSpec.JWTAuthentications() {
			source := jwtAuth.JWKSSource.(config.RemoteJWKS)
			provider := jwt.Provider{
				JWKSURL: source.URL,
				Refresh: source.CacheDuration,
			}
			jwtProviders = append(jwtProviders, provider)
		}
	}

	authMan, err := auth.NewManager(auth.Options{
		Client:              instrumentedClientFor(cfg, "auth", tr),
		APIKeyCacheDuration: cfg.Auth.APIKeyCacheDuration,
		Org:                 cfg.Tenant.OrgName,
		JWTProviders:        jwtProviders,
	})
	if err != nil {
		return nil, err
	}

	quotaMan, err := quota.NewManager(quota.Options{
		BaseURL: remoteServiceAPI,
		Client:  instrumentedClientFor(cfg, "quotas", tr),
		Org:     cfg.Tenant.OrgName,
	})
	if err != nil {
		return nil, err
	}

	tempDirMode := os.FileMode(0700)
	tempDir := cfg.Global.TempDir
	analyticsDir := filepath.Join(tempDir, "analytics")
	if err := os.MkdirAll(analyticsDir, tempDirMode); err != nil {
		return nil, err
	}

	var analyticsClient *http.Client
	if cfg.Analytics.Credentials != nil {
		// Attempts to get an authorized http client with given analytics credentials
		analyticsClient = clientAuthorizedByCredentials(cfg, "analytics", cfg.Analytics.Credentials)
		// overwrite the internalAPI to the GCP managed host if not initialized yet
		if internalAPI == nil {
			internalAPI, _ = url.Parse(config.GCPExperienceBase)
		}
	} else {
		log.Debugf("analytics http client not using GCP authorization")
		tlsConfig := config.TLSClientSpec{ // only use AllowUnverifiedSSLCert first
			AllowUnverifiedSSLCert: cfg.Tenant.TLS.AllowUnverifiedSSLCert,
		}
		if cfg.Analytics.LegacyEndpoint { // allow mTLS config for OPDK
			tlsConfig = cfg.Tenant.TLS
		}
		tr, err := roundTripperWithTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		// the same method is called previously with same inputs, no need to check error again
		tr, _ = AuthorizationRoundTripper(cfg, tr)
		analyticsClient = instrumentedClientFor(cfg, "analytics", tr)
	}

	analyticsMan, err := analytics.NewManager(analytics.Options{
		LegacyEndpoint:     cfg.Analytics.LegacyEndpoint,
		BufferPath:         analyticsDir,
		StagingFileLimit:   cfg.Analytics.FileLimit,
		BaseURL:            internalAPI,
		Client:             analyticsClient,
		SendChannelSize:    cfg.Analytics.SendChannelSize,
		CollectionInterval: cfg.Analytics.CollectionInterval,
	})
	if err != nil {
		return nil, err
	}

	h := &Handler{
		remoteServiceAPI:      remoteServiceAPI,
		internalAPI:           internalAPI,
		orgName:               cfg.Tenant.OrgName,
		envName:               cfg.Tenant.EnvName,
		productMan:            productMan,
		authMan:               authMan,
		analyticsMan:          analyticsMan,
		quotaMan:              quotaMan,
		apiKeyClaim:           cfg.Auth.APIKeyClaim,
		apiKeyHeader:          cfg.Auth.APIKeyHeader,
		apiHeader:             cfg.Auth.APIHeader,
		allowUnauthorized:     cfg.Auth.AllowUnauthorized,
		jwtProviderKey:        cfg.Auth.JWTProviderKey,
		appendMetadataHeaders: cfg.Auth.AppendMetadataHeaders,
		isMultitenant:         cfg.Tenant.IsMultitenant(),
		envSpecsByID:          environmentSpecsByID,
		operationConfigType:   cfg.Tenant.OperationConfigType,
		ready:                 util.NewAtomicBool(false),
		iamService:            iamsvc,
	}
	h.setReadyWhenReady()

	return h, nil
}

func (h Handler) setReadyWhenReady() {
	go func() {
		_ = h.productMan.Products() // blocks until loaded
		h.ready.SetTrue()
	}()
}

// instrumentedClientFor returns a http.Client with a given RoundTripper
func instrumentedClientFor(cfg *config.Config, api string, rt http.RoundTripper) *http.Client {
	rt = roundTripperWithPrometheus(cfg, api, rt)
	return &http.Client{
		Timeout:   cfg.Tenant.ClientTimeout,
		Transport: rt,
	}
}

// roundTripperWithPrometheus returns a http.RoundTripper with prometheus labels configured
func roundTripperWithPrometheus(cfg *config.Config, api string, rt http.RoundTripper) http.RoundTripper {
	promLabels := prometheus.Labels{"org": cfg.Tenant.OrgName, "env": cfg.Tenant.EnvName, "api": api}
	observer := prometheusApigeeRequests.MustCurryWith(promLabels)
	return promhttp.InstrumentRoundTripperDuration(observer, rt)
}

// clientAuthorizedByServiceAccount returns a http client authorized with the
// service account credentials provided as json data or application default credentials
func clientAuthorizedByCredentials(cfg *config.Config, api string, cred *google.Credentials) *http.Client {
	ctx := context.Background()

	client := oauth2.NewClient(ctx, cred.TokenSource)

	// modify base roundtripper to strip auth header on PUT requests
	rt := client.Transport.(*oauth2.Transport)
	rt.Base = NoAuthPUTRoundTripper()

	client.Transport = roundTripperWithPrometheus(cfg, api, rt)
	client.Timeout = cfg.Tenant.ClientTimeout
	return client
}

// roundTripperWithTLS returns a http.RoundTripper with given TLSClientConfig
// and the default http.Transport will be used given a default TLSClientConfig
func roundTripperWithTLS(cfg config.TLSClientSpec) (http.RoundTripper, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.AllowUnverifiedSSLCert {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	// add given CA to the RootCAs
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
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
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
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
