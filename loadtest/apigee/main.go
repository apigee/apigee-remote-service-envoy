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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/apigee/apigee-remote-service-golib/quota"
	"github.com/apigee/apigee-remote-service-golib/util"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"gopkg.in/yaml.v3"
)

const (
	ENV_NAME             = "test"
	DEFAULT_NUM_PRODUCTS = 100
	RESPONSE_DELAY       = time.Millisecond

	QUOTA_LIMIT     = "1000000" // 1m
	QUOTA_INTERVAL  = "1"
	QUOTA_TIME_UNIT = "minute"
)

func main() {
	var addr string
	var host string
	var numProducts int
	var tlsDir string
	flag.StringVar(&addr, "addr", "", "address, default is random free port")
	flag.StringVar(&host, "host", "", "host for signed url")
	flag.StringVar(&tlsDir, "tls", "", "directory for tls files")
	flag.IntVar(&numProducts, "num-products", DEFAULT_NUM_PRODUCTS, "num products")
	flag.Parse()

	if addr == "" {
		p, err := util.FreePort()
		if err != nil {
			log.Fatal(err)
		}
		addr = fmt.Sprintf(":%d", p)
	}

	ts := &TestServer{
		numProducts: numProducts,
		host:        host,
	}
	defer ts.Close()
	ts.srv = &http.Server{
		Addr:    addr,
		Handler: ts.Handler(),
	}

	config := ts.Config()
	crd, err := makeConfigCRD(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("# You can use this config:")
	if err = yaml.NewEncoder(os.Stdout).Encode(crd); err != nil {
		log.Fatal(err)
	}

	if tlsDir == "" {
		_ = ts.srv.ListenAndServe()
	} else {
		ts.hasTLS = true
		crt := path.Join(tlsDir, "tls.crt")
		key := path.Join(tlsDir, "tls.key")
		_ = ts.srv.ListenAndServeTLS(crt, key)
	}
	select {} // forever
}

type (
	TestServer struct {
		srv         *http.Server
		numProducts int
		quotas      map[string]*quota.Result
		quotaLock   sync.Mutex
		host        string
		hasTLS      bool
	}

	JWKS struct {
		Keys []jwk.Key `json:"keys"`
	}
)

func (ts *TestServer) Config() server.Config {
	return server.Config{
		Tenant: server.TenantConfig{
			InternalAPI:      ts.URL(),
			RemoteServiceAPI: ts.URL(),
			OrgName:          "org",
			EnvName:          ENV_NAME,
			Key:              "key",
			Secret:           "secret",
		},
	}
}

func (ts *TestServer) Handler() http.Handler {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	jwks, err := createJWKS(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	productsMap := createProducts(ts.numProducts)
	products := make([]product.APIProduct, 0, len(productsMap))
	for _, v := range productsMap {
		products = append(products, v)
	}
	productsResponse := product.APIResponse{APIProducts: products}

	m := http.NewServeMux()

	m.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(RESPONSE_DELAY)
		resp := productsResponse
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	m.HandleFunc("/verifyApiKey", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(RESPONSE_DELAY)
		var req auth.APIKeyRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Body.Close()

		resp := auth.APIKeyResponse{}
		if product, ok := productsMap[req.APIKey]; ok {
			resp, err = createVerifyAPIKeyResponse(product, privateKey)
			if err != nil {
				log.Fatal(err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	ts.quotas = map[string]*quota.Result{}
	m.HandleFunc("/quotas", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(RESPONSE_DELAY)

		var req quota.Request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Body.Close()
		ts.quotaLock.Lock()
		resp, ok := ts.quotas[req.Identifier]
		if !ok {
			resp = &quota.Result{}
			ts.quotas[req.Identifier] = resp
		}
		now := time.Now()
		resp.Allowed = req.Allow
		resp.Timestamp = now.UnixNano() / 1000
		if resp.Timestamp >= resp.ExpiryTime {
			resp.Used = 0
			resp.Exceeded = 0
			resp.ExpiryTime = now.Add(time.Minute).UnixNano() / 1000
		}
		resp.Used += req.Weight
		if resp.Used > resp.Allowed {
			resp.Exceeded = resp.Used - resp.Allowed
			resp.Used = resp.Allowed
		}
		ts.quotaLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	m.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(RESPONSE_DELAY)
		resp := jwks
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	// this is SaaS analytics
	m.HandleFunc("/analytics/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(RESPONSE_DELAY)
		url := "%s/signed-upload-url?relative_file_path=%s&tenant=%s"
		resp := map[string]interface{}{
			"url": fmt.Sprintf(url, ts.URL(), r.FormValue("relative_file_path"), r.FormValue("tenant")),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	// this is UAP analytics
	m.HandleFunc("/v1/organizations/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(RESPONSE_DELAY)
		url := "%s/signed-upload-url?relative_file_path=%s&tenant=%s"
		resp := map[string]interface{}{
			"url": fmt.Sprintf(url, ts.URL(), r.FormValue("relative_file_path"), r.FormValue("tenant")),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Fatal(err)
		}
	})

	// upload
	m.HandleFunc("/signed-upload-url", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(RESPONSE_DELAY)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Fatal(err)
		}
	})

	// m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {})
	// m.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {})
	// m.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {})

	return m
}

func (ts *TestServer) Close() { ts.srv.Close() }

func (ts *TestServer) URL() string {
	split := strings.Split(ts.srv.Addr, ":")
	var host, port string
	port = ts.srv.Addr
	if len(split) > 1 {
		host = split[0]
		port = split[1]
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if ts.host != "" {
		host = ts.host
	}
	if ts.hasTLS {
		return fmt.Sprintf("https://%s:%s", host, port)
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

// product-n where n in [1...num]
func createProducts(num int) map[string]product.APIProduct {
	products := make(map[string]product.APIProduct, num)
	for i := 1; i <= num; i++ {
		name := fmt.Sprintf("product-%d", i)
		product := product.APIProduct{
			Attributes: []product.Attribute{
				{Name: product.TargetsAttr, Value: name},
			},
			Description:   name,
			DisplayName:   name,
			Environments:  []string{ENV_NAME},
			Name:          name,
			Resources:     []string{"/"},
			Scopes:        []string{name},
			QuotaInterval: QUOTA_INTERVAL,
			QuotaLimit:    QUOTA_LIMIT,
			QuotaTimeUnit: QUOTA_TIME_UNIT,
		}
		products[name] = product
	}

	return products
}

func createVerifyAPIKeyResponse(product product.APIProduct, privateKey *rsa.PrivateKey) (auth.APIKeyResponse, error) {
	token := jwt.New()
	_ = token.Set(jwt.AudienceKey, "remote-service-client")
	_ = token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwt.IssuerKey, "testserver")
	_ = token.Set(jwt.NotBeforeKey, time.Now().Add(-10*time.Minute).Unix())
	_ = token.Set(jwt.IssuedAtKey, time.Now().Unix())
	_ = token.Set(jwt.ExpirationKey, (time.Now().Add(10 * time.Minute)).Unix())
	_ = token.Set("access_token", "f2d45913643bccf3ad92998d06aabbd445e5376271b83fc95e5fc8515f59a5e9")
	_ = token.Set("client_id", "f2d45913643bccf3ad92998d06aabbd445e5376271b83fc95e5fc8515f59a5e9")
	_ = token.Set("application_name", "application-name")
	_ = token.Set("api_product_list", []string{product.Name})
	payload, err := jwt.Sign(token, jwa.RS256, privateKey)

	return auth.APIKeyResponse{Token: string(payload)}, err
}

func createJWKS(privateKey *rsa.PrivateKey) (*JWKS, error) {
	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := key.Set("kid", "1"); err != nil {
		return nil, err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return nil, err
	}

	jwks := &JWKS{
		Keys: []jwk.Key{
			key,
		},
	}

	return jwks, nil
}

func makeConfigCRD(config server.Config) (*server.ConfigMapCRD, error) {
	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &server.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: server.Metadata{
			Name:      "test-apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: map[string]string{"config.yaml": string(configYAML)},
	}, nil
}
