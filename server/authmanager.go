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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	// PEMKeyType is the type of privateKey in the PEM file
	PEMKeyType  = "RSA PRIVATE KEY"
	jwtIssuer   = "apigee-remote-service-envoy"
	jwtAudience = "remote-service-client"
	authHeader  = "Authorization"
)

// AuthManager maintains an authorization header value
type AuthManager interface {
	getAuthorizationHeader() string
}

// NewAuthManager creates an auth manager
func NewAuthManager(config *Config) (AuthManager, error) {
	if config.IsGCPManaged() {
		m := &JWTAuthManager{}
		return m, m.start(config)
	}

	// basic API Key auth
	auth := fmt.Sprintf("%s:%s", config.Tenant.Key, config.Tenant.Secret)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	return &StaticAuthManager{
		authHeader: fmt.Sprintf("Basic %s", encodedAuth),
	}, nil
}

// StaticAuthManager just returns a static auth
type StaticAuthManager struct {
	authHeader string
}

func (a *StaticAuthManager) getAuthorizationHeader() string {
	return a.authHeader
}

// JWTAuthManager creates and maintains a current JWT token
type JWTAuthManager struct {
	authToken     *jwt.Token
	authHeader    string
	authHeaderMux sync.RWMutex
	timer         *time.Timer
}

func (a *JWTAuthManager) start(config *Config) error {

	privateKey := config.Tenant.PrivateKey
	kid := config.Tenant.PrivateKeyID
	jwtExpiration := config.Tenant.InternalJWTDuration
	jwtRefresh := config.Tenant.InternalJWTRefresh

	// set synchronously - if no error, should not occur thereafter
	if err := a.replaceJWT(privateKey, kid, jwtExpiration); err != nil {
		return err
	}

	a.timer = time.NewTimer(jwtRefresh)
	go func() {
		for {
			<-a.timer.C
			if err := a.replaceJWT(privateKey, kid, jwtExpiration); err != nil {
				panic(err)
			}
			a.timer.Reset(jwtRefresh)
		}
	}()

	return nil
}

func (a *JWTAuthManager) stop() {
	a.timer.Stop()
}

func (a *JWTAuthManager) replaceJWT(privateKey *rsa.PrivateKey, kid string, jwtExpiration time.Duration) error {
	log.Debugf("setting internal JWT")

	token, err := NewToken(jwtExpiration)
	if err != nil {
		return err
	}

	payload, err := SignJWT(token, jwa.RS256, privateKey, kid)
	if err != nil {
		return err
	}

	a.authHeaderMux.Lock()
	a.authToken = &token
	a.authHeader = fmt.Sprintf("Bearer %s", payload)
	a.authHeaderMux.Unlock()
	return nil
}

func (a *JWTAuthManager) getAuthorizationHeader() string {
	a.authHeaderMux.RLock()
	defer a.authHeaderMux.RUnlock()
	return a.authHeader
}

func (a *JWTAuthManager) getToken() *jwt.Token {
	a.authHeaderMux.RLock()
	defer a.authHeaderMux.RUnlock()
	return a.authToken
}

func LoadPrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {

	var err error
	privPem, _ := pem.Decode(privateKeyBytes)
	if privPem == nil {
		return nil, fmt.Errorf("bytes in bad format")
	}
	if PEMKeyType != privPem.Type {
		return nil, fmt.Errorf("%s required, found: %s", PEMKeyType, privPem.Type)
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			return nil, err
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, err
	}

	return privateKey, nil
}

// SignJWT signs an token with specified algorithm and keys
func SignJWT(t jwt.Token, method jwa.SignatureAlgorithm, key interface{}, kid string) ([]byte, error) {
	buf, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}

	hdr := jws.NewHeaders()
	if hdr.Set(jws.AlgorithmKey, method.String()) != nil {
		return nil, err
	}
	if hdr.Set(jws.TypeKey, "JWT") != nil {
		return nil, err
	}
	if hdr.Set(jws.KeyIDKey, kid) != nil {
		return nil, err
	}
	signed, err := jws.Sign(buf, method, key, jws.WithHeaders(hdr))
	if err != nil {
		return nil, err
	}

	return signed, nil
}

// NewToken generates a new jwt.Token with the necessary claims
func NewToken(jwtExpiration time.Duration) (jwt.Token, error) {
	now := time.Now()

	token := jwt.New()
	if err := token.Set(jwt.AudienceKey, jwtAudience); err != nil {
		return nil, err
	}
	if err := token.Set(jwt.IssuerKey, jwtIssuer); err != nil {
		return nil, err
	}
	if err := token.Set(jwt.IssuedAtKey, now.Unix()); err != nil {
		return nil, err
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(jwtExpiration)); err != nil {
		return nil, err
	}
	return token, nil
}

// RoundTripperFunc is a RoundTripper
type roundTripperFunc func(req *http.Request) (*http.Response, error)

// RoundTrip implements RoundTripper interface
func (rt roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

// AuthorizationRoundTripper adds an authorization header to any handled request
func AuthorizationRoundTripper(config *Config, next http.RoundTripper) (http.RoundTripper, error) {

	authManager, err := NewAuthManager(config)
	if err != nil {
		return nil, err
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// we won't override if set more locally
		if r.Header.Get(authHeader) == "" {
			r.Header.Add(authHeader, authManager.getAuthorizationHeader())
		}
		return next.RoundTrip(r)
	}), nil
}

// NoAuthPUTRoundTripper enables a http client to get rid of the authorization header in any PUT request,
// specifically used by the GCP managed analytics client to remove the header generated by the token source,
// which would otherwise interfere with the PUT request to the signed URL.
func NoAuthPUTRoundTripper() http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut {
			r.Header.Del(authHeader)
		}
		return http.DefaultTransport.RoundTrip(r)
	})
}
