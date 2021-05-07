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

package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	authjwt "github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// GenerateKeyAndJWKs generates a new key and JWKS, kid = "kid"
func GenerateKeyAndJWKs(kid string) (privateKey *rsa.PrivateKey, jwksBuf []byte, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	var key jwk.Key
	key, err = jwk.New(&privateKey.PublicKey)
	if err != nil {
		return
	}
	if err = key.Set(jwk.KeyIDKey, kid); err != nil {
		return
	}
	if err = key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return
	}

	jwksBuf, err = json.MarshalIndent(key, "", "")

	return
}

func GenerateJWT(privateKey *rsa.PrivateKey, claims map[string]interface{}) (string, error) {
	key, err := jwk.New(privateKey)
	if err != nil {
		return "", err
	}
	if err := key.Set(jwk.KeyIDKey, "1"); err != nil {
		return "", err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256.String()); err != nil {
		return "", err
	}

	token := jwt.New()
	for k, v := range claims {
		if err = token.Set(k, v); err != nil {
			return "", err
		}
	}

	payload, err := jwt.Sign(token, jwa.RS256, key)
	return string(payload), err
}

type MockJWTVerifier struct {
}

func (f MockJWTVerifier) Start() {
}

func (f MockJWTVerifier) Stop() {
}

func (f MockJWTVerifier) AddProvider(p authjwt.Provider) {
}

func (f MockJWTVerifier) EnsureProvidersLoaded(context.Context) error {
	return nil
}

func (f MockJWTVerifier) Parse(raw string, p authjwt.Provider) (map[string]interface{}, error) {
	token, err := jwt.Parse([]byte(raw))
	if err != nil {
		return nil, err
	}
	return token.AsMap(context.Background())
}
