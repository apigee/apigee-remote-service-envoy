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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	authjwt "github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// GenerateKeyAndJWKs generates a new key and JWKS, kid = "kid"
func GenerateKeyAndJWKs(kid string) (privateKey *rsa.PrivateKey, jwksBuf []byte, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	jwk := jose.JSONWebKey{
		KeyID:     kid,
		Algorithm: "RSA",
		Key:       &privateKey.PublicKey,
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	jwksBuf, err = json.MarshalIndent(jwks, "", "")

	return
}

// Generate a test JWT from a privateKey
func GenerateJWT(privateKey *rsa.PrivateKey, claims map[string]interface{}) (string, error) {
	rsaSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader("kid", "1"))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	jwt, err := jwt.Signed(rsaSigner).Claims(claims).CompactSerialize()
	return jwt, err
}

type MockJWTVerifier struct {
}

func (f MockJWTVerifier) Start() {
}

func (f MockJWTVerifier) Stop() {
}

func (f MockJWTVerifier) AddProvider(p authjwt.Provider) {
}

func (f MockJWTVerifier) Parse(raw string, p authjwt.Provider) (map[string]interface{}, error) {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	return claims, err
}
