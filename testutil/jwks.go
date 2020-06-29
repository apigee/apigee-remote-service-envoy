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

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
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
	key.Set(jwk.KeyIDKey, kid)
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	jwksBuf, err = json.MarshalIndent(key, "", "")

	return
}
