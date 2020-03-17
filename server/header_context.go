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
	"encoding/base64"
	"encoding/json"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
)

const headerContextKey = "x-apigee-hc"

// note: authContext Scopes, Expires, and APIKey are not needed for ax
type headerContext struct {
	DeveloperEmail string   `json:"DE"`
	Application    string   `json:"DA"`
	AccessToken    string   `json:"AT"`
	ClientID       string   `json:"CI"`
	Organization   string   `json:"Or"`
	Environment    string   `json:"En"`
	APIProducts    []string `json:"AP"`
}

func makeHeaderContext(ac *auth.Context) *headerContext {
	if ac == nil {
		return nil
	}
	return &headerContext{
		DeveloperEmail: ac.DeveloperEmail,
		Application:    ac.Application,
		AccessToken:    ac.AccessToken,
		ClientID:       ac.ClientID,
		Organization:   ac.Organization(),
		Environment:    ac.Environment(),
		APIProducts:    ac.APIProducts,
	}
}

func (hc *headerContext) encode() string {
	msg, err := json.Marshal(hc)
	if err != nil {
		log.Errorf("encode header: %v", err)
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(msg))
}

func decodeAuthContext(h *handler, data string) *auth.Context {
	hc := &headerContext{}
	msg, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		log.Errorf("decode header: %v", err)
	} else {
		json.Unmarshal(msg, hc)
	}

	return &auth.Context{
		Context:        h,
		ClientID:       hc.ClientID,
		AccessToken:    hc.AccessToken,
		Application:    hc.Application,
		APIProducts:    hc.APIProducts,
		DeveloperEmail: hc.DeveloperEmail,
	}
}
