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
	"strings"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/context"
	"github.com/apigee/apigee-remote-service-golib/log"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

const headerAuthorized = "x-apigee-authorized"
const headerAccessToken = "x-apigee-accesstoken"
const headerAPI = "x-apigee-api"
const headerAPIProducts = "x-apigee-apiproducts"
const headerApplication = "x-apigee-application"
const headerClientID = "x-apigee-clientid"
const headerDeveloperEmail = "x-apigee-developeremail"
const headerEnvironment = "x-apigee-environment"
const headerOrganization = "x-apigee-organization"
const headerScope = "x-apigee-scope"

func makeMetadataHeaders(api string, ac *auth.Context) []*core.HeaderValueOption {
	if ac == nil {
		return nil
	}

	return []*core.HeaderValueOption{
		header(headerAccessToken, ac.AccessToken),
		header(headerAPI, api),
		header(headerAPIProducts, strings.Join(ac.APIProducts, ",")),
		header(headerApplication, ac.Application),
		header(headerClientID, ac.ClientID),
		header(headerDeveloperEmail, ac.DeveloperEmail),
		header(headerEnvironment, ac.Environment()),
		header(headerOrganization, ac.Organization()),
		header(headerScope, strings.Join(ac.Scopes, " ")),
	}
}

func header(key, value string) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   key,
			Value: value,
		},
	}
}

func (h *Handler) decodeMetadataHeaders(headers map[string]string) (string, *auth.Context) {

	api, ok := headers[headerAPI]
	if !ok {
		if api, ok = headers[h.targetHeader]; ok {
			log.Debugf("No context header %s, using target header: %s", headerAPI, h.targetHeader)
		} else {
			log.Debugf("No context header %s or target header: %s", headerAPI, h.targetHeader)
			return "", nil
		}
	}

	var rootContext context.Context = h
	if h.isMultitenant {
		if headers[headerEnvironment] == "" {
			log.Warnf("Multitenant mode but %s header not found. Check Envoy config.", headerEnvironment)
		}
		rootContext = &multitenantContext{h, headers[headerEnvironment]}
	}

	return api, &auth.Context{
		Context:        rootContext,
		AccessToken:    headers[headerAccessToken],
		APIProducts:    strings.Split(headers[headerAPIProducts], ","),
		Application:    headers[headerApplication],
		ClientID:       headers[headerClientID],
		DeveloperEmail: headers[headerDeveloperEmail],
		Scopes:         strings.Split(headers[headerScope], " "),
	}
}
