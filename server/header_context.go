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

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func addMetadataHeaders(okResponse *envoy_auth.OkHttpResponse, api string, ac *auth.Context, authorized bool) {
	if ac == nil {
		return
	}

	addHeaderValueOption(okResponse, headerAccessToken, ac.AccessToken, false)
	addHeaderValueOption(okResponse, headerAPI, api, false)
	addHeaderValueOption(okResponse, headerAPIProducts, strings.Join(ac.APIProducts, ","), false)
	addHeaderValueOption(okResponse, headerApplication, ac.Application, false)
	addHeaderValueOption(okResponse, headerClientID, ac.ClientID, false)
	addHeaderValueOption(okResponse, headerDeveloperEmail, ac.DeveloperEmail, false)
	addHeaderValueOption(okResponse, headerEnvironment, ac.Environment(), false)
	addHeaderValueOption(okResponse, headerOrganization, ac.Organization(), false)
	addHeaderValueOption(okResponse, headerScope, strings.Join(ac.Scopes, " "), false)

	if authorized {
		addHeaderValueOption(okResponse, headerAuthorized, "true", false)
	}
}

func (h *Handler) decodeMetadataHeaders(headers map[string]string) (string, *auth.Context) {

	api, ok := headers[headerAPI]
	if !ok {
		if api, ok = headers[h.apiHeader]; ok {
			log.Debugf("No context header %s, using api header: %s", headerAPI, h.apiHeader)
		} else {
			log.Debugf("No context header %s or api header: %s", headerAPI, h.apiHeader)
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
