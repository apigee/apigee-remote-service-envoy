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
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func metadataHeaders(api string, ac *auth.Context) (headers []*corev3.HeaderValueOption) {
	if ac == nil {
		return
	}

	headers = append(headers, createHeaderValueOption(headerAccessToken, ac.AccessToken, false))
	headers = append(headers, createHeaderValueOption(headerAPI, api, false))
	headers = append(headers, createHeaderValueOption(headerAPIProducts, strings.Join(ac.APIProducts, ","), false))
	headers = append(headers, createHeaderValueOption(headerApplication, ac.Application, false))
	headers = append(headers, createHeaderValueOption(headerClientID, ac.ClientID, false))
	headers = append(headers, createHeaderValueOption(headerDeveloperEmail, ac.DeveloperEmail, false))
	headers = append(headers, createHeaderValueOption(headerEnvironment, ac.Environment(), false))
	headers = append(headers, createHeaderValueOption(headerOrganization, ac.Organization(), false))
	headers = append(headers, createHeaderValueOption(headerScope, strings.Join(ac.Scopes, " "), false))
	return
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
