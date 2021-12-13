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
	"os"
	"strings"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/fault"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/google/uuid"
)

const (
	// Same as header API but needed for monitoring purpose.
	headerProxy         = "x-apigee-proxy"
	headerProxyBasepath = "x-apigee-proxy-basepath"
	headerDPColor       = "x-apigee-dp-color"
	headerRegion        = "x-apigee-region"
	headerMessageID     = "x-apigee-message-id"

	headerFaultCode     = "x-apigee-fault-code"
	headerFaultFlag     = "x-apigee-fault-flag"
	headerFaultSource   = "x-apigee-fault-source"
	headerFaultRevision = "x-apigee-fault-revision"
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

// This returns HeaderValueOptions that have used to populate Apigee Dynamic Data access logs
// in Apigee X/Hybrid.
func apigeeDynamicDataHeaders(org, env, api string, apiSpec *config.APISpec, adapterFault *fault.AdapterFault) (headers []*corev3.HeaderValueOption) {
	headers = append(headers, createHeaderValueOption(headerOrganization, org, false))
	headers = append(headers, createHeaderValueOption(headerEnvironment, env, false))
	headers = append(headers, createHeaderValueOption(headerProxy, api, false))
	headers = append(headers, createHeaderValueOption(headerDPColor, os.Getenv("APIGEE_DPCOLOR"), false))
	headers = append(headers, createHeaderValueOption(headerRegion, os.Getenv("APIGEE_REGION"), false))
	headers = append(headers, createHeaderValueOption(headerMessageID, uuid.NewString(), false))
	headers = append(headers, createHeaderValueOption("verboseerrors", "false", false))

	if apiSpec != nil {
		headers = append(headers, createHeaderValueOption(headerProxyBasepath, apiSpec.BasePath, false))
	}

	// Include fault related headers.
	if adapterFault != nil {
		if adapterFault.RpcCode == rpc.INTERNAL {
			headers = append(headers, createHeaderValueOption(headerFaultSource, "ARC", false))
			headers = append(headers, createHeaderValueOption(headerFaultFlag, "true", false))
			if apiSpec != nil {
				headers = append(headers, createHeaderValueOption(headerFaultRevision, apiSpec.RevisionID, false))
			}

			if adapterFault.FaultCode == "" {
				// A placeholder fault code value.
				adapterFault.FaultCode = "fault"
			}

			headers = append(headers, createHeaderValueOption(headerFaultCode, adapterFault.FaultCode, false))
		}
	}

	return
}
