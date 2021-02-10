// Copyright 2021 Google LLC
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
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	extAuthzFilterNamespace = "envoy.filters.http.ext_authz"

	headerAuthorized     = "x-apigee-authorized"
	headerAccessToken    = "x-apigee-accesstoken"
	headerAPI            = "x-apigee-api"
	headerAPIProducts    = "x-apigee-apiproducts"
	headerApplication    = "x-apigee-application"
	headerClientID       = "x-apigee-clientid"
	headerDeveloperEmail = "x-apigee-developeremail"
	headerEnvironment    = "x-apigee-environment"
	headerOrganization   = "x-apigee-organization"
	headerScope          = "x-apigee-scope"
)

// encodeExtAuthzMetadata encodes given target and auth context into
// Envoy ext_authz's filter's dynamic metadata
func encodeExtAuthzMetadata(api string, ac *auth.Context, authorized bool) *structpb.Struct {
	if ac == nil {
		return nil
	}

	fields := map[string]*structpb.Value{
		headerAccessToken:    stringValueFrom(ac.AccessToken),
		headerAPI:            stringValueFrom(api),
		headerAPIProducts:    stringValueFrom(strings.Join(ac.APIProducts, ",")),
		headerApplication:    stringValueFrom(ac.Application),
		headerClientID:       stringValueFrom(ac.ClientID),
		headerDeveloperEmail: stringValueFrom(ac.DeveloperEmail),
		headerEnvironment:    stringValueFrom(ac.Environment()),
		headerOrganization:   stringValueFrom(ac.Organization()),
		headerScope:          stringValueFrom(strings.Join(ac.Scopes, " ")),
	}
	if authorized {
		fields[headerAuthorized] = stringValueFrom("true")
	}

	return &structpb.Struct{
		Fields: fields,
	}

}

// stringValueFrom returns a *structpb.Value with a StringValue Kind
func stringValueFrom(v string) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: v,
		},
	}
}

// stringValueFrom returns a *structpb.Value and status
func stringFrom(sv *structpb.Value) (string, bool) {
	if sv == nil {
		return "", false
	}
	v, ok := sv.GetKind().(*structpb.Value_StringValue)
	if !ok {
		return "", false
	}
	return v.StringValue, true
}

// decodeExtAuthzMetadata decodes the Envoy ext_authz's filter's metadata
// fields into target (api) and auth context
func (h *Handler) decodeExtAuthzMetadata(fields map[string]*structpb.Value) (string, *auth.Context) {

	api, ok := stringFrom(fields[headerAPI])
	if !ok {
		if api, ok = stringFrom(fields[headerAPI]); ok {
			log.Debugf("No context header %s, using target header: %s", headerAPI, h.targetHeader)
		} else {
			log.Debugf("No context header %s or target header: %s", headerAPI, h.targetHeader)
			return "", nil
		}
	}

	var rootContext context.Context = h
	if h.isMultitenant {
		env, ok := stringFrom(fields[headerEnvironment])
		if !ok {
			log.Warnf("Multitenant mode but %s header not found. Check Envoy config.", headerEnvironment)
		}
		rootContext = &multitenantContext{h, env}
	}

	ctx := &auth.Context{Context: rootContext}
	if token, ok := stringFrom(fields[headerAccessToken]); ok {
		ctx.AccessToken = token
	}
	if products, ok := stringFrom(fields[headerAPIProducts]); ok {
		ctx.APIProducts = strings.Split(products, ",")
	}
	if app, ok := stringFrom(fields[headerApplication]); ok {
		ctx.Application = app
	}
	if clientID, ok := stringFrom(fields[headerClientID]); ok {
		ctx.ClientID = clientID
	}
	if developerEmail, ok := stringFrom(fields[headerDeveloperEmail]); ok {
		ctx.DeveloperEmail = developerEmail
	}
	if scopes, ok := stringFrom(fields[headerScope]); ok {
		ctx.Scopes = strings.Split(scopes, " ")
	}

	return api, ctx
}
