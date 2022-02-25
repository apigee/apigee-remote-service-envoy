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

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
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
	headerGrpcService    = "x-apigee-grpcservice"
	headerOperation      = "x-apigee-operation"
)

//TODO: Decide if I want to keep this naming
//TODO: Determine if there is a better place for the stuct to live
type Metadata struct {
	Api string
	Ac *auth.Context
	Authorized bool
	GrpcService string
	Operation string
}

// encodeAuthMetadata encodes given api and auth context into
// Envoy ext_authz's filter's dynamic metadata
func encodeAuthMetadata(metadata *Metadata) (*structpb.Struct, error) {
	api := metadata.Api
	ac := metadata.Ac
	authorized := metadata.Authorized
	grpcService	:= metadata.GrpcService
	operation	:= metadata.Operation

	if ac == nil {
		return &structpb.Struct{Fields: make(map[string]*structpb.Value)}, nil
	}

	fields := map[string]interface{}{
		headerAccessToken:    ac.AccessToken,
		headerAPI:            api,
		headerAPIProducts:    strings.Join(ac.APIProducts, ","),
		headerApplication:    ac.Application,
		headerClientID:       ac.ClientID,
		headerDeveloperEmail: ac.DeveloperEmail,
		headerEnvironment:    ac.Environment(),
		headerOrganization:   ac.Organization(),
		headerScope:          strings.Join(ac.Scopes, " "),
		headerGrpcService:    grpcService,
		headerOperation:      operation,
	}
	if authorized {
		fields[headerAuthorized] = "true"
	}

	return structpb.NewStruct(fields)
}

// decodeAuthMetadata decodes the Envoy ext_authz's filter's metadata
// fields into api and auth context
func (h *Handler) decodeAuthMetadata(fields map[string]*structpb.Value) *Metadata {

	api := fields[headerAPI].GetStringValue()
	if api == "" {
		log.Debugf("No context header: %s", headerAPI)
		return nil
	}

	var rootContext context.Context = h
	if h.isMultitenant {
		env := fields[headerEnvironment].GetStringValue()
		if env == "" {
			log.Warnf("Multitenant mode but %s header not found. Check Envoy config.", headerEnvironment)
		}
		rootContext = &multitenantContext{h, env}
	}

	return &Metadata{
		Api: api,
		Ac: &auth.Context{
			Context:        rootContext,
			AccessToken:    fields[headerAccessToken].GetStringValue(),
			APIProducts:    strings.Split(fields[headerAPIProducts].GetStringValue(), ","),
			Application:    fields[headerApplication].GetStringValue(),
			ClientID:       fields[headerClientID].GetStringValue(),
			DeveloperEmail: fields[headerDeveloperEmail].GetStringValue(),
			Scopes:         strings.Split(fields[headerScope].GetStringValue(), " "),
		},
		Authorized: fields[headerAuthorized].GetBoolValue(),
		GrpcService: fields[headerGrpcService].GetStringValue(),
		Operation: fields[headerOperation].GetStringValue(),
	}
}
