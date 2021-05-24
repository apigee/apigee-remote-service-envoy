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

// Package config defines the API Runtime Control config and provides
// the config loading and validation functions.
package config

import (
	"strings"

	"github.com/apigee/apigee-remote-service-envoy/v2/transform"
	"github.com/apigee/apigee-remote-service-golib/v2/path"
)

// TODO: add path templating

// NewEnvironmentSpecExt creates an EnvironmentSpecExt
func NewEnvironmentSpecExt(spec *EnvironmentSpec) (*EnvironmentSpecExt, error) {
	jwtAuthentications := make(map[string]map[string]*JWTAuthentication)
	apiPathTree := path.NewTree()
	opPathTree := path.NewTree()
	parsedTransformations := make(map[string]*transform.Template)

	for i := range spec.APIs {
		api := spec.APIs[i]

		jwtAuthentications[api.ID] = map[string]*JWTAuthentication{}
		api.Authentication.mapJWTAuthentications(jwtAuthentications[api.ID])

		// tree: base path -> APISpec
		split := strings.Split(api.BasePath, "/")
		split = append([]string{"/"}, split...)
		apiPathTree.AddChild(split, 0, &api)

		// tree: api.ID -> method -> path -> APIOperation
		for i := range api.Operations {
			op := api.Operations[i]

			op.Authentication.mapJWTAuthentications(jwtAuthentications[api.ID])

			for _, m := range op.HTTPMatches {
				split = strings.Split(m.PathTemplate, "/")
				split = append([]string{api.ID, m.Method}, split...)
				opPathTree.AddChild(split, 0, &op)
			}

			for _, in := range op.ConsumerAuthorization.In {
				template, err := transform.Parse(in.Transformation.Template)
				parsedTransformations[in.Transformation.Template] = template
				if err != nil {
					return nil, err
				}
				template, _ = transform.Parse(in.Transformation.Substitution)
				parsedTransformations[in.Transformation.Substitution] = template
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &EnvironmentSpecExt{
		EnvironmentSpec:       spec,
		jwtAuthentications:    jwtAuthentications,
		apiPathTree:           apiPathTree,
		opPathTree:            opPathTree,
		parsedTransformations: parsedTransformations,
	}, nil
}

// EnvironmentSpecExt extends an EnvironmentSpec to hold cached values.
// Create using config.NewEnvironmentSpecExt()
type EnvironmentSpecExt struct {
	*EnvironmentSpec
	jwtAuthentications    map[string]map[string]*JWTAuthentication // api.ID -> auth.name -> *JWTAuthentication
	apiPathTree           path.Tree                                // base path -> *APISpec
	opPathTree            path.Tree                                // api.ID -> method -> sub path -> *Operation
	parsedTransformations map[string]*transform.Template
}

// JWTAuthentications returns a list of all JWTAuthentications for the Spec
func (e EnvironmentSpecExt) JWTAuthentications() []*JWTAuthentication {
	var auths []*JWTAuthentication
	for _, m := range e.jwtAuthentications {
		for _, v := range m {
			auths = append(auths, v)
		}
	}
	return auths
}

func (h HTTPRequestTransformations) isEmpty() bool {
	return len(h.AppendHeaders) == 0 && len(h.RemoveHeaders) == 0 && len(h.SetHeaders) == 0
}

func (c ConsumerAuthorization) isEmpty() bool {
	return len(c.In) == 0
}

func (a AuthenticationRequirement) IsEmpty() bool {
	return isEmpty(a)
}

// populates passed map with JWTAuthentication.name -> *JWTAuthentication for all enclosing Requirements
func (a AuthenticationRequirement) mapJWTAuthentications(nameMap map[string]*JWTAuthentication) {
	mapJWTRequirements(a, nameMap)
}

// populates passed map with JWTAuthentication.name -> *JWTAuthentication for all enclosing Requirements
func mapJWTRequirements(auth AuthenticationRequirement, nameMap map[string]*JWTAuthentication) {
	switch v := auth.Requirements.(type) {
	case JWTAuthentication:
		nameMap[v.Name] = &v
	case AnyAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			mapJWTRequirements(val, nameMap)
		}
	case AllAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			mapJWTRequirements(val, nameMap)
		}
	}
}

func isEmpty(auth AuthenticationRequirement) bool {
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return false
	case AnyAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !isEmpty(r) {
				return false
			}
		}
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !isEmpty(r) {
				return false
			}
		}
	}
	return true
}

// Transform uses StringTransformation syntax to transform the passed string.
func (e EnvironmentSpecExt) transform(s StringTransformation, in string) string {
	if s.Template == "" && s.Substitution == "" {
		return in
	}
	template := e.parsedTransformations[s.Template]
	substitution := e.parsedTransformations[s.Substitution]
	return transform.Substitute(template, substitution, in)
}
