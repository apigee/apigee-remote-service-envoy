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

	"github.com/apigee/apigee-remote-service-golib/v2/path"
)

// NewEnvironmentSpecExt creates an EnvironmentSpecExt
func NewEnvironmentSpecExt(spec *EnvironmentSpec) *EnvironmentSpecExt {
	apiJwtRequirements := make(map[string][]*JWTAuthentication)
	apiPathTree := path.NewTree()
	opPathTree := path.NewTree()
	for i := range spec.APIs {
		api := spec.APIs[i]

		jwtRequirements := api.Authentication.AllJWTRequirements()
		apiJwtRequirements[api.ID] = jwtRequirements

		// tree: base path -> APISpec
		split := strings.Split(api.BasePath, "/")
		split = append(split, "**")
		apiPathTree.AddChild(split, 0, api)

		// tree: api.ID -> method -> path -> APIOperation
		for i := range api.Operations {
			op := api.Operations[i]
			for _, m := range op.HTTPMatches {
				split = strings.Split(m.PathTemplate, "/") // todo: templating
				split = append([]string{api.ID, m.Method}, split...)
				opPathTree.AddChild(split, 0, op)
			}
		}
	}

	return &EnvironmentSpecExt{
		EnvironmentSpec:    spec,
		ApiJwtRequirements: apiJwtRequirements,
		ApiPathTree:        apiPathTree,
		OpPathTree:         opPathTree,
	}

}

// EnvironmentSpecExt extends an EnvironmentSpec to hold cached values
type EnvironmentSpecExt struct {
	*EnvironmentSpec
	ApiJwtRequirements map[string][]*JWTAuthentication // api.ID -> JWTAuthentication
	ApiPathTree        path.Tree                       // base path -> APISpec
	OpPathTree         path.Tree                       // api.ID -> method -> sub path -> Operation
}
