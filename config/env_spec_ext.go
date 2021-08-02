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
	"regexp"
	"strings"

	"github.com/apigee/apigee-remote-service-envoy/v2/transform"
	"github.com/apigee/apigee-remote-service-golib/v2/path"
)

const wildcard = "*"

// NewEnvironmentSpecExt creates an EnvironmentSpecExt
func NewEnvironmentSpecExt(spec *EnvironmentSpec) (*EnvironmentSpecExt, error) {
	ec := &EnvironmentSpecExt{
		EnvironmentSpec:    spec,
		apiPathTree:        path.NewTree(),
		opPathTree:         path.NewTree(),
		compiledTemplates:  make(map[string]*transform.Template),
		corsVary:           make(map[string]bool, len(spec.APIs)),
		corsAllowedOrigins: make(map[string]map[string]bool, len(spec.APIs)),
		compiledRegExps:    make(map[string]*regexp.Regexp),
	}

	for i := range spec.APIs {
		api := spec.APIs[i]

		split := strings.Split(api.BasePath, "/")
		split = append([]string{"/"}, split...)
		ec.apiPathTree.AddChild(split, 0, &api)

		var mustVary = false
		allowedOrigins := make(map[string]bool, len(api.Cors.AllowOrigins))
		for _, o := range api.Cors.AllowOrigins {
			allowedOrigins[o] = true
			if o == wildcard {
				mustVary = true
			}
		}
		ec.corsAllowedOrigins[api.ID] = allowedOrigins

		for _, r := range api.Cors.AllowOriginsRegexes {
			ec.compiledRegExps[r] = regexp.MustCompile(r)
		}

		ec.corsVary[api.ID] = mustVary || len(api.Cors.AllowOriginsRegexes) > 0 || len(api.Cors.AllowOrigins) > 1

		for i := range api.Operations {
			op := api.Operations[i]

			if len(op.HTTPMatches) == 0 { // empty is wildcard
				split = []string{api.ID, wildcard, wildcard}
				ec.opPathTree.AddChild(split, 0, &op)
			} else {
				for _, m := range op.HTTPMatches {
					split = strings.Split(m.PathTemplate, "/")
					method := m.Method
					if method == anyMethod {
						method = wildcard
					}
					split = append([]string{api.ID, method}, split...)
					ec.opPathTree.AddChild(split, 0, &op)
				}
			}

			for _, in := range op.ConsumerAuthorization.In {
				err := ec.parseAPIOperationParameter(in.Transformation)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	for _, j := range ec.JWTAuthentications() {
		for _, in := range j.In {
			err := ec.parseAPIOperationParameter(in.Transformation)
			if err != nil {
				return nil, err
			}
		}
	}

	return ec, nil
}

// EnvironmentSpecExt extends an EnvironmentSpec to hold cached values.
// Create using config.NewEnvironmentSpecExt()
type EnvironmentSpecExt struct {
	*EnvironmentSpec
	apiPathTree        path.Tree                      // base path -> *APISpec
	opPathTree         path.Tree                      // api.ID -> method -> sub path -> *Operation
	compiledTemplates  map[string]*transform.Template // string template -> Template
	corsVary           map[string]bool                // api ID -> true if vary header should be true
	corsAllowedOrigins map[string]map[string]bool     // api ID -> statically allowed origin -> true
	compiledRegExps    map[string]*regexp.Regexp      // uncompiled -> compiled
}

// JWTAuthentications returns a list of all JWTAuthentications for the Spec
func (e EnvironmentSpecExt) JWTAuthentications() []*JWTAuthentication {
	var auths []*JWTAuthentication
	for _, api := range e.APIs {
		for _, v := range api.jwtAuthentications {
			auths = append(auths, v)
		}
		for _, op := range api.Operations {
			for _, v := range op.jwtAuthentications {
				auths = append(auths, v)
			}
		}
	}
	return auths
}

func (h HTTPRequestTransformations) isEmpty() bool {
	return len(h.AppendHeaders) == 0 && len(h.RemoveHeaders) == 0 && len(h.SetHeaders) == 0
}

func (c ConsumerAuthorization) isEmpty() bool {
	return !c.Disabled && len(c.In) == 0
}

func (a AuthenticationRequirement) IsEmpty() bool {
	return !a.Disabled && isEmpty(a)
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

// parses the StringTransformation and adds to cache
func (e EnvironmentSpecExt) parseAPIOperationParameter(s StringTransformation) error {
	if s.Template == "" && s.Substitution == "" {
		return nil
	}
	template, err := transform.Parse(s.Template)
	e.compiledTemplates[s.Template] = template
	if err != nil {
		return err
	}
	template, _ = transform.Parse(s.Substitution)
	e.compiledTemplates[s.Substitution] = template
	return err
}

// Transform uses StringTransformation syntax to transform the passed string.
func (e EnvironmentSpecExt) transform(s StringTransformation, in string) string {
	if s.Template == "" && s.Substitution == "" {
		return in
	}
	template := e.compiledTemplates[s.Template]
	substitution := e.compiledTemplates[s.Substitution]
	return transform.Substitute(template, substitution, in)
}
