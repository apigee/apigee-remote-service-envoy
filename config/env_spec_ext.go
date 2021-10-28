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
	"fmt"
	"regexp"
	"strings"

	"github.com/apigee/apigee-remote-service-envoy/v2/iam/google"
	"github.com/apigee/apigee-remote-service-envoy/v2/transform"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/path"
	"google.golang.org/api/option"
)

const (
	wildcard       = "*"
	doubleWildcard = "**"
)

// EnvironmentSpecExtOption applies to the EnvironmentSpecExt.
type EnvironmentSpecExtOption func(e *EnvironmentSpecExt)

// WithIAMClientOptions returns an EnvironmentSpecExtOption that configures its iamsvc
// with the given client options.
func WithIAMClientOptions(opt ...option.ClientOption) EnvironmentSpecExtOption {
	return func(e *EnvironmentSpecExt) {
		svc, err := google.NewIAMService(opt...)
		if err != nil {
			log.Warnf("failed to create iam service: %v", err)
		} else {
			e.iamsvc = svc
		}
	}
}

func splitAndAddToPathTree(tree path.Tree, path string, api *APISpec) {
	split := strings.Split(path, "/")
	split = append([]string{"/"}, split...)
	tree.AddChild(split, 0, api)
}

// NewEnvironmentSpecExt creates an EnvironmentSpecExt
func NewEnvironmentSpecExt(spec *EnvironmentSpec, options ...EnvironmentSpecExtOption) (*EnvironmentSpecExt, error) {
	ec := &EnvironmentSpecExt{
		EnvironmentSpec:    spec,
		apiPathTree:        path.NewTree(),
		opPathTree:         path.NewTree(),
		compiledTemplates:  make(map[string]*transform.Template),
		corsVary:           make(map[string]bool, len(spec.APIs)),
		corsAllowedOrigins: make(map[string]map[string]bool, len(spec.APIs)),
		compiledRegExps:    make(map[string]*regexp.Regexp),
		apiVariables:       make(map[string][]Variable),
		opVariables:        make(map[string]map[string][]Variable),
	}

	// Apply options to mutate ec
	for _, opt := range options {
		opt(ec)
	}

	for i := range spec.APIs {
		api := spec.APIs[i]

		// Add basepath to apiPathTree.
		if api.BasePath != "" || api.GrpcService == "" {
			splitAndAddToPathTree(ec.apiPathTree, api.BasePath, &api)
		}

		// Add gRPC service to apiPathTree as well, so that a path that comes in
		// with the gRPC service name as the first component will match the same API.
		if api.GrpcService != "" {
			splitAndAddToPathTree(ec.apiPathTree, api.GrpcService, &api)
		}

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

		parseHTTPRequestTransforms := func(t HTTPRequestTransforms) error {
			_, err := ec.parseTemplate(t.PathTransform)
			if err != nil {
				return err
			}

			for _, a := range t.HeaderTransforms.Add {
				_, err := ec.parseTemplate(a.Value)
				if err != nil {
					return err
				}
			}

			for _, a := range t.QueryTransforms.Add {
				_, err := ec.parseTemplate(a.Value)
				if err != nil {
					return err
				}
			}
			return nil
		}

		for _, in := range api.ConsumerAuthorization.In {
			err := ec.parseAPIOperationParameter(in.Transformation)
			if err != nil {
				return nil, err
			}
		}

		err := parseHTTPRequestTransforms(api.HTTPRequestTransforms)
		if err != nil {
			return nil, err
		}

		for _, cv := range api.ContextVariables {
			v, err := generateVariableForGoogleIAM(&cv, ec.iamsvc)
			if err != nil {
				return nil, err
			}
			ec.apiVariables[api.ID] = append(ec.apiVariables[api.ID], v)
		}

		ec.opVariables[api.ID] = make(map[string][]Variable)
		for i := range api.Operations {
			isGRPC := api.GrpcService != ""
			op := api.Operations[i]

			// For gRPC APIs, always interpret the op Name as a gRPC method, so add it as a
			// child of the API.

			if isGRPC {
				split := []string{api.ID, "POST", op.Name}
				opMatch := OpTemplateMatch{&op, nil}
				ec.opPathTree.AddChild(split, 0, &opMatch)
			}

			if !isGRPC && len(op.HTTPMatches) == 0 { // empty is wildcard
				split := []string{api.ID, wildcard, doubleWildcard}
				opMatch := OpTemplateMatch{&op, nil}
				ec.opPathTree.AddChild(split, 0, &opMatch)
			} else if len(op.HTTPMatches) > 0 {
				for _, m := range op.HTTPMatches {
					split := strings.Split(m.PathTemplate, "/")
					method := m.Method
					if method == anyMethod {
						method = wildcard
					}
					split = append([]string{api.ID, method}, split...)

					// parse path template
					t, err := ec.parseTemplate(m.PathTemplate)
					if err != nil {
						return nil, err
					}

					opMatch := OpTemplateMatch{&op, t}
					ec.opPathTree.AddChild(split, 0, &opMatch)
				}
			}

			for _, in := range op.ConsumerAuthorization.In {
				err := ec.parseAPIOperationParameter(in.Transformation)
				if err != nil {
					return nil, err
				}
			}

			err := parseHTTPRequestTransforms(op.HTTPRequestTransforms)
			if err != nil {
				return nil, err
			}

			for _, cv := range op.ContextVariables {
				v, err := generateVariableForGoogleIAM(&cv, ec.iamsvc)
				if err != nil {
					return nil, err
				}
				ec.opVariables[api.ID][op.Name] = append(ec.opVariables[api.ID][op.Name], v)
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

func generateVariableForGoogleIAM(cv *ContextVariable, iamsvc *google.IAMService) (Variable, error) {
	switch v := cv.Value.(type) {
	case GoogleIAMCredentials:
		if iamsvc == nil {
			return nil, fmt.Errorf("google oauth required iam service to be configured")
		}
		switch tk := v.Token.(type) {
		case AccessToken:
			ts, err := iamsvc.AccessTokenSource(v.ServiceAccountEmail, tk.Scopes, v.RefreshInterval)
			if err != nil {
				return nil, err
			}
			return &accessTokenVariable{ts, cv.Name}, nil
		case IdentityToken:
			ts, err := iamsvc.IdentityTokenSource(v.ServiceAccountEmail, tk.Audience, tk.IncludeEmail, v.RefreshInterval)
			if err != nil {
				return nil, err
			}
			return &idTokenVariable{ts, cv.Name}, nil
		default:
			return nil, fmt.Errorf("unrecognized token type for google IAM credentials")
		}
	}
	return nil, fmt.Errorf("unrecognized value type for context variable")
}

type Variable interface {
	Name() string
	Value() (string, error)
}

type accessTokenVariable struct {
	ts   *google.AccessTokenSource
	name string
}

func (atv *accessTokenVariable) Name() string           { return atv.name }
func (atv *accessTokenVariable) Value() (string, error) { return atv.ts.Value() }

type idTokenVariable struct {
	ts   *google.IdentityTokenSource
	name string
}

func (itv *idTokenVariable) Name() string           { return itv.name }
func (itv *idTokenVariable) Value() (string, error) { return itv.ts.Value() }

type OpTemplateMatch struct {
	operation *APIOperation
	template  *transform.Template
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
	iamsvc             *google.IAMService
	apiVariables       map[string][]Variable            // api ID -> variables
	opVariables        map[string]map[string][]Variable // api ID -> op Name -> variables
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

func (h HTTPRequestTransforms) isEmpty() bool {
	return h.HeaderTransforms.isEmpty() &&
		h.QueryTransforms.isEmpty() &&
		len(strings.TrimSpace(h.PathTransform)) == 0
}

func (u NameValueTransforms) isEmpty() bool {
	return len(u.Add) == 0 && len(u.Remove) == 0
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

// parses and caches, use only during creation
func (e *EnvironmentSpecExt) parseTemplate(templateString string) (*transform.Template, error) {
	if templateString == "" {
		return nil, nil
	}
	template, err := transform.Parse(templateString)
	e.compiledTemplates[templateString] = template
	return template, err
}

// parses the StringTransformation and adds to cache
// use only during creation
func (e *EnvironmentSpecExt) parseAPIOperationParameter(s StringTransformation) error {
	if s.Template == "" && s.Substitution == "" {
		return nil
	}
	_, err := e.parseTemplate(s.Template)
	if err != nil {
		return err
	}
	_, err = e.parseTemplate(s.Substitution)
	return err
}

func (e *EnvironmentSpecExt) GetTemplate(templateString string) *transform.Template {
	return e.compiledTemplates[templateString]
}
