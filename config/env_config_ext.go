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

func (o APIOperation) GetAPIKey(req *EnvironmentSpecRequest) (apikey string) {
	for _, authorization := range o.ConsumerAuthorization.In {
		if apikey = req.GetParamValue(authorization); apikey != "" {
			return
		}
	}
	return
}

func (a AuthenticationRequirement) IsEmpty() bool {
	return isEmpty(a)
}

func (a AuthenticationRequirement) AllJWTRequirements() []*JWTAuthentication {
	return allJWTRequirements(a)
}

func allJWTRequirements(auth AuthenticationRequirement) []*JWTAuthentication {
	var found []*JWTAuthentication
	switch v := auth.Requirements.(type) {
	case JWTAuthentication:
		found = []*JWTAuthentication{&v}
	case AnyAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			found = append(found, allJWTRequirements(val)...)
		}
	case AllAuthenticationRequirements:
		for _, val := range []AuthenticationRequirement(v) {
			found = append(found, allJWTRequirements(val)...)
		}
	}
	return found
}

func isEmpty(auth AuthenticationRequirement) bool {
	switch a := auth.Requirements.(type) {
	case JWTAuthentication:
		return false
	case AnyAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !isEmpty(r) {
				return true
			}
		}
	case AllAuthenticationRequirements:
		for _, r := range []AuthenticationRequirement(a) {
			if !isEmpty(r) {
				return true
			}
		}
	}
	return true
}
