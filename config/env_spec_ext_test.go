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

// NOTE: This file should be kept free from any additional dependencies,
// especially those that are not commonly used libraries.

// "testing"
// "time"

// func TestOperationGetAPIKey(t *testing.T) {
// 	spec := EnvironmentSpec{
// 		APIs: []APISpec{
// 			{
// 				BasePath: "/v1",
// 				Authentication: AuthenticationRequirement{
// 					Requirements: JWTAuthentication{
// 						Name:       "foo",
// 						Issuer:     "bar",
// 						JWKSSource: RemoteJWKS{URL: "url", CacheDuration: time.Hour},
// 						In:         []APIOperationParameter{{Match: Header("header")}},
// 					},
// 				},
// 				ConsumerAuthorization: ConsumerAuthorization{
// 					In: []APIOperationParameter{{Match: Header("x-api-key")}},
// 				},
// 				Operations: []APIOperation{
// 					{
// 						Name: "op-1",
// 						HTTPMatches: []HTTPMatch{
// 							{
// 								PathTemplate: "/petstore",
// 								Method:       "GET",
// 							},
// 						},
// 					},
// 					{
// 						Name: "op-2",
// 						HTTPMatches: []HTTPMatch{
// 							{
// 								PathTemplate: "/bookshop",
// 								Method:       "POST",
// 							},
// 						},
// 					},
// 				},
// 				HTTPRequestTransforms: HTTPRequestTransformations{
// 					SetHeaders: map[string]string{
// 						"x-apigee-target": "target",
// 					},
// 				},
// 			},
// 		},
// 	}
// }
