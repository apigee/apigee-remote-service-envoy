// Copyright 2022 Google LLC
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

package fault

const (
	UnknownAPIProxy               = "messaging.runtime.UnknownAPIProxy"
	UnknownKeyManagementException = "keymanagement.service.UnknownException"
	InvalidAuthorizationCode      = "keymanagement.service.invalid_request-authorization_code_invalid"
	InternalError                 = "messaging.runtime.InternalError"
	NoApiProductMatchFound        = "keymanagement.service.InvalidAPICallAsNoApiProductMatchFound"
	OperationQuotaExceeded        = "policies.ratelimit.QuotaViolation"
	InternalQuotaError            = "policies.ratelimit.InternalError"
	JwtUnknownException           = "steps.jwt.UnknownException"
	JwtInvalidToken               = "steps.jwt.InvalidToken"
	JwtIssuerMismatch             = "steps.jwt.JwtIssuerMismatch"
	JwtAudienceMismatch           = "steps.jwt.JwtAudienceMismatch"
)
