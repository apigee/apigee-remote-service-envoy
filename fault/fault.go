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

package fault

import (
	"fmt"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
)

// AdapterFault encapsulates the fault information within ARC.
type AdapterFault struct {
	// FaultCode is the apigee fault code.
	// Refer: https://docs.apigee.com/api-monitoring/fault-codes for more information.
	FaultCode string
	// RpcCode is the RPC status for the ext_authz response.
	RpcCode rpc.Code
	// StatusCode is the http status code for user-facing response.
	StatusCode typev3.StatusCode
}

// Error() returns the human-readable string representation of the AdapterFault.
func (f *AdapterFault) Error() string {
	if f == nil {
		return fmt.Sprintf("AdapterFault: Error() called on a nil object")
	}
	return fmt.Sprintf("FaultCode:%v, RpcCode:%v, StatusCode:%v", f.FaultCode, f.RpcCode.String(), f.StatusCode.String())
}

// CreateAdapterFault() creates and returns a new AdapterFault with the provided input arguments.
func CreateAdapterFault(faultCode string, rpcCode rpc.Code, statusCode typev3.StatusCode) *AdapterFault {
	fault := new(AdapterFault)
	fault.FaultCode = faultCode
	fault.RpcCode = rpcCode
	fault.StatusCode = statusCode
	return fault
}
