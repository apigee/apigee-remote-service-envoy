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

// AdapterFault is blah
type AdapterFault struct {
	// FaultCode is for monitoring
	FaultCode string
	// RpcCode
	RpcCode rpc.Code
	// StatusCode http status code for user-facing response
	StatusCode typev3.StatusCode
}

// Error() is ...
func (f *AdapterFault) Error() string {
	return fmt.Sprintf(`{ "faultCode:" %v, "RpcCode:" %v", "StatusCode:" %v,}`, f.FaultCode, f.RpcCode.String(), f.StatusCode.String())
}

func CreateAdapterFault(faultCode string, rpcCode rpc.Code, statusCode typev3.StatusCode) *AdapterFault {
	fault := new(AdapterFault)
	fault.FaultCode = faultCode
	fault.RpcCode = rpcCode
	fault.StatusCode = statusCode
	return fault
}
