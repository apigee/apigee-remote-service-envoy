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
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
)

func TestErrorMessage(t *testing.T) {
	tests := []struct {
		desc                 string
		fault                *AdapterFault
		expectedErrorMessage string
	}{
		{
			desc:                 "test0",
			fault:                CreateAdapterFault("test-code", rpc.DEADLINE_EXCEEDED, typev3.StatusCode_Forbidden),
			expectedErrorMessage: "FaultCode:test-code, RpcCode:DEADLINE_EXCEEDED, StatusCode:Forbidden",
		},
		{
			desc:                 "test1",
			fault:                CreateAdapterFault("", 1, 0),
			expectedErrorMessage: "FaultCode:, RpcCode:CANCELLED, StatusCode:Empty",
		},
		{
			desc:                 "test2",
			fault:                nil,
			expectedErrorMessage: "AdapterFault: Error() called on a nil object",
		},
	}

	for _, test := range tests {
		t.Logf("Running test %v", test.desc)
		got := test.fault.Error()
		if got != test.expectedErrorMessage {
			t.Fatalf("want: %v\n, got: %v\v", test.expectedErrorMessage, got)
		}
	}
}

func TestCreateAdapterFault(t *testing.T) {
	tests := []struct {
		desc               string
		fault              *AdapterFault
		expectedFaultCode  string
		expectedRpcCode    rpc.Code
		expectedStatusCode typev3.StatusCode
	}{
		{
			desc:               "test0",
			fault:              CreateAdapterFault("test-code", rpc.DEADLINE_EXCEEDED, typev3.StatusCode_Forbidden),
			expectedFaultCode:  "test-code",
			expectedRpcCode:    rpc.DEADLINE_EXCEEDED,
			expectedStatusCode: typev3.StatusCode_Forbidden,
		},
		{
			desc:               "test1",
			fault:              CreateAdapterFault("", 1, 0),
			expectedFaultCode:  "",
			expectedRpcCode:    1,
			expectedStatusCode: 0,
		},
	}

	for _, test := range tests {
		t.Logf("Running test %v", test.desc)
		if test.fault.FaultCode != test.expectedFaultCode {
			t.Fatalf("want: %v\n, got: %v\v", test.expectedFaultCode, test.fault.FaultCode)
		}
		if test.fault.RpcCode != test.expectedRpcCode {
			t.Fatalf("want: %v\n, got: %v\v", test.expectedRpcCode, test.fault.RpcCode)
		}
		if test.fault.StatusCode != test.expectedStatusCode {
			t.Fatalf("want: %v\n, got: %v\v", test.expectedStatusCode, test.fault.StatusCode)
		}
	}
}
