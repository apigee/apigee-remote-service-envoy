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
	"errors"
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
			desc:                 "test valid input arguments",
			fault:                NewAdapterFault("test-code", rpc.DEADLINE_EXCEEDED, typev3.StatusCode_Forbidden),
			expectedErrorMessage: "FaultCode:test-code, RpcCode:DEADLINE_EXCEEDED, StatusCode:Forbidden",
		},
		{
			desc:                 "test valid default input arguments",
			fault:                NewAdapterFault("", 1, 0),
			expectedErrorMessage: "FaultCode:, RpcCode:CANCELLED, StatusCode:Empty",
		},
		{
			desc:                 "test invalid input arguments",
			fault:                nil,
			expectedErrorMessage: "AdapterFault: Error() called on a nil object",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := test.fault.Error()
			if got != test.expectedErrorMessage {
				t.Fatalf("want: %v\n, got: %v\v", test.expectedErrorMessage, got)
			}
		})
	}
}

func TestIsCheck(t *testing.T) {
	sampleFault := NewAdapterFault("sample", 1, 3)
	tests := []struct {
		desc           string
		fault          *AdapterFault
		target         error
		expectedOutput bool
	}{
		{
			desc:           "fault details match",
			fault:          NewAdapterFault("test-code", 1, 2),
			target:         NewAdapterFault("test-code", 1, 2),
			expectedOutput: true,
		},
		{
			desc:           "same fault object",
			fault:          sampleFault,
			target:         sampleFault,
			expectedOutput: true,
		},
		{
			desc:           "different fault object",
			fault:          NewAdapterFault("test-code", 1, 2),
			target:         NewAdapterFault("test-code", 3, 4),
			expectedOutput: false,
		},
		{
			desc:           "different error type",
			fault:          NewAdapterFault("test-code", 1, 2),
			target:         errors.New("error of different type"),
			expectedOutput: false,
		},
		{
			desc:           "nil comparable target",
			fault:          NewAdapterFault("test-code", 1, 2),
			target:         nil,
			expectedOutput: false,
		},
		{
			desc:           "nil input fault",
			fault:          nil,
			target:         NewAdapterFault("test-code", 1, 2),
			expectedOutput: false,
		},
		{
			desc:           "nil input as well as target",
			fault:          nil,
			target:         nil,
			expectedOutput: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := test.fault.Is(test.target)
			if got != test.expectedOutput {
				t.Fatalf("output mismatch for fault: %v,\n target: %v\n", test.fault, test.target)
			}
		})
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
			desc:               "test valid input arguments",
			fault:              NewAdapterFault("test-code", rpc.DEADLINE_EXCEEDED, typev3.StatusCode_Forbidden),
			expectedFaultCode:  "test-code",
			expectedRpcCode:    rpc.DEADLINE_EXCEEDED,
			expectedStatusCode: typev3.StatusCode_Forbidden,
		},
		{
			desc:               "test valid default input arguments",
			fault:              NewAdapterFault("", 1, 0),
			expectedFaultCode:  "",
			expectedRpcCode:    1,
			expectedStatusCode: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if test.fault.FaultCode != test.expectedFaultCode {
				t.Fatalf("want: %v\n, got: %v\v", test.expectedFaultCode, test.fault.FaultCode)
			}
			if test.fault.RpcCode != test.expectedRpcCode {
				t.Fatalf("want: %v\n, got: %v\v", test.expectedRpcCode, test.fault.RpcCode)
			}
			if test.fault.StatusCode != test.expectedStatusCode {
				t.Fatalf("want: %v\n, got: %v\v", test.expectedStatusCode, test.fault.StatusCode)
			}
		})
	}
}

func TestCreateAdapterFaultWithRpcCode(t *testing.T) {
	actualFault := NewAdapterFaultWithRpcCode(rpc.ALREADY_EXISTS)
	if actualFault.FaultCode != "" {
		t.Fatalf("want: %v\n, got: %v\v", "", actualFault.FaultCode)
	}
	if actualFault.RpcCode != rpc.ALREADY_EXISTS {
		t.Fatalf("want: %v\n, got: %v\v", rpc.ALREADY_EXISTS, actualFault.RpcCode)
	}
	if actualFault.StatusCode != 0 {
		t.Fatalf("want: %v\n, got: %v\v", 0, actualFault.StatusCode)
	}
}
