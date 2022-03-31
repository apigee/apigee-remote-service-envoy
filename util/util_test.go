// Copyright 2020 Google LLC
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

// Package protostruct supports operations on the protocol buffer Struct message.
package util_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/v2/testutil"
	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestLoadPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	goodKeyBuf := &bytes.Buffer{}
	if err := pem.Encode(goodKeyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		t.Fatal(err)
	}
	badKeyBuf1 := &bytes.Buffer{}
	if err := pem.Encode(badKeyBuf1, &pem.Block{Type: "UNKNOWN PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		t.Fatal(err)
	}
	badKeyBuf2 := &bytes.Buffer{}
	if err := pem.Encode(badKeyBuf2, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not a private key")}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		desc    string
		pkBytes []byte
		wantErr bool
	}{
		{
			desc:    "good private key bytes",
			pkBytes: goodKeyBuf.Bytes(),
		},
		{
			desc:    "private key bytes with bad pem type",
			pkBytes: badKeyBuf1.Bytes(),
			wantErr: true,
		},
		{
			desc:    "bad private key bytes",
			pkBytes: badKeyBuf2.Bytes(),
			wantErr: true,
		},
		{
			desc:    "bad bytes",
			pkBytes: []byte("not a private key"),
			wantErr: true,
		},
	}

	for _, test := range tests {
		if _, err := util.LoadPrivateKey(test.pkBytes); (err != nil) != test.wantErr {
			t.Errorf("LoadPrivateKey() error = %v, wantErr? %t", err, test.wantErr)
		}
	}
}

func TestDecodeToMap(t *testing.T) {
	if got := util.DecodeToMap(nil); !testutil.Equal(got, map[string]interface{}(nil)) {
		t.Errorf("DecodeToMap(nil) = %v, want nil", got)
	}
	nullv := &structpb.Value{Kind: &structpb.Value_NullValue{}}
	stringv := &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "x"}}
	boolv := &structpb.Value{Kind: &structpb.Value_BoolValue{BoolValue: true}}
	numberv := &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: 2.7}}
	in := &structpb.Struct{Fields: map[string]*structpb.Value{
		"n": nullv,
		"s": stringv,
		"b": boolv,
		"f": numberv,
		"l": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
			Values: []*structpb.Value{nullv, stringv, boolv, numberv},
		}}},
		"S": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
			"n1": nullv,
			"b1": boolv,
		}}}},
	}}
	want := map[string]interface{}{
		"n": nil,
		"s": "x",
		"b": true,
		"f": 2.7,
		"l": []interface{}{nil, "x", true, 2.7},
		"S": map[string]interface{}{"n1": nil, "b1": true},
	}
	got := util.DecodeToMap(in)
	if diff := testutil.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}

func TestProperties(t *testing.T) {
	want := map[string]string{
		"testKey1": "testValue1",
		"testKey2": "testValue2",
	}

	buffer := new(bytes.Buffer)

	err := util.WriteProperties(buffer, want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := util.ReadProperties(buffer)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("want: %v, got %v", want, got)
	}
}

func TestSimpleGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"", "", true},
		{"x", "x", true},
		{"x", "y", false},
		{"*", "x", true},
		{"x*", "x", true},
		{"x*", "xy", true},
		{"x*", "y", false},
		{"*x", "y", false},
		{"*x", "yx", true},
		{"x*y", "xdoggy", true},
		{"x*y", "axdoggy", false},
		{"x*y", "xdoggyz", false},
		{"*x*y", "xdoggy", true},
		{"x*y*", "xdoggygo", true},
		{"x**y", "xdoggy", true},
		{"*x*y*", "xdoggy", true},
		{"*x*y*", "axdoggyz", true},
		{"*z*", "doggy", false},
	}

	for _, test := range tests {
		if got := util.SimpleGlobMatch(test.pattern, test.target); got != test.want {
			t.Errorf("pattern %s on %s failed. got: %t, want: %t", test.pattern, test.target, got, test.want)
		}
	}
}
