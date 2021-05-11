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

package util

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	pb "github.com/golang/protobuf/ptypes/struct"
)

const (
	// PEMKeyType is the type of privateKey in the PEM file
	PEMKeyType = "RSA PRIVATE KEY"
)

// DecodeToMap converts a pb.Struct to a map from strings to Go types.
// DecodeToMap panics if s is invalid.
func DecodeToMap(s *pb.Struct) map[string]interface{} {
	if s == nil {
		return nil
	}
	m := make(map[string]interface{}, len(s.Fields))
	for k, v := range s.Fields {
		m[k] = decodeValue(v)
	}
	return m
}

func decodeValue(v *pb.Value) interface{} {
	switch k := v.Kind.(type) {
	case *pb.Value_NullValue:
		return nil
	case *pb.Value_NumberValue:
		return k.NumberValue
	case *pb.Value_StringValue:
		return k.StringValue
	case *pb.Value_BoolValue:
		return k.BoolValue
	case *pb.Value_StructValue:
		return DecodeToMap(k.StructValue)
	case *pb.Value_ListValue:
		s := make([]interface{}, len(k.ListValue.Values))
		for i, e := range k.ListValue.Values {
			s[i] = decodeValue(e)
		}
		return s
	default:
		panic("protostruct: unknown kind")
	}
}

// ReadProperties reads Java-style %s=%s properties (no escaping)
func ReadProperties(reader io.Reader) (map[string]string, error) {
	properties := map[string]string{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if equal := strings.Index(line, "="); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
				properties[key] = value
			}
		}
	}

	return properties, scanner.Err()
}

// WriteProperties writes Java-style %s=%s properties (no escaping)
func WriteProperties(writer io.Writer, props map[string]string) error {
	for k, v := range props {
		if _, err := writer.Write([]byte(fmt.Sprintf("%s=%s\n", k, v))); err != nil {
			return err
		}
	}

	return nil
}

// LoadPrivateKey load private key bytes into rsa.PrivateKey
func LoadPrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {

	var err error
	privPem, _ := pem.Decode(privateKeyBytes)
	if privPem == nil {
		return nil, fmt.Errorf("bytes in bad format")
	}
	if PEMKeyType != privPem.Type {
		return nil, fmt.Errorf("%s required, found: %s", PEMKeyType, privPem.Type)
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			return nil, err
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, err
	}

	return privateKey, nil
}

// SimpleGlobMatch returns true if target matches pattern using "*"
func SimpleGlobMatch(pattern, target string) bool {
	const STAR = "*"
	if pattern == STAR {
		return true
	}
	if pattern == "" {
		return target == pattern
	}

	splits := strings.Split(pattern, STAR)
	if len(splits) == 1 { // no glob
		return target == pattern
	}

	prefixed := strings.HasPrefix(pattern, STAR)
	suffixed := strings.HasSuffix(pattern, STAR)
	end := len(splits) - 1
	for i := 0; i < end; i++ {
		splitIndex := strings.Index(target, splits[i])
		switch i {
		case 0: // first
			if !prefixed && splitIndex != 0 {
				return false
			}
		default:
			if splitIndex < 0 {
				return false
			}
		}
		target = target[splitIndex+len(splits[i]):]
	}

	// final
	return suffixed || strings.HasSuffix(target, splits[end])
}
