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
package server

import (
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
)

func TestTimeToUnix(t *testing.T) {
	now := time.Now()
	want := now.UnixNano() / 1000000

	nowProto, err := ptypes.TimestampProto(now)
	if err != nil {
		t.Fatal(err)
	}
	got := pbTimestampToUnix(nowProto)

	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}

func TestAddDurationUnix(t *testing.T) {
	now := time.Now()
	duration := 6 * time.Minute
	want := now.Add(duration).UnixNano() / 1000000

	nowProto, err := ptypes.TimestampProto(now)
	if err != nil {
		t.Fatal(err)
	}
	durationProto := ptypes.DurationProto(duration)
	got := pbTimestampAddDurationUnix(nowProto, durationProto)

	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}
