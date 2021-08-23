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

package transform

import (
	"testing"
)

func TestParseErrors(t *testing.T) {
	for _, test := range []struct {
		template string
	}{
		{"unclosed {brace"},
		{"nested {braces {test}}"},
		{"double {{braces}}"},
		{"empty braces {}"},
	} {
		t.Run(test.template, func(t *testing.T) {
			_, err := Parse(test.template)
			if err == nil {
				t.Errorf("%s should not parse", test.template)
			}
		})
	}
}

func TestTransform(t *testing.T) {
	for _, test := range []struct {
		desc         string
		template     string
		substitution string
		input        string
		want         string
	}{
		{
			desc:         "bearer example",
			template:     "Bearer {token}",
			substitution: "{token}",
			input:        "Bearer hello_world",
			want:         "hello_world",
		},
		{
			desc:         "must do replacements",
			template:     "prefix-{foo}-{bar}-suffix",
			substitution: "{foo}_{bar}",
			input:        "prefix-hello-world-suffix",
			want:         "hello_world",
		},
		{
			desc:         "must skip missing vars",
			template:     "prefix-{foo}-{bar}-suffix",
			substitution: "{foo}_{baz}",
			input:        "prefix-hello-world-suffix",
			want:         "hello_",
		},
		{
			desc:         "strange but valid case",
			template:     "prefix-{foo}-{bar}",
			substitution: "{foo}_{bar}",
			input:        "prefix--",
			want:         "_",
		},
		{
			desc:         "must match all statics",
			template:     "prefix-{foo}-{bar}",
			substitution: "{foo}_{bar}",
			input:        "prefix-{foo}",
			want:         "_",
		},
		{
			desc:         "must work without suffix",
			template:     "prefix-{foo}-{bar}",
			substitution: "{foo}_{bar}",
			input:        "prefix-hello-world",
			want:         "hello_world",
		},
		{
			desc:         "must work without prefix",
			template:     "{foo}-{bar}",
			substitution: "{foo}_{bar}",
			input:        "hello-world",
			want:         "hello_world",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			template, err := Parse(test.template)
			if err != nil {
				t.Fatalf("%v", err)
			}
			substitution, err := Parse(test.substitution)
			if err != nil {
				t.Fatalf("%v", err)
			}

			got := Substitute(template, substitution, test.input)
			if test.want != got {
				t.Errorf("want: %q, got: %q", test.want, got)
			}
		})
	}
}

func TestExtractNilTemplate(t *testing.T) {
	var template *Template
	r := template.Extract("foo")
	if len(r) != 0 {
		t.Errorf("should be empty map")
	}
}
