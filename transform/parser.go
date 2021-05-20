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
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
)

type Template struct {
	Parts []*Part `@@*`
}

type Part struct {
	Variable *Variable `  @@`
	Static   *Static   `| @@`
}

type Static struct {
	Value string `@String`
}

type Variable struct {
	Name string `"{" @String "}"`
}

var lexer = stateful.MustSimple([]stateful.Rule{
	{
		Name:    `String`,
		Pattern: `[{}]|[^{}]*`,
	},
})

var parser = participle.MustBuild(&Template{}, participle.Lexer(lexer))

func Parse(val string) (*Template, error) {
	var template Template
	err := parser.ParseString("", val, &template)
	return &template, err
}

func Substitute(template, substitution *Template, in string) string {
	replacementMap := make(map[string]string)

	var variable *Variable
	var pos int
	for _, part := range template.Parts {
		if part.Static != nil {
			pos = strings.Index(in, part.Static.Value)
			if pos < 0 { // must match
				return ""
			}
			if variable != nil { // capture variable
				replacementMap[variable.Name] = in[:pos]
				in = in[pos:]
				variable = nil
			}
			in = in[len(part.Static.Value):] // discard
		} else {
			variable = part.Variable
		}
	}
	if variable != nil {
		replacementMap[variable.Name] = in // capture final variable
	}

	var b strings.Builder
	for _, p := range substitution.Parts {
		if p.Static != nil {
			b.WriteString(p.Static.Value)
		} else {
			b.WriteString(replacementMap[p.Variable.Name])
		}
	}
	return b.String()
}
