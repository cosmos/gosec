// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdk

import (
	"go/ast"
	"strings"

	"github.com/securego/gosec/v2"
)

type blocklistedImport struct {
	gosec.MetaData
	Blocklisted map[string]string
}

func unquote(original string) string {
	copy := strings.TrimSpace(original)
	copy = strings.TrimLeft(copy, `"`)
	return strings.TrimRight(copy, `"`)
}

func (r *blocklistedImport) ID() string {
	return r.MetaData.ID
}

func (r *blocklistedImport) Match(n ast.Node, c *gosec.Context) (*gosec.Issue, error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if description, ok := r.Blocklisted[unquote(node.Path.Value)]; ok {
			return gosec.NewIssue(c, node, r.ID(), description, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

// NewBlocklistedImports reports when a blocklisted import is being used.
// Typically when a deprecated technology is being used.
func NewBlocklistedImports(id string, conf gosec.Config, blocklist map[string]string) (gosec.Rule, []ast.Node) {
	return &blocklistedImport{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.Medium,
			Confidence: gosec.High,
		},
		Blocklisted: blocklist,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

// NewUnsafeImport fails if any of "unsafe", "reflect", "crypto/rand", "math/rand" are imported.
func NewUnsafeImport(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return NewBlocklistedImports(id, conf, map[string]string{
		// unsafe exposes memory bugs
		"unsafe": "Blocklisted import unsafe",

		// reflect allows reading private fields and calling private
		// methods from other pkgs.
		"reflect": "Blocklisted import reflect",

		// runtime data can be parsed to get pointer values.
		// but without unsafe, does it matter?
		"runtime": "Blocklisted import runtime",

		// rand is non-deterministic.
		// TODO: module.RandomizedParams takes a math/rand.Rand
		"math/rand":   "Blocklisted import math/rand",
		"crypto/rand": "Blocklisted import crypto/rand",
	})
}
