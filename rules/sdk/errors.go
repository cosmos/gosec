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
	"go/types"

	"github.com/cosmos/gosec/v2"
)

type noErrorCheck struct {
	gosec.MetaData
}

func (r *noErrorCheck) ID() string {
	return r.MetaData.ID
}

func returnsError(callExpr *ast.CallExpr, ctx *gosec.Context) int {
	if tv := ctx.Info.TypeOf(callExpr); tv != nil {
		switch t := tv.(type) {
		case *types.Tuple:
			for pos := 0; pos < t.Len(); pos++ {
				variable := t.At(pos)
				if variable != nil && variable.Type().String() == "error" {
					return pos
				}
			}
		case *types.Named:
			if t.String() == "error" {
				return 0
			}
		}
	}
	return -1
}

func (r *noErrorCheck) Match(n ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	// TODO: when an error is returned, ensure it's followed by a check that `err != nil`,
	// and that the BlockStmt there returns the error

	switch stmt := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range stmt.Rhs {
			if callExpr, ok := expr.(*ast.CallExpr); ok {
				pos := returnsError(callExpr, ctx)
				if pos < 0 || pos >= len(stmt.Lhs) {
					return nil, nil
				}
				id, ok := stmt.Lhs[pos].(*ast.Ident)
				if !ok {
					// don't think this should ever happen
					return gosec.NewIssue(ctx, n, r.ID(), "PANIC!", r.Severity, r.Confidence), nil
				} else if ok && id.Name == "_" {
					// error is just ignored!
					return gosec.NewIssue(ctx, n, r.ID(), r.What, r.Severity, r.Confidence), nil
				}

				// TODO: next line should check `id.Name != nil`,
				// and the BlockStmt that follows should have a ReturnStmt
				// that includes the id.Name
			}
		}
	}
	return nil, nil
}

// NewErrorNotPropagated detects if a returned error is not propagated up the stack.
func NewErrorNotPropagated(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {

	return &noErrorCheck{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.Low,
			Confidence: gosec.High,
			What:       "Returned error is not propagated up the stack.",
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ExprStmt)(nil)}
}
