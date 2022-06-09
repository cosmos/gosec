// (c) Copyright 2021 Hewlett Packard Enterprise Development LP
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
	"fmt"
	"go/ast"
	"go/types"

	"github.com/informalsystems/gosec/v2"
)

// This pass enforces ONLY key retrieval from maps. It resolves a problem that was
// discovered in the Cosmos-SDK in which maps were being iterated on by key and value
// and that produced non-determinism in upgrades.

type mapRanging struct {
	gosec.MetaData
	calls gosec.CallList
}

func (mr *mapRanging) ID() string {
	return mr.MetaData.ID
}

func (mr *mapRanging) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	rangeStmt, ok := node.(*ast.RangeStmt)
	if !ok {
		return nil, nil
	}

	if rangeStmt.X == nil {
		return nil, nil
	}

	// Algorithm:
	// 1. Ensure that right hand side's eventual type is a map.
	// 2. Ensure that only the form:
	//          for k := range m
	// is allowed, and NOT:
	//          for k, v := range m
	//    NOR
	//          for _, v := range m
	// 3. Ensure that only keys are appended
	// 4. The only exception is if we have the map clearing idiom.

	// 1. Ensure that the type of right hand side of the range is eventually a map.

	if typ := ctx.Info.TypeOf(rangeStmt.X); typ != nil {
		if _, ok := typ.Underlying().(*types.Map); !ok {
			return nil, nil
		}
	} else {
		return nil, fmt.Errorf("unable to get type of expr %#v", rangeStmt.X)
	}

	// 2. Let's be pedantic to only permit the keys to be iterated upon:
	// Allow only:
	//     for key := range m {
	// AND NOT:
	//     for _, value := range m {
	// NOR
	//     for key, value := range m {
	if rangeStmt.Key == nil {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "the key in the range statement should be non-nil: want: for key := range m", mr.Severity, mr.Confidence), nil
	}
	if rangeStmt.Value != nil {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "the value in the range statement should be nil: want: for key := range m", mr.Severity, mr.Confidence), nil
	}

	// Now ensure that only either "append" or "delete" statement is present in the range.
	rangeBody := rangeStmt.Body

	if n := len(rangeBody.List); n != 1 {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected exactly 1 statement (either append or delete) in a range with a map, got %d", n), mr.Severity, mr.Confidence), nil
	}

	stmt0 := rangeBody.List[0]
	switch stmt := stmt0.(type) {
	case *ast.ExprStmt:
		call := stmt.X.(*ast.CallExpr)
		if name, ok := onlyDeleteCall(call); !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected only delete, got: %q", name), mr.Severity, mr.Confidence), nil
		}
		// We got "delete", so this is safe to recognize
		// as this is the fast map clearing idiom.
		return nil, nil

	case *ast.AssignStmt:
		lhs0, ok := stmt.Lhs[0].(*ast.Ident)
		if !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expecting an identifier for an append call to a slice, got %T", stmt.Lhs[0]), mr.Severity, mr.Confidence), nil
		}
		if lhs0.Obj == nil {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "expecting an array/slice being used to retrieve keys, got _", mr.Severity, mr.Confidence), nil
		}

		if typ := ctx.Info.TypeOf(lhs0); typ != nil {
			switch typ := ctx.Info.Types[lhs0].Type; typ.(type) {
			case *types.Array:
			case *types.Slice:
			default:
				return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expecting an array/slice being used to retrieve keys, got %T", typ), mr.Severity, mr.Confidence), nil
			}
		} else {
			return nil, fmt.Errorf("unable to get type of %#v", lhs0)
		}

		rhs0, ok := stmt.Rhs[0].(*ast.CallExpr)
		if !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expecting only an append(), got: %#v", stmt.Rhs[0]), mr.Severity, mr.Confidence), nil
		}
		// The Right Hand Side should only contain the "append".
		if name, ok := onlyAppendCall(rhs0); !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expecting only an append(), got: %#v", name), mr.Severity, mr.Confidence), nil
		}
		return nil, nil

	default:
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("got %T; expecting exactly 1 statement (either append or delete) in a range with a map", stmt), mr.Severity, mr.Confidence), nil
	}
}

func onlyAppendCall(callExpr *ast.CallExpr) (string, bool) {
	fn, ok := callExpr.Fun.(*ast.Ident)
	if !ok {
		return "", false
	}
	return fn.Name, fn.Name == "append"
}

func onlyDeleteCall(callExpr *ast.CallExpr) (string, bool) {
	fn, ok := callExpr.Fun.(*ast.Ident)
	if !ok {
		return "", false
	}
	return fn.Name, fn.Name == "delete"
}

// NewMapRangingCheck returns an error if a map is being iterated over in a for loop outside
// of the context of keys being retrieved for sorting, or the delete map clearing idiom.
func NewMapRangingCheck(id string, config gosec.Config) (rule gosec.Rule, nodes []ast.Node) {
	calls := gosec.NewCallList()

	mr := &mapRanging{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.Medium,
			What:       "Non-determinism from ranging over maps",
		},
		calls: calls,
	}

	nodes = append(nodes, (*ast.RangeStmt)(nil))
	return mr, nodes
}
