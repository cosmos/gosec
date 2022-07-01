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
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
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
	// 4. Exceptions:
	//   * The map clearing idiom
	//   * `for k, v := range m`` is permitted for map copying

	// 1. Ensure that the type of right hand side of the range is eventually a map.

	if typ := ctx.Info.TypeOf(rangeStmt.X); typ != nil {
		if _, ok := typ.Underlying().(*types.Map); !ok {
			return nil, nil
		}
	} else {
		return nil, fmt.Errorf("unable to get type of expr %#v", rangeStmt.X)
	}

	// Ensure that the range body has only one statement.
	rangeBody := rangeStmt.Body
	if n := len(rangeBody.List); n != 1 {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected exactly 1 statement (either append, delete, or copying to another map) in a range with a map, got %d", n), mr.Severity, mr.Confidence), nil
	}
	stmt0 := rangeBody.List[0]

	// 2. Let's be pedantic to only permit the keys to be iterated upon:
	// Allow only:
	//     for key := range m {
	// AND NOT:
	//     for _, value := range m {
	// NOR*
	//     for key, value := range m {
	// * the value can be used when copying a map
	if rangeStmt.Key == nil {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "the key in the range statement should not be _: want: for key := range m", mr.Severity, mr.Confidence), nil
	}
	// If this is a map copy, rangeStmt.Value is allowed to be non-nil.
	if stmt, ok := stmt0.(*ast.AssignStmt); ok {
		mapCopy, err := isMapCopy(ctx, stmt, rangeStmt)
		if err != nil {
			return nil, err
		}
		if mapCopy {
			return nil, nil
		}
	}
	if rangeStmt.Value != nil {
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "the value in the range statement should be _ unless copying a map: want: for key := range m", mr.Severity, mr.Confidence), nil
	}

	//  Ensure that only either an "append" or "delete" statement is present in the range.
	switch stmt := stmt0.(type) {
	case *ast.ExprStmt:
		call := stmt.X.(*ast.CallExpr)
		if name, ok := onlyDeleteCall(call); !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected either an append, delete, or copy to another map in a range with a map, got: %q", name), mr.Severity, mr.Confidence), nil
		}
		// We got "delete", so this is safe to recognize
		// as this is the fast map clearing idiom.
		return nil, nil

	case *ast.AssignStmt:
		lhs0, ok := stmt.Lhs[0].(*ast.Ident)
		if !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "expected either an append, delete, or copy to another map in a range with a map", mr.Severity, mr.Confidence), nil
		}
		if lhs0.Obj == nil {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), "expected an array/slice being used to retrieve keys, got _", mr.Severity, mr.Confidence), nil
		}

		if typ := ctx.Info.TypeOf(lhs0); typ != nil {
			switch typ := ctx.Info.Types[lhs0].Type; typ.(type) {
			case *types.Array:
			case *types.Slice:
			default:
				return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected an array/slice being used to retrieve keys, got %T", typ), mr.Severity, mr.Confidence), nil
			}
		} else {
			return nil, fmt.Errorf("unable to get type of %#v", lhs0)
		}

		rhs0, ok := stmt.Rhs[0].(*ast.CallExpr)
		if !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected only an append(), got: %#v", stmt.Rhs[0]), mr.Severity, mr.Confidence), nil
		}
		// The Right Hand Side should only contain the "append".
		if name, ok := onlyAppendCall(rhs0); !ok {
			return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("expected only an append(), got: %#v", name), mr.Severity, mr.Confidence), nil
		}
		return nil, nil

	default:
		return gosec.NewIssue(ctx, rangeStmt, mr.ID(), fmt.Sprintf("got %T; expected exactly 1 statement (either append or delete) in a range with a map", stmt), mr.Severity, mr.Confidence), nil
	}
}

// isMapCopy returns true if:
// * stmt is a statement that writes a value to a map
// * the key used to write to the map is the same as rangeStmt.Key
// * the value written to the map is rangeStmt.Value
func isMapCopy(ctx *gosec.Context, stmt *ast.AssignStmt, rangeStmt *ast.RangeStmt) (bool, error) {
	// Ensure that the lhs is a map.
	if len(stmt.Lhs) != 1 {
		return false, nil
	}
	lhs, ok := stmt.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return false, nil
	}
	if typ := ctx.Info.TypeOf(lhs.X); typ != nil {
		if _, ok := typ.Underlying().(*types.Map); !ok {
			return false, nil
		}
	} else {
		return false, fmt.Errorf("unable to get type of expr %#v", lhs.X)
	}

	// Ensure that the key from the range is used to write to the map.
	lhsKey, ok := lhs.Index.(*ast.Ident)
	if !ok {
		return false, nil
	}
	rangeKey, ok := rangeStmt.Key.(*ast.Ident)
	if !ok {
		return false, nil
	}
	if ctx.Info.ObjectOf(lhsKey) != ctx.Info.ObjectOf(rangeKey) {
		return false, nil
	}

	// If rangeStmt.Value if present, ensure it is being written to the destination map.
	if rangeStmt.Value != nil {
		rhsValue, ok := stmt.Rhs[0].(*ast.Ident)
		if !ok {
			return false, nil
		}
		rangeValue, ok := rangeStmt.Value.(*ast.Ident)
		if !ok {
			return false, nil
		}
		return ctx.Info.ObjectOf(rhsValue) == ctx.Info.ObjectOf(rangeValue), nil
	}

	// Otherwise, ensure that:
	// 1. stmt.Rhs is an index expression and rangeStmt.Key is the index.
	// 2. The map being read in stmt.Rhs is the the source map (rangeStmt.X).

	// 1. Ensure that stmt.Rhs is an index expression and rangeStmt.Key is the index.
	indexExpr, ok := stmt.Rhs[0].(*ast.IndexExpr)
	if !ok {
		return false, nil
	}
	readKey, ok := indexExpr.Index.(*ast.Ident)
	if !ok {
		return false, nil
	}
	if ctx.Info.ObjectOf(readKey) != ctx.Info.ObjectOf(rangeKey) {
		return false, nil
	}

	// 2. Ensure that the map being read in stmt.Rhs is the same as the source map (rangeStmt.X).
	rangeXString := &bytes.Buffer{}
	printer.Fprint(rangeXString, ctx.FileSet, rangeStmt.X)
	indexExprXString := &bytes.Buffer{}
	printer.Fprint(indexExprXString, ctx.FileSet, indexExpr.X)

	if bytes.Equal(rangeXString.Bytes(), indexExprXString.Bytes()) {
		return true, nil
	}
	panic(fmt.Sprintf("asdfasdf: (%s) (%s)\n", rangeXString.String(), indexExprXString.String()))

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
