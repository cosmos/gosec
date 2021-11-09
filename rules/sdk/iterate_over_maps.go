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
	"errors"
	"fmt"
	"go/ast"

	"github.com/securego/gosec/v2"
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
	var decl interface{}
	switch rangeRHS := rangeStmt.X.(type) {
	case *ast.Ident:
		decl = rangeRHS.Obj.Decl

	case *ast.CallExpr:
		// Synthesize the declaration to be an *ast.FuncType from
		// either function declarations or function literals.
		idecl := rangeRHS.Fun.(*ast.Ident).Obj.Decl
		switch idecl := idecl.(type) {
		case *ast.FuncDecl:
			decl = idecl.Type

		case *ast.AssignStmt:
			decl = idecl.Rhs[0].(*ast.FuncLit).Type
		}
	}

	switch decl := decl.(type) {
	case *ast.FuncType:
		returns := decl.Results
		if g, w := len(returns.List), 1; g != w {
			return nil, fmt.Errorf("returns %d arguments, want %d", g, w)
		}
		returnType := returns.List[0].Type
		if _, ok := returnType.(*ast.MapType); !ok {
			return nil, nil
		}

	case *ast.AssignStmt:
		rhs0 := decl.Rhs[0].(*ast.CompositeLit)
		if _, ok := rhs0.Type.(*ast.MapType); !ok {
			return nil, nil
		}

	case *ast.ValueSpec:
		if _, ok := decl.Type.(*ast.MapType); !ok {
			return nil, nil
		}

	default:
		return nil, fmt.Errorf("unhandled type of declaration: %T", decl)
	}

	// 2. Let's be pedantic to only permit the keys to be iterated upon:
	// Allow only:
	//     for key := range m {
	// AND NOT:
	//     for _, value := range m {
	// NOR
	//     for key, value := range m {
	if rangeStmt.Key == nil {
		return nil, errors.New("the key in the range statement should be non-nil: want: for key := range m")
	}
	if rangeStmt.Value != nil {
		return nil, errors.New("the value in the range statement should be nil: want: for key := range m")
	}

	// Now ensure that only either "append" or "delete" statement is present in the range.
	rangeBody := rangeStmt.Body

	if n := len(rangeBody.List); n > 1 {
		return nil, fmt.Errorf("got %d statements, yet expecting exactly 1 statement (either append or delete) in a range with a map", n)
	}

	stmt0 := rangeBody.List[0]
	switch stmt := stmt0.(type) {
	case *ast.ExprStmt:
		call := stmt.X.(*ast.CallExpr)
		name, ok := eitherAppendOrDeleteCall(call)
		if !ok {
			return nil, fmt.Errorf("expecting only delete, got: %q", name)
		}
		// We got "delete", so this is safe to recognize
		// as this is the fast map clearing idiom.
		return nil, nil

	case *ast.AssignStmt:
		lhs0, ok := stmt.Lhs[0].(*ast.Ident)
		if !ok {
			return nil, fmt.Errorf("expecting an identifier for an append call to a slice, got %T", stmt.Lhs[0])
		}
		if _, ok := typeOf(lhs0.Obj).(*ast.ArrayType); !ok {
			return nil, fmt.Errorf("expecting an array/slice being used to retrieve keys, got %T", lhs0.Obj)
		}

		rhs0, ok := stmt.Rhs[0].(*ast.CallExpr)
		if !ok {
			return nil, fmt.Errorf("expecting only an append, got: %#v", stmt.Rhs[0])
		}
		// The Right Hand Side should only contain the "append".
		if name, ok := eitherAppendOrDeleteCall(rhs0); !ok {
			return nil, fmt.Errorf(`got call %q want "append" or "delete"`, name)
		}
		return nil, nil

	default:
		return nil, fmt.Errorf("got %T; expecting exactly 1 statement (either append or delete) in a range with a map", stmt)
	}
}

func eitherAppendOrDeleteCall(callExpr *ast.CallExpr) (string, bool) {
	fn, ok := callExpr.Fun.(*ast.Ident)
	if !ok {
		return "", false
	}
	switch fn.Name {
	case "append", "delete":
		return fn.Name, true
	default:
		return fn.Name, false
	}
}

func typeOf(value interface{}) ast.Node {
	switch typ := value.(type) {
	case *ast.Object:
		return typeOf(typ.Decl)

	case *ast.AssignStmt:
		decl := typ
		rhs := decl.Rhs[0]
		if _, ok := rhs.(*ast.CallExpr); ok {
			return typeOf(rhs)
		}

	case *ast.CallExpr:
		decl := typ
		fn := decl.Fun.(*ast.Ident)
		if fn.Name == "make" {
			// We can infer the type from the first argument.
			return decl.Args[0]
		}
		return typeOf(decl.Args[0])
	}

	panic(fmt.Sprintf("Unexpected type: %T", value))
}

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
