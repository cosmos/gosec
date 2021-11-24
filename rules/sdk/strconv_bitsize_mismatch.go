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
	"strconv"

	"github.com/securego/gosec/v2"
)

type bitsizeOverflowCheck struct {
	gosec.MetaData
	calls gosec.CallList
}

func (bc *bitsizeOverflowCheck) ID() string {
	return bc.MetaData.ID
}

func (bc *bitsizeOverflowCheck) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	var parseUintVarObj map[*ast.Object]ast.Node

	// Given that the code could be splayed over multiple line, we
	// examine ctx.PassedValues to check for temporarily stored data.
	if retr, ok := ctx.PassedValues[bc.ID()]; !ok {
		parseUintVarObj = make(map[*ast.Object]ast.Node)
		ctx.PassedValues[bc.ID()] = parseUintVarObj
	} else if saved, ok := retr.(map[*ast.Object]ast.Node); ok {
		parseUintVarObj = saved
	} else {
		return nil, fmt.Errorf("ctx.PassedValues[%s] is of type %T, want %T", bc.ID(), retr, parseUintVarObj)
	}

	// strconv.ParseUint*
	// To reduce false positives, detect code that is converted to any of: int16, int32, int64 only.
	switch n := node.(type) {
	case *ast.AssignStmt:
		for _, expr := range n.Rhs {
			callExpr, ok := expr.(*ast.CallExpr)
			if !ok {
				continue
			}

			if bc.calls.ContainsPkgCallExpr(callExpr, ctx, false) == nil {
				continue
			}

			ident, ok := n.Lhs[0].(*ast.Ident)
			if ok && ident.Name != "_" {
				parseUintVarObj[ident.Obj] = n
			}
		}

	case *ast.CallExpr:
		fn, ok := n.Fun.(*ast.Ident)
		if !ok {
			return nil, nil
		}

		switch fn.Name {
		default:
			return nil, nil

		case "int", "int16", "int32", "int64":
			ident, ok := n.Args[0].(*ast.Ident)
			if !ok {
				return nil, nil
			}

			nFound, ok := parseUintVarObj[ident.Obj]
			if !ok {
				return nil, nil
			}

			stmt, ok := nFound.(*ast.AssignStmt)
			if !ok {
				return nil, nil
			}
			r0 := stmt.Rhs[0]
			call, ok := r0.(*ast.CallExpr)
			if !ok {
				return nil, nil
			}
			bitSizeLit, ok := call.Args[2].(*ast.BasicLit)
			if !ok {
				return nil, nil
			}

			// Actually strconv parse it.
			bitSize, err := strconv.Atoi(bitSizeLit.Value)
			if err != nil {
				failure := fmt.Sprintf("Invalid bitSize %q parse failure: %v", bitSizeLit.Value, err)
				return gosec.NewIssue(ctx, nFound, bc.ID(), failure, bc.Severity, bc.Confidence), nil
			}

			failed := false
			switch {
			case fn.Name == "int16" && bitSize >= 16:
				failed = true
			case fn.Name == "int64" && bitSize >= 64:
				failed = true
			case fn.Name == "int32" && bitSize >= 32:
				failed = true
			case fn.Name == "int" && (bitSize == 32 || bitSize >= 64):
				failed = true
			}

			if !failed {
				return nil, nil
			}

			// Otherwise compose the message now.
			failure := fmt.Sprintf("Overflow in bitSize of %d for %q", bitSize, fn.Name)

			// The value was found, next let's check for the size of:
			// strconv.ParseUint(str, base, digits)
			// Awesome, we found the conversion to int*
			// Next we need to examine what the bitSize was.
			return gosec.NewIssue(ctx, nFound, bc.ID(), failure, bc.Severity, bc.Confidence), nil
		}
	}

	return nil, nil
}

// NewStrconvIntBitSizeOverflow returns an error if a constant bitSize is used
// for a cast signed value that was retrieved from strconv.ParseUint.
func NewStrconvIntBitSizeOverflow(id string, config gosec.Config) (rule gosec.Rule, nodes []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("strconv", "ParseUint")

	bc := &bitsizeOverflowCheck{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.Medium,
			What:       "Overflow due to wrong bitsize in strconv.ParseUint yet cast from uint64 to int*",
		},
		calls: calls,
	}

	nodes = append(nodes, (*ast.FuncDecl)(nil), (*ast.AssignStmt)(nil), (*ast.CallExpr)(nil))
	return bc, nodes
}
