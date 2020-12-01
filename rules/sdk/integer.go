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
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
)

// originally copied and simplified from the rules/integer_overflow.go
type integerOverflowCheck struct {
	gosec.MetaData
}

func (i *integerOverflowCheck) ID() string {
	return i.MetaData.ID
}

// To catch integer type conversion, check if we ever
// call functions `uintX(y)` or `intX(y)` for any X and y,
// where y is not an int literal.
// TODO: restrict it to just the possible bit-sizes for X (unspecified, 8, 16, 32, 64)
// TODO: check if y's bit-size is greater than X
func (i *integerOverflowCheck) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {

	// ignore if its protobuf
	fileName := ctx.FileSet.File(node.Pos()).Name()
	if strings.HasSuffix(fileName, ".pb.go") {
		return nil, nil
	}

	switch n := node.(type) {
	case *ast.CallExpr:
		if fun, ok := n.Fun.(*ast.Ident); ok {
			// Detect intX(y) and uintX(y) for any X, where y is not an int literal.
			if strings.HasPrefix(fun.Name, "int") || strings.HasPrefix(fun.Name, "uint") {

				// n.Args[0] is of type ast.Expr. It's the arg to the type conversion.
				// If the expression string is a constant integer, then ignore.
				// TODO: check that the constant will actually fit and wont overflow?
				arg := n.Args[0]
				exprString := types.ExprString(arg)
				intLiteral, err := strconv.Atoi(exprString)
				if err == nil {
					// TODO: probably use ParseInt and check if it fits in the target.
					_ = intLiteral
					return nil, nil
				}

				// TODO: run the go type checker to determine the
				// type of arg so we can check if the type
				// conversion is reducing the bit-size and could overflow.
				// If not, this will be a false positive for now ...
				// See https://golang.org/pkg/go/types/#Config.Check
				return gosec.NewIssue(ctx, n, i.ID(), i.What, i.Severity, i.Confidence), nil
			}
		}
	}

	return nil, nil
}

// NewIntegerCast detects if there is potential Integer OverFlow
func NewIntegerCast(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return &integerOverflowCheck{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.Medium,
			What:       "Potential integer overflow by integer type conversion",
		},
	}, []ast.Node{(*ast.FuncDecl)(nil), (*ast.AssignStmt)(nil), (*ast.CallExpr)(nil)}
}
