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

	"github.com/cosmos/gosec/v2"
)

// originally copied and simplified from the rules/integer_overflow.go
type integerOverflowCheck struct {
	gosec.MetaData
}

func (i *integerOverflowCheck) ID() string {
	return i.MetaData.ID
}

func hasAnyPrefix(src string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(src, prefix) {
			return true
		}
	}
	return false
}

// To catch integer type conversion, check if we ever
// call functions `uintX(y)` or `intX(y)` for any X and y,
// where y is not an int literal.
// TODO: restrict it to just the possible bit-sizes for X (unspecified, 8, 16, 32, 64)
// TODO: check if y's bit-size is greater than X
func (i *integerOverflowCheck) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	// ignore if it's protobuf
	fileName := ctx.FileSet.File(node.Pos()).Name()
	if strings.HasSuffix(fileName, ".pb.go") {
		return nil, nil
	}

	switch n := node.(type) {
	case *ast.CallExpr:
		fun, ok := n.Fun.(*ast.Ident)
		if !ok {
			return nil, nil
		}

		if len(n.Args) == 0 {
			return nil, nil
		}

		arg := n.Args[0]
		argT := ctx.Info.TypeOf(arg)
		if argT == nil {
			// TODO: Perhaps log and investigate this case more.
			return nil, nil
		}
		fnType := ctx.Info.TypeOf(fun)
		if fnType == nil {
			// TODO: Perhaps log and investigate this case more.
			return nil, nil
		}

		argType := argT.Underlying()
		destType := fnType.Underlying()
		intCast := hasAnyPrefix(destType.String(), "int", "uint")
		if !intCast {
			return nil, nil
		}

		// Detect intX(y) and uintX(y) for any X, where y is not an int literal.
		// n.Args[0] is of type ast.Expr. It's the arg to the type conversion.
		// If the expression string is a constant integer, then ignore.
		// TODO: check that the constant will actually fit and wont overflow?
		exprString := types.ExprString(arg)
		intLiteral, err := strconv.Atoi(exprString)
		if err == nil {
			// TODO: probably use ParseInt and check if it fits in the target.
			_ = intLiteral
			return nil, nil
		}

		switch arg := arg.(type) {
		case *ast.CallExpr:
			// len() returns an int that is always >= 0, so it will fit in a uint, uint64, or int64.
			argFun, ok := arg.Fun.(*ast.Ident)
			if !ok || argFun.Name != "len" {
				break
			}

			// Please see the rules for determining if *int*(len(...)) can overflow
			// as per: https://github.com/cosmos/gosec/issues/54
			lenCanOverflow := canLenOverflow64
			if is32Bit {
				lenCanOverflow = canLenOverflow32
			}

			if lenCanOverflow(fun.Name) {
				return gosec.NewIssue(ctx, n, i.ID(), i.What, i.Severity, i.Confidence), nil
			}
			return nil, nil
		}

		// If the argument is being cast to its underlying type, there's no risk.
		if argType == destType {
			return nil, nil
		}

		// Check if both are uint* values.
		argIsUint := hasAnyPrefix(argType.String(), "uint")
		if argIsUint && !canBothUintsOverflow(argType.String(), destType.String()) {
			return nil, nil
		}

		// Check if both are int* values.
		argIsInt := hasAnyPrefix(argType.String(), "int")
		if argIsInt && !canBothIntToIntOverflow(argType.String(), destType.String()) {
			return nil, nil
		}

		// ALl other cases should be flagged.
		return gosec.NewIssue(ctx, n, i.ID(), i.What, i.Severity, i.Confidence), nil
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

// Please see the rules at https://github.com/cosmos/gosec/issues/54
func canLenOverflow64(destKind string) bool {
	switch destKind {
	case "int8", "uint8", "int16", "uint16":
		return true

	case "uint64":
		// uint64([0, maxInt64])
		return false

	case "uint32":
		// uint32([0, maxInt64])
		return true

	case "uint":
		// uint => uint64 => uint64([0, maxInt64])
		return false

	case "int64":
		// int64([0, maxInt64])
		return false

	case "int32":
		// int32([0, maxInt64])
		return true

	case "int":
		// int64([0, maxInt64])
		return false

	default:
		return true
	}
}

const s = 1
const is32Bit = (^uint(s-1))>>32 == 0 // #nosec

// Please see the rules at https://github.com/cosmos/gosec/issues/54
func canLenOverflow32(destKind string) bool {
	switch destKind {
	case "int8", "uint8", "int16", "uint16":
		return true

	case "uint64":
		// uint64([0, maxInt32])
		return false

	case "uint32":
		// uint32([0, maxInt32])
		return false

	case "uint":
		// uint => uint32 => uint32([0, maxInt32])
		return false

	case "int64":
		// int64([0, maxInt32])
		return false

	case "int32":
		// int32([0, maxInt32])
		return false

	case "int":
		// int => int32 => int32([0, maxInt32])
		return false

	default:
		return true
	}
}

func canBothUintsOverflow(srcKind, destKind string) bool {
	bothUints := hasAnyPrefix(srcKind, "uint") && hasAnyPrefix(destKind, "uint")
	if !bothUints {
		return true
	}

	if destKind == "uint" {
		// Only in 32-bit is uint equal to uint32 hence can it overflow if src is uint64.
		return srcKind == "uint64" && is32Bit
	}
	if destKind == "uint64" {
		// Casting any uint type to uint64 cannot overflow.
		return false
	}
	if destKind == "uint32" {
		// Only uint64 or uint (when in 64-bits) can overflow when being cast to uint32.
		return srcKind == "uint64" || (srcKind == "uint" && !is32Bit)
	}
	if destKind == "uint16" {
		// Everything except "uint8" and "uint16" can overflow when cast to uint16.
		return srcKind == "uint64" || srcKind == "uint32" || srcKind == "uint"
	}
	if destKind == "uint8" {
		// Everything that isn't "uint8" will overflow when cast to uint8.
		return srcKind != "uint8"
	}
	return true
}

func canBothIntToIntOverflow(srcKind, destKind string) bool {
	bothInts := hasAnyPrefix(srcKind, "int") && hasAnyPrefix(destKind, "int")
	if !bothInts {
		return true
	}

	if destKind == "int" {
		// Only in 32-bit is int equal to int32 hence can it overflow if src is int64.
		return srcKind == "int64" && is32Bit
	}
	if destKind == "int64" {
		// Casting any int type to int64 cannot overflow.
		return false
	}
	if destKind == "int32" {
		// Only int64 or int (when in 64-bits) can overflow when being cast to int32.
		return srcKind == "int64" || (srcKind == "int" && !is32Bit)
	}
	if destKind == "int16" {
		// Everything except "int8" and "int16" can overflow when cast to int16.
		return srcKind == "int64" || srcKind == "int32" || srcKind == "int"
	}
	if destKind == "int8" {
		// Everything that isn't "int8" will overflow when cast to int8.
		return srcKind != "int8"
	}
	return true
}
