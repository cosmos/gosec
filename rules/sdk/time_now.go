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
	"go/ast"

	"github.com/cosmos/gosec/v2"
)

type timeNowCheck struct {
	gosec.MetaData
	calls gosec.CallList
}

func (tmc *timeNowCheck) ID() string { return tmc.MetaData.ID }

func (tmc *timeNowCheck) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	// We want to catch all function invocations as well as assignments of any of the form:
	// .Value = time.Now().*
	// fn := time.Now
	callExpr, ok := node.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	sel, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}

	if sel.Sel.Name != "Now" {
		return nil, nil
	}

	switch x := sel.X.(type) {
	case *ast.Ident:
		if x.Name != "time" {
			return nil, nil
		}

	case *ast.SelectorExpr:
		if x.Sel.Name != "time" {
			return nil, nil
		}
	}

	// By this point issue the error.
	return nil, errors.New("time.Now() is non-deterministic for distributed consensus, you should use the current Block's timestamp")
}

// NewTimeNowRefusal discourages the use of time.Now() as it was discovered that
// its usage caused local non-determinism and chain halting, as reported and detailed at
// https://forum.cosmos.network/t/cosmos-sdk-vulnerability-retrospective-security-advisory-jackfruit-october-12-2021/5349
func NewTimeNowRefusal(id string, config gosec.Config) (rule gosec.Rule, nodes []ast.Node) {
	calls := gosec.NewCallList()

	tnc := &timeNowCheck{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.High,
			What:       "Non-determinism from using non-consensus aware time.Now() can cause a chain halt",
		},
		calls: calls,
	}

	nodes = append(nodes, (*ast.CallExpr)(nil))
	return tnc, nodes
}
