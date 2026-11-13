// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policyconflict

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

func compile(t *testing.T, files map[string]string) (map[string]*ast.Module, *ast.Compiler) {
	t.Helper()
	modules := map[string]*ast.Module{}
	for name, src := range files {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{
			RegoVersion:       ast.RegoV1,
			ProcessAnnotation: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = m
	}
	c := ast.NewCompiler()
	c.Compile(modules)
	if c.Failed() {
		t.Fatal(c.Errors)
	}
	return modules, c
}

func TestCheck(t *testing.T) {
	tests := []struct {
		note  string
		base  map[string]string
		head  map[string]string
		count int
	}{
		{
			note: "new deny overlaps allow",
			base: map[string]string{"p.rego": `package test

allow if input.user == "admin"
`},
			head: map[string]string{"p.rego": `package test

allow if input.user == "admin"

deny if input.user == "admin"
`},
			count: 1,
		},
		{
			note: "changed helper affects allow",
			base: map[string]string{"p.rego": `package test

allow if helper
deny if input.user == "bob"
helper if false
`},
			head: map[string]string{"p.rego": `package test

allow if helper
deny if input.user == "bob"
helper if true
`},
			count: 1,
		},
		{
			note: "local input variable",
			base: map[string]string{"p.rego": `package test

allow if {
	x := input.user
	x == "admin"
}
`},
			head: map[string]string{"p.rego": `package test

allow if {
	x := input.user
	x == "admin"
}

deny if input.user == "admin"
`},
			count: 1,
		},
		{
			note: "different values do not overlap",
			base: map[string]string{"p.rego": `package test

allow if input.kind == "a"
`},
			head: map[string]string{"p.rego": `package test

allow if input.kind == "a"

deny if input.kind == "b"
`},
		},
		{
			note: "inequality overlaps an unconditional allow",
			base: map[string]string{"p.rego": `package test

allow if true
`},
			head: map[string]string{"p.rego": `package test

allow if true

deny if input.kind != "b"
`},
			count: 1,
		},
		{
			note: "equality and inequality do not overlap",
			base: map[string]string{"p.rego": `package test

allow if input.kind == "b"
`},
			head: map[string]string{"p.rego": `package test

allow if input.kind == "b"

deny if input.kind != "b"
`},
		},
		{
			note: "existing overlap is not new",
			base: map[string]string{"p.rego": `package test

allow if input.user == "admin"
deny if input.user == "admin"
`},
			head: map[string]string{"p.rego": `package test

allow if input.user == "admin"
deny if input.user == "admin"

deny if input.user == "bob"
`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			baseModules, baseCompiler := compile(t, tc.base)
			modules, compiler := compile(t, tc.head)
			conflicts, err := Check(t.Context(), modules, compiler, baseModules, baseCompiler)
			if err != nil {
				t.Fatal(err)
			}
			if len(conflicts) != tc.count {
				t.Fatalf("got %d conflicts, want %d: %+v", len(conflicts), tc.count, conflicts)
			}
			for _, c := range conflicts {
				if err := c.FormatError(); err == nil {
					t.Fatal("expected an error")
				}
			}
		})
	}
}

func TestCheckWithoutBaseReportsAllOverlaps(t *testing.T) {
	modules, compiler := compile(t, map[string]string{"p.rego": `package test

allow if input.user == "admin"
deny if input.user == "admin"
`})
	conflicts, err := Check(context.Background(), modules, compiler, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
}
