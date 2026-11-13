// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package policyconflict reports newly introduced allow/deny overlaps.
package policyconflict

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Conflict describes an input for which an allow and a deny decision are both
// positive. When Base is non-nil, only conflicts not present in Base are
// returned.
type Conflict struct {
	Package string
	Allow   *ast.Rule
	Deny    *ast.Rule
	Input   map[string]any
}

// Check reports allow/deny overlaps introduced by modules relative to base.
// Both compilers must have compiled their corresponding modules. If base is
// nil, every overlap in modules is reported.
func Check(ctx context.Context, modules map[string]*ast.Module, compiler *ast.Compiler, base map[string]*ast.Module, baseCompiler *ast.Compiler) ([]Conflict, error) {
	changed := changedRules(modules, base)
	decisions := decisionRules(modules)
	if len(decisions) == 0 {
		return nil, nil
	}

	compiled, compiledKeys := compiledRulesBySource(compiler)
	affected := affectedRules(compiler, changed, compiled)
	affectedKeys := make(map[ast.RuleKey]struct{}, len(affected))
	for r := range affected {
		affectedKeys[compiledKeys[r]] = struct{}{}
	}
	pairs := conflictPairs(affectedKeys, decisions)
	if len(pairs) == 0 {
		return nil, nil
	}

	eval, err := newPairEvaluator(ctx, compiler, pairs)
	if err != nil {
		return nil, err
	}
	defer eval.close()

	var baseEval *pairEvaluator
	if baseCompiler != nil {
		baseEval, err = newPairEvaluator(ctx, baseCompiler, pairs)
		if err != nil {
			return nil, err
		}
		defer baseEval.close()
	}

	var conflicts []Conflict
	seen := map[string]struct{}{}
	for _, p := range pairs {
		for _, input := range candidateInputs(p.allow, p.deny) {
			ok, err := eval.bothTrue(ctx, p, input)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if baseEval != nil {
				ok, err = baseEval.bothTrue(ctx, p, input)
				if err != nil {
					return nil, err
				}
				if ok {
					continue
				}
			}
			key := conflictKey(p, input)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			conflicts = append(conflicts, Conflict{
				Package: p.pkg,
				Allow:   p.allow,
				Deny:    p.deny,
				Input:   input,
			})
		}
	}
	slices.SortFunc(conflicts, func(a, b Conflict) int {
		if c := strings.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		if c := strings.Compare(loc(a.Allow.Location), loc(b.Allow.Location)); c != 0 {
			return c
		}
		if c := strings.Compare(loc(a.Deny.Location), loc(b.Deny.Location)); c != 0 {
			return c
		}
		return strings.Compare(string(mustJSON(a.Input)), string(mustJSON(b.Input)))
	})
	return conflicts, nil
}

// FormatError turns a conflict into a compile-style error suitable for the
// check command.
func (c Conflict) FormatError() *ast.Error {
	input, _ := json.Marshal(c.Input)
	return ast.NewError(ast.CompileErr, c.Allow.Location,
		"%s: conflicting decisions: %v at %s and %v at %s both match input %s",
		c.Package, c.Allow.Ref(), loc(c.Allow.Location), c.Deny.Ref(), loc(c.Deny.Location), input)
}

func loc(l *ast.Location) string {
	if l == nil {
		return "<unknown>"
	}
	return l.String()
}

type decisionSet struct {
	pkg   string
	allow []decisionRule
	deny  []decisionRule
}

type decisionRule struct {
	key  ast.RuleKey
	rule *ast.Rule
}

type rulePair struct {
	pkg   string
	allow *ast.Rule
	deny  *ast.Rule
}

func decisionRules(modules map[string]*ast.Module) map[string]*decisionSet {
	out := map[string]*decisionSet{}
	for _, m := range modules {
		for _, r := range m.Rules {
			ref := r.Ref()
			if len(ref) < 2 {
				continue
			}
			name, ok := ref[len(ref)-1].Value.(ast.String)
			if !ok {
				continue
			}
			var d *decisionSet
			if name == "allow" || name == "deny" {
				pkg := ref[:len(ref)-1].String()
				d = out[pkg]
				if d == nil {
					d = &decisionSet{pkg: pkg}
					out[pkg] = d
				}
			} else {
				continue
			}
			if name == "allow" {
				d.allow = append(d.allow, decisionRule{key: ruleSourceKey(m, r), rule: r})
			} else {
				d.deny = append(d.deny, decisionRule{key: ruleSourceKey(m, r), rule: r})
			}
		}
	}
	return out
}

func changedRules(modules, base map[string]*ast.Module) map[ast.RuleKey]struct{} {
	out := map[ast.RuleKey]struct{}{}
	if base == nil {
		for _, m := range modules {
			for _, r := range m.Rules {
				out[ruleSourceKey(m, r)] = struct{}{}
			}
		}
		return out
	}
	changedModules := map[string]struct{}{}
	for name, m := range modules {
		bm, ok := base[name]
		if !ok || moduleSourceKey(m) != moduleSourceKey(bm) {
			changedModules[name] = struct{}{}
		}
	}
	old := map[ast.RuleKey]struct{}{}
	for name, m := range base {
		if _, ok := changedModules[name]; ok {
			continue
		}
		for _, r := range m.Rules {
			old[ruleSourceKey(m, r)] = struct{}{}
		}
	}
	for name, m := range modules {
		_, moduleChanged := changedModules[name]
		for _, r := range m.Rules {
			k := ruleSourceKey(m, r)
			if moduleChanged {
				out[k] = struct{}{}
				continue
			}
			if _, ok := old[k]; !ok {
				out[k] = struct{}{}
			}
		}
	}
	return out
}

func moduleSourceKey(m *ast.Module) ast.RuleKey {
	texts := [][]byte{[]byte(m.Package.Path.String())}
	for _, imp := range m.Imports {
		texts = append(texts, []byte(imp.String()))
	}
	for _, a := range m.Annotations {
		if a.Location != nil {
			texts = append(texts, a.Location.Text)
		}
	}
	return ast.ReuseKey("module", texts...)
}

func ruleSourceKey(m *ast.Module, r *ast.Rule) ast.RuleKey {
	var texts [][]byte
	for _, a := range r.Annotations {
		if a.Location != nil {
			texts = append(texts, a.Location.Text)
		}
	}
	if r.Location != nil && len(r.Location.Text) > 0 {
		texts = append(texts, r.Location.Text)
	} else {
		texts = append(texts, []byte(r.String()))
	}
	return ast.ReuseKey(m.Package.Path.String(), texts...)
}

func compiledRulesBySource(c *ast.Compiler) (map[ast.RuleKey][]*ast.Rule, map[*ast.Rule]ast.RuleKey) {
	out := map[ast.RuleKey][]*ast.Rule{}
	reverse := map[*ast.Rule]ast.RuleKey{}
	for _, m := range c.Modules {
		for _, r := range m.Rules {
			key := ruleSourceKey(m, r)
			out[key] = append(out[key], r)
			reverse[r] = key
		}
	}
	return out, reverse
}

func affectedRules(c *ast.Compiler, changed map[ast.RuleKey]struct{}, compiled map[ast.RuleKey][]*ast.Rule) map[*ast.Rule]struct{} {
	out := map[*ast.Rule]struct{}{}
	queue := make([]*ast.Rule, 0, len(changed))
	for k := range changed {
		queue = append(queue, compiled[k]...)
	}
	for len(queue) > 0 {
		r := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, ok := out[r]; ok {
			continue
		}
		out[r] = struct{}{}
		for dep := range c.Graph.Dependents(r) {
			if dr, ok := dep.(*ast.Rule); ok {
				queue = append(queue, dr)
			}
		}
	}
	return out
}

func conflictPairs(affected map[ast.RuleKey]struct{}, decisions map[string]*decisionSet) []rulePair {
	var out []rulePair
	for _, d := range decisions {
		if len(d.allow) == 0 || len(d.deny) == 0 {
			continue
		}
		for _, a := range d.allow {
			if _, ok := affected[a.key]; !ok {
				continue
			}
			for _, n := range d.deny {
				out = append(out, rulePair{pkg: d.pkg, allow: a.rule, deny: n.rule})
			}
		}
		for _, n := range d.deny {
			if _, ok := affected[n.key]; !ok {
				continue
			}
			for _, a := range d.allow {
				out = append(out, rulePair{pkg: d.pkg, allow: a.rule, deny: n.rule})
			}
		}
	}
	return out
}

func conflictKey(p rulePair, input map[string]any) string {
	b, _ := json.Marshal(input)
	return p.allow.Ref().String() + "\x00" + p.deny.Ref().String() + "\x00" + string(b)
}

type pairEvaluator struct {
	queries map[string]rego.PreparedEvalQuery
}

func newPairEvaluator(ctx context.Context, c *ast.Compiler, pairs []rulePair) (*pairEvaluator, error) {
	e := &pairEvaluator{queries: map[string]rego.PreparedEvalQuery{}}
	for _, p := range pairs {
		if _, ok := e.queries[p.pkg]; ok {
			continue
		}
		pq, err := rego.New(
			rego.Query(fmt.Sprintf("%s = __allowed; %s = __denied", p.pkg+".allow", p.pkg+".deny")),
			rego.Compiler(c),
		).PrepareForEval(ctx)
		if err != nil {
			e.close()
			return nil, err
		}
		e.queries[p.pkg] = pq
	}
	return e, nil
}

func (e *pairEvaluator) close() {
	for _, pq := range e.queries {
		pq.Close()
	}
}

func (e *pairEvaluator) bothTrue(ctx context.Context, p rulePair, input map[string]any) (bool, error) {
	rs, err := e.queries[p.pkg].Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}
	for _, r := range rs {
		if positive(r.Bindings["__allowed"]) && positive(r.Bindings["__denied"]) {
			return true, nil
		}
	}
	return false, nil
}

func positive(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

type inputConstraint struct {
	values map[string]any
	not    map[string][]any
	locals map[ast.Var][]string
}

func candidateInputs(allow, deny *ast.Rule) []map[string]any {
	a := constraintsFor(allow)
	d := constraintsFor(deny)
	merged, ok := a.merge(d)
	if !ok {
		return nil
	}
	out := []map[string]any{merged.build()}
	if v := a.build(); !slices.Equal(mustJSON(out[0]), mustJSON(v)) {
		out = append(out, v)
	}
	if v := d.build(); !slices.Equal(mustJSON(out[0]), mustJSON(v)) {
		out = append(out, v)
	}
	return out
}

func constraintsFor(r *ast.Rule) *inputConstraint {
	c := &inputConstraint{
		values: map[string]any{},
		not:    map[string][]any{},
		locals: localInputPaths(r),
	}
	if r == nil || r.Body == nil {
		return c
	}
	ast.WalkExprs(r.Body, func(expr *ast.Expr) bool {
		op := ""
		if expr.IsCall() {
			op = expr.Operator().String()
		}
		if (expr.IsEquality() || op == "equal") && len(expr.Operands()) >= 2 {
			c.addEq(expr.Operands()[0], expr.Operands()[1], expr.IsNegated())
			c.addEq(expr.Operands()[1], expr.Operands()[0], expr.IsNegated())
			return true
		}
		if expr.IsCall() && len(expr.Operands()) >= 2 {
			switch op {
			case "neq":
				c.addNeq(expr.Operands()[0], expr.Operands()[1], expr.IsNegated())
			case "gt", "gte", "lt", "lte":
				c.addCompare(op, expr.Operands()[0], expr.Operands()[1], expr.IsNegated())
			}
		}
		return true
	})
	return c
}

func (c *inputConstraint) addEq(a, b *ast.Term, negated bool) {
	path, ok := c.inputPath(a)
	if !ok || !b.IsGround() || c.isInputValue(b.Value) {
		return
	}
	v, err := ast.JSON(b.Value)
	if err != nil {
		return
	}
	c.set(path, v, negated)
}

func (c *inputConstraint) addNeq(a, b *ast.Term, negated bool) {
	path, ok := c.inputPath(a)
	if !ok || !b.IsGround() || c.isInputValue(b.Value) {
		return
	}
	v, err := ast.JSON(b.Value)
	if err != nil {
		return
	}
	if negated {
		c.set(path, v, false)
		return
	}
	if alt, ok := alternative(v); ok {
		c.set(path, alt, false)
	}
}

func (c *inputConstraint) addCompare(op string, a, b *ast.Term, negated bool) {
	path, ok := c.inputPath(a)
	if !ok || !b.IsGround() || c.isInputValue(b.Value) {
		return
	}
	n, ok := b.Value.(ast.Number)
	if !ok {
		return
	}
	value, ok := number(n)
	if !ok {
		return
	}
	switch op {
	case "gt":
		value++
	case "lt":
		value--
	}
	c.set(path, value, negated)
}

func (c *inputConstraint) set(path []string, value any, forbidden bool) {
	key := strings.Join(path, "\x00")
	if forbidden {
		c.not[key] = append(c.not[key], value)
		return
	}
	if old, ok := c.values[key]; ok && !slices.Equal(mustJSON(old), mustJSON(value)) {
		c.not[key] = append(c.not[key], value)
		return
	}
	c.values[key] = value
}

func (c *inputConstraint) merge(other *inputConstraint) (*inputConstraint, bool) {
	out := &inputConstraint{values: map[string]any{}, not: map[string][]any{}, locals: c.locals}
	for k, v := range c.values {
		out.values[k] = v
	}
	for k, v := range c.not {
		out.not[k] = slices.Clone(v)
	}
	for k, v := range other.values {
		if old, ok := out.values[k]; ok && !slices.Equal(mustJSON(old), mustJSON(v)) {
			return nil, false
		}
		for _, forbidden := range out.not[k] {
			if slices.Equal(mustJSON(forbidden), mustJSON(v)) {
				return nil, false
			}
		}
		out.values[k] = v
	}
	for k, vs := range other.not {
		for _, v := range vs {
			if old, ok := out.values[k]; ok && slices.Equal(mustJSON(old), mustJSON(v)) {
				return nil, false
			}
			out.not[k] = append(out.not[k], v)
		}
	}
	return out, true
}

func (c *inputConstraint) build() map[string]any {
	out := map[string]any{}
	for key, value := range c.values {
		setInputValue(out, strings.Split(key, "\x00"), value)
	}
	return out
}

func inputPath(t *ast.Term) ([]string, bool) {
	ref, ok := t.Value.(ast.Ref)
	if !ok || !ref.HasPrefix(ast.InputRootRef) || len(ref) < 2 {
		return nil, false
	}
	path := make([]string, 0, len(ref)-1)
	for _, p := range ref[1:] {
		switch x := p.Value.(type) {
		case ast.String:
			path = append(path, string(x))
		case ast.Number:
			path = append(path, x.String())
		default:
			return nil, false
		}
	}
	return path, true
}

func (c *inputConstraint) inputPath(t *ast.Term) ([]string, bool) {
	if path, ok := inputPath(t); ok {
		return path, true
	}
	if v, ok := t.Value.(ast.Var); ok {
		path, ok := c.locals[v]
		return path, ok
	}
	return nil, false
}

func (c *inputConstraint) isInputValue(v ast.Value) bool {
	ref, ok := v.(ast.Ref)
	if ok && ref.HasPrefix(ast.InputRootRef) {
		return true
	}
	_, ok = v.(ast.Var)
	return ok
}

func localInputPaths(r *ast.Rule) map[ast.Var][]string {
	out := map[ast.Var][]string{}
	if r == nil || r.Body == nil {
		return out
	}
	ast.WalkExprs(r.Body, func(expr *ast.Expr) bool {
		if (!expr.IsAssignment() && !expr.IsEquality()) || len(expr.Operands()) < 2 {
			return true
		}
		left, right := expr.Operands()[0], expr.Operands()[1]
		if v, ok := left.Value.(ast.Var); ok {
			if path, ok := inputPath(right); ok {
				out[v] = path
			}
		}
		if v, ok := right.Value.(ast.Var); ok {
			if path, ok := inputPath(left); ok {
				out[v] = path
			}
		}
		return true
	})
	return out
}

func setInputValue(m map[string]any, path []string, value any) {
	for _, p := range path[:len(path)-1] {
		child, ok := m[p].(map[string]any)
		if !ok {
			child = map[string]any{}
			m[p] = child
		}
		m = child
	}
	m[path[len(path)-1]] = value
}

func number(n ast.Number) (float64, bool) {
	v, ok := n.Int64()
	if !ok {
		f, ok := n.Float64()
		return f, ok
	}
	return float64(v), true
}

func alternative(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		return x + "\x00other", true
	case bool:
		return !x, true
	case float64:
		return x + 1, true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i + 1, true
		}
		if f, err := x.Float64(); err == nil {
			return f + 1, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
