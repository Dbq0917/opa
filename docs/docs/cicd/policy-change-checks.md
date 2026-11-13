---
sidebar_label: Policy Change Checks
sidebar_position: 3
---

# Policy Change Checks

Large policy repositories usually have a stable set of rules and a small pull
request that adds or changes a few of them. Compiling the entire library on
every change is both slow and does not answer the important review question:
can the new rule produce a decision that an existing rule already produces in
the opposite direction?

`opa check --base` addresses both concerns without changing Rego syntax:

```bash
git worktree add /tmp/policy-base origin/main
opa check --base /tmp/policy-base/policies policies
```

The baseline is compiled once. The current policy then reuses the compiled
rules whose source and source location are unchanged, compiling only added or
changed rules when the dependency graph permits it. If an incremental compile
cannot produce the same result as a full compile, OPA falls back to the full
compile automatically.

## Allow/Deny Conflicts

When `--base` is set, OPA also checks newly added or changed `allow` and `deny`
decision documents in the same package. It derives candidate inputs from the
rules' input constraints and evaluates both decisions. A conflict is reported
only when:

- both decisions are positive for the same concrete input, and
- the baseline does not already produce that conflict for the same input.

This keeps existing, intentionally overridden decisions from making every pull
request fail, while surfacing newly introduced overlaps before merge. A
changed helper rule is followed through the compiler's dependency graph, so
the `allow` and `deny` rules that depend on it are checked as well.

To audit all current conflicts without a baseline, run:

```bash
opa check --conflicts policies
```

The check is a concrete evaluation of candidate inputs, not a general
theorem-prover for all possible Rego expressions. It intentionally reports
only conflicts for which it can construct and verify an input.

## CI Example

```yaml title=".github/workflows/policy.yaml"
- name: Check policy changes
  run: |
    git worktree add /tmp/policy-base origin/main
    opa check --base /tmp/policy-base/policies policies
```

A non-zero exit code fails the pull request when compilation fails or when a
new allow/deny conflict is found.
