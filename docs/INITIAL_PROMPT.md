# Zigma Development Session

## Context

You are working on **zigma**, a Zig-based ErgoTree interpreter. Significant implementation already exists. This session focuses on **audit, alignment, and hardening** based on expert review feedback.

### What Exists

```
src/
├── core/           ← types.zig, opcodes.zig
├── crypto/         ← bigint.zig, hash.zig, secp256k1.zig
├── interpreter/    ← evaluator.zig, memory.zig, value_pool.zig, context.zig
│   └── ops/        ← arithmetic, comparison, logical, collection, box, crypto, etc.
├── serialization/  ← vlq.zig, type/data/expr/ergotree_serializer.zig
├── sigma/          ← sigma_tree.zig, challenge.zig, schnorr.zig, verifier.zig
└── root.zig
```

### Session Goal

Audit existing code against expert feedback and the design spec. Create tasks for identified gaps. Fix critical issues.

---

## Session Initialization

### Step 1: Read Core Documentation

```
@CLAUDE.md                      # Rules, commands, workflow
@docs/ZUTXO_STYLE.md            # Safety, determinism guidelines  
@docs/INTERPRETER_DESIGN.md     # Architecture and requirements
@docs/EXPERT_REVIEW.md          # Critical feedback to address
```

### Step 2: Understand Critical Requirements

From expert review, these are **must-fix** items:

| Issue | Component | Why Critical |
|-------|-----------|--------------|
| Cost model is static | evaluator.zig | Costs must be size/type-dependent |
| Missing VersionContext | evaluator.zig | Behavior varies by protocol version |
| Point validation incomplete | secp256k1.zig | Invalid points break consensus |
| No constant-time ops | crypto/, sigma/ | Timing attacks leak secrets |
| No soft-fork handling | evaluator.zig | Unknown opcodes must be accepted |
| Assertion density low | All files | Target 3+ per function |

### Step 3: Run Initial Assessment

```bash
# Build and test current state
cd ~/orgs/zutxo/zigma
zig build test 2>&1 | tail -50

# Count assertions per file
for f in src/**/*.zig; do
  count=$(grep -c "assert\|std.debug.assert" "$f" 2>/dev/null || echo 0)
  funcs=$(grep -c "pub fn\|fn " "$f" 2>/dev/null || echo 1)
  ratio=$(echo "scale=1; $count / $funcs" | bc 2>/dev/null || echo "?")
  echo "$f: $count assertions / $funcs functions = $ratio per fn"
done

# Check for forbidden patterns
echo "=== HashMap usage (forbidden in output paths) ==="
grep -rn "HashMap\|AutoHashMap" src/

echo "=== Floating point (forbidden) ==="
grep -rn "f32\|f64\|@float" src/

echo "=== Check for VersionContext ==="
grep -rn "VersionContext\|version.*context" src/

# Current task state
bd list --all 2>/dev/null || echo "No tasks yet"
```

---

## Audit Workflow

### Phase 1: Critical Path Audit

Audit these files FIRST (consensus-critical):

#### 1.1 Evaluator (`src/interpreter/evaluator.zig`)

```bash
# View the file
cat src/interpreter/evaluator.zig
```

**Check for:**
- [ ] Iterative evaluation (work stack, no recursion)
- [ ] Cost check BEFORE every operation
- [ ] VersionContext threading
- [ ] Soft-fork handling for unknown opcodes
- [ ] Wall-clock timeout
- [ ] Iteration limit
- [ ] Size-dependent cost calculation (NOT static lookup)

**Create tasks for gaps:**
```bash
bd create "evaluator: Add VersionContext threading" -t bug -p 1 --label critical
bd create "evaluator: Implement size-dependent costs" -t bug -p 1 --label critical
bd create "evaluator: Add soft-fork condition handling" -t bug -p 1 --label critical
bd create "evaluator: Add wall-clock timeout" -t task -p 2 --label safety
```

#### 1.2 Cryptography (`src/crypto/secp256k1.zig`)

```bash
cat src/crypto/secp256k1.zig
```

**Check for:**
- [ ] Point validation: `isOnCurve()`
- [ ] Point validation: `!isInfinity()`
- [ ] Point validation: `isValidFieldElement(x)`
- [ ] All deserialized points validated
- [ ] Constant-time comparison function exists

**Create tasks:**
```bash
bd create "secp256k1: Complete point validation (infinity, field check)" -t bug -p 1 --label critical
bd create "crypto: Add constant-time comparison utilities" -t task -p 1 --label critical
```

#### 1.3 Sigma Verification (`src/sigma/verifier.zig`)

```bash
cat src/sigma/verifier.zig
```

**Check for:**
- [ ] Uses constant-time comparison for signature checks
- [ ] Correct Fiat-Shamir challenge computation
- [ ] All GroupElements validated before use

### Phase 2: Foundation Audit

#### 2.1 Type System (`src/core/types.zig`)

**Check for:**
- [ ] TypeCode values match ErgoTree spec exactly
- [ ] SType uses index-based references (not recursive pointers)
- [ ] `isSubtypeOf()` handles Any/Unit
- [ ] comptime validation of type codes

#### 2.2 Opcodes (`src/core/opcodes.zig`)

**Check for:**
- [ ] All 100+ opcodes present
- [ ] `min_version` field in metadata
- [ ] comptime uniqueness validation
- [ ] Metadata table is complete

#### 2.3 Memory Pools (`src/interpreter/memory.zig`)

**Check for:**
- [ ] SoA layout (separate arrays for opcodes, types, children)
- [ ] Power-of-two CAPACITY
- [ ] O(1) reset (no zeroing)
- [ ] `hasCapacity()` for pre-validation

### Phase 3: Operations Audit

For each file in `src/interpreter/ops/`:

```bash
for f in src/interpreter/ops/*.zig; do
  echo "=== $f ==="
  # Count assertions
  grep -c "assert" "$f"
  # Check for overflow handling
  grep -c "WithOverflow\|error.Overflow" "$f"
  # Check for bounds
  grep -c "error.OutOfBounds\|error.IndexOutOfBounds" "$f"
done
```

**Arithmetic (`arithmetic.zig`) must have:**
- [ ] `@addWithOverflow` / `@subWithOverflow` / `@mulWithOverflow`
- [ ] Division by zero check
- [ ] `MIN / -1` overflow case

**Collection (`collection.zig`) must have:**
- [ ] Bounds checking on index access
- [ ] Size limits enforced
- [ ] Per-element cost accounting

### Phase 4: Serialization Audit

**Check each serializer for:**
- [ ] Size limits (4KB max ErgoTree)
- [ ] Nesting depth limits
- [ ] "All bytes consumed" assertion at end
- [ ] Valid error returns for malformed input

---

## Task Creation Guidelines

### Priority Levels

| Priority | Meaning | Examples |
|----------|---------|----------|
| 1 | Critical/Consensus | Cost model, VersionContext, point validation |
| 2 | High/Safety | Timeout, iteration limit, assertion density |
| 3 | Medium/Quality | comptime validation, test coverage |
| 4 | Low/Polish | Documentation, benchmarks |

### Labels

```bash
--label critical     # Consensus-breaking if wrong
--label safety       # Defense in depth
--label conformance  # Match reference implementation
--label performance  # Optimization
--label testing      # Test coverage
```

### Task Template

```bash
bd create "[component]: [specific issue]" -t [bug|task|feature] -p [1-4] --label [label]
```

**Examples:**
```bash
bd create "evaluator: Cost calculation is static, should be size-dependent" -t bug -p 1 --label critical
bd create "secp256k1: Add isInfinity check to point validation" -t bug -p 1 --label critical
bd create "arithmetic: Add MIN/-1 overflow case to evalDiv" -t bug -p 1 --label conformance
bd create "verifier: Use constant-time comparison for challenge" -t task -p 1 --label critical
bd create "memory: Add hasCapacity() for pre-validation" -t task -p 2 --label safety
bd create "types: Add comptime uniqueness validation" -t task -p 3 --label quality
```

---

## Session Output

After audit, provide:

```markdown
## Audit Summary

### Tests
- Passing: X
- Failing: Y
- Coverage gaps: [list]

### Critical Issues Found
1. [issue] in [file] - [why critical]
2. ...

### Tasks Created
- Priority 1 (Critical): X tasks
- Priority 2 (High): Y tasks  
- Priority 3+ (Medium/Low): Z tasks

### Immediate Focus
Task: [bd task ID]
File: [specific file]
Issue: [what's wrong]
Fix: [approach]
```

---

## Reference Commands

### Comparing with Reference

```bash
# Clone if missing
git clone https://github.com/ergoplatform/sigmastate-interpreter.git ~/ergotree-research/scala/sigmastate
git clone https://github.com/ergoplatform/sigma-rust.git ~/ergotree-research/rust/sigma-rust

# Find cost calculation in Scala
grep -rn "JitCost\|costOf" ~/ergotree-research/scala/sigmastate --include="*.scala" | head -20

# Find version handling
grep -rn "VersionContext\|isJitActivated" ~/ergotree-research/scala/sigmastate --include="*.scala" | head -20

# Find point validation in Rust
grep -rn "is_on_curve\|validate" ~/ergotree-research/rust/sigma-rust --include="*.rs" | head -20
```

### Task Management

```bash
bd ready --json           # Unblocked tasks
bd list --all             # All tasks
bd update <id> --status in_progress
bd close <id> --reason "Fixed in commit abc123"
```

### Testing

```bash
zig build test                              # All tests
zig build test -- --test-filter "evaluator" # Specific
zig build test 2>&1 | grep -E "PASS|FAIL"   # Summary
```

---

## Constraints

- **Do NOT refactor working code without a specific issue**
- **Do NOT change public APIs without updating tests**
- **Do NOT skip critical issues to work on lower priority**
- **Do commit `.beads/issues.jsonl` with related code changes**

---

## Success Criteria

Session complete when:
- [ ] All files audited against requirements
- [ ] Critical issues identified and tasked
- [ ] At least one critical issue fixed
- [ ] Tests pass after changes
- [ ] `.beads/issues.jsonl` updated
