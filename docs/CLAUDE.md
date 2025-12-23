# CLAUDE.md

Zig-based ErgoTree Interpreter following TigerBeetle-style data-oriented design.

## Critical Rules

- **ALWAYS** read `ZUTXO_STYLE.md` before writing code
- **ALWAYS** use `bd` (beads) for task tracking, **NEVER** markdown TODOs
- **ALWAYS** run `zig fmt src/` before committing
- **ALWAYS** run `zig build test` before committing (all tests must pass)
- **ALWAYS** commit `.beads/issues.jsonl` with related code changes
- **NEVER** use dynamic allocation during evaluation (pre-allocate everything)
- **NEVER** use recursion in the interpreter (use explicit work stacks)
- **NEVER** use `usize` except where Zig requires it for slice indexing
- **NEVER** ignore errors—handle explicitly or assert unreachable with justification
- **NEVER** add Claude co-author credits or generated-with footers to commits
- Keep commits atomic and messages concise (sacrifice grammar for brevity)

## Commands

```bash
# Build & Test
zig build                            # Debug build
zig build -Doptimize=ReleaseFast     # Release build
zig build test                       # Run all tests
zig build test -- --test-filter "vlq" # Run specific tests

# Development
zig fmt src/                         # Format code (ALWAYS before commit)
zig build docs                       # Generate documentation

# Benchmarks
zig build bench                      # Run benchmarks
zig build bench -Doptimize=ReleaseFast  # Release benchmarks

# Cross-compilation
zig build -Dtarget=x86_64-linux-gnu
zig build -Dtarget=aarch64-linux-gnu
zig build -Dtarget=wasm32-freestanding

# Task Tracking
bd ready --json                      # Check available work
bd create "Title" -t task -p 2       # Create issue (types: bug|feature|task|epic|chore)
bd update <id> --status in_progress  # Claim task
bd close <id> --reason "Done"        # Complete task
```

## Project Structure

```
zigma/
├── src/
│   ├── root.zig              # Main module, public exports
│   ├── main.zig              # CLI entry point
│   ├── core/
│   │   ├── types.zig         # SType system (TypePool, type codes)
│   │   └── opcodes.zig       # Opcode catalog with metadata
│   ├── serialization/
│   │   ├── vlq.zig           # VLQ/ZigZag encoding
│   │   ├── type_serializer.zig
│   │   ├── data_serializer.zig
│   │   ├── expr_serializer.zig
│   │   └── ergotree_serializer.zig
│   ├── interpreter/
│   │   ├── memory.zig        # Pre-allocated pools (ExpressionPool, etc.)
│   │   ├── context.zig       # Execution context (boxes, headers)
│   │   ├── values.zig        # Value representation
│   │   ├── evaluator.zig     # Main evaluation loop
│   │   ├── cost.zig          # Cost accounting
│   │   └── ops/              # Operation implementations
│   │       ├── arithmetic.zig
│   │       ├── comparison.zig
│   │       ├── logical.zig
│   │       ├── collection.zig
│   │       └── crypto.zig
│   ├── crypto/
│   │   ├── bigint.zig        # 256-bit integer arithmetic
│   │   ├── secp256k1.zig     # Elliptic curve operations
│   │   └── hash.zig          # Blake2b256, SHA256
│   └── sigma/
│       ├── sigma_tree.zig    # SigmaBoolean tree
│       ├── prover.zig        # Proof generation
│       └── verifier.zig      # Proof verification
├── tests/
│   ├── conformance/          # Tests against Scala/Rust vectors
│   └── vectors/              # Test vector JSON files
├── benchmarks/
│   └── main.zig              # Benchmark harness
├── docs/
│   ├── ZUTXO_STYLE.md        # Coding style guide
│   └── PREDEV_PLAN.md        # Implementation roadmap
├── history/                  # AI planning docs, session logs
├── .beads/                   # Task tracking (commit with code changes)
│   └── issues.jsonl
├── build.zig                 # Build configuration
└── build.zig.zon             # Dependencies
```

## Development Workflow

### Before Starting Work

1. Check `bd ready --json` for unblocked work
2. Claim task: `bd update <id> --status in_progress`
3. Read relevant section of `PREDEV_PLAN.md` for context
4. Review `ZUTXO_STYLE.md` for the specific area (crypto, serialization, etc.)

### Implementation Loop

1. **Write tests first** (conformance test if vector exists, unit test otherwise)
2. **Implement** with assertions (minimum 3 per function)
3. **Verify determinism**: same input → same output
4. **Run full test suite**: `zig build test`
5. **Format**: `zig fmt src/`
6. **Discovered related work?** `bd create "Issue" --deps discovered-from:<parent-id>`
7. **Commit** code + `.beads/issues.jsonl` together
8. **Close task**: `bd close <id> --reason "Done"`

### For New Opcodes

```bash
# 1. Find Scala implementation
grep -rn "OpCodeName\|opCode.*0xNN" ~/ergotree-research/scala/sigmastate --include="*.scala" -A 20

# 2. Find Rust implementation  
grep -rn "OpCodeName" ~/ergotree-research/rust/sigma-rust --include="*.rs" -A 20

# 3. Add test vector (if exists)
# 4. Implement in src/interpreter/ops/<category>.zig
# 5. Add to dispatch table in evaluator.zig
# 6. Update cost table in cost.zig
# 7. Run conformance tests
```

## Testing

```bash
# Run all tests
zig build test

# Run specific test file
zig build test -- --test-filter "vlq"
zig build test -- --test-filter "type_serializer"

# Run with verbose output
zig build test 2>&1 | head -100

# Conformance tests against reference implementations
zig build test -- --test-filter "conformance"
```

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `src/*.zig` (inline) | Function-level correctness |
| Conformance | `tests/conformance/` | Match Scala/Rust output exactly |
| Property | `tests/property/` | Invariants hold for random inputs |
| Fuzz | `tests/fuzz/` | Find crashes and hangs |

### Test Naming Convention

```zig
test "module: specific behavior being tested" { }
test "vlq: roundtrip preserves value for u64 max" { }
test "eval_add: overflow returns error not wraparound" { }
test "group_element: rejects point not on curve" { }
```

## Reference Implementations

```bash
# Scala (canonical) - check for edge cases
~/ergotree-research/scala/sigmastate/

# Rust (cleaner) - better for understanding data structures  
~/ergotree-research/rust/sigma-rust/

# Useful grep patterns
grep -rn "def serialize" --include="*.scala" -A 10
grep -rn "impl.*Serialize" --include="*.rs" -A 10
grep -rn "costOf\|JitCost" --include="*.scala"
```

## Key Files to Reference

| What | Scala | Rust |
|------|-------|------|
| Type system | `core/.../sigma/ast/SType.scala` | `ergotree-ir/src/types/` |
| Serialization | `core/.../serialization/*.scala` | `ergotree-ir/src/serialization/` |
| Operations | `core/.../sigma/ast/operations.scala` | `ergotree-ir/src/mir/` |
| Cost model | `interpreter/.../JitCost.scala` | `ergotree-interpreter/src/eval/costs.rs` |
| Interpreter | `interpreter/.../CErgoTreeEvaluator.scala` | `ergotree-interpreter/src/eval/` |

## Safety Checklist

### Before Every Commit

- [ ] `zig fmt src/` run
- [ ] `zig build test` passes (all tests)
- [ ] `.beads/issues.jsonl` included if task-related
- [ ] No dynamic allocation in hot paths
- [ ] Assertions present (min 3 per new function)
- [ ] Error handling explicit (no ignored errors)

### For Cryptographic Code

- [ ] Points validated on curve AND in subgroup
- [ ] Constant-time for secret-dependent operations
- [ ] Known-answer tests from reference implementation
- [ ] Invalid input tests (malformed, off-curve, infinity)

### For Serialization

- [ ] Roundtrip test: `deserialize(serialize(x)) == x`
- [ ] Golden test against known-good vector
- [ ] Malformed input handling
- [ ] "All bytes consumed" assertion

## Protocol Versions

| Version | Ergo Release | Key Features |
|---------|--------------|--------------|
| v0 | Pre-4.0 | Original (legacy) |
| v1 | 4.0 | Hard fork, AOT interpreter |
| v2 | 5.0 | Soft fork, JIT interpreter |
| v3 | 6.0 | EIP-50, new opcodes |

**Target**: Implement v2 first (current mainnet), then add v3 support.

## Common Issues

### "Recursion depth exceeded"
The interpreter uses explicit work stacks, not recursion. If you see stack overflow, you're doing it wrong.

### "Determinism failure"
Check for: HashMap iteration, uninitialized memory, system time usage, floating point.

### "Cost mismatch with reference"
Costs are version-dependent. Check `VersionContext` in Scala to see which cost table applies.

### "Point validation failed"
Every GroupElement from untrusted input MUST be validated. This is non-negotiable.

## Notes

- Store AI planning docs in `history/` directory
- The ErgoTree PDF spec (2020) is outdated—use code as source of truth for v2+
- Join Ergo Discord #development for protocol clarifications
- See `docs/ZUTXO_STYLE.md` for detailed coding guidelines
