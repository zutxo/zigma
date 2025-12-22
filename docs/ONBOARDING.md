# Zigma Onboarding Guide

A comprehensive guide for new contributors to the Zigma ErgoTree interpreter project.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Key Modules](#key-modules)
5. [Development Workflow](#development-workflow)
6. [Common Tasks](#common-tasks)
7. [Testing Strategy](#testing-strategy)
8. [Debugging](#debugging)
9. [Performance](#performance)
10. [Gotchas and Pitfalls](#gotchas-and-pitfalls)

---

## Project Overview

**Zigma** is a high-performance ErgoTree bytecode interpreter written in Zig, following TigerBeetle-style data-oriented design principles.

### What is ErgoTree?

ErgoTree is the bytecode format for Ergo blockchain smart contracts. It's a stack-based bytecode that:
- Validates UTXO spending conditions
- Supports sigma protocols (zero-knowledge proofs)
- Has deterministic cost accounting
- Must produce identical results across all nodes

### Design Goals (in priority order)

1. **Safety** - Cryptographic correctness, no undefined behavior
2. **Determinism** - Bit-identical results across platforms
3. **Performance** - Sub-millisecond transaction validation
4. **Developer Experience** - Clear code, good documentation

### Project Status

- **Lines of code:** ~33,000
- **Test coverage:** All modules have inline tests
- **Opcodes implemented:** ~62/92 (67%)
- **Issues:** 11 open, 165 closed

---

## Quick Start

### Prerequisites

```bash
# Zig is bundled - no system install needed
# Just run the download script if zig/zig doesn't exist
./zig/download.sh
```

### Essential Commands

```bash
# Build & Test (ALWAYS use ./zig/zig, not system zig)
./zig/zig build                        # Debug build
./zig/zig build test                   # Run ALL tests (required before commit)
./zig/zig fmt src/                     # Format code (required before commit)

# Run specific tests
./zig/zig build test -- --test-filter "vlq"
./zig/zig build test -- --test-filter "evaluator"

# CLI
./zig/zig build
./zig-out/bin/zigma version
./zig-out/bin/zigma eval <hex> --height=500000
./zig-out/bin/zigma hash blake2b256 <hex>

# Benchmarks (use ReleaseFast for accurate numbers)
./zig/zig build bench -Doptimize=ReleaseFast

# Deterministic Simulation Testing
./zig/zig build dst
./zig-out/bin/zigma-dst --seed=12345 --ticks=10000

# Task tracking
bd ready                               # Show available work
bd show <id>                           # Issue details
bd update <id> --status=in_progress    # Claim work
bd close <id>                          # Complete work
```

---

## Architecture

### Directory Structure

```
zigma/
├── src/
│   ├── root.zig              # Library exports
│   ├── main.zig              # CLI entry point
│   ├── core/
│   │   ├── types.zig         # SType system (TypePool, 92 type codes)
│   │   └── opcodes.zig       # Opcode catalog with metadata
│   ├── serialization/        # Byte stream parsing
│   │   ├── vlq.zig           # Variable-length quantity encoding
│   │   ├── type_serializer.zig
│   │   ├── data_serializer.zig
│   │   ├── expr_serializer.zig   # Expression tree deserialization
│   │   └── ergotree_serializer.zig # Full ErgoTree parsing
│   ├── interpreter/          # Core evaluation engine
│   │   ├── evaluator.zig     # Main loop (11k lines, the heart)
│   │   ├── context.zig       # Blockchain context (boxes, headers)
│   │   ├── memory.zig        # Pre-allocated pools
│   │   ├── value_pool.zig    # Value storage
│   │   └── ops/              # Operation implementations
│   ├── crypto/               # Cryptographic primitives
│   │   ├── secp256k1.zig     # Elliptic curve (870 lines)
│   │   ├── bigint.zig        # 256-bit integers (2000 lines)
│   │   ├── avl_tree.zig      # AVL+ tree verification (3700 lines)
│   │   └── hash.zig          # Blake2b256, SHA256
│   ├── sigma/                # Zero-knowledge proofs
│   │   ├── sigma_tree.zig    # SigmaBoolean representation
│   │   ├── verifier.zig      # Proof verification (1000 lines)
│   │   ├── schnorr.zig       # ProveDlog verification
│   │   └── challenge.zig     # Fiat-Shamir transform
│   └── dst/                  # Deterministic Simulation Testing
│       ├── dst.zig           # Main simulator
│       ├── generators/       # Random expression generation
│       └── checkers/         # Property checkers
├── tests/
│   ├── conformance/          # Reference implementation tests
│   └── vectors/              # JSON test vectors
├── benchmarks/               # Performance benchmarks
└── docs/                     # Documentation
```

### Data Flow

```
ErgoTree bytes
    ↓
ergotree_serializer.deserialize()
    ↓
ExprTree (pre-order node array)
    ↓
Evaluator.evaluate()
    ├── Work stack (iterative, not recursive)
    ├── Value stack (intermediate results)
    └── Cost tracking
    ↓
Value (result) or EvalError
```

### Key Design Decisions

1. **No recursion in interpreter** - Explicit work stack prevents stack overflow
2. **Static allocation only** - All pools pre-allocated at init, no malloc during eval
3. **Version-aware cost model** - JIT (v2+) vs AOT (v0/v1) costs differ
4. **Pre-order expression layout** - Enables single-pass evaluation

---

## Key Modules

### evaluator.zig (11,130 lines)

The heart of the interpreter. Key structures:

```zig
pub const Evaluator = struct {
    tree: *const ExprTree,      // Expression tree
    ctx: *const Context,        // Blockchain context
    version_ctx: VersionContext, // Protocol version
    work_stack: [256]WorkItem,  // Pending evaluation
    value_stack: [256]Value,    // Results
    cost_used: u64,             // Gas consumed
    cost_limit: u64,            // Gas limit
};
```

The main loop:
```zig
pub fn evaluate(self: *Evaluator) EvalError!Value {
    while (self.work_sp > 0) {
        const work = self.pop_work();
        switch (work.phase) {
            .evaluate => // Push children onto work stack
            .compute => // Compute result from child values
        }
    }
    return self.pop_value();
}
```

### types.zig (939 lines)

The type system with 92+ type codes:
- Primitives: Unit, Boolean, Byte, Short, Int, Long, BigInt
- Complex: GroupElement, SigmaProp, Box, Header, AvlTree
- Collections: Coll[T], Option[T], Tuple2[A,B], etc.

```zig
pub const TypePool = struct {
    pub const UNIT: TypeIndex = 0;
    pub const BOOLEAN: TypeIndex = 1;
    pub const BYTE: TypeIndex = 2;
    // ... 89 more type codes
};
```

### secp256k1.zig (868 lines)

Pure Zig implementation of secp256k1:
- Field element arithmetic (mod p)
- Point addition and multiplication
- SEC1 compressed encoding
- Full curve validation

### avl_tree.zig (3,671 lines)

AVL+ tree proof verification:
- Lookup with Merkle proof
- Insert/Update/Remove verification
- Batch operations

### verifier.zig (1,052 lines)

Sigma protocol verification:
- ProveDlog (Schnorr signatures)
- ProveDHTuple (DH tuple proofs)
- AND/OR/THRESHOLD connectives
- Fiat-Shamir challenge computation

---

## Development Workflow

### Before Starting Work

1. Check for available work:
   ```bash
   bd ready
   ```

2. Read the issue details:
   ```bash
   bd show <id>
   ```

3. Claim the work:
   ```bash
   bd update <id> --status=in_progress
   ```

### Implementation Loop

1. **Write test first** - Add test vector or unit test
2. **Implement** - Follow ZIGMA_STYLE.md, min 3 assertions per function
3. **Verify determinism** - Same input → same output
4. **Run tests**: `./zig/zig build test`
5. **Format**: `./zig/zig fmt src/`
6. **Commit** - Include `.beads/issues.jsonl` if task-related
7. **Close task**: `bd close <id>`

### For New Opcodes

1. Find in Scala: `grep -rn "OpCodeName" ~/ergotree-research/scala/sigmastate --include="*.scala"`
2. Find in Rust: `grep -rn "OpCodeName" ~/ergotree-research/rust/sigma-rust --include="*.rs"`
3. Add to `ExprTag` enum in expr_serializer.zig
4. Add deserialization case
5. Add evaluation case in evaluator.zig
6. Add cost in the cost tables
7. Write conformance test

---

## Common Tasks

### Adding a New Opcode

1. **expr_serializer.zig**: Add to `ExprTag` enum
2. **expr_serializer.zig**: Add deserialize case in `deserializeExpr`
3. **evaluator.zig**: Add evaluate case in `evaluateNode`
4. **evaluator.zig**: Add compute case in `computeNode`
5. Add to cost tables (JIT_COSTS, AOT_COSTS)

### Adding a Test Vector

Test vectors live in `tests/vectors/`. Format:

```json
{
  "name": "descriptive name",
  "ergotree": "hex-encoded bytes",
  "height": 500000,
  "expected": {
    "type": "Boolean",
    "value": true
  },
  "cost": 123
}
```

### Debugging a Deserialization Issue

1. Use the CLI: `./zig-out/bin/zigma deserialize <hex>`
2. Add `std.debug.print` in expr_serializer.zig
3. Check byte alignment (common issue with method calls)

---

## Testing Strategy

### Test Categories

| Type | Location | Purpose |
|------|----------|---------|
| Unit | Inline in `src/*.zig` | Function-level correctness |
| Conformance | `tests/conformance/` | Match Scala/Rust exactly |
| Property | `tests/property/` | Invariants hold for random inputs |
| DST | `src/dst/` | Find crashes via simulation |
| Mainnet | `tests/conformance/mainnet.zig` | Real-world ErgoTree scripts |

### Running Tests

```bash
# All tests (required before commit)
./zig/zig build test

# Specific module
./zig/zig build test -- --test-filter "vlq"
./zig/zig build test -- --test-filter "secp256k1"

# Conformance only
./zig/zig build conformance

# DST (finds bugs via random testing)
./zig/zig build dst
./zig-out/bin/zigma-dst --seed=$(git rev-parse HEAD) --ticks=100000
```

### DST (Deterministic Simulation Testing)

DST generates random expressions and evaluates them, checking:
- **Determinism**: Same seed → same results
- **Type safety**: Well-typed expressions
- **Cost monotonicity**: Cost only increases
- **Crash freedom**: No panics

```bash
# Run with specific seed (reproducible)
./zig-out/bin/zigma-dst --seed=12345 --ticks=10000

# Run with git hash as seed (CI mode)
./zig-out/bin/zigma-dst --seed=$(git rev-parse HEAD)
```

---

## Debugging

### Common Errors

| Error | Likely Cause |
|-------|--------------|
| `InvalidTypeCode` | Byte stream misalignment |
| `InvalidConstantIndex` | Constant pool index OOB |
| `CostLimitExceeded` | Complex script or cost bug |
| `TypeMismatch` | Wrong operand types |
| `ArithmeticOverflow` | Integer overflow |

### Debugging Tips

1. **Add print statements** (temporary):
   ```zig
   std.debug.print("tag={}, pos={}\n", .{ tag, reader.pos });
   ```

2. **Use the CLI**:
   ```bash
   ./zig-out/bin/zigma eval <hex> --height=500000
   ./zig-out/bin/zigma deserialize <hex>
   ```

3. **Check Scala reference**:
   ```bash
   grep -rn "case OpCode" ~/ergotree-research/scala/sigmastate --include="*.scala" -A 5
   ```

4. **Run DST with specific seed** to reproduce:
   ```bash
   ./zig-out/bin/zigma-dst --seed=<failing_seed>
   ```

### Known Issues (as of writing)

1. **zigma-32oh**: `divInts(MIN_INT, -1)` causes overflow
2. **zigma-pp80**: 13 scenarios have deserialization alignment issues

---

## Performance

### Benchmark Results (ReleaseFast)

```
blake2b256 (64 bytes)    149 ns/op    6.7M ops/sec
sha256 (64 bytes)         99 ns/op   10.0M ops/sec
BigInt256.add             16 ns/op   62.2M ops/sec
BigInt256.mul             22 ns/op   44.4M ops/sec
Point.decode           8,094 ns/op  123.5K ops/sec
Point.mul          2,168,380 ns/op      461 ops/sec
```

### Hot Paths

1. **Evaluator main loop** (evaluator.zig:800-850)
2. **Binary operations** (evaluator.zig:2800-3200)
3. **Collection operations** (ops/collection.zig)
4. **Point multiplication** (secp256k1.zig) - most expensive

### Optimization Guidelines

- No dynamic allocation in hot paths
- Use pre-allocated pools
- Avoid HashMap iteration (non-deterministic order)
- Batch operations where possible

---

## Gotchas and Pitfalls

### NEVER Do

1. **Never use `usize`** except for slice indexing - use `u32`, `u16`, etc.
2. **Never use recursion** in interpreter - use explicit work stacks
3. **Never ignore errors** - handle explicitly or `assert(false)`
4. **Never use floating point** - determinism requires integer-only
5. **Never use HashMap iteration** for serialization - order varies
6. **Never add dynamic allocation** during evaluation

### ALWAYS Do

1. **Always use `./zig/zig`** not system zig
2. **Always run `./zig/zig fmt src/`** before commit
3. **Always run `./zig/zig build test`** before commit
4. **Always validate points** on curve AND in subgroup
5. **Always check overflow** with `@addWithOverflow`, etc.
6. **Always have 3+ assertions** per new function

### Common Mistakes

1. **Forgetting to handle MIN_INT/-1 overflow** in division
2. **Off-by-one in collection slicing**
3. **Type code vs opcode confusion** (type codes are 1-111, opcodes 112+)
4. **Forgetting cost accounting** for new operations
5. **Not reading existing code patterns** before implementing

---

## Reference Resources

### In Codebase

- `CLAUDE.md` - Essential rules and commands
- `docs/ZIGMA_STYLE.md` - Coding style guide (must read!)
- `docs/guides/phase_*.md` - Development phases
- `docs/design/DST_*.md` - DST design documents

### External

- [sigmastate-interpreter](https://github.com/ergoplatform/sigmastate-interpreter) - Scala reference
- [sigma-rust](https://github.com/ergoplatform/sigma-rust) - Rust reference
- [Ergo Discord #development](https://discord.gg/ergo-platform) - Protocol questions

### Key Reference Files

| What | Scala | Rust |
|------|-------|------|
| Types | `core/.../sigma/ast/SType.scala` | `ergotree-ir/src/types/` |
| Serialization | `core/.../serialization/*.scala` | `ergotree-ir/src/serialization/` |
| Operations | `core/.../sigma/ast/operations.scala` | `ergotree-ir/src/mir/` |
| Costs | `interpreter/.../JitCost.scala` | `ergotree-interpreter/src/eval/costs.rs` |

---

## Current Work Priorities

### Ready Issues (no blockers)

1. **[P1] zigma-pp80**: Fix InvalidTypeCode deserialization bugs
2. **[P2] zigma-zqk7**: Implement slice operation for collections
3. **[P2] zigma-2u0z**: Implement append/concat for collections
4. **[P2] zigma-deyt**: Implement proveDlog sigma proposition
5. **[P2] zigma-wapu**: Implement getVar for context extension
6. **[P2] zigma-gb5t**: Implement sigmaPropBytes

### Blocked Issues

- Phase 3-5 conformance tests blocked on Phase 2 completion

---

## Contributing Checklist

Before submitting:

- [ ] `./zig/zig fmt src/` run
- [ ] `./zig/zig build test` passes
- [ ] No dynamic allocation in hot paths
- [ ] Assertions present (min 3 per function)
- [ ] Error handling explicit
- [ ] Cost accounting for new operations
- [ ] `.beads/issues.jsonl` included if task-related
- [ ] Commit message concise (sacrifice grammar for brevity)
- [ ] No Claude co-author credits in commit

---

*Last updated: 2025-12-22*
