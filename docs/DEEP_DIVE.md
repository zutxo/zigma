# Zigma Deep Dive: Architecture, Gap Analysis, and Expert Recommendations

A comprehensive analysis of the Zigma ErgoTree interpreter from the perspective of Scala/Rust implementers and TigerBeetle engineers.

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Reference Implementation Analysis](#reference-implementation-analysis)
3. [Gap Analysis: Zigma vs Reference](#gap-analysis)
4. [Transaction Validation Pipeline](#transaction-validation-pipeline)
5. [Prover/Signing Architecture](#prover-signing-architecture)
6. [TigerBeetle Engineering Lessons](#tigerbeetle-engineering-lessons)
7. [Critical Missing Features](#critical-missing-features)
8. [Performance Considerations](#performance-considerations)
9. [Security Audit Checklist](#security-audit-checklist)
10. [Recommended Development Roadmap](#recommended-roadmap)

---

## Executive Summary

### Current State

Zigma is a Zig-based ErgoTree interpreter at ~33k lines, implementing:
- **Deserialization**: ~85% complete (most opcodes parseable)
- **Evaluation**: ~67% complete (62/92 opcodes)
- **Verification**: Partial (ProveDlog, ProveDHTuple, AND/OR/THRESHOLD)
- **Proving/Signing**: **NOT IMPLEMENTED** (critical gap)
- **Transaction Validation**: **NOT IMPLEMENTED** (requires prover)

### What's Required for Full Transaction Validation

1. **Script Reduction** - Evaluate ErgoTree → SigmaBoolean (implemented)
2. **Proof Verification** - Verify signature against SigmaBoolean (partially implemented)
3. **Proof Generation** - Generate proofs for spending (NOT IMPLEMENTED)
4. **Context Construction** - Build execution context from blockchain state (partial)

### Critical Gaps

| Feature | Scala | Rust | Zigma | Priority |
|---------|-------|------|-------|----------|
| Full opcode coverage | 100% | 100% | 67% | P1 |
| Proof verification | Yes | Yes | Partial | P1 |
| Proof generation/signing | Yes | Yes | **No** | P0 |
| Transaction context | Yes | Yes | Partial | P1 |
| AVL tree mutations | Yes | Yes | Verify only | P2 |
| DeserializeContext | Yes | Yes | Parse only | P2 |
| Cost model accuracy | JIT | JIT | Approximate | P2 |

---

## Reference Implementation Analysis

### Scala sigmastate-interpreter (~100k lines)

**Key Architecture:**
```
sigmastate-interpreter/
├── core/           # Types, serialization primitives
├── data/           # Data structures (SType, Values)
├── interpreter/    # Main evaluation + proving
│   ├── CErgoTreeEvaluator.scala   # JIT evaluator (key file)
│   ├── Interpreter.scala          # Verification interface
│   ├── ProverInterpreter.scala    # Proving interface
│   └── CostAccumulator.scala      # Cost tracking
├── parsers/        # ErgoScript → AST
└── sc/             # Compiler phases
```

**Evaluation Strategy (Scala):**
- Big-step recursive interpreter
- Immutable data structures
- DataEnv maps ValDef IDs to computed values
- Lazy evaluation for short-circuiting

**Prover Algorithm (9 steps from ErgoScript whitepaper):**
1. Mark real/simulated nodes based on available secrets
2. Reject if root is simulated (not enough witnesses)
3. Polish simulated (ensure proper child counts)
4. Find challenges for simulated nodes
5. Simulate simulated leaves
6. Compute commitments for real leaves
7. Serialize tree for Fiat-Shamir (Strong FS transform)
8. Compute root challenge as hash of (tree_bytes || message)
9. Compute challenges and responses for real nodes

### Rust sigma-rust (~90k lines, 553 files)

**Key Architecture:**
```
sigma-rust/
├── ergotree-ir/              # IR types, serialization
│   ├── src/mir/              # Mid-level IR (80+ operation types)
│   └── src/serialization/    # OpCode enum, parsers
├── ergotree-interpreter/     # Evaluation + protocols
│   ├── src/eval/             # 80+ evaluation modules
│   ├── src/sigma_protocol/   # Prover/verifier
│   │   ├── prover.rs         # Proof generation
│   │   ├── verifier.rs       # Proof verification
│   │   ├── fiat_shamir.rs    # Challenge computation
│   │   └── sig_serializer.rs # Proof (de)serialization
│   └── src/json/             # JSON serialization
├── ergo-lib/                 # High-level wallet API
│   └── src/chain/transaction.rs  # Transaction handling
└── gf2_192/                  # GF(2^192) polynomial arithmetic
```

**Key Insight: Rust modular eval design**
Each operation is a separate module in `ergotree-interpreter/src/eval/`:
- `calc_blake2b256.rs`, `calc_sha256.rs` - Hash ops
- `coll_map.rs`, `coll_filter.rs`, `coll_fold.rs` - Collection HOFs
- `create_provedlog.rs`, `create_prove_dh_tuple.rs` - Sigma props
- `tree_lookup.rs`, `savltree.rs` - AVL tree ops

This is **cleaner than Zigma's monolithic evaluator.zig** (11k lines).

---

## Gap Analysis

### Opcode Implementation Status

| Category | Opcodes | Zigma Status | Notes |
|----------|---------|--------------|-------|
| Constants | TrueLeaf, FalseLeaf, Unit, GroupGen | ✓ Complete | |
| Arithmetic | +, -, *, /, %, Min, Max, Neg | ✓ Complete | MIN_INT/-1 fixed |
| Comparison | <, <=, >, >=, ==, != | ✓ Complete | |
| Logical | And, Or, BinAnd, BinOr, Not, Xor | ✓ Complete | |
| Bitwise | BitOr, BitAnd, BitXor, Shifts | ✓ Complete | |
| Context | HEIGHT, INPUTS, OUTPUTS, SELF | ✓ Complete | |
| Box | ExtractAmount, Id, Bytes, RegAs | ✓ Complete | |
| Hash | Blake2b256, SHA256 | ✓ Complete | |
| Crypto | DecodePoint, Exponentiate, MultiplyGroup | ✓ Complete | |
| Collection | Map, Filter, Fold, Exists, ForAll | ✓ Complete | |
| **Collection** | **Slice, Append, ByIndex** | **Partial** | Slice/Append missing |
| **Option** | **Get, GetOrElse, IsDefined** | ✓ Complete | |
| **Tuple** | **SelectField, Construct** | ✓ Complete | |
| **Sigma** | **ProveDlog, ProveDHTuple** | **Eval only** | Verify partial |
| **Sigma** | **SigmaAnd, SigmaOr, AtLeast** | **Parse only** | Verify incomplete |
| **Context** | **GetVar, DeserializeContext** | **Stub** | Needs full impl |
| **AVL** | **Lookup, Insert, Update, Remove** | **Lookup only** | Mutations incomplete |
| **Block** | **ValDef, ValUse, BlockValue, Apply** | ✓ Complete | |
| **Convert** | **Upcast, Downcast, LongToBytes** | ✓ Complete | |
| **SubstConstants** | **SubstConstants** | **Stub** | Complex, low priority |

### Missing Critical Features

#### 1. Proof Generation (Prover)

**What Scala does:**
```scala
trait ProverInterpreter extends Interpreter with ProverUtils {
  def secrets: Seq[SigmaProtocolPrivateInput[_]]

  def prove(ergoTree: ErgoTree, context: CTX, message: Array[Byte]): Try[CostedProverResult] = Try {
    val reduced = fullReduction(ergoTree, context, env)  // Already in Zigma
    val fullCost = addCryptoCost(reduced.value, reduced.cost, context.costLimit)
    val proof = generateProof(resValue, message, hintsBag)  // NOT IN ZIGMA
    CostedProverResult(proof, context.extension, resCost)
  }
}
```

**What Zigma needs:**
```zig
// src/sigma/prover.zig (NEW FILE)
pub const Prover = struct {
    secrets: []const PrivateInput,

    pub fn prove(
        self: *Prover,
        sigma_tree: SigmaBoolean,
        message: []const u8,
    ) ProverError!ProofBytes {
        // 1. Convert to UnprovenTree with markReal
        // 2. Polish simulated nodes
        // 3. Simulate simulated leaves + compute real commitments
        // 4. Fiat-Shamir hash for root challenge
        // 5. Compute responses for real nodes
        // 6. Convert to UncheckedTree and serialize
    }
};
```

#### 2. Full Proof Verification

**Current Zigma verifier** (src/sigma/verifier.zig):
- Parses proof bytes
- Computes challenges
- Verifies commitments for ProveDlog and ProveDHTuple
- Handles AND/OR connectives

**Missing:**
- THRESHOLD verification with polynomial interpolation
- getMany/containsMultiple for batch AVL proofs
- Full cost accounting during verification

#### 3. Transaction Context Construction

**Rust approach:**
```rust
pub struct Context<'ctx> {
    pub height: u32,
    pub self_box: &'ctx ErgoBox,
    pub inputs: TxIoVec<&'ctx ErgoBox>,
    pub outputs: TxIoVec<ErgoBoxCandidate>,
    pub data_inputs: Option<TxIoVec<&'ctx ErgoBox>>,
    pub extension: ContextExtension,
    pub pre_header: PreHeader,
    pub headers: Vec<Header>,  // Last 10 headers
}
```

**Zigma has partial Context** but needs:
- Full Header population (last 10 blocks)
- PreHeader with votes, timestamp
- ContextExtension for GetVar
- DataInputs array

---

## Transaction Validation Pipeline

### Complete Flow (from Rust)

```
UnsignedTransaction
    │
    ├── For each input box:
    │   │
    │   ├── 1. Build Context (height, boxes, headers, extension)
    │   │
    │   ├── 2. Deserialize ErgoTree from input box
    │   │
    │   ├── 3. Reduce ErgoTree → SigmaBoolean (Zigma: ✓)
    │   │   └── Includes cost accounting
    │   │
    │   ├── 4. If TrivialProp(true): accept immediately
    │   │   If TrivialProp(false): reject immediately
    │   │
    │   └── 5. Verify proof against SigmaBoolean (Zigma: partial)
    │       ├── Parse proof bytes
    │       ├── Compute challenges (Fiat-Shamir)
    │       ├── Verify commitments at leaves
    │       └── Check root challenge matches
    │
    ├── Verify box conservation (values, tokens)
    │
    └── Return (success, total_cost)
```

### Zigma Implementation Status

| Step | Status | Notes |
|------|--------|-------|
| Context construction | Partial | Missing headers, extension |
| ErgoTree deserialization | ✓ | ~85% opcodes |
| Reduction to SigmaBoolean | ✓ | evaluator.zig |
| TrivialProp handling | ✓ | |
| Proof verification | Partial | Missing THRESHOLD |
| **Proof generation** | **Missing** | Needed for signing |
| Box conservation | **Missing** | Token/value checks |

---

## Prover/Signing Architecture

### Sigma Protocol Proving (from ErgoScript whitepaper Appendix A)

```
┌─────────────────────────────────────────────────────────────┐
│                    UnprovenTree                              │
│  (SigmaBoolean with real/simulated markers)                 │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 1: markReal(tree)                                     │
│  - Traverse tree, mark nodes "real" if prover has secret    │
│  - ProveDlog is real if we have the discrete log            │
│  - AND is real if ALL children are real                     │
│  - OR is real if AT LEAST ONE child is real                 │
│  - THRESHOLD(k, n) is real if AT LEAST k children are real  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Check root is real                                 │
│  - If root is simulated → error "not enough witnesses"      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: polishSimulated(tree)                              │
│  - For OR with n children, ensure n-1 are simulated         │
│  - For THRESHOLD(k,n), ensure n-k are simulated             │
│  - Convert excess "real" children to "simulated"            │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Steps 4-6: simulateAndCommit(tree)                         │
│  - Generate random challenges for simulated nodes           │
│  - Compute simulated responses (z = random)                 │
│  - Compute real commitments (a = g^r for random r)          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 7: Fiat-Shamir serialization                          │
│  - Serialize tree structure + commitments                   │
│  - propBytes = serialize(tree_with_commitments)             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 8: Compute root challenge                             │
│  - rootChallenge = Blake2b256(propBytes || message)         │
│  - This binds the proof to the transaction bytes            │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 9: proving(tree, rootChallenge)                       │
│  - Push challenge down to children:                         │
│    * AND: all children get same challenge                   │
│    * OR: children challenges XOR to root challenge          │
│    * THRESHOLD: polynomial interpolation for challenges     │
│  - At real leaves: compute response z = r + e*x (mod q)     │
│    where r = commitment randomness, e = challenge, x = secret│
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  convertToUnchecked(tree) → ProofBytes                      │
│  - Serialize challenges and responses                       │
│  - Omit redundant challenges (AND children, last OR child)  │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Effort Estimate

| Component | Complexity | Lines (est.) | Dependencies |
|-----------|------------|--------------|--------------|
| UnprovenTree types | Medium | ~200 | sigma_tree.zig |
| markReal | Low | ~100 | secrets storage |
| polishSimulated | Medium | ~150 | tree traversal |
| simulateAndCommit | High | ~300 | random number gen |
| Fiat-Shamir serialize | Medium | ~200 | existing code |
| Challenge distribution | High | ~250 | polynomial math |
| Response computation | Medium | ~150 | bigint mod ops |
| Proof serialization | Low | ~100 | existing SigSerializer |
| **Total** | | ~1450 | |

---

## TigerBeetle Engineering Lessons

### Patterns to Adopt

#### 1. Static Allocation Philosophy
From `TIGER_STYLE.md`:
> "All memory must be statically allocated at startup. No memory may be dynamically allocated (or freed and reallocated) after initialization."

**Zigma currently does this well**, but could be more explicit:
```zig
// GOOD (Zigma pattern)
pub const Evaluator = struct {
    work_stack: [max_work_stack]WorkItem = undefined,
    value_stack: [max_value_stack]Value = undefined,
    // ...
};

// COULD IMPROVE: Add comptime assertions
comptime {
    assert(@sizeOf(Evaluator) < 64 * 1024); // Keep on stack
}
```

#### 2. Assertion Density
From TIGER_STYLE:
> "The assertion density of the code must average a minimum of two assertions per function."

**Zigma should add more precondition/postcondition assertions:**
```zig
fn divInts(left: Value, right: Value) EvalError!Value {
    // PRECONDITIONS (add these)
    assert(left == .byte or left == .short or left == .int or left == .long);
    assert(right == .byte or right == .short or right == .int or right == .long);

    const l = try extractInt(left);
    const r = try extractInt(right);

    if (r == 0) return error.DivisionByZero;
    if (r == -1 and l == std.math.minInt(i64)) return error.ArithmeticOverflow;

    const result = @divTrunc(l, r);

    // POSTCONDITION (add this)
    assert(result >= std.math.minInt(i64) and result <= std.math.maxInt(i64));

    return switch (left) { ... };
}
```

#### 3. Function Size Limits
From TIGER_STYLE:
> "Hard limit of 70 lines per function"

**Zigma's evaluator.zig has functions over 200 lines** - should be refactored:
- `computeNode` (300+ lines) → split into `computeArithmetic`, `computeCollection`, etc.
- `evaluateMethodCall` (200+ lines) → dispatch table with small handlers

#### 4. Centralized Control Flow
From TIGER_STYLE:
> "Push ifs up and fors down"

**Example improvement:**
```zig
// BEFORE (scattered control flow)
fn evaluate(self: *Evaluator) !Value {
    while (self.work_sp > 0) {
        const work = self.popWork();
        switch (work.phase) {
            .evaluate => {
                if (node.tag == .constant) { ... }
                else if (node.tag == .bin_op) { ... }
                // ... 50 more cases
            },
            .compute => { ... }
        }
    }
}

// AFTER (dispatch table, smaller functions)
const EvalFn = fn (*Evaluator, NodeIdx) EvalError!void;
const eval_table: [std.meta.fields(ExprTag).len]EvalFn = init: {
    var table: [std.meta.fields(ExprTag).len]EvalFn = undefined;
    table[@intFromEnum(.constant)] = evalConstant;
    table[@intFromEnum(.bin_op)] = evalBinOp;
    // ...
    break :init table;
};
```

#### 5. Compile-Time Verification
From TigerBeetle's `constants.zig`:
```zig
comptime {
    assert(vsr_checkpoint_ops + lsm_compaction_ops + pipeline_prepare_queue_max * 2 <=
        journal_slot_count);
    assert(vsr_checkpoint_ops >= pipeline_prepare_queue_max);
    assert(vsr_checkpoint_ops >= lsm_compaction_ops);
    assert(vsr_checkpoint_ops % lsm_compaction_ops == 0);
}
```

**Zigma should add more:**
```zig
// In types.zig
comptime {
    // Verify type code ranges
    assert(TypePool.BYTE == 2);
    assert(TypePool.LONG == 5);
    assert(TypePool.SIGMA_PROP == 8);

    // Verify size constraints
    assert(@sizeOf(Value) <= 64);
    assert(@sizeOf(ExprNode) <= 32);
}
```

---

## Critical Missing Features

### Priority 0: Proof Generation (Required for Signing)

**Files to create:**
- `src/sigma/prover.zig` - Main prover logic
- `src/sigma/unproven_tree.zig` - Intermediate tree representation
- `src/sigma/hints.zig` - Hint bag for distributed signing

**Key types:**
```zig
pub const UnprovenTree = union(enum) {
    unproven_leaf: UnprovenLeaf,
    unproven_and: UnprovenAnd,
    unproven_or: UnprovenOr,
    unproven_threshold: UnprovenThreshold,
};

pub const UnprovenLeaf = struct {
    proposition: SigmaBoolean,
    commitment_opt: ?FirstProverMessage,
    randomness_opt: ?Scalar,
    is_simulated: bool,
    challenge_opt: ?Challenge,
};

pub const PrivateInput = union(enum) {
    dlog_secret: DlogSecret,
    dh_tuple_secret: DhTupleSecret,
};
```

### Priority 1: Full Opcode Coverage

**Missing high-impact opcodes:**
1. `Slice` (0xB4) - Collection slicing
2. `Append` (0xB3) - Collection concatenation
3. `GetVar` (0xE3) - Context extension access
4. `AtLeast` (0x98) - THRESHOLD sigma prop

### Priority 2: Transaction Context

**Required additions to Context:**
```zig
pub const Context = struct {
    height: u32,
    self_box: *const BoxView,
    inputs: []const BoxView,
    outputs: []const BoxView,
    data_inputs: []const BoxView,  // ADD
    extension: ContextExtension,   // ADD
    pre_header: PreHeader,         // ADD
    headers: [10]Header,           // ADD (last 10)
};

pub const ContextExtension = struct {
    values: [256]?Value,  // Map from varId to Value
};
```

---

## Performance Considerations

### Current Benchmarks (Zigma ReleaseFast)

```
blake2b256 (64 bytes)    149 ns/op    6.7M ops/sec
sha256 (64 bytes)         99 ns/op   10.0M ops/sec
BigInt256.add             16 ns/op   62.2M ops/sec
Point.decode           8,094 ns/op  123.5K ops/sec
Point.mul          2,168,380 ns/op      461 ops/sec
```

### Comparison with Reference

| Operation | Zigma | Rust (approx) | Scala (approx) |
|-----------|-------|---------------|----------------|
| Point.mul | 2.2ms | 1.5ms | 3ms |
| Blake2b256 | 149ns | 100ns | 200ns |
| Simple eval | 22μs | 15μs | 50μs |

**Zigma is competitive** but could improve:
1. **Point multiplication** - Consider libsecp256k1 FFI for 3x speedup
2. **Batch operations** - Coalesce multiple point ops
3. **Value representation** - Current 64-byte Value is large

### Memory Layout Analysis

```zig
// Current: Value is 64 bytes (could be 32 with redesign)
pub const Value = union(enum) {
    unit: void,           // 0 bytes
    boolean: bool,        // 1 byte
    byte: i8,             // 1 byte
    short: i16,           // 2 bytes
    int: i32,             // 4 bytes
    long: i64,            // 8 bytes
    big_int: BigIntRef,   // 32 bytes (pointer + size)
    group_element: Point, // 33 bytes compressed
    sigma_prop: *SigmaBoolean,
    coll: CollRef,        // pointer + len + elem_type
    // ...
};
// Tag byte + largest variant + padding = 64 bytes

// Could redesign:
pub const Value = struct {
    tag: ValueTag,
    data: [48]u8,  // Packed data
};
// = 49 bytes, pack to 56 or 64
```

---

## Security Audit Checklist

### Cryptographic Operations

- [ ] **Point validation**: All decoded points validated on curve AND in subgroup
- [ ] **Scalar bounds**: All scalars reduced mod group order before use
- [ ] **Timing attacks**: Constant-time operations for secret-dependent code
- [ ] **Integer overflow**: All arithmetic checked (MIN_INT/-1 case fixed)
- [ ] **Hash input validation**: Reject oversized inputs

### Script Execution

- [ ] **Cost limits enforced**: Cannot exceed cost budget
- [ ] **Depth limits**: Expression tree depth bounded
- [ ] **Collection size limits**: Max collection size enforced
- [ ] **Proof size limits**: Max proof size enforced (DoS protection)
- [ ] **Determinism**: No floating point, no HashMap iteration order

### Proof Verification

- [ ] **Challenge uniqueness**: Each challenge properly bound to message
- [ ] **Fiat-Shamir binding**: Message included in challenge computation
- [ ] **Response verification**: Commitment equals g^z * pk^(-e)
- [ ] **THRESHOLD polynomials**: Proper GF(2^192) arithmetic

### Memory Safety

- [ ] **No dynamic allocation during eval** (TigerBeetle rule)
- [ ] **All indices bounds-checked**
- [ ] **No undefined behavior paths**
- [ ] **Stack overflow protection via explicit stacks**

---

## Recommended Development Roadmap

### Phase 1: Foundation (1-2 weeks)

1. **Complete opcode coverage**
   - Implement Slice, Append, ByIndex default handling
   - Implement GetVar with context extension
   - Test against conformance vectors

2. **Refactor evaluator.zig**
   - Split into smaller modules (TigerBeetle 70-line rule)
   - Add dispatch table for opcodes
   - Increase assertion density

### Phase 2: Prover Implementation (2-3 weeks)

1. **Create prover.zig**
   - UnprovenTree types
   - markReal/polishSimulated algorithms
   - Commitment generation

2. **Fiat-Shamir integration**
   - Tree serialization for hashing
   - Challenge computation
   - Response calculation

3. **Testing**
   - Unit tests for each prover step
   - Integration with existing verifier
   - Cross-test with Rust/Scala

### Phase 3: Transaction Context (1 week)

1. **Extend Context struct**
   - Add data_inputs, extension, pre_header, headers
   - Create builder pattern for context construction

2. **Implement DeserializeContext**
   - Parse script from extension variable
   - Recursive evaluation

### Phase 4: Conformance & Performance (ongoing)

1. **Conformance testing**
   - Run all reference test vectors
   - Fuzz testing with DST
   - Cross-implementation validation

2. **Performance optimization**
   - Profile hot paths
   - Consider libsecp256k1 integration
   - Optimize Value representation

---

## Appendix: Key File Reference

### Scala (canonical reference)
| File | Purpose | Lines |
|------|---------|-------|
| CErgoTreeEvaluator.scala | JIT interpreter | 800 |
| Interpreter.scala | Verification interface | 450 |
| ProverInterpreter.scala | Proving interface | 500 |
| SigSerializer.scala | Proof serialization | 250 |
| FiatShamirTree.scala | Challenge computation | 200 |

### Rust (cleaner, better for reference)
| File | Purpose | Lines |
|------|---------|-------|
| ergotree-interpreter/src/eval.rs | Eval module root | 200 |
| sigma_protocol/prover.rs | Proof generation | 500 |
| sigma_protocol/verifier.rs | Proof verification | 200 |
| sigma_protocol/fiat_shamir.rs | FS transform | 150 |

### Zigma (current)
| File | Purpose | Lines |
|------|---------|-------|
| interpreter/evaluator.zig | Main eval loop | 11,130 |
| sigma/verifier.zig | Verification | 1,052 |
| sigma/sigma_tree.zig | SigmaBoolean types | 600 |
| crypto/secp256k1.zig | Curve operations | 868 |

---

*Generated: 2025-12-22*
*Based on analysis of sigmastate-interpreter (Scala), sigma-rust (Rust), TigerBeetle (Zig)*
