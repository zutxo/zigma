# Cross-Implementation Conformance Testing Plan

## Executive Summary

**Goal**: Establish comprehensive conformance testing across Scala, Rust, and Zig ErgoTree implementations with full interpreter evaluation as priority.

**Priority**: End-to-end ErgoTree evaluation matching Scala output first, then crypto, then serialization.

**Expert Review**: Ergo core team (protocol), sigma-rust maintainers (cross-impl), external crypto auditor (security).

---

## Current State Analysis

### Scala (Reference Implementation)

**Test Framework**: ScalaTest 3.2.14 + ScalaCheck 1.15.2 + ScalaMeter 0.19

**Key Patterns**:
- Property-based tests with `forAll` and generators in `ObjectGenerators.scala`
- Roundtrip serialization: `deserialize(serialize(x)) == x`
- Version-aware testing via `VersionContext.withVersions(v1, v2)`
- Known-answer vectors hardcoded as Base16 hex strings
- Cost tracing with `CErgoTreeEvaluator.DefaultEvalSettings`

**Critical Test Files**:
```
~/ergotree-research/scala/sigmastate/
├── interpreter/shared/src/test/scala/sigma/serialization/
│   ├── SerializationSpecification.scala      # Roundtrip framework
│   ├── generators/ObjectGenerators.scala     # Type generators
│   └── TypeSerializerSpecification.scala     # Type encoding
├── interpreter/shared/src/test/scala/sigmastate/crypto/
│   ├── CryptoFacadeSpecification.scala       # Hash vectors
│   └── SigningSpecification.scala            # Signature vectors
└── sc/shared/src/test/scala/sigma/
    ├── LanguageSpecificationV5.scala         # v5 interpreter tests
    └── LanguageSpecificationV6.scala         # v6 interpreter tests
```

### Rust (sigma-rust)

**Test Framework**: Rust `#[test]` + proptest 1.6.0 + criterion 0.5.1

**Key Patterns**:
- Hardcoded vectors from Scala with source comments
- `sigma_test_util::force_any_val<T>()` for arbitrary generation
- `expect-test` for snapshot testing
- Thread-local context caching

**Critical Test Files**:
```
~/ergotree-research/rust/sigma-rust/
├── ergotree-interpreter/src/sigma_protocol/
│   └── sig_serializer.rs                     # Signature tests
├── ergotree-ir/src/
│   ├── serialization/                        # Roundtrip tests
│   └── mir/                                  # Expression tests
└── sigma-test-util/src/lib.rs                # Test helpers
```

### Zig (Zigma)

**Test Framework**: Zig native `test` + std.testing

**Current Structure**:
```
~/orgs/zutxo/zigma/
├── tests/conformance/runner.zig              # Conformance harness
├── tests/conformance/mainnet.zig             # Real script tests
├── tests/property/main.zig                   # Property tests
└── benchmarks/main.zig                       # TigerBeetle-style bench
```

**DST Coverage**: 91.2% (62/68 opcodes)

---

## Shared Test Vector Schema

**Location**: `~/ergotree-research/vectors/schema.json`

```json
{
  "typed_value": {
    "type": "SType string (e.g., 'SInt', 'Coll[Byte]')",
    "value": "Native representation",
    "hex": "Base16 serialized bytes"
  },
  "test_case": {
    "id": "unique_identifier",
    "operation": "operation_name",
    "inputs": { ... },
    "version": { "block_version": 2, "ergo_tree_version": 2 },
    "expected": {
      "success": { "type": "...", "value": ... },
      "cost": 12345
    }
  }
}
```

**Vector Categories**:
- `crypto/signing.json` - Signature verification
- `evaluation/arithmetic.json` - All arithmetic ops by version
- `evaluation/logical.json` - Boolean operations
- `serialization/*.json` - Type and value encoding

---

## Expert Review Strategy

### 1. Ergo Core Team (kushti, morphic)

**Focus Areas**:
- Protocol version semantics (v0 → v3 transitions)
- Cost model accuracy (JitCost tables)
- Soft-fork placeholder behavior
- Edge cases in official scripts

**Deliverables**:
- Approve test vector schema
- Provide mainnet script samples
- Review cost assertions

### 2. Sigma-Rust Maintainers (greenhat)

**Focus Areas**:
- Cross-implementation conformance patterns
- Known pitfalls from Rust implementation
- Serialization edge cases
- JSON vector sharing strategy

**Deliverables**:
- Review vector format compatibility
- Share existing conformance infrastructure
- Identify Scala-Rust divergence cases

### 3. External Crypto Auditor

**Focus Areas**:
- secp256k1 point validation
- Blake2b256, SHA256 implementations
- Schnorr signature verification
- Threshold signature schemes

**Deliverables**:
- Audit crypto test vectors
- Verify constant-time properties
- Review invalid input handling

---

## Implementation Plan

### Phase 1: Test Vector Infrastructure

**Goal**: Create JSON vector generation from Scala, consumption in all implementations.

#### 1.1 Scala Vector Generator

**File**: `~/ergotree-research/scala/sigmastate/test-vectors/VectorGenerator.scala`

```scala
object VectorGenerator {
  def generateEvaluationVectors(): Seq[TestVector] = {
    // For each opcode and input combination:
    // 1. Create ErgoTree
    // 2. Evaluate with CErgoTreeEvaluator
    // 3. Capture result + cost
    // 4. Serialize to JSON
  }
}
```

**Vector Categories**:
1. **Arithmetic**: Add, Sub, Mul, Div, Mod with overflow cases
2. **Comparison**: LT, GT, LE, GE, EQ, NE for all types
3. **Logical**: AND, OR, XOR, NOT, SigmaAnd, SigmaOr
4. **Collection**: Map, Filter, Fold, FlatMap, Exists, ForAll
5. **Crypto**: Blake2b256, SHA256, ProveDlog, ProveDHTuple
6. **Context**: HEIGHT, INPUTS, OUTPUTS, SELF

#### 1.2 Zigma Vector Consumer

**File**: `tests/conformance/vectors.zig`

```zig
const TestVector = struct {
    id: []const u8,
    ergotree_hex: []const u8,
    context: ContextData,
    expected_result: ExpectedResult,
    expected_cost: u64,
};

pub fn loadVectors(path: []const u8) ![]TestVector {
    // Parse JSON vectors
    // Return structured test cases
}
```

#### 1.3 Rust Vector Consumer

**File**: `~/ergotree-research/rust/sigma-rust/conformance/src/lib.rs`

```rust
#[derive(Deserialize)]
struct TestVector {
    id: String,
    ergotree_hex: String,
    context: ContextData,
    expected: Expected,
}

fn load_vectors(path: &str) -> Vec<TestVector> { ... }
```

---

### Phase 2: Full Interpreter Evaluation (Priority)

**Goal**: End-to-end ErgoTree evaluation matching Scala output.

#### 2.1 Zigma CLI Enhancements

**File**: `src/main.zig`

Add commands:
```bash
zigma eval <ergotree_hex> --context=<json> --version=<v>
# Output: { "result": ..., "cost": N, "error": null }

zigma conformance <vectors.json>
# Output: { "passed": N, "failed": M, "errors": [...] }
```

#### 2.2 Conformance Test Runner

**File**: `tests/conformance/evaluator_conformance.zig`

```zig
test "conformance: full evaluation vectors" {
    const vectors = try loadVectors("vectors/evaluation/*.json");

    for (vectors) |v| {
        const tree = try deserialize(v.ergotree_hex);
        const ctx = try buildContext(v.context);

        var eval = Evaluator.init(&tree, &ctx);
        const result = eval.evaluate();

        try expectEqualResult(v.expected_result, result);
        try expectEqual(v.expected_cost, eval.cost_used);
    }
}
```

#### 2.3 Version-Aware Testing

```zig
fn testWithVersions(vector: TestVector) !void {
    for ([_]u8{0, 1, 2, 3}) |block_v| {
        for ([_]u8{0, 1, 2, 3}) |tree_v| {
            const ctx = VersionContext{ .block = block_v, .tree = tree_v };
            // Test with this version combination
        }
    }
}
```

---

### Phase 3: Crypto Conformance

**Goal**: Exact match on all cryptographic operations.

#### 3.1 Hash Function Vectors

```json
{
  "id": "blake2b256_empty",
  "operation": "blake2b256",
  "input": "",
  "expected": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
}
```

#### 3.2 Signature Vectors

```json
{
  "id": "provedlog_basic",
  "operation": "verify_dlog",
  "message": "1dc01772ee0171f5f614c673e3c7fa1107a8cf727bdf5a6dadb379e93c0d1d00",
  "public_key": "03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8f1ef40dd80d08a70b7028",
  "signature": "bcb866ba434d5c77869ddcbc3f09ddd62dd2d2539bf99076674d1ae0c32338ea95581fdc18a3b66789904f35efa8df1599812aa3395a4f5f6a4c5a0f8f30e4ff",
  "expected": true
}
```

#### 3.3 Curve Operation Vectors

- Point decoding (compressed/uncompressed)
- Point addition, negation
- Scalar multiplication
- Invalid point rejection (off-curve, infinity, wrong subgroup)

---

### Phase 4: Serialization Conformance

**Goal**: Byte-exact serialization matching.

#### 4.1 Roundtrip Tests

```zig
test "conformance: serialization roundtrip" {
    for (type_vectors) |v| {
        const bytes = hexToBytes(v.hex);
        const value = try deserialize(bytes, v.type_code);
        const reserialized = try serialize(value);
        try expectEqualSlices(u8, bytes, reserialized);
    }
}
```

#### 4.2 Type Encoding Vectors

```json
{
  "type": "Coll[Coll[Byte]]",
  "type_code_hex": "6c0c",
  "sample_value": [[1,2,3], [4,5]],
  "value_hex": "02030102030204050406"
}
```

---

### Phase 5: Benchmark Framework

**Goal**: Cross-implementation performance comparison.

#### 5.1 Benchmark Categories

| Category | Operations | Parameters |
|----------|------------|------------|
| Crypto | blake2b256, sha256 | 1, 64, 256, 1024, 4096 bytes |
| Curve | point_decode, point_mul | Single ops, batch |
| Arithmetic | BigInt add, mul, mod | Random 256-bit inputs |
| Collection | map, filter, fold | 10, 100, 1000 elements |
| Evaluation | Simple → complex scripts | Per-script timing |

#### 5.2 Comparison Script

**File**: `~/ergotree-research/conformance/benchmark_compare.py`

```python
implementations = {
    'scala': ScalaBenchAdapter(),
    'rust': RustBenchAdapter(),
    'zigma': ZigmaBenchAdapter(),
}

for name, input_data in benchmarks:
    results = {}
    for impl_name, adapter in implementations.items():
        results[impl_name] = adapter.benchmark(name, input_data)

    print(f"{name}:")
    for impl, result in results.items():
        print(f"  {impl}: {result.ns_per_op} ns/op")
```

#### 5.3 Zigma Benchmark Enhancements

**File**: `benchmarks/main.zig`

Add:
- JSON output for comparison scripts
- Parametric benchmarks (size sweeps)
- Statistical aggregation (min, max, stddev)

---

## Conformance Runner Architecture

```
~/ergotree-research/conformance/
├── vectors/
│   ├── schema.json                  # JSON Schema for all vectors
│   ├── evaluation/
│   │   ├── arithmetic.json
│   │   ├── logical.json
│   │   ├── comparison.json
│   │   └── collection.json
│   ├── crypto/
│   │   ├── hash.json
│   │   ├── signing.json
│   │   └── curve.json
│   └── serialization/
│       ├── types.json
│       └── values.json
├── generators/
│   └── scala/                       # Scala vector generators
├── adapters/
│   ├── scala_adapter.py
│   ├── rust_adapter.py
│   └── zigma_adapter.py
├── runner.py                        # Main conformance runner
└── benchmark_compare.py             # Performance comparison
```

---

## CI Pipeline (Future)

```yaml
# .github/workflows/conformance.yml
name: Cross-Implementation Conformance

on: [push, pull_request]

jobs:
  generate-vectors:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-scala@v2
      - run: sbt "testOnly VectorGenerator"
      - uses: actions/upload-artifact@v3
        with: { name: vectors, path: vectors/ }

  test-zigma:
    needs: generate-vectors
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
      - run: ./zig/zig build test
      - run: ./zig/zig build conformance

  test-rust:
    needs: generate-vectors
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --all
      - run: cargo run --bin conformance

  compare-results:
    needs: [test-zigma, test-rust]
    runs-on: ubuntu-latest
    steps:
      - run: python conformance/compare.py
```

---

## Files to Create/Modify

### Zigma

| File | Purpose |
|------|---------|
| `src/main.zig` | Add `conformance` command |
| `tests/conformance/vectors.zig` | JSON vector loader |
| `tests/conformance/evaluator_conformance.zig` | Full evaluation tests |
| `benchmarks/main.zig` | Add JSON output, parametric benchmarks |

### Cross-Implementation

| File | Purpose |
|------|---------|
| `~/ergotree-research/conformance/runner.py` | Main test runner |
| `~/ergotree-research/conformance/adapters/zigma_adapter.py` | Zigma CLI interface |
| `~/ergotree-research/vectors/schema.json` | JSON Schema definition |

### Scala

| File | Purpose |
|------|---------|
| `VectorGenerator.scala` | Generate JSON test vectors |

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Evaluation Conformance | 100% | All vectors pass in all implementations |
| Crypto Conformance | 100% | Exact byte match on all operations |
| Serialization Conformance | 100% | Roundtrip exact for all types |
| Cost Accuracy | ±0 | Costs match Scala exactly |
| Benchmark Coverage | All categories | ns/op for every operation type |

---

## Implementation Order

1. **Week 1**: Test vector schema + Scala generator skeleton
2. **Week 2**: Zigma JSON vector loader + basic evaluation conformance
3. **Week 3**: Full evaluation vector generation + testing
4. **Week 4**: Crypto conformance vectors + testing
5. **Week 5**: Serialization vectors + roundtrip testing
6. **Week 6**: Benchmark framework + comparison scripts
7. **Week 7**: Expert review preparation + documentation
8. **Week 8**: Address review feedback + CI setup

---

## Open Questions for Expert Review

1. **Protocol**: Are there undocumented edge cases in version transitions?
2. **Cost**: How strict should cost matching be? (exact vs ±epsilon)
3. **Soft-fork**: What should happen with unknown opcodes in v3+ scripts?
4. **Mainnet**: Can we get a curated set of "critical path" scripts to test?
5. **Security**: Which crypto operations need constant-time verification?
