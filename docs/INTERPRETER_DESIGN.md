# Zigma Interpreter Design

## Overview

Zigma is an ErgoTree interpreter in Zig following data-oriented design principles. ErgoTree is the bytecode format for Ergo blockchain's Σ-protocol smart contracts—scripts that reduce to cryptographic propositions.

This document defines the architecture, invariants, and requirements. Use it to audit existing code and guide new development.

---

## Design Goals (Ordered by Priority)

1. **Correctness** — Bit-identical results to reference implementations
2. **Safety** — No undefined behavior, validated inputs, bounded resources
3. **Determinism** — Same input → same output across all platforms
4. **Performance** — Zero allocation during evaluation, cache-efficient

---

## Execution Pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           ErgoTree Evaluation                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────┐  │
│  │  ErgoTree   │───▶│ Deserialize │───▶│  Evaluate   │───▶│  Sigma   │  │
│  │   Bytes     │    │             │    │             │    │  Verify  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └──────────┘  │
│                            │                  │                  │       │
│                            ▼                  ▼                  ▼       │
│                     ┌─────────────┐    ┌─────────────┐    ┌──────────┐  │
│                     │   Pools     │    │  Context    │    │  Proof   │  │
│                     │ (pre-alloc) │    │ (read-only) │    │  Bytes   │  │
│                     └─────────────┘    └─────────────┘    └──────────┘  │
│                                                                          │
│  Result: bool (valid/invalid transaction input)                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Deserialization
Parse ErgoTree bytes into expression pool. Validate structure and enforce limits.

### Phase 2: Evaluation  
Reduce expressions to a `SigmaBoolean` using iterative work-stack evaluation.

### Phase 3: Sigma Verification
Verify the cryptographic proof against the reduced `SigmaBoolean`.

---

## Critical Invariants

These invariants MUST hold. Violations are consensus bugs.

### INV-1: Determinism
```
∀ ergotree, context:
  evaluate(ergotree, context) on Platform A 
  == evaluate(ergotree, context) on Platform B
```

**Forbidden patterns:**
- HashMap iteration in any output-affecting path
- Uninitialized memory reads
- Floating point arithmetic
- System time during evaluation
- Platform-dependent integer semantics

### INV-2: Cost Accounting
```
∀ operation:
  cost_check() BEFORE operation execution
  cost >= 0 after every operation
  cost_limit_exceeded → evaluation stops immediately
```

### INV-3: Memory Bounds
```
∀ pool access:
  index < pool.len
  pool.len <= pool.CAPACITY
  no allocation after init()
```

### INV-4: Cryptographic Validity
```
∀ GroupElement from untrusted input:
  isOnCurve(point) ∧ ¬isInfinity(point) ∧ isValidFieldElement(x)
```

### INV-5: Version Consistency
```
∀ evaluation:
  VersionContext threaded to all version-dependent operations
  behavior matches reference implementation for that version
```

---

## Architecture

### Component Map (Current Implementation)

```
src/
├── core/
│   ├── types.zig         ← SType, TypeCode, type utilities
│   └── opcodes.zig       ← OpCode enum, metadata, dispatch info
│
├── serialization/
│   ├── vlq.zig           ← VLQ/ZigZag encoding
│   ├── type_serializer.zig
│   ├── data_serializer.zig
│   ├── expr_serializer.zig
│   └── ergotree_serializer.zig
│
├── interpreter/
│   ├── memory.zig        ← Expression/Constant pools
│   ├── value_pool.zig    ← Value storage during evaluation
│   ├── context.zig       ← Blockchain context (boxes, headers)
│   ├── evaluator.zig     ← Main evaluation loop
│   ├── ops.zig           ← Operation dispatch
│   └── ops/
│       ├── arithmetic.zig
│       ├── comparison.zig
│       ├── logical.zig
│       ├── collection.zig
│       ├── box.zig
│       ├── context_ops.zig
│       ├── header_ops.zig
│       └── crypto.zig
│
├── crypto/
│   ├── bigint.zig        ← 256-bit integer arithmetic
│   ├── secp256k1.zig     ← Elliptic curve operations
│   └── hash.zig          ← Blake2b256, SHA256
│
├── sigma/
│   ├── sigma_tree.zig    ← SigmaBoolean tree representation
│   ├── challenge.zig     ← Fiat-Shamir challenge computation
│   ├── schnorr.zig       ← Schnorr protocol
│   └── verifier.zig      ← Proof verification
│
└── root.zig              ← Public API
```

---

## Component Specifications

### 1. Type System (`core/types.zig`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| All primitive type codes match ErgoTree spec Table 5 | Ergo Core | Critical |
| Constructed types use index references (not recursive pointers) | Zig Experts | Critical |
| Subtyping: Any is supertype of all, Unit is subtype of all | Ergo Core | High |
| Type equality handles all cases | Formal Methods | High |
| comptime validation of type code uniqueness | Zig Experts | Medium |

#### Specification

```zig
pub const TypeCode = enum(u8) {
    // Embeddable (1-8)
    boolean = 1,
    byte = 2,
    short = 3,
    int = 4,
    long = 5,
    big_int = 6,
    group_element = 7,
    sigma_prop = 8,
    
    // Non-embeddable
    box = 99,
    avl_tree = 100,
    context = 101,
    header = 104,
    pre_header = 105,
    
    // Special
    any = 97,
    unit = 98,
    
    comptime {
        // Validate no collisions
        var seen: [256]bool = .{false} ** 256;
        for (std.enums.values(TypeCode)) |tc| {
            const code = @intFromEnum(tc);
            std.debug.assert(!seen[code]);
            seen[code] = true;
        }
    }
};

pub const SType = union(enum) {
    // Primitives
    boolean, byte, short, int, long, big_int,
    group_element, sigma_prop,
    box, avl_tree, context, header, pre_header,
    any, unit,
    
    // Constructed (index into TypePool)
    collection: TypeIndex,
    option: TypeIndex,
    tuple: TupleRef,
    func: FuncRef,
    
    pub fn isSubtypeOf(self: SType, other: SType) bool {
        if (std.meta.eql(self, other)) return true;
        if (other == .any) return true;  // Any is supertype of all
        if (self == .unit) return true;   // Unit is subtype of all
        // Collection covariance: Coll[T] <: Coll[U] if T <: U
        return false;
    }
};

pub const TypeIndex = u16;
```

---

### 2. Opcodes (`core/opcodes.zig`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| All opcodes from Operations.scala included | Ergo Core | Critical |
| Opcode metadata includes version introduced | Ergo Core | Critical |
| Cost lookup is O(1) via table | VM Designers | High |
| comptime validation of opcode uniqueness | Zig Experts | Medium |
| Soft-fork opcodes identified | Ergo Core | High |

#### Specification

```zig
pub const OpCode = enum(u8) {
    // Constants (0x00-0x80 encode constant type+value)
    
    // Arithmetic
    add = 0x93,
    sub = 0x94,
    mul = 0x95,
    div = 0x96,
    mod = 0x97,
    // ... all 100+ opcodes
    
    pub const Metadata = struct {
        arity: u8,
        base_cost: u32,
        min_version: u8,  // Protocol version that introduced this
        category: Category,
    };
    
    pub const metadata: [256]?Metadata = comptime blk: {
        var table: [256]?Metadata = .{null} ** 256;
        table[@intFromEnum(OpCode.add)] = .{
            .arity = 2,
            .base_cost = 36,
            .min_version = 0,
            .category = .arithmetic,
        };
        // ... fill all opcodes at comptime
        break :blk table;
    };
    
    pub fn isValidForVersion(self: OpCode, version: u8) bool {
        const meta = metadata[@intFromEnum(self)] orelse return false;
        return version >= meta.min_version;
    }
};
```

---

### 3. Memory Pools (`interpreter/memory.zig`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| Structure of Arrays layout for hot data | TigerBeetle | High |
| Fixed capacity, no dynamic allocation | TigerBeetle | Critical |
| O(1) reset between evaluations | TigerBeetle | High |
| Power-of-two capacities | TigerBeetle | Medium |
| Pre-validation of capacity before operations | TigerBeetle | High |

#### Specification

```zig
pub const ExpressionPool = struct {
    pub const CAPACITY = 16384;  // 2^14
    
    // Hot: touched during dispatch (sequential access)
    opcodes: [CAPACITY]OpCode align(64),
    
    // Warm: touched after dispatch
    type_codes: [CAPACITY]TypeCode,
    child_counts: [CAPACITY]u8,
    
    // Cold: touched only for specific opcodes
    child_indices: [CAPACITY][4]ExprIndex,
    constant_refs: [CAPACITY]ConstRef,
    
    len: u32,
    
    comptime {
        std.debug.assert(@popCount(CAPACITY) == 1); // Power of two
    }
    
    pub fn reset(self: *ExpressionPool) void {
        self.len = 0;  // O(1) - don't zero arrays
    }
    
    pub fn hasCapacity(self: *const ExpressionPool, needed: u32) bool {
        return self.len + needed <= CAPACITY;
    }
};
```

---

### 4. Evaluator (`interpreter/evaluator.zig`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| Iterative (work stack), not recursive | TigerBeetle | Critical |
| Cost check BEFORE every operation | Ergo Core | Critical |
| VersionContext threaded through | Ergo Core | Critical |
| Size-dependent costs (not static lookup) | Ergo Core | Critical |
| Short-circuit AND/OR evaluation | Ergo Core | High |
| Wall-clock timeout (defense in depth) | Operators | High |
| Soft-fork condition handling | Ergo Core | High |
| Maximum iteration limit | Operators | High |

#### Specification

```zig
pub const Evaluator = struct {
    expr_pool: *ExpressionPool,
    value_pool: *ValuePool,
    context: *const Context,
    
    // CRITICAL: Version context affects behavior everywhere
    version: VersionContext,
    
    // Cost tracking
    cost_remaining: u64,
    
    // Work stack for iterative evaluation
    work_stack: std.BoundedArray(WorkItem, 4096),
    
    // Safety limits
    deadline_ns: i128,
    iterations: u32,
    
    pub const MAX_ITERATIONS = 100_000;
    
    pub fn evaluate(self: *Evaluator, root: ExprIndex) !Value {
        try self.work_stack.append(.{ .expr = root, .phase = .evaluate });
        
        while (self.work_stack.popOrNull()) |work| {
            self.iterations += 1;
            if (self.iterations > MAX_ITERATIONS) return error.TooManyIterations;
            if (std.time.nanoTimestamp() > self.deadline_ns) return error.TimeoutExceeded;
            
            switch (work.phase) {
                .evaluate => try self.evaluatePhase(work),
                .compute => try self.computePhase(work),
            }
        }
        
        return self.value_pool.pop() orelse error.EmptyResult;
    }
    
    fn computePhase(self: *Evaluator, work: WorkItem) !void {
        const opcode = self.expr_pool.opcodes[work.expr];
        
        // Soft-fork handling
        if (!opcode.isValidForVersion(self.version.activated)) {
            if (self.version.allowsSoftFork()) {
                try self.value_pool.push(.{ .soft_fork_marker = {} });
                return;
            }
            return error.UnsupportedOpcode;
        }
        
        // CRITICAL: Cost check BEFORE execution
        // Costs are SIZE-DEPENDENT, not static!
        const cost = self.costOf(opcode, work.expr);
        if (self.cost_remaining < cost) return error.CostLimitExceeded;
        self.cost_remaining -= cost;
        
        const result = try self.dispatch(opcode, work.expr);
        try self.value_pool.push(result);
    }
    
    /// Cost calculation - size and type dependent
    fn costOf(self: *Evaluator, opcode: OpCode, expr: ExprIndex) u64 {
        const base = OpCode.metadata[@intFromEnum(opcode)].?.base_cost;
        
        return base + switch (opcode) {
            .collection_map, .collection_fold => self.getCollSize(expr) * 30,
            .bigint_add, .bigint_mul => self.getBigIntBits(expr) / 64 * 10,
            else => 0,
        };
    }
};

pub const VersionContext = struct {
    activated: u8,
    script_version: u8,
    
    pub fn isJitActivated(self: VersionContext) bool { return self.activated >= 2; }
    pub fn isV6Activated(self: VersionContext) bool { return self.activated >= 3; }
    pub fn allowsSoftFork(self: VersionContext) bool { 
        return self.script_version > self.activated; 
    }
};
```

---

### 5. Cryptography (`crypto/`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| Point validation: on curve, not infinity, valid field | Crypto | Critical |
| Constant-time comparison for signatures | Crypto | Critical |
| BigInt overflow detection on all operations | Crypto | Critical |
| libsecp256k1 bindings for production | Crypto | High |

#### Point Validation (secp256k1.zig)

```zig
pub fn validatePoint(point: Point) !void {
    if (point.isInfinity()) return error.PointAtInfinity;
    if (!point.x.isValidFieldElement()) return error.InvalidFieldElement;
    if (!point.isOnCurve()) return error.PointNotOnCurve;
}

pub fn deserializeCompressed(bytes: *const [33]u8) !Point {
    const point = try decompress(bytes);
    try validatePoint(point);  // CRITICAL: Always validate
    return point;
}
```

#### Constant-Time Operations

```zig
// REQUIRED for signature verification
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}
```

---

### 6. Serialization (`serialization/`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| VLQ/ZigZag encoding exact match | Ergo Core | Critical |
| Size limits enforced (4KB max ErgoTree) | Operators | High |
| Nesting depth limits | Operators | High |
| All bytes consumed assertion | Ergo Core | Medium |

#### Limits

```zig
pub const Limits = struct {
    pub const MAX_ERGOTREE_SIZE: u32 = 4096;
    pub const MAX_NESTING_DEPTH: u8 = 10;
    pub const MAX_COLLECTION_SIZE: u32 = 10000;
    pub const MAX_CONSTANTS: u16 = 1000;
};
```

---

### 7. Sigma Protocols (`sigma/`)

#### Requirements

| Requirement | Source | Priority |
|-------------|--------|----------|
| SigmaBoolean tree matches spec | Ergo Core | Critical |
| Fiat-Shamir challenge correct | Crypto | Critical |
| Schnorr verification correct | Crypto | Critical |
| AND/OR/THRESHOLD composition | Ergo Core | Critical |
| Constant-time verification | Crypto | High |

---

## Testing Requirements

### Required Test Types

| Type | Purpose | Minimum Coverage |
|------|---------|------------------|
| Unit | Per-function correctness | Every public function |
| Conformance | Match Scala/Rust output | 100+ test vectors |
| Property | Invariants for random input | All invariants |
| Fuzz | Find crashes | All deserializers |
| Differential | Same as reference | Full pipeline |

### Property Tests

```zig
test "INV-1: determinism" { /* same input → same output */ }
test "INV-2: cost accounting" { /* cost checked before every op */ }
test "INV-3: memory bounds" { /* no out-of-bounds access */ }
test "INV-4: point validation" { /* all points validated */ }
test "roundtrip: deserialize(serialize(x)) == x" { }
test "cost monotonicity: cost(expr) >= sum(cost(children))" { }
```

---

## Performance Contracts

| Metric | Target |
|--------|--------|
| Simple tx p99 | < 1ms |
| Complex tx p99 | < 10ms |
| Memory per interpreter | < 4MB |
| Allocation during eval | 0 bytes |
| Pool reset | < 1μs |

---

## Audit Checklist Template

For each component:

```markdown
## [Component Name]

### Structure
- [ ] Matches design spec
- [ ] comptime validations present

### Safety  
- [ ] Assertions: X per function (target: 3+)
- [ ] Bounds checking complete
- [ ] Error handling complete

### Determinism
- [ ] No HashMap iteration
- [ ] No uninitialized reads
- [ ] Explicit overflow handling

### Tests
- [ ] Unit tests present
- [ ] Conformance tests linked
```
