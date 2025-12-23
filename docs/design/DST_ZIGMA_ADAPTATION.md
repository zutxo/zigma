# Zigma DST Adaptation Guide

## Applying TigerBeetle's VOPR Patterns to Zigma

**Document Type:** Implementation Guide
**Purpose:** Bridge TigerBeetle's distributed DST patterns to zigma's interpreter testing

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Gap Analysis](#2-gap-analysis)
3. [Applicable Patterns](#3-applicable-patterns)
4. [Non-Applicable Patterns](#4-non-applicable-patterns)
5. [Recommended Enhancements](#5-recommended-enhancements)
6. [Implementation Roadmap](#6-implementation-roadmap)
7. [Code Migration Examples](#7-code-migration-examples)

---

## 1. Executive Summary

### 1.1 Context Differences

| Aspect | TigerBeetle | Zigma |
|--------|-------------|-------|
| System Type | Distributed consensus | Single-threaded interpreter |
| Components | Replicas, clients, network | Evaluator, expressions, contexts |
| Failure Modes | Partitions, crashes, delays | Stack overflow, OOM, cost limit |
| State | Replicated across nodes | Single evaluation state |
| Time | Tick-based simulation | Expression evaluation steps |

### 1.2 What Zigma Already Has

Zigma's `src/dst/` directory already implements TigerBeetle-inspired patterns:

| Component | File | Status |
|-----------|------|--------|
| PRNG | `prng.zig` | Complete - matches TigerBeetle |
| Ratio Type | `prng.zig` | Complete |
| Seed Parsing | `prng.zig` | Complete |
| Main Simulator | `dst.zig` | Core structure complete |
| Expr Generator | `generators/expr_gen.zig` | Type-directed generation |
| Context Generator | `generators/context_gen.zig` | Context fuzzing |
| Determinism Checker | `checkers/determinism.zig` | Run-twice verification |
| Cost Checker | `checkers/cost_checker.zig` | Cost invariant checking |
| Fault Injection | `fault_injection/injector.zig` | Basic injection |

### 1.3 Key Takeaways

1. **Zigma's DST foundation is solid** - core patterns already implemented
2. **Focus on interpreter-specific enhancements** - not distributed system patterns
3. **Swarm testing is highly applicable** - randomize expression generation
4. **Safety/liveness phases don't apply** - interpreter has no liveness concept
5. **Output format improvements** - adopt TigerBeetle's VOPR output style

---

## 2. Gap Analysis

### 2.1 PRNG Module Comparison

#### TigerBeetle (`src/stdx/prng.zig`)

```zig
// XoShiro256++ with 4 x u64 state
s: [4]u64,

pub fn from_seed(seed: u64) PRNG {
    var s = seed;
    return .{ .s = .{
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
    } };
}

// NO FLOATING POINT in API
pub const Ratio = struct {
    numerator: u64,
    denominator: u64,
};
```

#### Zigma (`src/dst/prng.zig`)

```zig
// Uses std.Random.DefaultPrng (same algorithm)
state: std.Random.DefaultPrng,

pub fn from_seed(seed: u64) PRNG {
    return .{ .state = std.Random.DefaultPrng.init(seed) };
}

// Ratio type matches TigerBeetle
pub const Ratio = struct {
    numerator: u64,
    denominator: u64,
};
```

**Gap:** Minor - zigma wraps std PRNG instead of custom implementation.
**Impact:** Low - same algorithm, deterministic.
**Recommendation:** Keep current implementation; TigerBeetle's custom impl is for stdlib isolation.

### 2.2 Simulator Structure Comparison

#### TigerBeetle VOPR

```zig
pub const Simulator = struct {
    prng: *PRNG,
    options: Options,
    cluster: *Cluster,        // Manages replicas
    workload: Workload,       // Generates operations

    // Phase tracking
    requests_sent: usize,
    requests_replied: usize,
    core: Core,               // Liveness core set

    pub fn tick() void {
        cluster.tick();       // Advance replicas
        tick_requests();      // Send requests
        tick_crash();         // Inject crashes
        tick_upgrade();       // Version upgrades
        tick_pause();         // VM migration sim
    }
};
```

#### Zigma DST

```zig
pub const Simulator = struct {
    prng: PRNG,
    options: Options,
    expr_gen: ExprGenerator,
    context_gen: ContextGenerator,
    determinism_checker: DeterminismChecker,
    tree: ExprTree,

    pub fn tick(self: *Simulator) TickResult {
        self.tree.reset();
        self.expr_gen.generate();        // Generate expression
        const ctx = self.context_gen.generate();
        self.determinism_checker.check(&self.tree, &ctx);
        return .success;
    }
};
```

**Gap:** Zigma lacks:
- Crash/restart simulation (N/A for interpreter)
- Network/storage simulation (N/A for interpreter)
- Liveness phase (N/A for interpreter)
- Progress tracking (partially applicable)

### 2.3 Checker Comparison

#### TigerBeetle Checkers

| Checker | Purpose | Zigma Equivalent |
|---------|---------|------------------|
| StateChecker | Commit consistency | DeterminismChecker |
| StorageChecker | Byte-identical storage | N/A |
| GridChecker | LSM block coherence | N/A |
| JournalChecker | WAL consistency | N/A |
| ManifestChecker | LSM manifest | N/A |

#### Zigma Checkers

| Checker | Purpose | Status |
|---------|---------|--------|
| DeterminismChecker | Same input → same output | Complete |
| CostChecker | Cost limits, bounds | Complete |
| TypeChecker | Expression typing | Partial |

**Gap:** Zigma needs:
- **Conformance Checker** - Compare with Scala/Rust reference
- **Memory Checker** - Track allocation patterns
- **Coverage Checker** - Track opcode coverage

### 2.4 Fault Injection Comparison

#### TigerBeetle Faults

| Category | Faults |
|----------|--------|
| Storage | Read fault, write fault, misdirect, crash fault |
| Network | Loss, delay, reorder, partition, clog |
| Replica | Crash, restart, reformat, pause, upgrade |

#### Zigma Faults (Current)

| Category | Faults |
|----------|--------|
| (Limited) | Basic injection scaffolding |

**Gap:** Zigma needs interpreter-specific faults:
- **Cost Limit Variation** - Randomize cost limits
- **Stack Limit Variation** - Randomize stack depth
- **Memory Pressure** - Simulate allocation failures
- **Expression Corruption** - Mutate generated trees

---

## 3. Applicable Patterns

### 3.1 Pattern: Swarm Testing

**TigerBeetle Approach:**
```zig
fn options_swarm(prng: *PRNG) Options {
    return .{
        .replica_count = prng.range_inclusive(u8, 1, 6),
        .packet_loss = ratio(prng.int_inclusive(u8, 30), 100),
        .partition_mode = prng.enum_uniform(PartitionMode),
        // ... many randomized parameters
    };
}
```

**Zigma Adaptation:**
```zig
fn options_swarm(prng: *PRNG) ExprGenOptions {
    return .{
        .max_depth = prng.range_inclusive(u8, 3, 15),
        .max_nodes = prng.range_inclusive(u16, 10, 500),

        // Swarm weights for opcode categories
        .leaf_weight = prng.range_inclusive(u8, 0, 100),
        .arithmetic_weight = prng.range_inclusive(u8, 0, 100),
        .comparison_weight = prng.range_inclusive(u8, 0, 100),
        .logical_weight = prng.range_inclusive(u8, 0, 100),
        .collection_weight = prng.range_inclusive(u8, 0, 100),
        .crypto_weight = prng.range_inclusive(u8, 0, 50),

        .constant_probability = Ratio.percent(prng.range_inclusive(u8, 10, 80)),
    };
}
```

**Status:** Partially implemented in `expr_gen.zig`. Enhance with full swarm randomization.

### 3.2 Pattern: Enum Weight Swarm

**TigerBeetle Approach:**
```zig
pub fn enum_weights(prng: *PRNG, E: type) EnumWeightsType(E) {
    var weights: EnumWeightsType(E) = undefined;
    for (fields) |field| {
        @field(weights, field.name) = if (prng.chance(ratio(70, 100)))
            prng.range_inclusive(u64, 1, 100)
        else
            0;  // Completely disable some variants
    }
    return weights;
}
```

**Zigma Implementation:**
Already in `prng.zig`:
```zig
pub fn random_enum_weights(prng: *PRNG, comptime E: type) PRNG.EnumWeightsType(E) {
    // 70% chance to enable each variant
    @field(weights, field.name) = if (prng.chance(.{ .numerator = 70, .denominator = 100 }))
        prng.range_inclusive(u64, 1, 100)
    else
        0;
}
```

**Status:** Complete. Use for opcode category selection.

### 3.3 Pattern: Seed-Based Reproducibility

**TigerBeetle Approach:**
```
SEED=8675309
zig build vopr -- --seed=8675309
```

**Zigma Implementation:**
Already in `dst.zig`:
```zig
// Parse seed from CLI
const final_seed = seed orelse std.crypto.random.int(u64);

log.info("SEED={}", .{final_seed});

var sim = Simulator.init(.{ .seed = final_seed, ... });
```

**Status:** Complete.

### 3.4 Pattern: Git Commit as Seed

**TigerBeetle Approach:**
```zig
pub fn parse_seed(bytes: []const u8) ?u64 {
    if (bytes.len == 40) {
        // Git SHA-1 hash (40 hex chars)
        const hash = parseUnsigned(u160, bytes, 16);
        return @truncate(hash);  // Truncate to u64
    }
    return parseUnsigned(u64, bytes, 10);
}
```

**Zigma Implementation:**
Already in `prng.zig`:
```zig
pub fn parse_seed(bytes: []const u8) ?u64 {
    if (bytes.len == 40) {
        const commit_hash = std.fmt.parseUnsigned(u160, bytes, 16) catch return null;
        return @truncate(commit_hash);
    }
    return std.fmt.parseUnsigned(u64, bytes, 10) catch null;
}
```

**Status:** Complete.

### 3.5 Pattern: Tick-Based Simulation

**TigerBeetle Approach:**
- Everything happens in discrete ticks
- Priority queues order events by tick
- No real time dependency

**Zigma Adaptation:**
- Expression evaluation already step-based
- Each tick = one expression generation + evaluation
- Track ticks for progress and limits

**Status:** Complete in `dst.zig`.

---

## 4. Non-Applicable Patterns

### 4.1 Network Simulation

**TigerBeetle Use:**
- Packet delays, loss, reordering
- Network partitions
- Path clogging

**Why Not Applicable:**
- Zigma is single-process interpreter
- No network communication
- No distributed state

### 4.2 Storage Fault Injection

**TigerBeetle Use:**
- Read/write faults
- Misdirected writes
- Crash faults on pending writes

**Why Not Applicable:**
- Zigma interpreter doesn't persist state
- No disk I/O during evaluation
- Context is read-only

### 4.3 Cluster/Replica Management

**TigerBeetle Use:**
- Multiple replicas with consensus
- Crash/restart/reformat cycles
- Standby replicas

**Why Not Applicable:**
- Single evaluator instance
- No replication concept
- No crash recovery needed

### 4.4 Liveness Verification

**TigerBeetle Use:**
- "Eventually makes progress"
- Core selection for convergence
- Heal partitions, verify convergence

**Why Not Applicable:**
- Interpreter either completes or fails
- No "eventually" semantics
- Deterministic execution

### 4.5 Multi-Version Testing

**TigerBeetle Use:**
- Rolling version upgrades
- Client compatibility checks
- Upgrade propagation testing

**Why Not Applicable:**
- Zigma has protocol versions (v0-v3)
- But version is fixed per evaluation
- No runtime version mixing

---

## 5. Recommended Enhancements

### 5.1 Enhanced Trace Recording

**Current State:** `src/dst/trace/recorder.zig` exists but minimal.

**Enhancement:** Add detailed evaluation traces for debugging.

```zig
pub const TraceRecorder = struct {
    events: ArrayList(TraceEvent),

    pub const TraceEvent = union(enum) {
        eval_start: struct { node_idx: u16, opcode: ExprTag },
        eval_end: struct { node_idx: u16, result: Value, cost: u32 },
        stack_push: struct { depth: u16, value: Value },
        stack_pop: struct { depth: u16 },
        error: struct { kind: EvalError, node_idx: u16 },
    };

    pub fn record(self: *TraceRecorder, event: TraceEvent) void {
        self.events.append(event) catch {};
    }

    pub fn dump(self: *TraceRecorder, writer: anytype) void {
        for (self.events.items) |event| {
            // Format like TigerBeetle VOPR output
            switch (event) {
                .eval_start => |e| writer.print("+ {d} {s}\n", .{e.node_idx, @tagName(e.opcode)}),
                .eval_end => |e| writer.print("- {d} -> {any} (cost={})\n", .{e.node_idx, e.result, e.cost}),
                // ...
            }
        }
    }
};
```

### 5.2 Conformance Checker

**Purpose:** Compare zigma output with Scala/Rust reference implementations.

```zig
pub const ConformanceChecker = struct {
    reference_results: HashMap(TestVector, ExpectedResult),

    pub fn check(self: *ConformanceChecker, tree: *ExprTree, ctx: *Context) ConformanceResult {
        const result = evaluate(tree, ctx);
        const expected = self.reference_results.get(tree.hash());

        if (expected) |exp| {
            if (!result.matches(exp)) {
                return .{ .mismatch = .{ .expected = exp, .got = result } };
            }
        }

        return .conformant;
    }
};
```

### 5.3 Coverage Tracker

**Purpose:** Track which opcodes/paths have been exercised.

```zig
pub const CoverageTracker = struct {
    opcode_hits: [256]u64 = [_]u64{0} ** 256,
    type_hits: [128]u64 = [_]u64{0} ** 128,
    branch_hits: HashMap(BranchKey, u64),

    pub fn record_eval(self: *CoverageTracker, node: ExprNode) void {
        self.opcode_hits[@intFromEnum(node.tag)] += 1;
        self.type_hits[node.result_type] += 1;
    }

    pub fn report(self: *CoverageTracker, writer: anytype) void {
        writer.print("Opcode Coverage:\n", .{});
        for (self.opcode_hits, 0..) |hits, opcode| {
            if (hits > 0) {
                writer.print("  {s}: {}\n", .{@tagName(@as(ExprTag, @enumFromInt(opcode))), hits});
            }
        }
    }
};
```

### 5.4 Interpreter-Specific Fault Injection

```zig
pub const InterpreterFaults = struct {
    prng: *PRNG,

    // Cost limit faults
    cost_limit_reduction: Ratio = Ratio.zero(),  // Randomly reduce limit

    // Stack faults
    stack_limit_reduction: Ratio = Ratio.zero(),  // Randomly reduce stack

    // Expression corruption
    node_corruption_probability: Ratio = Ratio.zero(),  // Mutate nodes

    pub fn maybe_reduce_cost_limit(self: *InterpreterFaults, limit: u64) u64 {
        if (self.prng.chance(self.cost_limit_reduction)) {
            // Reduce by 10-90%
            const reduction = self.prng.range_inclusive(u64, 10, 90);
            return limit * (100 - reduction) / 100;
        }
        return limit;
    }

    pub fn maybe_corrupt_node(self: *InterpreterFaults, node: *ExprNode) void {
        if (self.prng.chance(self.node_corruption_probability)) {
            // Swap opcode with similar type
            node.tag = self.prng.enum_uniform(ExprTag);
        }
    }
};
```

### 5.5 TigerBeetle-Style Output Format

**Current Zigma Output:**
```
tick 1000/10000 (1234 ticks/s) evals=1000 det_checks=1000 cost_checks=1000
```

**Enhanced Output (TigerBeetle-style):**
```
========================================
    ZIGMA Deterministic Simulation Testing
========================================

SEED=8675309
mode=swarm
ticks_max=10000

Options:
  max_depth=12
  max_nodes=150
  leaf_weight=85
  arithmetic_weight=42
  crypto_weight=0 (disabled)

Progress:
  tick 1000/10000 | 1234 ticks/s
  evals: 1000 (980 ok, 20 err)
  det_checks: 1000 (0 fail)
  cost_checks: 1000 (0 violation)
  coverage: 45/128 opcodes

========================================
PASSED (10000 ticks)
========================================

Statistics:
  evaluations: 10000 (9800 success, 200 failed)
  determinism_checks: 10000 (0 failures)
  cost_checks: 10000 (0 violations)
  coverage: 45/128 opcodes (35%)
```

---

## 6. Implementation Roadmap

### 6.1 Phase 1: Quick Wins (Low Effort, High Value)

| Task | Effort | File(s) |
|------|--------|---------|
| Improve CLI output format | 2h | `dst.zig` |
| Add swarm config generator | 2h | `dst.zig` |
| Add opcode coverage tracking | 3h | New: `checkers/coverage.zig` |

### 6.2 Phase 2: Enhanced Tracing

| Task | Effort | File(s) |
|------|--------|---------|
| Evaluation trace recorder | 4h | `trace/recorder.zig` |
| Trace serialization (JSON) | 2h | `trace/recorder.zig` |
| Trace comparison tool | 3h | New: `trace/comparator.zig` |

### 6.3 Phase 3: Conformance Testing

| Task | Effort | File(s) |
|------|--------|---------|
| Test vector loader | 3h | New: `checkers/conformance.zig` |
| Reference result cache | 2h | `checkers/conformance.zig` |
| CI integration | 2h | Build config |

### 6.4 Phase 4: Advanced Features

| Task | Effort | File(s) |
|------|--------|---------|
| Interpreter fault injection | 4h | `fault_injection/injector.zig` |
| Expression mutation | 3h | New: `generators/mutator.zig` |
| Regression detection | 4h | New: `checkers/regression.zig` |

---

## 7. Code Migration Examples

### 7.1 From TigerBeetle Ratio to Zigma

TigerBeetle:
```zig
const ratio = stdx.PRNG.ratio;
const packet_loss = ratio(prng.int_inclusive(u8, 30), 100);
```

Zigma (already compatible):
```zig
const Ratio = prng_mod.Ratio;
const constant_prob = Ratio{ .numerator = prng.range_inclusive(u64, 10, 80), .denominator = 100 };
```

### 7.2 From TigerBeetle Swarm Options to Zigma

TigerBeetle `options_swarm`:
```zig
fn options_swarm(prng: *PRNG) Simulator.Options {
    const replica_count = prng.range_inclusive(u8, 1, 6);
    const packet_loss = ratio(prng.int_inclusive(u8, 30), 100);
    // ...
}
```

Zigma equivalent:
```zig
fn options_swarm(prng: *PRNG) Options {
    return .{
        .seed = prng.int(u64),
        .ticks_max = prng.range_inclusive(u64, 1000, 100_000),
        .expr_gen = .{
            .max_depth = prng.range_inclusive(u8, 3, 15),
            .max_nodes = prng.range_inclusive(u16, 10, 500),
            .leaf_weight = if (prng.boolean()) prng.range_inclusive(u8, 0, 100) else 0,
            .arithmetic_weight = if (prng.boolean()) prng.range_inclusive(u8, 0, 100) else 0,
            // ...
        },
        .determinism_repetitions = prng.range_inclusive(u8, 2, 10),
    };
}
```

### 7.3 From TigerBeetle Checker to Zigma

TigerBeetle StateChecker pattern:
```zig
pub fn on_commit(replica: u8, op: u64, header: Header) void {
    // Track commits, check consistency
    if (self.canonical[op] != null) {
        assert(self.canonical[op].checksum == header.checksum);
    }
    self.canonical[op] = header;
}
```

Zigma DeterminismChecker (similar pattern):
```zig
pub fn check(tree: *ExprTree, ctx: *Context) DeterminismResult {
    var first_result: ?EvalResult = null;

    for (0..repetitions) |rep| {
        const result = evaluate(tree, ctx);

        if (first_result) |expected| {
            if (!expected.eql(result)) {
                return .{ .non_deterministic = ... };
            }
        } else {
            first_result = result;
        }
    }
    return .deterministic;
}
```

### 7.4 Adding Coverage Tracking (New Feature)

Inspired by TigerBeetle's grid_checker, but for opcodes:
```zig
pub const CoverageChecker = struct {
    opcode_coverage: std.EnumSet(ExprTag),
    type_coverage: std.DynamicBitSetUnmanaged,

    pub fn init(allocator: Allocator) !CoverageChecker {
        return .{
            .opcode_coverage = std.EnumSet(ExprTag){},
            .type_coverage = try std.DynamicBitSetUnmanaged.initEmpty(allocator, 128),
        };
    }

    pub fn record_evaluation(self: *CoverageChecker, tree: *ExprTree) void {
        for (tree.nodes[0..tree.node_count]) |node| {
            self.opcode_coverage.insert(node.tag);
            self.type_coverage.set(node.result_type);
        }
    }

    pub fn coverage_percentage(self: *CoverageChecker) f32 {
        const total = std.meta.fields(ExprTag).len;
        const covered = self.opcode_coverage.count();
        return @as(f32, @floatFromInt(covered)) / @as(f32, @floatFromInt(total)) * 100.0;
    }
};
```

---

## Appendix: File Mapping

| TigerBeetle File | Zigma Equivalent | Notes |
|------------------|------------------|-------|
| `src/vopr.zig` | `src/dst/dst.zig` | Main simulator |
| `src/stdx/prng.zig` | `src/dst/prng.zig` | PRNG + Ratio |
| `src/testing/fuzz.zig` | (inline in prng.zig) | Utilities |
| `src/testing/cluster.zig` | N/A | Distributed only |
| `src/testing/storage.zig` | N/A | Distributed only |
| `src/testing/packet_simulator.zig` | N/A | Distributed only |
| `src/testing/cluster/state_checker.zig` | `src/dst/checkers/determinism.zig` | Core checker |
| `src/testing/cluster/storage_checker.zig` | N/A | Distributed only |
| `src/testing/state_machine.zig` | `src/dst/generators/expr_gen.zig` | Workload gen |
| (N/A) | `src/dst/generators/context_gen.zig` | Zigma-specific |
| (N/A) | `src/dst/checkers/cost_checker.zig` | Zigma-specific |

---

## Summary

Zigma's DST implementation is already well-aligned with TigerBeetle's philosophy:
- **Seeded determinism** - Implemented
- **Ratio-based probabilities** - Implemented
- **Swarm testing concepts** - Partially implemented
- **Property checking** - Implemented (determinism, cost)

**Recommended focus:**
1. **Enhance swarm testing** - Full parameter randomization
2. **Improve output format** - TigerBeetle-style progress/results
3. **Add coverage tracking** - Know what's been tested
4. **Add conformance checking** - Compare with reference impls
5. **Add interpreter-specific faults** - Cost limits, stack limits

The distributed patterns (network, storage, replicas) are appropriately **not applicable** to zigma's single-threaded interpreter architecture.

---

*End of Adaptation Guide*
