# Deterministic Simulation Testing Design Reference

## TigerBeetle's VOPR/VORTEX Architecture

**Document Type:** Design Reference Guide
**Purpose:** Narrative explanation of DST architecture for implementers

---

## Table of Contents

1. [Philosophy and Approach](#1-philosophy-and-approach)
2. [Architecture Overview](#2-architecture-overview)
3. [Determinism Deep Dive](#3-determinism-deep-dive)
4. [Fault Injection Patterns](#4-fault-injection-patterns)
5. [Swarm Testing](#5-swarm-testing)
6. [Verification Strategies](#6-verification-strategies)
7. [Code Examples](#7-code-examples)
8. [Design Rationale](#8-design-rationale)
9. [Implementation Patterns](#9-implementation-patterns)

---

## 1. Philosophy and Approach

### 1.1 The Core Insight

Traditional testing approaches have a fundamental limitation: **they can only test scenarios the developer imagined**. Real-world failures often arise from unexpected combinations of:

- Network conditions (partitions, delays, reordering)
- Timing (race conditions, slow operations)
- Storage failures (corruption, misdirects)
- Concurrent operations
- Version mismatches

### 1.2 Deterministic Simulation Testing (DST)

DST inverts the testing paradigm:

1. **Replace non-determinism** - Stub out all sources of non-determinism (time, network, disk)
2. **Control via PRNG** - All "random" behavior derives from a single seed
3. **Accelerate time** - Simulate days of operation in minutes
4. **Inject faults** - Systematically test failure scenarios
5. **Reproduce exactly** - Any failure can be replayed from seed + commit

### 1.3 The Power of Reproduction

When VOPR discovers a failure:
```
SEED=8675309
```

Any developer can:
1. Check out the exact commit
2. Run with the same seed
3. See the exact same sequence of events
4. Debug with full visibility

This transforms distributed systems debugging from archaeology to science.

---

## 2. Architecture Overview

### 2.1 VOPR (Single-Process Simulator)

```
┌─────────────────────────────────────────────────────────────────────┐
│                           VOPR Simulator                            │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                      Cluster                                │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │    │
│  │  │Replica 0│  │Replica 1│  │Replica 2│  │Replica N│       │    │
│  │  │  + Time │  │  + Time │  │  + Time │  │  + Time │       │    │
│  │  │  + Store│  │  + Store│  │  + Store│  │  + Store│       │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘       │    │
│  │       │            │            │            │             │    │
│  │       └────────────┴─────┬──────┴────────────┘             │    │
│  │                          │                                  │    │
│  │                ┌─────────┴──────────┐                      │    │
│  │                │  PacketSimulator   │                      │    │
│  │                │   (Network Sim)    │                      │    │
│  │                └─────────┬──────────┘                      │    │
│  │                          │                                  │    │
│  │  ┌─────────┐  ┌─────────┴─────────┐  ┌─────────┐          │    │
│  │  │Client 0 │──│   Message Bus     │──│Client N │          │    │
│  │  └─────────┘  └───────────────────┘  └─────────┘          │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     Verification Layer                       │   │
│  │  ┌─────────────┐ ┌────────────────┐ ┌──────────────────┐   │   │
│  │  │StateChecker │ │StorageChecker  │ │ GridChecker      │   │   │
│  │  └─────────────┘ └────────────────┘ └──────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                        PRNG (Seed)                            │  │
│  │                     ↓ Derives All Randomness ↓                │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 VORTEX (Multi-Process Chaos Testing)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Linux Namespace (Isolated)                        │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                      Supervisor Process                         │ │
│  │   • Spawns child processes                                      │ │
│  │   • Injects network faults                                      │ │
│  │   • Monitors progress                                           │ │
│  │   • Terminates on completion                                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│              ┌───────────────┼───────────────┐                      │
│              ▼               ▼               ▼                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │   Replica 0    │  │   Replica 1    │  │   Replica 2    │        │
│  │ (child process)│  │ (child process)│  │ (child process)│        │
│  │                │  │                │  │                │        │
│  │  Real disk I/O │  │  Real disk I/O │  │  Real disk I/O │        │
│  │  Real network  │  │  Real network  │  │  Real network  │        │
│  └────────────────┘  └────────────────┘  └────────────────┘        │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                     Driver Process                              │ │
│  │   • Zig / Java / Rust implementation                           │ │
│  │   • Uses tb_client library                                     │ │
│  │   • Sends requests to cluster                                  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Workload Process                             │ │
│  │   • Generates operations                                        │ │
│  │   • Maintains model state                                       │ │
│  │   • Validates results                                          │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Component Relationships

```
                    ┌──────────────────┐
                    │      Seed        │
                    │     (u64)        │
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Cluster PRNG  │ │  Network PRNG   │ │  Storage PRNG   │
│                 │ │                 │ │                 │
│ • Replica IDs   │ │ • Packet delays │ │ • Read latency  │
│ • Client order  │ │ • Packet loss   │ │ • Write latency │
│ • Upgrade times │ │ • Partitions    │ │ • Fault sectors │
│ • Crash timing  │ │ • Clogging      │ │ • Misdirects    │
└─────────────────┘ └─────────────────┘ └─────────────────┘
         │                   │                   │
         └───────────────────┴───────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │  Deterministic │
                    │   Simulation   │
                    └────────────────┘
```

---

## 3. Determinism Deep Dive

### 3.1 The Determinism Chain

Every source of non-determinism must be controlled:

```
┌────────────────────────────────────────────────────────────────┐
│                    Sources of Non-Determinism                   │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Real System              │   Simulation                       │
│  ───────────              │   ──────────                       │
│                           │                                    │
│  System clock             │   TimeSim (tick-based)             │
│  Network I/O              │   PacketSimulator                  │
│  Disk I/O                 │   Storage (in-memory)              │
│  Thread scheduling        │   Single-threaded tick loop        │
│  Random numbers           │   Seeded PRNG                      │
│  HashMap iteration        │   Avoided (use arrays)             │
│  Floating point           │   Avoided (use Ratio)              │
│                           │                                    │
└────────────────────────────────────────────────────────────────┘
```

### 3.2 PRNG Design Decisions

**Why XoShiro256++?**
- Fast: ~4 cycles per 64-bit output
- Quality: Passes all BigCrush tests
- Portable: Same output on all platforms
- Simple: Easy to verify correctness

**Why no floating point?**
```zig
// BAD: Platform-dependent rounding
fn probability(prng: *PRNG, p: f64) bool {
    return prng.float() < p;  // Different on x86 vs ARM!
}

// GOOD: Integer-only arithmetic
fn chance(prng: *PRNG, ratio: Ratio) bool {
    return prng.int_inclusive(u64, ratio.denominator - 1) < ratio.numerator;
}
```

### 3.3 Tick-Based Time

```
Real Time                    Simulated Time
─────────                    ──────────────

wall clock                   ticks counter
    │                             │
    ▼                             ▼
unpredictable                predictable
    │                             │
    ▼                             ▼
"after 5ms"                  "after 5 ticks"
means ???                    means exactly 5
```

**Benefits:**
- Reproducible timing
- Instant "sleep" (just increment counter)
- No real-time dependencies

---

## 4. Fault Injection Patterns

### 4.1 Storage Fault Injection

```
┌─────────────────────────────────────────────────────────────────┐
│                     Storage Fault Model                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Write Path                                                      │
│  ──────────                                                      │
│                                                                  │
│  Application ──write()──▶ [Decision Point]                      │
│                                │                                 │
│                    ┌───────────┼───────────┐                    │
│                    ▼           ▼           ▼                    │
│               [Normal]    [Corrupt]   [Misdirect]               │
│                    │           │           │                    │
│                    ▼           ▼           ▼                    │
│               Write to    Write bad   Write to                  │
│               correct     data to     wrong                     │
│               sector      correct     sector                    │
│                           sector                                │
│                                                                  │
│  Read Path                                                       │
│  ─────────                                                       │
│                                                                  │
│  Application ◀──read()─── [Decision Point]                      │
│                                │                                 │
│                    ┌───────────┴───────────┐                    │
│                    ▼                       ▼                    │
│               [Normal]               [Corrupt]                  │
│                    │                       │                    │
│                    ▼                       ▼                    │
│               Return                  Return                    │
│               pristine                corrupted                 │
│               data                    data                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Network Fault Injection

```
┌─────────────────────────────────────────────────────────────────┐
│                    Network Fault Model                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Packet Journey                                                  │
│  ──────────────                                                  │
│                                                                  │
│  Sender ──submit()──▶ [Link Queue]                              │
│                            │                                     │
│            ┌───────────────┼───────────────┐                    │
│            ▼               ▼               ▼                    │
│        [Filter]        [Loss]         [Partition]               │
│            │               │               │                    │
│            ▼               ▼               ▼                    │
│     Allowed by        Random drop     Path blocked              │
│     command set?                      by partition              │
│            │                                                    │
│            ▼                                                    │
│        [Delay]                                                  │
│            │                                                    │
│            ▼                                                    │
│     Calculate ready_at = now + exponential(mean)                │
│            │                                                    │
│            ▼                                                    │
│        [Clog Check]                                             │
│            │                                                    │
│            ▼                                                    │
│     If clogged, extend delay                                    │
│            │                                                    │
│            ▼                                                    │
│        [Enqueue]                                                │
│            │                                                    │
│            ▼                                                    │
│     Priority queue ordered by ready_at                          │
│            │                                                    │
│            ▼                                                    │
│        [Deliver]                                                │
│            │                                                    │
│            ▼                                                    │
│     When ready_at <= now, deliver to receiver                   │
│            │                                                    │
│            ▼                                                    │
│        [Replay?]                                                │
│            │                                                    │
│            ▼                                                    │
│     Possibly clone and re-submit                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 Partition Modes

```
┌───────────────────────────────────────────────────────────────────┐
│                      Partition Modes                               │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│  uniform_size                    uniform_partition                 │
│  ─────────────                   ─────────────────                 │
│                                                                    │
│   ┌─────┐ ┌─────┐               ┌─────┐ ┌─────┐                   │
│   │ R0  │ │ R1  │               │ R0  │ │ R1  │                   │
│   └─────┘ └─────┘               └─────┘ └─────┘                   │
│      ╳      ╳                      │      ╳                       │
│   ┌─────┐ ┌─────┐               ┌─────┐ ┌─────┐                   │
│   │ R2  │ │ R3  │               │ R2  │ │ R3  │                   │
│   └─────┘ └─────┘               └─────┘ └─────┘                   │
│                                                                    │
│   Size N drawn randomly          Each node assigned              │
│   Nodes assigned randomly        uniformly at random             │
│                                                                    │
│  isolate_single                  asymmetric                       │
│  ──────────────                  ─────────                        │
│                                                                    │
│   ┌─────┐ ┌─────┐               ┌─────┐ ───▶ ┌─────┐             │
│   │ R0  │─│ R1  │               │ R0  │      │ R1  │             │
│   └─────┘ └─────┘               └─────┘ ◀─╳─ └─────┘             │
│      ╳                                                            │
│   ┌─────┐ ┌─────┐               A can send to B,                 │
│   │ R2  │─│ R3  │               but B cannot send to A           │
│   └─────┘ └─────┘                                                 │
│                                                                    │
│   One node fully isolated                                         │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

### 4.4 Replica Fault Injection

```
┌───────────────────────────────────────────────────────────────────┐
│                    Replica Lifecycle                               │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│                         ┌─────────┐                                │
│                         │ Running │                                │
│                         │   (up)  │                                │
│                         └────┬────┘                                │
│                              │                                     │
│          ┌───────────────────┼───────────────────┐                │
│          │                   │                   │                │
│          ▼                   ▼                   ▼                │
│    ┌──────────┐       ┌──────────┐       ┌──────────┐            │
│    │  Crash   │       │  Pause   │       │ Upgrade  │            │
│    │  (down)  │       │ (paused) │       │(restart) │            │
│    └────┬─────┘       └────┬─────┘       └────┬─────┘            │
│         │                  │                  │                   │
│         │                  │                  │                   │
│    ┌────┴─────┐            │             ┌────┴─────┐            │
│    │ Reformat │            │             │   New    │            │
│    │(optional)│            │             │ Version  │            │
│    └────┬─────┘            │             └────┬─────┘            │
│         │                  │                  │                   │
│         └───────────┬──────┴──────────────────┘                   │
│                     │                                              │
│                     ▼                                              │
│               ┌──────────┐                                         │
│               │ Restart  │                                         │
│               │   (up)   │                                         │
│               └──────────┘                                         │
│                                                                    │
│  Probabilities (per tick):                                        │
│  • crash:    ~0.00002% (rare but eventual)                        │
│  • pause:    ~0.00008% (simulates VM migration)                   │
│  • upgrade:  ~0.0001%  (version advancement)                      │
│  • restart:  ~0.0002%  (after crash/pause)                        │
│  • reformat: ~30%      (of restarts)                              │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

---

## 5. Swarm Testing

### 5.1 Concept

Instead of testing with fixed parameters, **randomize the parameter space** to discover emergent behaviors:

```
Traditional Testing:
────────────────────
  Test Case 1: 3 replicas, no faults
  Test Case 2: 3 replicas, 10% packet loss
  Test Case 3: 5 replicas, partition

Swarm Testing:
──────────────
  Each run: random(1-6) replicas,
            random(0-30%) packet loss,
            random partition mode,
            random storage latency,
            random crash probability,
            ...
```

### 5.2 Parameter Generation

```zig
fn options_swarm(prng: *PRNG) Options {
    // Cluster configuration
    const replica_count = prng.range_inclusive(u8, 1, 6);
    const standby_count = prng.int_inclusive(u8, constants.standbys_max);
    const client_count = prng.range_inclusive(u8, 1, constants.clients_max * 2 - 1);

    // Network configuration
    const packet_loss = ratio(prng.int_inclusive(u8, 30), 100);
    const partition_mode = prng.enum_uniform(PartitionMode);
    const partition_probability = ratio(prng.int_inclusive(u8, 3), 100);

    // Storage configuration
    const read_latency = range_inclusive_ms(prng, 0, 100);
    const write_latency = range_inclusive_ms(prng, 0, 1000);
    const read_fault_prob = ratio(prng.range_inclusive(u8, 0, 10), 100);

    // ... combine into Options struct
}
```

### 5.3 Enum Weight Swarm

For weighted random selection, swarm testing randomizes the weights themselves:

```zig
pub fn enum_weights(prng: *PRNG, E: type) EnumWeightsType(E) {
    var weights: EnumWeightsType(E) = undefined;

    // Randomly enable/disable each variant
    for (fields) |field| {
        // Some variants completely disabled (weight=0)
        // Others get random weight (1-100)
        @field(weights, field.name) = if (prng.chance(ratio(70, 100)))
            prng.range_inclusive(u64, 1, 100)
        else
            0;
    }

    return weights;
}
```

---

## 6. Verification Strategies

### 6.1 Safety vs Liveness

```
┌───────────────────────────────────────────────────────────────────┐
│                   Two-Phase Verification                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Phase 1: SAFETY (40M ticks default)                              │
│  ─────────────────────────────────                                │
│                                                                    │
│  "Under arbitrary failures, bad things never happen"              │
│                                                                    │
│  • Inject all fault types                                         │
│  • Process many requests                                          │
│  • Verify:                                                        │
│    - No split-brain (divergent commits)                           │
│    - No data loss for committed operations                        │
│    - No assertion failures                                        │
│                                                                    │
│  Phase 2: LIVENESS (10M ticks default)                            │
│  ─────────────────────────────────────                            │
│                                                                    │
│  "Given a stable subset, good things eventually happen"           │
│                                                                    │
│  • Select core (view-change quorum)                               │
│  • Heal partitions affecting core                                 │
│  • Disable faults on core                                         │
│  • Restart crashed core replicas                                  │
│  • Verify:                                                        │
│    - All core replicas converge                                   │
│    - Pending requests complete                                    │
│    - Upgrades propagate                                           │
│    - Storage becomes byte-identical                               │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

### 6.2 State Checker Flow

```
                    ┌─────────────────────┐
                    │   Replica Commits   │
                    │     Operation       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   State Checker     │
                    │   Records Commit    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
    ┌─────────────────────┐          ┌─────────────────────┐
    │ Compare to Canonical │          │ Track Client Reply  │
    │   Commit Sequence    │          │    Consistency     │
    └──────────┬──────────┘          └──────────┬──────────┘
               │                                 │
               ▼                                 ▼
    ┌─────────────────────┐          ┌─────────────────────┐
    │ If mismatch:        │          │ If reply differs:   │
    │   SPLIT-BRAIN!      │          │   CONSISTENCY       │
    │   FAILURE           │          │   VIOLATION!        │
    └─────────────────────┘          └─────────────────────┘
```

### 6.3 Storage Checker Flow

```
                    ┌─────────────────────┐
                    │  Replica Reaches    │
                    │    Checkpoint       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Storage Checker    │
                    │  Captures Snapshot  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Compare Byte-for-  │
                    │  Byte with Others   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
    ┌─────────────────────┐          ┌─────────────────────┐
    │ Exclude Intentional │          │  Grid Blocks        │
    │ Differences:        │          │  Must Match         │
    │ • SuperBlock headers│          │                     │
    │ • WAL (async)       │          │                     │
    └─────────────────────┘          └─────────────────────┘
```

---

## 7. Code Examples

### 7.1 PRNG Initialization

```zig
// From src/stdx/prng.zig

pub fn from_seed(seed: u64) PRNG {
    var s = seed;
    return .{ .s = .{
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
    } };
}

fn split_mix_64(s: *u64) u64 {
    s.* +%= 0x9e3779b97f4a7c15;

    var z = s.*;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}
```

### 7.2 Ratio-Based Probability

```zig
// From src/stdx/prng.zig

pub const Ratio = struct {
    numerator: u64,
    denominator: u64,

    pub fn zero() Ratio {
        return .{ .numerator = 0, .denominator = 1 };
    }
};

pub fn chance(prng: *PRNG, probability: Ratio) bool {
    assert(probability.denominator > 0);
    assert(probability.numerator <= probability.denominator);
    return prng.int_inclusive(u64, probability.denominator - 1)
        < probability.numerator;
}
```

### 7.3 Packet Delay Calculation

```zig
// From src/testing/fuzz.zig

pub fn random_int_exponential(prng: *PRNG, avg: anytype) @TypeOf(avg) {
    const T = @TypeOf(avg);
    comptime assert(@typeInfo(T).int.signedness == .unsigned);

    // Exponential distribution via inverse transform sampling
    const r = prng.random();
    const exp = r.floatExp(f64) * @as(f64, @floatFromInt(avg));
    return std.math.lossyCast(T, exp);
}

// Usage in packet simulator
fn calculate_delay(self: *PacketSimulator, path: Path) Duration {
    const min = self.options.one_way_delay_min.ns;
    const mean = self.options.one_way_delay_mean.ns;
    const extra = fuzz.random_int_exponential(&self.prng, mean - min);
    return .{ .ns = min + extra };
}
```

### 7.4 Fault Atlas Distribution

```zig
// Conceptual example from storage fault coordination

fn generate_fault_distribution(prng: *PRNG, replica_count: u8) []FaultMask {
    var masks: [MAX_REPLICAS]FaultMask = undefined;

    // For each sector that may be faulty...
    for (0..sector_count) |sector| {
        // Ensure at least one replica has valid copy
        const valid_replica = prng.int_inclusive(u8, replica_count - 1);

        // Other replicas may or may not have faults
        for (0..replica_count) |replica| {
            if (replica == valid_replica) {
                masks[replica].set_valid(sector);
            } else if (prng.chance(ratio(10, 100))) {
                masks[replica].set_faulty(sector);
            }
        }
    }

    return masks[0..replica_count];
}
```

### 7.5 Simulation Main Loop

```zig
// From src/vopr.zig

pub fn main() !void {
    // ... initialization ...

    var simulator = try Simulator.init(gpa, &prng, options);
    defer simulator.deinit(gpa);

    // Phase 1: Safety
    var tick: u64 = 0;
    while (tick < ticks_max_requests) : (tick += 1) {
        const requests_replied_old = simulator.requests_replied;
        simulator.tick();  // Advance simulation

        // Reset tick counter on progress
        if (simulator.requests_replied > requests_replied_old) {
            tick = 0;
        }

        // Check completion
        if (simulator.requests_replied == simulator.options.requests_max) {
            break;
        }
    }

    // Phase 2: Liveness
    const core = random_core(prng, replica_count, standby_count);
    simulator.transition_to_liveness_mode(core);

    tick = 0;
    while (tick < ticks_max_convergence) : (tick += 1) {
        simulator.tick();
        if (simulator.pending() == null) {
            break;  // Converged!
        }
    }

    if (simulator.pending()) |reason| {
        // Check if failure is expected (unrecoverable state)
        if (!simulator.cluster_recoverable()) {
            return;  // Known limitation
        }
        // Real failure!
        fatal(.liveness, "no convergence: {s}", .{reason});
    }
}
```

---

## 8. Design Rationale

### 8.1 Why Single-Process Simulation?

**Advantages:**
- Perfect determinism (no thread scheduling variance)
- Fast (no IPC overhead)
- Simple debugging (single stack trace)
- Complete control (can inspect all state)

**Trade-offs:**
- Doesn't test real I/O paths
- Doesn't test actual network code
- May miss threading bugs

**Solution:** Use VOPR for algorithm testing + VORTEX for integration testing.

### 8.2 Why Ratio Instead of Float?

```
// Problem: Floating point is non-deterministic across platforms

x86:    0.1 + 0.2 = 0.30000000000000004
ARM:    0.1 + 0.2 = 0.30000000000000004 (usually, but not guaranteed!)
WASM:   0.1 + 0.2 = ??? (implementation-defined)

// Solution: Use integer ratios

Ratio(1, 10) + Ratio(2, 10) = Ratio(3, 10)  // Always exact!
```

### 8.3 Why Tick-Based Time?

```
// Problem: Real time is non-deterministic

Thread 1: sleep(10ms) → actually sleeps 10.3ms
Thread 2: sleep(10ms) → actually sleeps 10.1ms
Race condition depends on which wakes first!

// Solution: Discrete tick advancement

Tick 100: Thread 1 schedules work for tick 110
Tick 100: Thread 2 schedules work for tick 110
Tick 110: Both wake simultaneously (deterministic order)
```

### 8.4 Why Separate Safety and Liveness Phases?

**Safety Phase:**
- Tests that the system never enters an incorrect state
- Allows unlimited failures
- Runs until requests complete (or timeout)

**Liveness Phase:**
- Tests that the system eventually makes progress
- Requires a stable "core" subset
- Heals failures to give system a chance

**Rationale:** Distributed systems can't guarantee liveness under arbitrary failures (FLP impossibility). By separating phases, we can verify safety unconditionally and liveness conditionally.

### 8.5 Why Fault Atlas?

Without coordination:
- Random faults might corrupt all copies of data
- System becomes unrecoverable (by design)
- False failures in testing

With Fault Atlas:
- Guarantee at least one valid copy exists
- Test recovery mechanisms
- Avoid false failures from "impossible" scenarios

---

## 9. Implementation Patterns

### 9.1 Pattern: Seeded Component

```zig
pub const Component = struct {
    prng: PRNG,
    // ... other state

    pub fn init(seed: u64) Component {
        return .{
            .prng = PRNG.from_seed(seed),
        };
    }

    pub fn random_action(self: *Component) void {
        if (self.prng.chance(ratio(30, 100))) {
            // 30% chance action
        }
    }
};
```

### 9.2 Pattern: Priority Queue Scheduling

```zig
const ScheduledItem = struct {
    ready_at: Instant,
    data: Data,

    fn less_than(_: void, a: ScheduledItem, b: ScheduledItem) Order {
        return std.math.order(a.ready_at.ns, b.ready_at.ns);
    }
};

pub const Scheduler = struct {
    queue: PriorityQueue(ScheduledItem, void, ScheduledItem.less_than),
    now: Instant,

    pub fn schedule(self: *Scheduler, item: Data, delay: Duration) void {
        self.queue.add(.{
            .ready_at = self.now.add(delay),
            .data = item,
        });
    }

    pub fn tick(self: *Scheduler) void {
        self.now = self.now.add(.{ .ns = tick_resolution });
        while (self.queue.peek()) |item| {
            if (item.ready_at.ns > self.now.ns) break;
            const ready = self.queue.remove();
            self.deliver(ready.data);
        }
    }
};
```

### 9.3 Pattern: Fault Injection Layer

```zig
pub const FaultyStorage = struct {
    inner: *Storage,
    prng: PRNG,
    fault_probability: Ratio,

    pub fn read(self: *FaultyStorage, offset: u64, buffer: []u8) void {
        self.inner.read(offset, buffer);

        if (self.prng.chance(self.fault_probability)) {
            // Corrupt the data
            self.prng.fill(buffer[0..1]);  // Corrupt first byte
        }
    }
};
```

### 9.4 Pattern: Stability Tracking

```zig
// Prevent rapid oscillation (crash → restart → crash)

pub const StabilityTracker = struct {
    last_transition: u64,
    min_stability: u64,

    pub fn can_transition(self: *StabilityTracker, current_tick: u64) bool {
        return current_tick >= self.last_transition + self.min_stability;
    }

    pub fn record_transition(self: *StabilityTracker, current_tick: u64) void {
        self.last_transition = current_tick;
    }
};
```

### 9.5 Pattern: Core Selection

```zig
// Select a subset that can make progress

pub fn select_core(
    prng: *PRNG,
    replica_count: u8,
    quorum_size: u8,
) Core {
    var core = Core{};

    // Must have at least quorum_size replicas
    while (core.count() < quorum_size) {
        const replica = prng.int_inclusive(u8, replica_count - 1);
        core.set(replica);
    }

    return core;
}
```

---

## Appendix: Key Files Quick Reference

| File | What to Learn |
|------|---------------|
| `src/vopr.zig` | Main simulation loop, CLI, phases |
| `src/stdx/prng.zig` | PRNG implementation, Ratio type |
| `src/testing/cluster.zig` | Cluster orchestration |
| `src/testing/storage.zig` | Storage fault injection |
| `src/testing/packet_simulator.zig` | Network fault injection |
| `src/testing/time.zig` | Time simulation |
| `src/testing/fuzz.zig` | Exponential distribution, utilities |
| `src/testing/cluster/state_checker.zig` | Safety verification |
| `src/testing/cluster/storage_checker.zig` | Storage verification |

---

*End of Design Reference*
