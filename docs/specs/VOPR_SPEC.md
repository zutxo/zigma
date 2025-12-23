# VOPR/VORTEX Deterministic Simulation Testing Framework

## Formal Technical Specification v1.0

**Document Status:** Reference Specification
**Source:** TigerBeetle (https://github.com/tigerbeetle/tigerbeetle)
**Based on:** Commit 42b495631 (December 2024)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [PRNG Module Specification](#3-prng-module-specification)
4. [Time Simulation Specification](#4-time-simulation-specification)
5. [Storage Simulation Specification](#5-storage-simulation-specification)
6. [Network Simulation Specification](#6-network-simulation-specification)
7. [Cluster Simulation Specification](#7-cluster-simulation-specification)
8. [Verification Checkers Specification](#8-verification-checkers-specification)
9. [VOPR Simulator Specification](#9-vopr-simulator-specification)
10. [VORTEX Specification](#10-vortex-specification)
11. [Invariants and Guarantees](#11-invariants-and-guarantees)
12. [Configuration Parameters Reference](#12-configuration-parameters-reference)

---

## 1. Introduction

### 1.1 Purpose

The VOPR (Viewstamped Operation Replicator) and VORTEX frameworks provide deterministic simulation testing for TigerBeetle's distributed consensus system. This specification documents the architecture, components, and protocols used to achieve:

1. **Deterministic reproducibility** - Any failure can be exactly reproduced from a seed value
2. **Accelerated testing** - One minute of simulation equals days of real-world operation
3. **Comprehensive fault injection** - Network, storage, and replica failures under controlled conditions
4. **Safety and liveness verification** - Formal checking of cluster correctness properties

### 1.2 Inspiration

The framework draws from:
- **FoundationDB** - Deterministic simulation testing methodology
- **Antithesis** - Autonomous testing platform concepts
- **WarGames (1983)** - Naming inspiration (WOPR -> VOPR)

### 1.3 Scope

This specification covers:
- VOPR: Single-process deterministic simulator
- VORTEX: Multi-process chaos testing framework
- All supporting infrastructure (PRNG, storage, network, checkers)

### 1.4 Source Files

| Component | Primary Source | Lines |
|-----------|---------------|-------|
| VOPR Main | `src/vopr.zig` | 1,785 |
| VORTEX Main | `src/vortex.zig` | 105 |
| Cluster | `src/testing/cluster.zig` | 1,195 |
| Storage | `src/testing/storage.zig` | 1,246 |
| Network | `src/testing/packet_simulator.zig` | 533 |
| PRNG | `src/stdx/prng.zig` | 679 |
| Time | `src/testing/time.zig` | 98 |
| State Checker | `src/testing/cluster/state_checker.zig` | ~500 |
| Storage Checker | `src/testing/cluster/storage_checker.zig` | ~600 |

---

## 2. Terminology

### 2.1 Core Concepts

| Term | Definition |
|------|------------|
| **Seed** | 64-bit unsigned integer determining all PRNG output |
| **Tick** | Discrete unit of simulated time advancement |
| **Ratio** | Probability expressed as numerator/denominator (no floats) |
| **Core** | Subset of replicas forming a strongly-connected component |
| **Safety** | Property that incorrect states are never reached |
| **Liveness** | Property that the system eventually makes progress |

### 2.2 Replica States

| State | Description |
|-------|-------------|
| `up` | Replica is running and participating in consensus |
| `down` | Replica has crashed, not responding |
| `reformatting` | Replica is recovering with `tigerbeetle recover` |
| `paused` | Replica frozen (simulates VM migration) |

### 2.3 Network States

| State | Description |
|-------|-------------|
| `connected` | Path allows message delivery |
| `partitioned` | Path blocks all messages |
| `clogged` | Path temporarily at capacity |

---

## 3. PRNG Module Specification

### 3.1 Overview

The PRNG module provides deterministic pseudo-random number generation. All randomness in the simulation flows through this module, ensuring reproducibility from a single seed.

**Source:** `src/stdx/prng.zig`

### 3.2 Algorithm

**Type:** XoShiro256++ (4 × u64 state)

**Initialization:** SplitMix64 hash function expands seed to state:

```
state[0] = split_mix_64(seed)
state[1] = split_mix_64(seed)
state[2] = split_mix_64(seed)
state[3] = split_mix_64(seed)
```

Where `split_mix_64` is:
```
z = (seed +% 0x9e3779b97f4a7c15)
z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9
z = (z ^ (z >> 27)) *% 0x94d049bb133111eb
return z ^ (z >> 31)
```

### 3.3 State Structure

```zig
const PRNG = struct {
    s: [4]u64,  // 256-bit state
};
```

### 3.4 Core Operations

#### 3.4.1 `next() -> u64`
Generates next 64-bit value using XoShiro256++ algorithm.

#### 3.4.2 `from_seed(seed: u64) -> PRNG`
Creates deterministic PRNG from 64-bit seed.

#### 3.4.3 `fill(buffer: []u8) -> void`
Fills buffer with random bytes.

### 3.5 Ratio Type

**Purpose:** Express probabilities without floating-point arithmetic.

```zig
pub const Ratio = struct {
    numerator: u64,    // INVARIANT: numerator <= denominator
    denominator: u64,  // INVARIANT: denominator != 0
};
```

**Operations:**
- `ratio(n, d)` - Constructor with assertions
- `Ratio.zero()` - Returns {0, 1}
- `chance(r: Ratio) -> bool` - Returns true with probability n/d

### 3.6 Integer Generation

| Function | Description |
|----------|-------------|
| `int(T)` | Uniform random integer of type T |
| `int_inclusive(T, max)` | Uniform in [0, max] |
| `range_inclusive(T, min, max)` | Uniform in [min, max] |

**Algorithm:** Lemire's method (unbiased, no modulo bias)

### 3.7 Enum Operations

| Function | Description |
|----------|-------------|
| `enum_uniform(E)` | Random enum value (uniform) |
| `enum_weighted(E, weights)` | Random enum with weights |
| `enum_weights(E)` | Generate swarm testing weights |

### 3.8 Seed Parsing

Seeds can be provided as:
- 64-bit decimal integer: `"12345"`
- 40-character Git SHA (truncated): `"a1b2c3d4..."`

**Requirement:** Same seed + same Git commit = identical simulation.

### 3.9 Critical Invariant

**NO FLOATING POINT IN PUBLIC API**

This ensures:
1. Determinism across platforms
2. Isolation from stdlib changes
3. Reproducible probability calculations

---

## 4. Time Simulation Specification

### 4.1 Overview

Time simulation replaces real clocks with tick-based deterministic time.

**Source:** `src/testing/time.zig`

### 4.2 TimeSim Structure

```zig
pub const TimeSim = struct {
    resolution: u64,           // Nanoseconds per tick
    offset_type: OffsetType,   // Clock behavior model
    offset_coefficient_A: i64, // Primary coefficient
    offset_coefficient_B: i64, // Secondary coefficient
    offset_coefficient_C: u32, // Tertiary coefficient
    prng: PRNG,                // For non-ideal mode
    ticks: u64,                // Current tick count
    epoch: i64,                // Base timestamp
};
```

### 4.3 Offset Types

#### 4.3.1 Linear
```
offset(t) = A * t + B
```
- A: Drift per tick (nanoseconds)
- B: Initial offset

#### 4.3.2 Periodic
```
offset(t) = A * sin(t * 2π / B)
```
- A: Amplitude
- B: Period in ticks

#### 4.3.3 Step
```
offset(t) = A if t > B else 0
```
- A: Step amplitude
- B: Step point (tick)

#### 4.3.4 Non-Ideal
```
phase = t * 2π / (B + normal(0, 10))
offset(t) = A * sin(phase) + random(-C, C)
```
- A: Amplitude
- B: Base period
- C: Random offset bound

### 4.4 Time Functions

| Function | Returns |
|----------|---------|
| `monotonic()` | `ticks * resolution` (nanoseconds) |
| `realtime()` | `epoch + monotonic - offset(ticks)` |
| `tick()` | Increments ticks by 1 |

### 4.5 Default Resolution

```zig
resolution = constants.tick_ms * ns_per_ms
```

Typically 1ms per tick for cluster testing.

---

## 5. Storage Simulation Specification

### 5.1 Overview

In-memory storage with simulated faults and latency for testing storage subsystems.

**Source:** `src/testing/storage.zig`

### 5.2 Storage Structure

```zig
pub const Storage = struct {
    allocator: Allocator,
    size: u64,
    options: Options,
    prng: PRNG,

    memory: []u8,           // Pristine data
    memory_written: BitSet, // Written sectors
    faults: BitSet,         // Faulty sectors
    overlays: IOPS,         // Misdirect overlays

    reads: PriorityQueue(*Read),
    writes: PriorityQueue(*Write),

    ticks: u64,
    faulty: bool,  // Master fault enable
};
```

### 5.3 Configuration Options

```zig
pub const Options = struct {
    size: u64,
    seed: u64,
    replica_index: ?u8,

    // Latency (exponential distribution)
    read_latency_min: Duration,
    read_latency_mean: Duration,
    write_latency_min: Duration,
    write_latency_mean: Duration,

    // Fault probabilities
    read_fault_probability: Ratio,
    write_fault_probability: Ratio,
    write_misdirect_probability: Ratio,
    crash_fault_probability: Ratio,

    // Coordination
    fault_atlas: ?*ClusterFaultAtlas,
    grid_checker: ?*GridChecker,
};
```

### 5.4 Fault Types

#### 5.4.1 Read Fault
Corrupts sector data during read operation.
- Probability: `read_fault_probability`
- Scope: Faulty areas only

#### 5.4.2 Write Fault
Corrupts sector data during write operation.
- Probability: `write_fault_probability`
- Scope: Faulty areas only

#### 5.4.3 Write Misdirect
Write lands on wrong sector (but correct data format).
- Probability: `write_misdirect_probability`
- Constraint: Same zone, aligned offset
- Implementation: Overlay system preserves pristine data

#### 5.4.4 Crash Fault
Corrupts pending write target during crash.
- Probability: `crash_fault_probability`
- Triggered: In `reset()` for pending writes

### 5.5 Latency Model

Latency uses exponential distribution:
```
latency = min + exponential(mean - min)
```

Where `exponential(λ)` = `-ln(random()) * λ`

### 5.6 Fault Atlas

**Purpose:** Coordinate faults across replicas to ensure recoverability.

```zig
pub const ClusterFaultAtlas = struct {
    pub const Options = struct {
        faulty_superblock: bool,
        faulty_wal_headers: bool,
        faulty_wal_prepares: bool,
        faulty_client_replies: bool,
        faulty_grid: bool,
    };
};
```

**Invariant:** At least one replica has valid copy of any data for repair.

### 5.7 Zone-Specific Fault Rules

| Zone | Fault Policy |
|------|--------------|
| superblock | 1 fault per area + 1 during crash |
| wal_headers | Distributed via ClusterFaultAtlas |
| wal_prepares | Distributed via ClusterFaultAtlas |
| client_replies | Distributed via ClusterFaultAtlas |
| grid | Distributed via ClusterFaultAtlas (disabled if R≤2) |

### 5.8 Operations

#### 5.8.1 Read
```zig
pub fn read(
    zone: Zone,
    offset: u64,
    buffer: []u8,
    callback: fn(*Read) void,
) void
```
Queued with `ready_at = now + latency`.

#### 5.8.2 Write
```zig
pub fn write(
    zone: Zone,
    offset: u64,
    buffer: []const u8,
    callback: fn(*Write) void,
) void
```
Queued with `ready_at = now + latency`.

#### 5.8.3 Reset (Crash)
```zig
pub fn reset() void
```
- Cancels pending reads/writes
- Applies crash faults to pending write targets

#### 5.8.4 Tick
```zig
pub fn tick() void
```
- Increments `ticks`
- Completes ready operations (callback invocation)

### 5.9 Liveness Mode Transition

```zig
pub fn transition_to_liveness_mode() void
```
- Disables all fault injection
- Clears fault bits

---

## 6. Network Simulation Specification

### 6.1 Overview

Packet-based network simulation with delays, loss, replay, and partitions.

**Source:** `src/testing/packet_simulator.zig`

### 6.2 PacketSimulator Structure

```zig
pub const PacketSimulator = struct {
    options: Options,
    prng: PRNG,
    ticks: u64,
    links: []Link,
    recorded: ArrayList(RecordedPacket),

    // Partition state
    auto_partition: []bool,
    auto_partition_active: bool,
    auto_partition_stability: u32,
};
```

### 6.3 Configuration Options

```zig
pub const PacketSimulatorOptions = struct {
    node_count: u8,
    client_count: u8,
    seed: u64,

    // Delay model
    one_way_delay_mean: Duration,
    one_way_delay_min: Duration,

    // Loss and replay
    packet_loss_probability: Ratio,
    packet_replay_probability: Ratio,

    // Partitioning
    partition_mode: PartitionMode,
    partition_symmetry: PartitionSymmetry,
    partition_probability: Ratio,
    unpartition_probability: Ratio,
    partition_stability: u32,
    unpartition_stability: u32,

    // Capacity
    path_maximum_capacity: u8,
    path_clog_duration_mean: Duration,
    path_clog_probability: Ratio,
};
```

### 6.4 Link Structure

Each source-target pair has a dedicated link:

```zig
const Link = struct {
    queue: PriorityQueue(LinkPacket),
    filter: LinkFilter,           // Allowed commands
    drop_packet_fn: ?DropFn,      // Custom drop logic
    record: LinkFilter,           // Commands to record
    clogged_till: Instant,        // Clog expiry
};
```

### 6.5 Partition Modes

#### 6.5.1 None
No automatic partitioning.

#### 6.5.2 Uniform Size
- Partition size drawn uniformly from [1, n-1]
- Replicas randomly assigned to partitions

#### 6.5.3 Uniform Partition
- Each replica assigned uniformly at random
- Biases toward equal-size partitions

#### 6.5.4 Isolate Single
- Exactly one replica isolated
- Remaining replicas fully connected

### 6.6 Partition Symmetry

| Mode | Behavior |
|------|----------|
| `symmetric` | A↔B blocked if partitioned |
| `asymmetric` | A→B may work while B→A blocked |

### 6.7 Delay Model

```
delay = one_way_delay_min + exponential(one_way_delay_mean - one_way_delay_min)
```

### 6.8 Operations

#### 6.8.1 Submit Packet
```zig
pub fn submit_packet(packet: Packet, path: Path) void
```
1. Check link filter (drop if command not allowed)
2. Check packet loss probability
3. Check path clogged status
4. Calculate `ready_at = now + delay`
5. Enqueue to link priority queue

#### 6.8.2 Tick
```zig
pub fn tick() void
```
1. Increment `ticks`
2. Update partition state (stability, transitions)
3. Process clog expiry

#### 6.8.3 Deliver
```zig
pub fn deliver() bool
```
1. Find packet with earliest `ready_at`
2. If `ready_at <= now`, deliver and optionally replay
3. Return true if delivered

### 6.9 Path Clogging

Simulates temporary network congestion:
- Probability: `path_clog_probability` per tick
- Duration: `exponential(path_clog_duration_mean)`
- Effect: All packets on path delayed until clog expires

### 6.10 Liveness Mode Transition

```zig
pub fn transition_to_liveness_mode(core: Core) void
```
- Fully connects all core replicas
- Disables partition probability
- Clears all filters for core paths

---

## 7. Cluster Simulation Specification

### 7.1 Overview

Orchestrates multiple replicas, clients, storage, and network in-memory.

**Source:** `src/testing/cluster.zig`

### 7.2 ClusterType Structure

```zig
pub fn ClusterType(StateMachineType: type) type {
    return struct {
        replicas: []Replica,
        replica_health: []ReplicaHealth,
        replica_times: []TimeSim,

        clients: []?Client,
        client_eviction_reasons: []?Eviction.Reason,

        storages: []Storage,
        network: *Network,

        state_checker: StateChecker,
        storage_checker: StorageChecker,
        grid_checker: *GridChecker,
        manifest_checker: ManifestChecker,
    };
}
```

### 7.3 Replica Health States

```zig
pub const ReplicaHealth = union(enum) {
    up: struct { paused: bool },
    down,
    reformatting,
};
```

### 7.4 Cluster Operations

#### 7.4.1 Initialization
```zig
pub fn init(allocator: Allocator, options: Options) !*Cluster
```
- Creates replicas with StorageFaultAtlas coordination
- Initializes network with packet simulator
- Sets up verification checkers

#### 7.4.2 Tick
```zig
pub fn tick() void
```
1. Advance all replica times
2. Tick network (deliver packets)
3. Tick each running replica
4. Process storage completions
5. Update checkers

#### 7.4.3 Replica Operations

| Operation | Effect |
|-----------|--------|
| `replica_crash(i)` | Stops replica, resets storage |
| `replica_restart(i)` | Reinitializes replica from storage |
| `replica_reformat(i)` | Runs recovery, clears faults |
| `replica_pause(i)` | Freezes replica (no tick/IO) |
| `replica_unpause(i)` | Resumes replica |

#### 7.4.4 Client Operations

| Operation | Effect |
|-----------|--------|
| `register(i)` | Registers client session |
| `request(i, op, data)` | Submits client request |

### 7.5 Configuration Options

```zig
pub const Options = struct {
    cluster_id: u128,
    replica_count: u8,
    standby_count: u8,
    client_count: u8,
    storage_size_limit: u64,
    seed: u64,
    releases: []Release,
    client_release: Release,
    reformats_max: u8,
    state_machine: StateMachine.Options,
};
```

### 7.6 Release Management

```zig
pub const Release = struct {
    release: vsr.Release,
    release_client_min: vsr.Release,
};
```

Supports multi-version testing with rolling upgrades.

---

## 8. Verification Checkers Specification

### 8.1 State Checker

**Source:** `src/testing/cluster/state_checker.zig`

**Purpose:** Verify commit consistency across replicas.

#### 8.1.1 Tracked State
- Canonical commit sequence
- Per-replica commit history
- Client reply consistency

#### 8.1.2 Invariants Verified
1. All replicas agree on committed operations
2. Commit sequence is append-only
3. Client replies match committed state
4. No divergent commits (split-brain)

#### 8.1.3 Key Functions
```zig
pub fn on_commit(replica: u8, op: u64, header: Header) void
pub fn replica_convergence(replica: u8) bool
pub fn assert_cluster_convergence() void
```

### 8.2 Storage Checker

**Source:** `src/testing/cluster/storage_checker.zig`

**Purpose:** Verify byte-for-byte storage identity.

#### 8.2.1 Verification Points
- At compaction bars (grid blocks)
- At checkpoints (superblock, client replies, grid)

#### 8.2.2 Exclusions
- SuperBlock headers (replica-specific data)
- WAL (intentional differences during operation)

#### 8.2.3 Key Functions
```zig
pub fn on_checkpoint(replica: u8) void
pub fn assert_storage_identity() void
```

### 8.3 Grid Checker

**Source:** `src/testing/cluster/grid_checker.zig`

**Purpose:** Verify LSM grid block coherence.

#### 8.3.1 Verification
- Block checksums match
- Block addresses valid
- No orphaned blocks

### 8.4 Journal Checker

**Source:** `src/testing/cluster/journal_checker.zig`

**Purpose:** Verify WAL journal consistency.

#### 8.4.1 Verification
- Header checksums valid
- Prepare checksums valid
- Sequence numbers monotonic

### 8.5 Manifest Checker

**Source:** `src/testing/cluster/manifest_checker.zig`

**Purpose:** Verify LSM forest manifest integrity.

#### 8.5.1 Verification
- Table references valid
- Level structure correct
- Compaction state consistent

---

## 9. VOPR Simulator Specification

### 9.1 Overview

Main deterministic simulation orchestrator.

**Source:** `src/vopr.zig`

### 9.2 Simulator Structure

```zig
pub const Simulator = struct {
    prng: *PRNG,
    options: Options,
    cluster: *Cluster,
    workload: Workload,

    replica_releases: []usize,
    replica_releases_limit: usize,
    replica_reformats: Core,
    replica_crash_stability: []usize,

    reply_sequence: ReplySequence,
    core: Core,

    requests_sent: usize,
    requests_replied: usize,
    requests_idle: bool,
};
```

### 9.3 Simulation Modes

#### 9.3.1 Lite Mode (`--lite`)
```zig
replica_count = 3
standby_count = 0
// Minimal faults, crash detection focus
```

#### 9.3.2 Swarm Mode (default)
```zig
replica_count = random(1, 6)
standby_count = random(0, standbys_max)
client_count = random(1, clients_max * 2 - 1)
// Full randomization of all parameters
```

#### 9.3.3 Performance Mode (`--performance`)
```zig
replica_count = 6
standby_count = 0
client_count = 4
// Minimal faults, throughput measurement
```

### 9.4 Simulation Phases

#### 9.4.1 Safety Phase
**Duration:** Up to `ticks_max_requests` (default: 40M)

**Behavior:**
1. Process `requests_max` operations
2. Inject faults randomly
3. Crash/restart replicas
4. Upgrade replica versions
5. Verify no split-brain

**Exit Conditions:**
- All requests processed AND at least one replica upgraded
- Timeout reached

#### 9.4.2 Liveness Phase
**Duration:** Up to `ticks_max_convergence` (default: 10M)

**Behavior:**
1. Select core (view-change quorum of connected replicas)
2. Restart crashed core replicas
3. Heal partitions affecting core
4. Disable faults on core storages
5. Wait for convergence

**Convergence Criteria:**
- No pending client requests
- All core replicas at same release
- All core replicas converged (state_checker)
- No pending journal repair
- No pending sync content
- All core replicas at identical checkpoint

### 9.5 Tick Function

```zig
pub fn tick() void {
    cluster.tick();
    tick_requests();
    tick_upgrade();
    tick_crash();
    tick_pause();
}
```

### 9.6 Core Selection

A core is a strongly-connected subgraph containing a view-change quorum:

```zig
fn random_core(prng: *PRNG, replica_count: u8, standby_count: u8) Core
fn full_core(replica_count: u8, standby_count: u8) Core
```

### 9.7 Failure Diagnosis

```zig
pub fn cluster_recoverable() bool {
    if (core_missing_primary()) return false;
    if (core_missing_quorum()) return false;
    if (core_missing_prepare()) return false;
    if (core_missing_blocks()) return false;
    if (core_missing_reply()) return false;
    if (core_reformat_evicted()) return false;
    return true;
}
```

### 9.8 CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--lite` | false | Run lite mode |
| `--performance` | false | Run performance mode |
| `--seed <value>` | random | PRNG seed |
| `--ticks-max-requests` | 40M | Safety phase timeout |
| `--ticks-max-convergence` | 10M | Liveness phase timeout |
| `--packet-loss-ratio` | varies | Override packet loss |
| `--replica-missing` | none | Crash specific replica |
| `--requests-max` | varies | Override request count |

---

## 10. VORTEX Specification

### 10.1 Overview

Multi-process chaos testing with real client drivers.

**Source:** `src/vortex.zig`, `src/testing/vortex/`

### 10.2 Architecture

```
┌─────────────────────────────────────────────┐
│               Supervisor                     │
│  (Linux namespace: fresh PID/network)        │
├─────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  │Replica 0│ │Replica 1│ │Replica 2│  ...   │
│  └─────────┘ └─────────┘ └─────────┘        │
├─────────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐    │
│  │         Driver (Zig/Java/Rust)      │    │
│  │         (uses tb_client library)    │    │
│  └─────────────────────────────────────┘    │
├─────────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐    │
│  │            Workload                  │    │
│  │  (generates operations, validates)   │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

### 10.3 Components

#### 10.3.1 Supervisor
**Source:** `src/testing/vortex/supervisor.zig`

Responsibilities:
- Spawn and manage child processes
- Inject network faults
- Monitor progress
- Terminate on completion/failure

#### 10.3.2 Driver
**Sources:**
- `src/testing/vortex/zig_driver.zig`
- `src/testing/vortex/java_driver/`
- `src/testing/vortex/rust_driver/`

Responsibilities:
- Connect to cluster via tb_client
- Forward operations from workload
- Report results back

#### 10.3.3 Workload
**Source:** `src/testing/vortex/workload.zig`

Responsibilities:
- Generate TigerBeetle operations
- Track model state
- Validate results

### 10.4 Workload Model

```zig
const Model = struct {
    accounts: ArrayList(Account),
    pending_transfers: HashMap(u128, void),
    transfers_created: u64,
};
```

### 10.5 Command Generation

```zig
fn random_command(prng: *PRNG, model: *Model) Command {
    return prng.enum_weighted(Command, .{
        .create_accounts = if (model.accounts.len < 128) 1 else 0,
        .create_transfers = if (model.accounts.len > 2) 10 else 0,
        .lookup_all_accounts = 0,
        .lookup_latest_transfers = 5,
    });
}
```

### 10.6 Comparison: VOPR vs VORTEX

| Aspect | VOPR | VORTEX |
|--------|------|--------|
| Determinism | Yes | No |
| Speed | Fast | Slow |
| Processes | Single | Multiple |
| Faults | All simulated | Network + real crashes |
| Reproducibility | Exact | Logs only |
| Coverage | Algorithm depth | Integration breadth |

---

## 11. Invariants and Guarantees

### 11.1 Determinism Invariants

1. **Seed Reproducibility:** Same seed + git commit = identical simulation
2. **No External Dependencies:** No real time, network, or disk I/O
3. **No Floating Point:** PRNG uses integer arithmetic only
4. **Tick-Based Time:** Discrete time advancement

### 11.2 Safety Invariants

1. **No Split-Brain:** Committed operations never diverge
2. **Durability:** Committed operations survive failures
3. **Consistency:** All replicas agree on commit sequence

### 11.3 Liveness Invariants

1. **Progress:** Core replicas eventually converge
2. **Repair:** Faulty data eventually repaired
3. **Upgrade:** Replicas eventually reach latest version

### 11.4 Fault Tolerance Invariants

1. **Redundancy:** At least one replica has valid copy
2. **Recovery:** Reformatted replicas can rejoin
3. **Bounded Faults:** Fault atlas prevents unrecoverable states

---

## 12. Configuration Parameters Reference

### 12.1 Cluster Parameters

| Parameter | Type | Range | Default |
|-----------|------|-------|---------|
| `replica_count` | u8 | 1-6 | swarm |
| `standby_count` | u8 | 0-N | swarm |
| `client_count` | u8 | 1-N | swarm |
| `storage_size_limit` | u64 | - | 200 MiB |

### 12.2 Network Parameters

| Parameter | Type | Range | Default |
|-----------|------|-------|---------|
| `one_way_delay_min` | Duration | 0-30ms | swarm |
| `one_way_delay_mean` | Duration | 30-100ms | swarm |
| `packet_loss_probability` | Ratio | 0-30% | swarm |
| `packet_replay_probability` | Ratio | 0-50% | swarm |
| `partition_mode` | enum | - | swarm |
| `partition_probability` | Ratio | 0-3% | swarm |
| `path_clog_probability` | Ratio | 0-2% | swarm |

### 12.3 Storage Parameters

| Parameter | Type | Range | Default |
|-----------|------|-------|---------|
| `read_latency_min` | Duration | 0-30ms | swarm |
| `read_latency_mean` | Duration | 0-100ms | swarm |
| `write_latency_min` | Duration | 0-30ms | swarm |
| `write_latency_mean` | Duration | 0-1000ms | swarm |
| `read_fault_probability` | Ratio | 0-10% | swarm |
| `write_fault_probability` | Ratio | 0-10% | swarm |
| `crash_fault_probability` | Ratio | 80-100% | swarm |

### 12.4 Replica Parameters

| Parameter | Type | Range | Default |
|-----------|------|-------|---------|
| `crash_probability` | Ratio | 0.00002% | per tick |
| `crash_stability` | u32 | 0-1000 | ticks |
| `restart_probability` | Ratio | 0.0002% | per tick |
| `restart_stability` | u32 | 0-1000 | ticks |
| `reformat_probability` | Ratio | 30% | per restart |
| `pause_probability` | Ratio | 0.00008% | per tick |

### 12.5 Request Parameters

| Parameter | Type | Range | Default |
|-----------|------|-------|---------|
| `requests_max` | usize | - | journal_slot_count * 3 |
| `request_probability` | Ratio | 1-100% | per tick |
| `idle_on_probability` | Ratio | 0-20% | per tick |
| `idle_off_probability` | Ratio | 10-20% | per tick |

---

## Appendix A: File Reference

| File Path | Purpose |
|-----------|---------|
| `src/vopr.zig` | Main VOPR simulator |
| `src/vortex.zig` | VORTEX entry point |
| `src/stdx/prng.zig` | PRNG implementation |
| `src/testing/time.zig` | Time simulation |
| `src/testing/storage.zig` | Storage simulation |
| `src/testing/packet_simulator.zig` | Network simulation |
| `src/testing/cluster.zig` | Cluster orchestration |
| `src/testing/cluster/network.zig` | Network layer |
| `src/testing/cluster/message_bus.zig` | Message bus |
| `src/testing/cluster/state_checker.zig` | State verification |
| `src/testing/cluster/storage_checker.zig` | Storage verification |
| `src/testing/cluster/grid_checker.zig` | Grid verification |
| `src/testing/cluster/journal_checker.zig` | Journal verification |
| `src/testing/cluster/manifest_checker.zig` | Manifest verification |
| `src/testing/fuzz.zig` | Fuzz utilities |
| `src/testing/state_machine.zig` | Test state machine |
| `src/testing/vortex/supervisor.zig` | VORTEX supervisor |
| `src/testing/vortex/workload.zig` | VORTEX workload |
| `docs/internals/vopr.md` | VOPR documentation |
| `docs/internals/testing.md` | Testing documentation |

---

## Appendix B: VOPR Output Format

### Columns

1. Replica index
2. Event: `!` crash, `^` recover, ` ` commit, `$` sync, `X` reformat, `[` checkpoint start, `]` checkpoint done
3. Role: `/` primary, `\` backup, `|` standby, `~` syncing, `#` crashed, `F` reformatting
4. Status: `.` normal, `v` view_change, `r` recovering, `h` recovering_head, `s` sync
5. View number
6. Checkpoint/Commit: `checkpoint/commit_min/commit_max`
7. Journal ops: `min:maxJo`
8. Journal faults: `faulty/dirtyJ!`
9. WAL ops: `min:maxWo`
10. Sync ops: `<min:max>`
11. Release: `vCurrent:Max`
12. Grid acquired: `NNGa`
13. Grid remote queue: `NNG!`
14. Grid missing: `NNG?`
15. Pipeline prepares: `N/NPp`
16. Pipeline requests: `N/NRq`

---

*End of Specification*
