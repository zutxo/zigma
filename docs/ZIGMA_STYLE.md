# ZIGMA_STYLE

## The Essence of Style

> "In cryptography, the devil is in the bits." — Bruce Schneier

Zigma's coding style is born from TigerBeetle's battle-tested principles, adapted for the unique
demands of blockchain script interpretation. Where TigerBeetle guards financial transactions,
Zigma guards cryptographic proofs. Both demand the same uncompromising rigor: correctness is not
negotiable, performance is not optional, and every byte matters.

## Why Have Style?

> "The design is not just what it looks like and feels like. The design is how it works." — Steve
> Jobs

Our design goals are **safety**, **determinism**, **performance**, and **developer experience**.
In that order. All four are essential. Good style advances these goals.

For a blockchain script interpreter, style is existential:
- **Safety** because we handle cryptographic secrets and validate proofs
- **Determinism** because every node must produce identical results
- **Performance** because we're called on every transaction
- **Developer experience** because we need eyes on this code

## On Determinism

> "Consensus requires that all correct nodes process the same inputs and produce the same outputs."
> — Distributed Systems, First Principles

Zigma has a **zero non-determinism policy**. Every execution of the same ErgoTree with the same
context MUST produce bit-identical results across:
- Different CPU architectures (x86, ARM, RISC-V)
- Different operating systems
- Different optimization levels
- Different points in time

This means:
- **No floating point** (ErgoTree doesn't use it anyway, but never introduce it)
- **No HashMap iteration** during serialization (iteration order is undefined)
- **No uninitialized memory reads** (use explicit zeroing)
- **No system time** during evaluation (use block height/timestamp from context)
- **No randomness** during evaluation
- **Explicit overflow handling** (use @addWithOverflow, not silent wraparound)
- **Platform-independent integer semantics** (ZigZag encoding, explicit signedness)

```zig
// WRONG: Non-deterministic iteration order
var results = std.ArrayList(u8).init(allocator);
var iter = hash_map.iterator();
while (iter.next()) |entry| {
    results.append(entry.value);  // Order varies by run!
}

// RIGHT: Deterministic via sorted keys
var keys = try allocator.alloc(KeyType, hash_map.count());
defer allocator.free(keys);
var i: usize = 0;
for (hash_map.keys()) |key| {
    keys[i] = key;
    i += 1;
}
std.sort.sort(KeyType, keys, {}, comptime std.sort.asc(KeyType));
for (keys) |key| {
    results.append(hash_map.get(key).?);
}
```

## On Simplicity And Elegance

Simplicity in Zigma means:
- One way to represent each ErgoTree type
- One code path for each opcode (version-gated, not duplicated)
- One memory layout, documented and stable
- One evaluation strategy (iterative, never recursive)

> "Simplicity and elegance are unpopular because they require hard work and discipline to achieve"
> — Edsger Dijkstra

The Scala reference is elegant but JVM-idiomatic. The Rust reference is cleaner. Our Zig
implementation should be cleaner still—every abstraction must earn its place.

## Technical Debt

Zigma has a **zero technical debt policy**. We do it right the first time because:
- A consensus bug deployed to mainnet is catastrophic
- A cryptographic weakness cannot be patched away
- The cost of "fixing it later" in blockchain code is mass coordination

> "You shall not pass!" — Gandalf

When we find a potential issue—an unchecked overflow, an unvalidated point, a cost accounting
gap—we fix it before merging. The second time may not come, and in consensus code, there is no
second chance.

## Safety

> "The rules act like the seat-belt in your car: initially they are perhaps a little uncomfortable,
> but after a while their use becomes second-nature and not using them becomes unimaginable." —
> Gerard J. Holzmann

### NASA's Power of Ten, Adapted for Zigma

1. **Use only very simple, explicit control flow.** No recursion in the interpreter—use an explicit
   work stack. The evaluator must never stack overflow regardless of input.

2. **Put a limit on everything.** Every loop has a maximum iteration count. Every collection has a
   maximum size. Every recursion depth (in parsing only) has a limit. These limits come from the
   Ergo protocol specification.

   ```zig
   // Every loop must have a bounded iteration count
   const MAX_ERGOTREE_NODES = 4096;
   
   var iterations: u32 = 0;
   while (work_stack.pop()) |work_item| : (iterations += 1) {
       if (iterations >= MAX_ERGOTREE_NODES) {
           return error.ExpressionTooComplex;
       }
       // ... process work item
   }
   ```

3. **Use explicitly-sized types.** `u32` for indices, `i64` for Ergo Long, `u256` for BigInt.
   Never use `usize` except for slice indexing where Zig requires it.

4. **Assertions are sacred.** In Zigma, assertions serve three purposes:
   - **Document invariants** for human readers
   - **Catch programmer errors** before they become consensus bugs
   - **Enable fuzzing** to find edge cases

### Assertion Discipline

The assertion density of Zigma code must average **minimum three assertions per function**:
- Precondition assertions on inputs
- Invariant assertions during processing
- Postcondition assertions on outputs

```zig
fn evaluateArithmetic(
    self: *Evaluator,
    op: ArithOp,
    left: Value,
    right: Value,
) EvalError!Value {
    // PRECONDITIONS
    assert(left.isNumeric());
    assert(right.isNumeric());
    assert(left.typeCode() == right.typeCode()); // Type checker guarantees this
    
    // COST CHECK (invariant: never execute without budget)
    const cost = self.cost_table.arithmetic_cost;
    if (self.remaining_cost < cost) {
        return error.CostLimitExceeded;
    }
    self.remaining_cost -= cost;
    
    // OPERATION
    const result = switch (op) {
        .add => blk: {
            const overflow = @addWithOverflow(left.asLong(), right.asLong());
            if (overflow[1] != 0) return error.ArithmeticOverflow;
            break :blk overflow[0];
        },
        // ... other operations
    };
    
    // POSTCONDITION
    assert(self.remaining_cost <= self.initial_cost); // Cost only decreases
    return Value.fromLong(result);
}
```

### Pair Assertions

For every critical property, assert it in at least two places:

```zig
// Assert before write
fn serializeGroupElement(self: *Serializer, point: GroupElement) !void {
    assert(point.isOnCurve()); // CRITICAL: Never serialize invalid point
    assert(point.isInSubgroup());
    
    const encoded = point.toCompressedSec1();
    try self.writer.writeAll(&encoded);
}

// Assert after read
fn deserializeGroupElement(self: *Deserializer) !GroupElement {
    var buf: [33]u8 = undefined;
    try self.reader.readNoEof(&buf);
    
    const point = GroupElement.fromCompressedSec1(&buf) orelse {
        return error.InvalidGroupElement;
    };
    
    assert(point.isOnCurve()); // CRITICAL: Verify after deserialize
    assert(point.isInSubgroup());
    return point;
}
```

### Compile-Time Assertions

Assert relationships between constants at compile time:

```zig
const ExpressionPool = struct {
    const CAPACITY = 16384;
    const NODE_SIZE = @sizeOf(ExpressionNode);
    
    // Compile-time sanity checks
    comptime {
        // Pool must be power of two for efficient indexing
        assert(@popCount(CAPACITY) == 1);
        
        // Node size must be cache-line friendly
        assert(NODE_SIZE <= 64);
        assert(NODE_SIZE >= 16);
        
        // Total pool size must fit in reasonable memory
        assert(CAPACITY * NODE_SIZE <= 4 * 1024 * 1024); // 4MB max
    }
};
```

### Memory: Static Allocation Only

All memory must be statically allocated at startup. **No dynamic allocation during evaluation.**

```zig
pub const InterpreterState = struct {
    // Pre-allocated pools - sized for worst-case ErgoTree
    expression_pool: ExpressionPool,
    constant_pool: ConstantPool,
    value_stack: ValueStack,
    work_stack: WorkStack,
    
    // Cost tracking
    remaining_cost: u64,
    
    pub fn init() InterpreterState {
        return .{
            .expression_pool = ExpressionPool.init(),
            .constant_pool = ConstantPool.init(),
            .value_stack = ValueStack.init(),
            .work_stack = WorkStack.init(),
            .remaining_cost = 0,
        };
    }
    
    pub fn reset(self: *InterpreterState, cost_limit: u64) void {
        // O(1) reset - just reset indices, don't zero memory
        self.expression_pool.reset();
        self.constant_pool.reset();
        self.value_stack.reset();
        self.work_stack.reset();
        self.remaining_cost = cost_limit;
    }
};
```

### Function Size Limit

**Hard limit: 70 lines per function.** For interpreter code, this is even more important:
- Each opcode handler should be a focused function
- Complex operations should be split into phases
- Serialization should be separate from validation

### Error Handling

All errors must be handled explicitly. In Zigma, errors fall into two categories:

1. **Validation Errors** (expected, from untrusted input):
   ```zig
   // Return error, let caller handle
   if (!point.isOnCurve()) {
       return error.InvalidGroupElement;
   }
   ```

2. **Programmer Errors** (unexpected, internal bugs):
   ```zig
   // Assert and crash - this should never happen
   assert(type_code <= MAX_TYPE_CODE);
   ```

Never silently ignore errors. Never use `catch unreachable` on fallible operations from external
input.

## Cryptographic Safety

> "In cryptography, you don't get partial credit." — Unknown

### Point Validation is Non-Negotiable

Every GroupElement deserialized from untrusted input MUST be validated:

```zig
pub fn deserializeGroupElement(bytes: *const [33]u8) !GroupElement {
    // 1. Decode the point
    const point = secp256k1.Point.decompress(bytes) orelse {
        return error.InvalidPointEncoding;
    };
    
    // 2. Verify on curve: y² = x³ + 7 (mod p)
    if (!point.isOnCurve()) {
        return error.PointNotOnCurve;
    }
    
    // 3. Verify in correct subgroup (cofactor = 1 for secp256k1, but check anyway)
    if (!point.isInPrimeOrderSubgroup()) {
        return error.PointNotInSubgroup;
    }
    
    // 4. Check for point at infinity if protocol forbids it
    if (point.isIdentity()) {
        return error.PointAtInfinity;
    }
    
    return GroupElement{ .inner = point };
}
```

### Constant-Time Operations for Secrets

Any operation that touches secret data must be constant-time:

```zig
// WRONG: Variable-time comparison
fn checkSignature(sig: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, sig, expected);  // Early exit leaks timing!
}

// RIGHT: Constant-time comparison
fn checkSignature(sig: []const u8, expected: []const u8) bool {
    return std.crypto.utils.timingSafeEql(u8, sig, expected);
}
```

Operations that MUST be constant-time in Zigma:
- Signature verification comparisons
- Secret key operations in prover mode
- Any branching on secret-dependent values

### Hash Function Usage

Use the correct hash for the correct purpose:
- **Blake2b256**: Box IDs, tree roots, ErgoTree hashing (Ergo-native)
- **SHA256**: Bitcoin compatibility, some proof constructions

```zig
const Hasher = struct {
    // Use Zig's well-tested crypto library
    pub fn blake2b256(data: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2b256.hash(data, &out, .{});
        return out;
    }
};
```

## Performance

> "The lack of back-of-the-envelope performance sketches is the root of all evil." — Rivacindela
> Hudsoni

### Know Your Costs

ErgoTree has an explicit cost model. Know it, respect it, mirror it:

| Operation | Cost (approximate) | Notes |
|-----------|-------------------|-------|
| Arithmetic | 36 | Per operation |
| Comparison | 36 | Per operation |
| Collection access | 20 | Per element |
| Hashing | 100-500 | Depends on size |
| GroupElement multiply | 2500 | Expensive! |
| Signature verify | 4000+ | Very expensive |

Design your data structures knowing these costs. A cache miss during a tight loop can cost more
than the operation itself.

### Data-Oriented Design

Structure data for cache efficiency:

```zig
// WRONG: Array of Structures (AoS) - poor cache locality
const BadNode = struct {
    opcode: u8,
    padding: [7]u8,
    left_child: u32,
    right_child: u32,
    type_code: u8,
    more_padding: [7]u8,
    value: u64,
};
const bad_nodes: [1000]BadNode = undefined; // 32KB, scattered access

// RIGHT: Structure of Arrays (SoA) - excellent cache locality
const GoodNodes = struct {
    opcodes: [1000]u8,      // 1KB, sequential scan
    left_children: [1000]u32,  // 4KB
    right_children: [1000]u32, // 4KB
    type_codes: [1000]u8,   // 1KB
    values: [1000]u64,      // 8KB
    
    // Hot path: opcode dispatch only touches opcodes array
    // Saves ~7 cache lines per 64 nodes
};
```

### Batch Operations

Where possible, batch operations for amortized costs:

```zig
// WRONG: Validate one at a time
for (group_elements) |ge| {
    if (!ge.isValid()) return error.Invalid;
}

// RIGHT: Batch validation (if library supports)
if (!GroupElement.batchValidate(group_elements)) {
    return error.Invalid;
}
```

### The Evaluation Loop

The interpreter's hot loop must be as tight as possible:

```zig
fn evaluate(self: *Evaluator) !Value {
    while (self.work_stack.pop()) |work| {
        // 1. Cost check (branch-free if possible)
        self.remaining_cost -|= work.cost; // Saturating subtract
        if (self.remaining_cost == 0) return error.CostExceeded;
        
        // 2. Dispatch (consider @setEvalBranchQuota for comptime)
        const result = switch (work.opcode) {
            inline 0x00...0xFF => |op| self.handlers[op](work),
        };
        
        // 3. Push result (no allocation, just index increment)
        self.value_stack.push(result);
    }
    
    return self.value_stack.pop();
}
```

## Developer Experience

> "There are only two hard things in Computer Science: cache invalidation, naming things, and
> off-by-one errors." — Phil Karlton

### Naming Conventions

**Domain-Specific Names** (use ErgoTree terminology):
- `SType` not `Type` (matches Scala reference)
- `GroupElement` not `Point` (Ergo terminology)
- `SigmaProp` not `CryptoProposition`
- `ErgoBox` not `UTXO`
- `ContextExtension` not `Variables`

**Prefixes for Clarity**:
- `serialize_*` / `deserialize_*` for encoding/decoding
- `validate_*` for input checking
- `eval_*` for evaluation handlers
- `cost_*` for cost-related functions

**Units in Names**:
```zig
const cost_nanoerg: u64 = ...;     // Currency amount
const size_bytes: u32 = ...;       // Byte count
const height_blocks: u32 = ...;    // Block height
const timeout_ms: u64 = ...;       // Time duration
const index_expr: u16 = ...;       // Expression pool index
```

### Protocol Version Handling

ErgoTree has multiple versions. Handle them explicitly:

```zig
pub const ProtocolVersion = enum(u8) {
    v0 = 0, // Pre-4.0 (legacy)
    v1 = 1, // Post-4.0 hard fork
    v2 = 2, // 5.0 soft fork (JIT)
    v3 = 3, // 6.0 soft fork (EIP-50)
    
    pub fn supportsJIT(self: ProtocolVersion) bool {
        return @intFromEnum(self) >= 2;
    }
    
    pub fn supportsV6Features(self: ProtocolVersion) bool {
        return @intFromEnum(self) >= 3;
    }
};

// Version-gated features
fn evalGetVar(self: *Evaluator, var_id: u8, input_index: ?u8) !Value {
    if (input_index) |idx| {
        // GetVar from another input - v6+ only
        if (!self.version.supportsV6Features()) {
            return error.FeatureNotSupported;
        }
        return self.context.getVarFromInput(idx, var_id);
    }
    return self.context.getVar(var_id);
}
```

### Comments

Comments are sentences. They explain **why**, not what:

```zig
// WRONG: States the obvious
// Increment the counter
counter += 1;

// RIGHT: Explains the why
// Skip the header byte which was already validated during deserialization.
reader.skipBytes(1);

// EXCELLENT: Documents non-obvious invariant
// The constant segregation flag guarantees all constants appear before
// expressions in the serialized form. This allows single-pass deserialization
// without backtracking, which is critical for DoS resistance.
assert(self.constants_complete);
```

### Error Messages

Error messages should help debugging:

```zig
// WRONG: Unhelpful
return error.InvalidInput;

// RIGHT: Specific
return error.TypeMismatch; // Can be pattern matched

// EXCELLENT: With context (in debug builds)
if (builtin.mode == .Debug) {
    std.log.err("Type mismatch: expected {}, got {} at expression index {}", .{
        expected_type.name(),
        actual_type.name(),
        expr_index,
    });
}
return error.TypeMismatch;
```

## Testing

### Test Categories

1. **Unit Tests**: Every function with logic
2. **Conformance Tests**: Match Scala/Rust output exactly
3. **Property Tests**: Invariants hold for random inputs
4. **Differential Tests**: Same input → same output as reference
5. **Fuzz Tests**: Find crashes and hangs
6. **Cost Tests**: Verify cost calculations match reference

### Test Naming

```zig
test "vlq: roundtrip preserves value for u64 max" { ... }
test "type_serializer: Coll[Byte] encodes as single byte 0x0E" { ... }
test "eval_add: overflow returns error not wraparound" { ... }
test "group_element: rejects point not on curve" { ... }
test "cost: arithmetic operations match CostTable.scala" { ... }
```

### Golden Tests

For serialization, use golden tests with known-good vectors:

```zig
test "ergotree: deserialize mainnet transaction" {
    // Real transaction from Ergo mainnet
    const ergotree_hex = "100204a00b08cd...";
    const expected_root_opcode = 0x96; // AND
    
    const bytes = try std.fmt.hexToBytes(ergotree_hex);
    const tree = try ErgoTree.deserialize(bytes);
    
    try std.testing.expectEqual(expected_root_opcode, tree.root.opcode);
}
```

## Dependencies

Zigma has a **minimal dependencies policy**:

**Allowed**:
- Zig standard library (std.crypto, std.mem, etc.)
- libsecp256k1 (via C bindings) - ONLY for production cryptography

**Forbidden**:
- Dynamic linking to system libraries
- Network libraries (interpreter is pure computation)
- File I/O libraries (context is passed in)

For cryptography, we have two paths:
1. **Pure Zig** (for clarity and auditability) - used in tests
2. **libsecp256k1** (for production) - battle-tested, constant-time

## The Last Stage

Keep it small. Keep it correct. Keep it fast.

Zigma's success is measured by:
- **Zero consensus bugs** in production
- **Identical results** to reference implementations
- **Sub-millisecond** typical transaction validation
- **Auditable** by cryptographers and blockchain developers

> "You don't really suppose, do you, that all your adventures and escapes were managed by mere luck,
> just for your sole benefit? You are a very fine person, Mr. Baggins, and I am very fond of you;
> but you are only quite a little fellow in a wide world after all!"
>
> "Thank goodness!" said Bilbo laughing, and handed him the tobacco-jar.

---

## Quick Reference Checklist

### Before Every Function
- [ ] Precondition assertions on all inputs
- [ ] Cost check if this is an evaluation function
- [ ] Explicit error handling (no ignored errors)

### Before Every Merge
- [ ] All tests pass (unit, conformance, property)
- [ ] No dynamic allocation in hot paths
- [ ] Determinism verified (same output on different platforms)
- [ ] Cost calculations match reference implementation

### For Cryptographic Code
- [ ] All points validated on curve and in subgroup
- [ ] Constant-time operations for secret-dependent code
- [ ] Known-answer tests from reference implementation

### For Serialization
- [ ] Roundtrip tests (deserialize(serialize(x)) == x)
- [ ] Golden tests against known-good vectors
- [ ] Malformed input tests (fuzzing)
- [ ] All bytes consumed assertion
