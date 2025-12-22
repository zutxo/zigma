# Skills Reference for Zigma Development

Practical tools, techniques, and knowledge areas needed for effective Zigma development.

## Essential Zig Patterns

### Compile-Time Assertions
```zig
comptime {
    assert(@sizeOf(Value) <= 64);
    assert(max_stack_depth >= 256);
    assert(TypePool.LONG == 5);  // Verify type code
}
```

### Error Handling (TigerBeetle style)
```zig
// Return error union with explicit handling
fn deserialize(bytes: []const u8) DeserializeError!ExprTree {
    if (bytes.len == 0) return error.EmptyInput;

    const tag = bytes[0];
    if (tag > 255) return error.InvalidTag;  // Impossible, but defensive

    // ...
}

// At call site: handle all errors explicitly
const tree = deserialize(bytes) catch |err| switch (err) {
    error.EmptyInput => return .{ .empty = true },
    error.InvalidTag => {
        log.warn("Invalid tag in input", .{});
        return error.MalformedInput;
    },
    else => return err,
};
```

### Static Allocation Patterns
```zig
// Pre-allocate all pools at init
pub const Evaluator = struct {
    work_stack: [256]WorkItem = undefined,
    value_stack: [256]Value = undefined,
    work_sp: u16 = 0,
    value_sp: u16 = 0,

    pub fn init() Evaluator {
        return .{};  // All fields have defaults
    }
};

// Never allocate during evaluation
fn evaluate(self: *Evaluator) !Value {
    // Only use pre-allocated arrays
    while (self.work_sp > 0) {
        // ...
    }
}
```

### Iterative vs Recursive
```zig
// BAD: Recursive (can stack overflow)
fn evalRecursive(node: *Node) Value {
    return switch (node.tag) {
        .add => evalRecursive(node.left) + evalRecursive(node.right),
        // ...
    };
}

// GOOD: Iterative with explicit stack (TigerBeetle pattern)
fn evalIterative(self: *Evaluator, root: NodeIdx) !Value {
    self.pushWork(root, .evaluate);

    while (self.work_sp > 0) {
        const work = self.popWork();
        switch (work.phase) {
            .evaluate => {
                // Push children, then self for compute
                self.pushWork(work.node_idx, .compute);
                for (self.getChildren(work.node_idx)) |child| {
                    self.pushWork(child, .evaluate);
                }
            },
            .compute => {
                // Children already evaluated, compute result
                const result = self.computeNode(work.node_idx);
                self.pushValue(result);
            },
        }
    }

    return self.popValue();
}
```

### Tagged Unions for Values
```zig
pub const Value = union(enum) {
    unit: void,
    boolean: bool,
    int: i32,
    long: i64,
    coll: struct { ptr: [*]u8, len: u32, elem_type: u8 },

    // Type-safe extraction
    pub fn asInt(self: Value) ?i32 {
        return if (self == .int) self.int else null;
    }

    pub fn asIntOrError(self: Value) !i32 {
        return self.asInt() orelse error.TypeMismatch;
    }
};
```

## Reference Implementation Lookup

### Finding Scala Implementation
```bash
# Find opcode implementation
grep -rn "case OpCode" ~/ergotree-research/scala/sigmastate --include="*.scala" -A 10

# Find method implementation
grep -rn "def serialize" ~/ergotree-research/scala/sigmastate --include="*.scala" -A 5

# Find cost model
grep -rn "costOf\|JitCost" ~/ergotree-research/scala/sigmastate --include="*.scala"

# Find type definitions
grep -rn "case class.*SType" ~/ergotree-research/scala/sigmastate --include="*.scala"
```

### Finding Rust Implementation
```bash
# Find operation eval
ls ~/ergotree-research/rust/sigma-rust/ergotree-interpreter/src/eval/

# Read specific operation
cat ~/ergotree-research/rust/sigma-rust/ergotree-interpreter/src/eval/calc_blake2b256.rs

# Find serialization
grep -rn "impl.*Serialize" ~/ergotree-research/rust/sigma-rust --include="*.rs" -A 10

# Find type codes
cat ~/ergotree-research/rust/sigma-rust/ergotree-ir/src/serialization/op_code.rs | head -100
```

### Comparing Implementations
```bash
# Compare opcode handling
diff <(grep -A5 "CalcBlake2b256" ~/ergotree-research/scala/sigmastate/**/*.scala) \
     <(grep -A5 "calc_blake2b256" ~/ergotree-research/rust/sigma-rust/**/*.rs)
```

## Debugging Techniques

### Deserialization Debugging
```zig
// Add temporary debug prints
fn deserializeExpr(reader: *Reader, depth: u8) !ExprNode {
    const tag = try reader.readByte();
    std.debug.print("tag=0x{x:0>2} pos={d} depth={d}\n", .{ tag, reader.pos, depth });
    // ...
}
```

### CLI Testing
```bash
# Test specific ErgoTree hex
./zig-out/bin/zigma eval 00d191a37300 --height=500000

# Deserialize and print tree
./zig-out/bin/zigma deserialize 00d191a37300

# Hash test
./zig-out/bin/zigma hash blake2b256 deadbeef
```

### DST for Bug Finding
```bash
# Run with specific seed (reproducible)
./zig-out/bin/zigma-dst --seed=12345 --ticks=10000

# Run with git hash (for CI)
./zig-out/bin/zigma-dst --seed=$(git rev-parse HEAD | head -c8) --ticks=100000

# Quick coverage check
./zig-out/bin/zigma-dst --seed=1 --ticks=1000 2>&1 | grep "cov="
```

## Cost Model Reference

### JIT Costs (v2+, current mainnet)
```zig
// From evaluator.zig JIT_COSTS table
const JIT_COSTS = .{
    .comparison = 20,      // GT, GE, LT, LE
    .arithmetic = 15,      // Plus, Minus, etc.
    .logical = 20,         // BinAnd, BinOr
    .height = 26,          // Context.HEIGHT
    .constant = 5,         // Constant value
    .decode_point = 300,   // DecodePoint
    .exponentiate = 900,   // Group exponentiation
    .multiply_group = 40,  // Point addition
    .blake2b256_base = 20, // Hash base cost
    .hash_per_chunk = 7,   // Per 128-byte chunk
};
```

### Per-Item Costs (collections)
```zig
// From CollectionCost
pub const map = PerItemCost{ .base = 20, .per_chunk = 1, .chunk_size = 10 };
pub const filter = PerItemCost{ .base = 20, .per_chunk = 1, .chunk_size = 10 };
pub const fold = PerItemCost{ .base = 3, .per_chunk = 1, .chunk_size = 10 };
```

## Conformance Testing

### Test Vector Format
```json
{
  "id": "height_gt_100",
  "ergotree_hex": "0008d19373007202930100",
  "context": { "height": 500 },
  "expected": {
    "success": { "type": "SBoolean", "value": true },
    "cost": 400
  }
}
```

### Running Conformance Tests
```bash
# All tests
./zig/zig build test -- --test-filter "conformance"

# Specific test
./zig/zig build test -- --test-filter "mainnet"

# With verbose output
./zig/zig build test 2>&1 | head -100
```

## Cryptographic Operations

### secp256k1 Point Operations
```zig
const secp256k1 = @import("crypto/secp256k1.zig");

// Decode compressed point (33 bytes)
const point = try secp256k1.Point.decode(compressed_bytes);

// Scalar multiplication (g^x)
const result = point.mul(scalar);

// Point addition
const sum = point.add(other_point);

// Validate point is on curve and in subgroup
if (!point.isValid()) return error.InvalidPoint;
```

### Hash Operations
```zig
const hash = @import("crypto/hash.zig");

// Blake2b256
var digest: [32]u8 = undefined;
hash.blake2b256(input, &digest);

// SHA256
hash.sha256(input, &digest);
```

### BigInt Operations
```zig
const BigInt256 = @import("crypto/bigint.zig").BigInt256;

// Create from bytes (big-endian)
const a = BigInt256.fromBytes(bytes);

// Arithmetic
const sum = a.add(b) catch return error.Overflow;
const diff = a.sub(b) catch return error.Underflow;
const prod = a.mul(b) catch return error.Overflow;
const quot = a.div(b) catch return error.DivisionByZero;

// Modular arithmetic (mod secp256k1 order)
const reduced = a.mod(secp256k1.ORDER);
```

## Task Tracking (bd)

### Common Commands
```bash
# Find work
bd ready                      # Available tasks
bd list --status=open         # All open
bd show zigma-xxxx            # Details

# Work on task
bd update zigma-xxxx --status=in_progress

# Complete
bd close zigma-xxxx --reason="Implemented in commit abc123"

# Create new
bd create --title="Implement Slice opcode" --type=task --priority=2
bd create --title="Fix overflow bug" --type=bug --priority=1

# Dependencies
bd dep add zigma-child zigma-parent   # child depends on parent
bd blocked                            # Show blocked tasks

# Sync (important for ephemeral branches)
bd sync --from-main
```

## Git Workflow

### Before Commit
```bash
./zig/zig fmt src/          # Format
./zig/zig build test        # All tests pass
git status                  # Review changes
```

### Commit Format
```bash
# Concise message (sacrifice grammar for brevity)
git commit -m "$(cat <<'EOF'
Fix MIN_INT/-1 overflow in divInts, add slice opcode

- evaluator: check MIN_INT before @divTrunc
- collection: implement slice with bounds checking
EOF
)"
```

### Session End Protocol
```bash
git status                  # Check changes
git add <files>             # Stage code
bd sync --from-main         # Pull beads updates
git commit -m "..."         # Commit
```

## Common Gotchas

### Type Code vs Opcode Confusion
- Type codes: 0x01-0x70 (1-112)
- Opcodes: 0x71+ (113+)
- `LastConstantCode = 112`, `OpCode = LastConstantCode + shift`

### Integer Overflow Cases
```zig
// Must check these explicitly:
// - MIN_INT / -1 (result overflows)
// - MIN_INT * -1 (result overflows)
// - -MIN_INT (result overflows)
// - MAX_INT + 1, MIN_INT - 1
```

### Method Call Deserialization Order
```
MethodCall = type_code | method_id | type_args | receiver | args
PropertyCall = type_code | prop_id | receiver
```

### Collection Element Types
```zig
// Coll[Byte] = type_code 12 with elem_type 2
// Coll[Int] = type_code 12 with elem_type 4
// Coll[Box] = type_code 12 with elem_type 99
```

---

*Keep this document updated as you discover new patterns and gotchas.*
