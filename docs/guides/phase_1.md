## Phase 1: Foundation Layer

### Prompt 1.1: VLQ and ZigZag Encoding

```
TASK: Implement VLQ and ZigZag encoding with full test coverage

CONTEXT (From TigerBeetle Engineers):
"This is your first module. It sets the pattern for everything else.
Requirements:
1. Zero allocations
2. Explicit error handling (no exceptions)
3. Const-correct (reader methods don't mutate state)
4. Comprehensive assertions in debug mode
5. Test with boundary values

Use fixed-size buffers. The VLQ spec says max 10 bytes for 64-bit."

PREREQUISITE KNOWLEDGE:
- VLQ uses 7 bits per byte, MSB is continuation flag
- ZigZag maps signed to unsigned: 0→0, -1→1, 1→2, -2→3...
- ErgoTree uses VLQ for: lengths, indices, unsigned integers
- ErgoTree uses ZigZag+VLQ for: signed integers (Byte, Short, Int, Long)
- Reference: ErgoTree Spec Appendix E

REFERENCE CODE (From Scala):
```scala
// From sigmastate.serialization.CoreByteWriter
def putULong(x: Long): this.type = {
  var value = x
  while ((value & 0xFFFFFFFFFFFFFF80L) != 0L) {
    put((value & 0x7F | 0x80).toByte)
    value >>>= 7
  }
  put(value.toByte)
}

// ZigZag encoding
def encodeZigZag64(n: Long): Long = (n << 1) ^ (n >> 63)
def decodeZigZag64(n: Long): Long = (n >>> 1) ^ -(n & 1)
```

CREATE FILE: src/serialization/vlq.zig

IMPLEMENTATION CHECKLIST:
[ ] VLQ.encodeUnsigned - encode u16/u32/u64 to bytes
[ ] VLQ.decodeUnsigned - decode bytes to u16/u32/u64  
[ ] VLQ.encodedSize - calculate size without encoding
[ ] ZigZag.encode - i8/i16/i32/i64 to unsigned
[ ] ZigZag.decode - unsigned to signed
[ ] SignedVLQ.encode - combines ZigZag + VLQ
[ ] SignedVLQ.decode - combines VLQ + ZigZag

TESTS TO INCLUDE:
[ ] Roundtrip for all powers of 2
[ ] Roundtrip for max/min values of each type
[ ] Boundary: 127→128 (1 byte→2 bytes)
[ ] Boundary: 16383→16384 (2 bytes→3 bytes)
[ ] ZigZag: verify 0,-1,1,-2,2 map to 0,1,2,3,4
[ ] Error: VLQ too long (>10 bytes)
[ ] Error: unexpected EOF during decode

ASSERTIONS (Debug mode):
[ ] assert(encoded_size <= VLQ_MAX_BYTES)
[ ] assert(decoded_value == original_value) in tests
```

### Prompt 1.2: Type System Definitions

```
TASK: Implement type system with index-based representation

CONTEXT (From Zig Experts):
"Recursive types with pointers are problematic in Zig. Use indices.

Instead of:
  collection: *const SType  // Pointer to element type

Use:
  collection: TypeIndex     // Index into type pool

This also makes serialization trivial and enables copy-free operations."

PREREQUISITE KNOWLEDGE:
- ErgoTree has ~15 primitive types (see Spec Table 8)
- Type constructors: Coll[T], Option[T], (T1,T2,...), T1=>T2
- Type codes encode type structure compactly
- Types are compared structurally (not by identity)
- Any is top type, Unit is bottom type

REFERENCE (From Rust sigma-rust):
```rust
pub enum SType {
    SAny,
    SUnit,
    SBoolean,
    SByte,
    SShort,
    SInt,
    SLong,
    SBigInt,
    SGroupElement,
    SSigmaProp,
    SBox,
    SAvlTree,
    SOption(Box<SType>),
    SColl(Box<SType>),
    STuple(STuple),
    SFunc(SFunc),
    // ...
}
```

CREATE FILE: src/core/types.zig

KEY DESIGN:
```zig
/// Type index for pool-based storage
pub const TypeIndex = u16;
pub const INVALID_TYPE: TypeIndex = std.math.maxInt(TypeIndex);

/// Primitive type codes (embeddable)
pub const PrimType = enum(u8) {
    boolean = 1,
    byte = 2,
    short = 3,
    int = 4,
    long = 5,
    big_int = 6,
    group_element = 7,
    sigma_prop = 8,
};

/// Type representation without pointers
pub const SType = union(enum) {
    /// Primitive types (leaf nodes)
    prim: PrimType,
    
    /// Predefined complex types
    predef: PredefType,
    
    /// Collection: element type is another TypeIndex
    coll: TypeIndex,
    
    /// Option: wrapped type is another TypeIndex
    option: TypeIndex,
    
    /// Tuple: indices stored in separate array
    tuple: struct { start: u16, len: u8 },
    
    /// Function: param indices and result index
    func: struct { params_start: u16, params_len: u8, result: TypeIndex },
};

/// Type pool for storing types without recursion
pub const TypePool = struct {
    types: [MAX_TYPES]SType,
    /// Tuple element storage
    tuple_elements: [MAX_TUPLE_ELEMENTS]TypeIndex,
    /// Function parameter storage  
    func_params: [MAX_FUNC_PARAMS]TypeIndex,
    
    type_count: u16,
    tuple_elem_count: u16,
    func_param_count: u16,
    
    pub fn addColl(self: *TypePool, elem_type: TypeIndex) !TypeIndex;
    pub fn addOption(self: *TypePool, inner_type: TypeIndex) !TypeIndex;
    pub fn addTuple(self: *TypePool, elements: []const TypeIndex) !TypeIndex;
    pub fn addFunc(self: *TypePool, params: []const TypeIndex, result: TypeIndex) !TypeIndex;
    
    pub fn equals(self: *const TypePool, a: TypeIndex, b: TypeIndex) bool;
    pub fn isSubtype(self: *const TypePool, sub: TypeIndex, super: TypeIndex) bool;
};
```

TESTS:
[ ] Create each primitive type
[ ] Create nested types: Coll[Coll[Byte]]
[ ] Type equality: structural comparison
[ ] Subtyping: Int <: Any, Coll[Int] <: Coll[Any]
[ ] Pool exhaustion handling
```

### Prompt 1.3: Opcode Definitions

```
TASK: Define complete opcode catalog with metadata

CONTEXT (From Ergo Core Developers):
"The opcode space is organized as:
- 0x00-0x80: Constants (type in opcode)
- 0x81-0xFF: Operations

Each operation needs:
- Opcode byte
- Mnemonic name
- Input types (for type checking)
- Output type
- Cost (may be parameterized)
- Serialization format
- Protocol version introduced

Check OpCodes.scala and operations.scala for the complete list."

PREREQUISITE KNOWLEDGE:
- ~100 distinct operations
- Some operations are generic (work on multiple types)
- Costs can depend on input sizes (collection operations)
- Some operations are desugared during compilation

CREATE FILE: src/core/opcodes.zig

INCLUDE ALL OPCODES:
```zig
pub const OpCode = enum(u8) {
    // === Constants (type encoded) ===
    // 0x01-0x0B: Primitive constants
    // 0x0C-0x6F: Composite type constants
    
    // === Operations ===
    // Collection construction
    concrete_collection = 0x83,
    concrete_collection_bool = 0x85,
    tuple = 0x86,
    
    // Selection
    select_field = 0x8C,
    
    // Comparison (0x8F-0x94)
    lt = 0x8F,
    le = 0x90,
    gt = 0x91,
    ge = 0x92,
    eq = 0x93,
    neq = 0x94,
    
    // Control flow
    @"if" = 0x95,
    
    // Logical
    and_op = 0x96,
    or_op = 0x97,
    at_least = 0x98,
    
    // Arithmetic (0x99-0x9E)
    minus = 0x99,
    plus = 0x9A,
    xor = 0x9B,
    multiply = 0x9C,
    division = 0x9D,
    modulo = 0x9E,
    
    // Group operations
    exponentiate = 0x9F,
    multiply_group = 0xA0,
    
    // Min/Max
    min = 0xA1,
    max = 0xA2,
    
    // ... (continue for all opcodes)
    
    _,  // Allow unknown opcodes for forward compatibility
};

/// Operation metadata
pub const OpInfo = struct {
    code: OpCode,
    name: []const u8,
    /// Number of operands (0xFF = variable)
    arity: u8,
    /// Base cost (may be multiplied by input size)
    base_cost: u32,
    /// Cost multiplier for collection operations
    per_item_cost: u32,
    /// Protocol version when introduced
    since_version: u8,
    /// Serialization format descriptor
    format: SerFormat,
};

/// Lookup table for all operations
pub const OP_INFO: [256]?OpInfo = init_op_info();

fn init_op_info() [256]?OpInfo {
    var table: [256]?OpInfo = .{null} ** 256;
    table[@intFromEnum(OpCode.plus)] = .{
        .code = .plus,
        .name = "+",
        .arity = 2,
        .base_cost = 10,
        .per_item_cost = 0,
        .since_version = 1,
        .format = .{ .binary = {} },
    };
    // ... initialize all opcodes
    return table;
}
```

VALIDATION:
[ ] Compare against Scala OpCodes.scala - must match exactly
[ ] Verify cost values against CostTable.scala
[ ] Test lookup performance (should be O(1))
```

### Prompt 1.4: Memory Pools (TigerBeetle Style)

```
TASK: Implement pre-allocated memory pools for zero-allocation execution

CONTEXT (From TigerBeetle Engineers):
"This is the core of TigerBeetle-style design. Rules:

1. ALL memory allocated upfront, BEFORE execution begins
2. Fixed-size pools with explicit capacity limits
3. NO dynamic allocation (no ArrayList, no allocator calls)
4. Validate that input fits in pools BEFORE parsing
5. Use Structure of Arrays for cache efficiency
6. Align to cache lines (64 bytes) for hot data
7. Reset pools (don't deallocate) between executions

Your pools should handle:
- Expression nodes (up to 16K nodes)
- Constants (up to 1K constants)
- Evaluation stack (256 deep)
- Collections (for intermediate results)
- Bytes (for string/byte array data)"

PREREQUISITE KNOWLEDGE:
- Cache line is typically 64 bytes on modern CPUs
- Structure of Arrays (SoA) > Array of Structures (AoS) for iteration
- Pool exhaustion must be detected and reported as error
- Pools should be reusable (reset, don't reallocate)

CREATE FILE: src/interpreter/memory.zig

STRUCTURE:
```zig
/// Capacities (compile-time constants)
pub const Capacity = struct {
    pub const max_nodes: usize = 16384;
    pub const max_constants: usize = 1024;
    pub const max_stack: usize = 256;
    pub const max_bytes: usize = 64 * 1024;
    pub const max_collections: usize = 256;
    pub const max_collection_items: usize = 16384;
};

/// Expression pool using Structure of Arrays
pub const ExpressionPool = struct {
    // Hot data (accessed during every evaluation step)
    opcodes: [Capacity.max_nodes]u8 align(64),
    arities: [Capacity.max_nodes]u8 align(64),
    
    // Warm data (accessed for operand lookup)
    first_operand: [Capacity.max_nodes]u32 align(64),
    result_types: [Capacity.max_nodes]u16 align(64),
    
    // Cold data (operand storage)
    operand_indices: [Capacity.max_nodes * 4]u16 align(64),
    
    // Counts
    node_count: u16,
    operand_count: u32,
    
    /// Reset for reuse (O(1) - just reset counts)
    pub fn reset(self: *ExpressionPool) void {
        self.node_count = 0;
        self.operand_count = 0;
        // Note: Don't zero memory - unnecessary and slow
    }
    
    /// Validate capacity before parsing
    pub fn canFit(self: *const ExpressionPool, nodes: usize, operands: usize) bool {
        return (self.node_count + nodes <= Capacity.max_nodes) and
               (self.operand_count + operands <= Capacity.max_nodes * 4);
    }
};

/// Value stack with type-segregated lanes
pub const ValueStack = struct {
    // Type tags (determines which lane to read)
    types: [Capacity.max_stack]u8 align(64),
    
    // Value lanes (only one is valid per slot based on type)
    booleans: [Capacity.max_stack]bool align(64),
    integers: [Capacity.max_stack]i64 align(64),
    references: [Capacity.max_stack]u32 align(64),
    
    sp: u16,
    
    // TigerBeetle-style assertions
    pub fn push(self: *ValueStack, value: anytype, type_code: u8) !void {
        std.debug.assert(self.sp < Capacity.max_stack); // Debug assertion
        if (self.sp >= Capacity.max_stack) return error.StackOverflow;
        // ... push logic
    }
};

/// Complete interpreter state
pub const InterpreterState = struct {
    expressions: ExpressionPool,
    constants: ConstantPool,
    stack: ValueStack,
    types: TypePool,
    
    cost: u64,
    cost_limit: u64,
    
    /// Validate input fits before parsing
    pub fn validateCapacity(self: *const InterpreterState, 
                            estimated_nodes: usize,
                            estimated_constants: usize) !void {
        if (!self.expressions.canFit(estimated_nodes, estimated_nodes * 4))
            return error.TreeTooLarge;
        if (!self.constants.canFit(estimated_constants))
            return error.TooManyConstants;
    }
};
```

TESTS:
[ ] Pool exhaustion returns error (not crash)
[ ] Reset is O(1) (benchmark it)
[ ] Alignment is correct (check with @alignOf)
[ ] Memory layout matches expected size
```

---
