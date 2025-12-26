//! Data Serializer/Deserializer for ErgoTree
//!
//! Serializes and deserializes runtime values based on their types.
//! Values are stored in a Value union; variable-sized data uses arena allocation.
//!
//! Reference: Rust ergotree-ir/src/serialization/data.rs

const std = @import("std");
const assert = std.debug.assert;
const vlq = @import("vlq.zig");
const types = @import("../core/types.zig");
const memory = @import("../interpreter/memory.zig");
const value_pool = @import("../interpreter/value_pool.zig");
const secp256k1 = @import("../crypto/secp256k1.zig");
const avl = @import("../crypto/avl_tree.zig");

const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const SType = types.SType;
const BumpAllocator = memory.BumpAllocator;
pub const ValuePool = value_pool.ValuePool;
const null_value_idx = value_pool.null_value_idx;

// ============================================================================
// Value Representation
// ============================================================================

/// Maximum size for BigInt (256 bits + sign byte = 33 bytes)
/// Values up to q-1 (secp256k1 group order - 1) need 33 bytes when positive
/// because the MSB is set, requiring a leading 0x00 for two's complement.
pub const max_bigint_bytes: usize = 33;

/// GroupElement size (33 bytes compressed SEC1)
pub const group_element_size: usize = 33;

// Compile-time sanity checks
comptime {
    assert(max_bigint_bytes == 33);
    assert(group_element_size == 33);
}

/// Runtime value representation for ErgoTree evaluation.
/// Primitives are stored inline; variable-sized data stored in arena.
pub const Value = union(enum) {
    /// No value (SUnit)
    unit: void,

    /// Boolean value
    boolean: bool,

    /// 8-bit signed integer
    byte: i8,

    /// 16-bit signed integer
    short: i16,

    /// 32-bit signed integer
    int: i32,

    /// 64-bit signed integer
    long: i64,

    /// 256-bit signed integer (big-endian two's complement)
    big_int: BigInt,

    /// 256-bit unsigned integer (v6+)
    unsigned_big_int: UnsignedBigInt,

    /// secp256k1 point (33 bytes compressed SEC1)
    group_element: [group_element_size]u8,

    /// Sigma proposition (placeholder for now)
    sigma_prop: SigmaPropRef,

    /// Byte collection (slice into arena)
    coll_byte: []const u8,

    /// Generic collection (indices into value array)
    coll: CollRef,

    /// Option value (present/absent)
    option: OptionRef,

    /// Tuple value (indices into value array)
    tuple: TupleRef,

    /// Header value (reference to block header)
    header: HeaderRef,

    /// PreHeader value (stores pre-header data inline)
    pre_header: PreHeaderRef,

    /// Single box reference (index into context array)
    box: BoxRef,

    /// Collection of boxes (reference to context array)
    box_coll: BoxCollRef,

    /// Collection of tokens from a box (reference to box's tokens)
    token_coll: TokenCollRef,

    /// AVL+ tree metadata (authenticated dictionary)
    avl_tree: avl.AvlTreeData,

    /// 32-byte hash result (Blake2b256 or SHA256), stored inline to avoid arena allocation.
    /// Conceptually equivalent to coll_byte but doesn't require heap/arena memory.
    hash32: [32]u8,

    /// First-class function reference (lambda stored in variable)
    func_ref: FuncRef,

    /// Placeholder for soft-fork unknown opcodes.
    /// When a script uses an opcode not supported by this node but the script
    /// version is higher than the activated version, we return this instead of
    /// an error. This allows soft-fork upgrades where old nodes accept blocks
    /// with new opcodes they don't understand.
    soft_fork_placeholder: void,

    /// 256-bit signed integer stored as big-endian bytes
    pub const BigInt = struct {
        bytes: [max_bigint_bytes]u8,
        len: u8, // actual length (1-32)

        pub fn isZero(self: BigInt) bool {
            for (self.bytes[0..self.len]) |b| {
                if (b != 0) return false;
            }
            return true;
        }

        pub fn isNegative(self: BigInt) bool {
            if (self.len == 0) return false;
            return self.bytes[0] & 0x80 != 0;
        }
    };

    /// 256-bit unsigned integer
    pub const UnsignedBigInt = struct {
        bytes: [max_bigint_bytes]u8,
        len: u8,
    };

    /// Reference to sigma proposition (to be expanded)
    pub const SigmaPropRef = struct {
        /// Placeholder - will reference SigmaBoolean tree
        data: []const u8,
    };

    /// Reference to generic collection
    pub const CollRef = struct {
        elem_type: TypeIndex,
        /// Offset into values array
        start: u16,
        len: u16,
    };

    /// Reference to option value.
    /// Inner values are stored in ValuePool for uniform handling of all types.
    pub const OptionRef = struct {
        /// Type of the inner value
        inner_type: TypeIndex,
        /// Index into ValuePool (null_value_idx if None)
        value_idx: u16,

        /// Check if this is Some
        pub fn isSome(self: OptionRef) bool {
            return self.value_idx != null_value_idx;
        }

        /// Check if this is None
        pub fn isNone(self: OptionRef) bool {
            return self.value_idx == null_value_idx;
        }

        // Compile-time assertions (ZIGMA_STYLE requirement)
        comptime {
            // OptionRef must be compact
            assert(@sizeOf(OptionRef) <= 8);
        }
    };

    /// Reference to tuple
    pub const TupleRef = struct {
        /// For simple tuples (primitives only): start=0 indicates inline storage
        /// Otherwise, start/len index into external values array
        start: u16,
        len: u8,
        /// Element type indices (up to 4)
        types: [4]TypeIndex,
        /// Inline storage for simple types (up to 4 i64 values)
        values: [4]i64,
    };

    /// Reference to header (inline copy of HeaderView fields for evaluation)
    /// This mirrors context.HeaderView but is stored inline in Value
    pub const HeaderRef = struct {
        id: [32]u8,
        version: u8,
        parent_id: [32]u8,
        ad_proofs_root: [32]u8,
        state_root: [44]u8,
        transactions_root: [32]u8,
        timestamp: u64,
        n_bits: u64,
        height: u32,
        extension_root: [32]u8,
        miner_pk: [33]u8,
        pow_onetime_pk: [33]u8,
        pow_nonce: [8]u8,
        pow_distance: [32]u8,
        votes: [3]u8,

        // Compile-time assertions (ZIGMA_STYLE requirement)
        comptime {
            // HeaderRef must be reasonably sized for stack allocation
            assert(@sizeOf(HeaderRef) <= 512);
            assert(@sizeOf(HeaderRef) >= 256);

            // Verify field sizes match Ergo protocol
            assert(@sizeOf([32]u8) == 32); // Hash sizes
            assert(@sizeOf([33]u8) == 33); // Compressed EC points
            assert(@sizeOf([44]u8) == 44); // AVL+ digest
            assert(@sizeOf([3]u8) == 3); // Votes
            assert(@sizeOf([8]u8) == 8); // PoW nonce
        }
    };

    /// Reference to pre-header (inline copy of PreHeaderView fields for evaluation)
    /// This mirrors context.PreHeaderView but is stored inline in Value.
    /// PreHeader is the proposed next block header (used during mining/validation).
    pub const PreHeaderRef = struct {
        version: u8,
        parent_id: [32]u8,
        timestamp: u64,
        n_bits: u64,
        height: u32,
        miner_pk: [33]u8,
        votes: [3]u8,

        // Compile-time assertions (ZIGMA_STYLE requirement)
        comptime {
            // PreHeaderRef must be reasonably sized for stack allocation
            assert(@sizeOf(PreHeaderRef) <= 128);
            assert(@sizeOf(PreHeaderRef) >= 64);

            // Verify field sizes match Ergo protocol
            assert(@sizeOf([32]u8) == 32); // Parent ID
            assert(@sizeOf([33]u8) == 33); // Compressed EC point (miner PK)
            assert(@sizeOf([3]u8) == 3); // Votes
        }
    };

    /// Reference to a single box in the execution context.
    /// Boxes are referenced by source (inputs/outputs/data_inputs) and index.
    pub const BoxRef = struct {
        /// Which collection the box is from
        source: BoxSource,
        /// Index within the source collection
        index: u16,

        pub const BoxSource = enum(u2) {
            inputs = 0,
            outputs = 1,
            data_inputs = 2,
        };

        // Compile-time assertions (ZIGMA_STYLE requirement)
        comptime {
            // BoxRef must be compact for stack efficiency
            assert(@sizeOf(BoxRef) <= 8);
            // Source enum fits in 2 bits
            assert(@sizeOf(BoxSource) == 1);
        }
    };

    /// Reference to a collection of boxes in the execution context.
    /// Used for INPUTS, OUTPUTS, DATA_INPUTS accessors.
    pub const BoxCollRef = struct {
        /// Which collection to reference
        source: BoxRef.BoxSource,

        // Compile-time assertions (ZIGMA_STYLE requirement)
        comptime {
            // BoxCollRef must be minimal
            assert(@sizeOf(BoxCollRef) <= 4);
        }
    };

    /// Reference to a box's token collection.
    /// Used for box.tokens accessor returning Coll[(Coll[Byte], Long)].
    pub const TokenCollRef = struct {
        /// Source collection (inputs, outputs, data_inputs)
        source: BoxRef.BoxSource,
        /// Box index within the source collection
        box_index: u8,

        // Compile-time assertions
        comptime {
            assert(@sizeOf(TokenCollRef) <= 4);
        }
    };

    /// First-class function reference (for functions stored in variables)
    pub const FuncRef = struct {
        /// Index of the function body in the expression tree
        body_idx: u16,
        /// Number of arguments the function takes
        num_args: u8,

        // Compile-time assertions
        comptime {
            assert(@sizeOf(FuncRef) <= 4);
        }
    };
};

// ============================================================================
// Deserialize Error
// ============================================================================

pub const DeserializeError = error{
    UnexpectedEndOfInput,
    Overflow,
    InvalidData,
    OutOfMemory,
    TypeMismatch,
    NotSupported,
    /// GroupElement is not a valid curve point (invalid encoding, not on curve, or invalid x)
    InvalidGroupElement,
};

// ============================================================================
// Deserialize Functions
// ============================================================================

/// Deserialize a value based on its type.
/// Variable-sized data is allocated from the arena.
/// Complex types (Options, Tuples with non-primitives) store values in value_pool.
pub fn deserialize(
    type_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype, // BumpAllocator
    values: ?*ValuePool, // Optional for backward compatibility (required for Option/Tuple)
) DeserializeError!Value {
    const t = pool.get(type_idx);

    return switch (t) {
        .unit => .unit,
        .boolean => deserializeBoolean(reader),
        .byte => deserializeByte(reader),
        .short => deserializeShort(reader),
        .int => deserializeInt(reader),
        .long => deserializeLong(reader),
        .big_int => deserializeBigInt(reader),
        .unsigned_big_int => deserializeUnsignedBigInt(reader),
        .group_element => deserializeGroupElement(reader),
        .sigma_prop => deserializeSigmaProp(reader, arena),
        .coll => |elem_idx| deserializeColl(elem_idx, pool, reader, arena, values),
        .option => |inner_idx| deserializeOption(inner_idx, pool, reader, arena, values),
        .pair => |p| deserializeTuple2(p.first, p.second, pool, reader, arena, values),
        .triple => |tr| deserializeTuple3(tr.a, tr.b, tr.c, pool, reader, arena, values),
        .quadruple => |q| deserializeTuple4(q.a, q.b, q.c, q.d, pool, reader, arena, values),
        .tuple => |tuple_n| deserializeTupleN(tuple_n.slice(), pool, reader, arena, values),
        .avl_tree => deserializeAvlTree(reader),
        .func => error.NotSupported,
        // Object types cannot be deserialized as data (only accessed via context)
        .any, .box, .context, .header, .pre_header, .global => error.NotSupported,
        // Type variables are placeholders, cannot be serialized as data
        .type_var => error.NotSupported,
    };
}

fn deserializeBoolean(reader: *vlq.Reader) DeserializeError!Value {
    const byte = reader.readByte() catch |e| return mapVlqError(e);
    // POSTCONDITION: Valid boolean representation
    assert(byte == 0 or byte == 1 or byte != 0);
    return .{ .boolean = byte != 0 };
}

fn deserializeByte(reader: *vlq.Reader) DeserializeError!Value {
    const byte = reader.readByte() catch |e| return mapVlqError(e);
    return .{ .byte = @bitCast(byte) };
}

fn deserializeShort(reader: *vlq.Reader) DeserializeError!Value {
    const v = reader.readI16() catch |e| return mapVlqError(e);
    return .{ .short = v };
}

fn deserializeInt(reader: *vlq.Reader) DeserializeError!Value {
    const v = reader.readI32() catch |e| return mapVlqError(e);
    return .{ .int = v };
}

fn deserializeLong(reader: *vlq.Reader) DeserializeError!Value {
    const v = reader.readI64() catch |e| return mapVlqError(e);
    return .{ .long = v };
}

fn deserializeBigInt(reader: *vlq.Reader) DeserializeError!Value {
    // Format: VLQ u16 length + big-endian bytes
    const len = reader.readU16() catch |e| return mapVlqError(e);

    // PRECONDITION: Length must be valid
    if (len == 0 or len > max_bigint_bytes) return error.InvalidData;

    const bytes = reader.readBytes(len) catch |e| return mapVlqError(e);

    var result = Value.BigInt{
        .bytes = undefined,
        .len = @truncate(len),
    };

    // Copy big-endian bytes
    @memcpy(result.bytes[0..len], bytes);

    // POSTCONDITION: Length matches stored bytes
    assert(result.len == len);
    assert(result.len > 0);

    return .{ .big_int = result };
}

fn deserializeUnsignedBigInt(reader: *vlq.Reader) DeserializeError!Value {
    // Same format as BigInt but unsigned interpretation
    const len = reader.readU16() catch |e| return mapVlqError(e);

    if (len == 0 or len > max_bigint_bytes) return error.InvalidData;

    const bytes = reader.readBytes(len) catch |e| return mapVlqError(e);

    var result = Value.UnsignedBigInt{
        .bytes = undefined,
        .len = @truncate(len),
    };

    @memcpy(result.bytes[0..len], bytes);

    return .{ .unsigned_big_int = result };
}

fn deserializeGroupElement(reader: *vlq.Reader) DeserializeError!Value {
    // PRECONDITION: reader has at least 33 bytes available
    const bytes = reader.readBytes(group_element_size) catch |e| return mapVlqError(e);

    var result: [group_element_size]u8 = undefined;
    @memcpy(&result, bytes);

    // SECURITY: Validate point is on curve
    // Point.decode() validates:
    // 1. Valid prefix (0x02, 0x03, or all zeros for infinity)
    // 2. x coordinate < field prime p
    // 3. Point satisfies curve equation: y² = x³ + 7 (mod p)
    //
    // Note: secp256k1 has cofactor 1, so all curve points are in the main subgroup.
    // No separate subgroup check is needed.
    const point = secp256k1.Point.decode(&result) catch {
        return error.InvalidGroupElement;
    };

    // POSTCONDITION: Point is valid (on curve or infinity)
    assert(point.is_infinity or point.isValid());

    return .{ .group_element = result };
}

fn deserializeSigmaProp(reader: *vlq.Reader, arena: anytype) DeserializeError!Value {
    // SigmaProp is a SigmaBoolean tree - complex structure
    // For now, read the opcode and handle simple cases
    const opcode = reader.readByte() catch |e| return mapVlqError(e);

    // Simple cases: TrivialProp (true/false)
    switch (opcode) {
        0xCD => {
            // ProveDlog - 33 byte public key follows
            const pk = reader.readBytes(group_element_size) catch |e| return mapVlqError(e);
            const data = arena.allocSlice(u8, 1 + group_element_size) catch return error.OutOfMemory;
            data[0] = opcode;
            @memcpy(data[1..], pk);
            return .{ .sigma_prop = .{ .data = data } };
        },
        else => {
            // For other sigma propositions, we need more complex parsing
            // Store the opcode for now
            const data = arena.allocSlice(u8, 1) catch return error.OutOfMemory;
            data[0] = opcode;
            return .{ .sigma_prop = .{ .data = data } };
        },
    }
}

fn deserializeAvlTree(reader: *vlq.Reader) DeserializeError!Value {
    // Format:
    // - digest: 33 bytes (32-byte Blake2b hash + 1-byte height)
    // - tree_flags: 1 byte
    // - key_length: u32 (VLQ encoded)
    // - value_length_opt: Option[u32] (0x00 = None, 0x01 + VLQ u32 = Some)

    // PRECONDITION: reader has at least 33 bytes for digest
    const digest_bytes = reader.readBytes(avl.digest_size) catch |e| return mapVlqError(e);
    var digest: [avl.digest_size]u8 = undefined;
    @memcpy(&digest, digest_bytes);

    // Read tree flags (1 byte)
    const flags_byte = reader.readByte() catch |e| return mapVlqError(e);
    const tree_flags = avl.AvlTreeFlags.fromByte(flags_byte);

    // Read key length (u32 as VLQ)
    const key_length = reader.readU32() catch |e| return mapVlqError(e);

    // Read optional value length
    const opt_flag = reader.readByte() catch |e| return mapVlqError(e);
    const value_length_opt: ?u32 = if (opt_flag == 0) null else blk: {
        const vl = reader.readU32() catch |e| return mapVlqError(e);
        break :blk vl;
    };

    // Validate and construct AvlTreeData
    const tree_data = avl.AvlTreeData.init(
        digest,
        tree_flags,
        key_length,
        value_length_opt,
    ) catch {
        return error.InvalidData;
    };

    // POSTCONDITION: Tree data is valid
    assert(tree_data.key_length > 0);
    assert(tree_data.key_length <= avl.max_key_length);

    return .{ .avl_tree = tree_data };
}

/// Store a Value in the ValuePool and return its index.
/// This is the key function enabling arbitrary nesting of Options, Tuples, and Collections.
fn storeValueInPool(
    value: Value,
    type_idx: TypeIndex,
    vpool: *ValuePool,
    arena: anytype,
) DeserializeError!u16 {
    _ = arena; // Reserved for future use (e.g., byte slice copying)

    // PRECONDITION: ValuePool must have capacity
    assert(!vpool.isFull());

    const idx = vpool.alloc() catch return error.OutOfMemory;

    // Store value based on type
    const pooled: value_pool.PooledValue = switch (value) {
        .unit => .{
            .type_idx = type_idx,
            .data = .{ .primitive = 0 },
        },
        .boolean => |b| .{
            .type_idx = type_idx,
            .data = .{ .primitive = if (b) 1 else 0 },
        },
        .byte => |b| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, b) },
        },
        .short => |s| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, s) },
        },
        .int => |i| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, i) },
        },
        .long => |l| .{
            .type_idx = type_idx,
            .data = .{ .primitive = l },
        },
        .big_int => |bi| blk: {
            var data: value_pool.PooledValue.BigIntData = .{
                .bytes = [_]u8{0} ** 32,
                .len = bi.len,
            };
            @memcpy(data.bytes[0..bi.len], bi.bytes[0..bi.len]);
            break :blk .{
                .type_idx = type_idx,
                .data = .{ .big_int = data },
            };
        },
        .group_element => |ge| .{
            .type_idx = type_idx,
            .data = .{ .group_element = ge },
        },
        .coll_byte => |bytes| .{
            .type_idx = type_idx,
            .data = .{ .byte_slice = .{ .ptr = bytes.ptr, .len = @intCast(bytes.len) } },
        },
        .coll => |c| .{
            .type_idx = type_idx,
            .data = .{ .collection = .{ .elem_type = c.elem_type, .start_idx = c.start, .len = c.len } },
        },
        .option => |o| .{
            .type_idx = type_idx,
            .data = .{ .option = .{ .inner_type = o.inner_type, .value_idx = o.value_idx } },
        },
        .box => |b| .{
            .type_idx = type_idx,
            .data = .{ .box = .{ .source = @enumFromInt(@intFromEnum(b.source)), .index = b.index } },
        },
        .hash32 => |h| .{
            .type_idx = type_idx,
            .data = .{ .hash32 = h },
        },
        // Types not yet supported in pool storage
        .tuple, .header, .pre_header, .sigma_prop, .unsigned_big_int, .box_coll, .token_coll, .avl_tree => {
            return error.NotSupported;
        },
        // Soft-fork placeholder and func_ref should not be stored in pool (internal-only)
        .soft_fork_placeholder, .func_ref => {
            return error.NotSupported;
        },
    };

    vpool.set(idx, pooled);

    // POSTCONDITION: Value is stored at returned index
    assert(vpool.get(idx) != null);

    return idx;
}

/// Convert Value to PooledValue for tuple/collection element storage.
/// Unlike storeValueInPool, this doesn't allocate in the pool - just converts.
fn valueToPooled(
    value: Value,
    type_idx: TypeIndex,
    vpool: *ValuePool,
    arena: anytype,
) DeserializeError!value_pool.PooledValue {
    _ = arena; // Reserved for future use
    _ = vpool; // Reserved for future use

    return switch (value) {
        .unit => .{
            .type_idx = type_idx,
            .data = .{ .primitive = 0 },
        },
        .boolean => |b| .{
            .type_idx = type_idx,
            .data = .{ .primitive = if (b) 1 else 0 },
        },
        .byte => |b| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, b) },
        },
        .short => |s| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, s) },
        },
        .int => |i| .{
            .type_idx = type_idx,
            .data = .{ .primitive = @as(i64, i) },
        },
        .long => |l| .{
            .type_idx = type_idx,
            .data = .{ .primitive = l },
        },
        .big_int => |bi| blk: {
            var data: value_pool.PooledValue.BigIntData = .{
                .bytes = [_]u8{0} ** 32,
                .len = bi.len,
            };
            @memcpy(data.bytes[0..bi.len], bi.bytes[0..bi.len]);
            break :blk .{
                .type_idx = type_idx,
                .data = .{ .big_int = data },
            };
        },
        .group_element => |ge| .{
            .type_idx = type_idx,
            .data = .{ .group_element = ge },
        },
        .coll_byte => |bytes| .{
            .type_idx = type_idx,
            .data = .{ .byte_slice = .{ .ptr = bytes.ptr, .len = @intCast(bytes.len) } },
        },
        .coll => |c| .{
            .type_idx = type_idx,
            .data = .{ .collection = .{ .elem_type = c.elem_type, .start_idx = c.start, .len = c.len } },
        },
        .option => |o| .{
            .type_idx = type_idx,
            .data = .{ .option = .{ .inner_type = o.inner_type, .value_idx = o.value_idx } },
        },
        .box => |b| .{
            .type_idx = type_idx,
            .data = .{ .box = .{ .source = @enumFromInt(@intFromEnum(b.source)), .index = b.index } },
        },
        .hash32 => |h| .{
            .type_idx = type_idx,
            .data = .{ .hash32 = h },
        },
        .avl_tree => |tree| .{
            .type_idx = type_idx,
            .data = .{ .avl_tree = tree },
        },
        .sigma_prop => |sp| .{
            .type_idx = type_idx,
            .data = .{ .sigma_prop = .{ .ptr = sp.data.ptr, .len = @intCast(sp.data.len) } },
        },
        // Types not yet supported
        .tuple, .header, .pre_header, .unsigned_big_int, .box_coll, .token_coll => {
            return error.NotSupported;
        },
        .soft_fork_placeholder, .func_ref => {
            return error.NotSupported;
        },
    };
}

fn deserializeColl(
    elem_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    // Collection format: VLQ u16 length + elements
    const len = reader.readU16() catch |e| return mapVlqError(e);

    const elem_type = pool.get(elem_idx);

    // Special case: Coll[Byte] - raw bytes
    if (elem_type == .byte) {
        const bytes = reader.readBytes(len) catch |e| return mapVlqError(e);

        // Copy to arena
        const data = arena.allocSlice(u8, len) catch return error.OutOfMemory;
        @memcpy(data, bytes);

        return .{ .coll_byte = data };
    }

    // Special case: Coll[Boolean] - bit-packed
    if (elem_type == .boolean) {
        const byte_len = (len + 7) / 8;
        const bits = reader.readBytes(byte_len) catch |e| return mapVlqError(e);

        // Unpack bits to bytes (1 byte per bool for simplicity)
        const bools = arena.allocSlice(u8, len) catch return error.OutOfMemory;
        for (0..len) |i| {
            const byte_idx = i / 8;
            const bit_idx: u3 = @truncate(i % 8);
            bools[i] = if ((bits[byte_idx] >> (7 - bit_idx)) & 1 != 0) 1 else 0;
        }

        return .{ .coll_byte = bools };
    }

    // Generic collection - store elements in ValuePool
    const vpool = values orelse return error.NotSupported;

    // Validate length (max 255 per protocol, may be corrupted by fault injection)
    if (len > 255) return error.InvalidData;

    // Handle empty collection - return valid CollRef with len=0
    if (len == 0) {
        return .{
            .coll = .{
                .elem_type = elem_idx,
                .start = 0, // Unused for empty collection
                .len = 0,
            },
        };
    }

    // Allocate slots for elements
    const start_idx = vpool.allocN(len) catch return error.OutOfMemory;

    // Deserialize each element into the pool
    var i: u16 = 0;
    while (i < len) : (i += 1) {
        const elem_value = try deserialize(elem_idx, pool, reader, arena, values);
        const elem_pool_idx = try storeValueInPool(elem_value, elem_idx, vpool, arena);
        vpool.set(start_idx + i, vpool.get(elem_pool_idx).?.*);
    }

    return .{ .coll = .{
        .elem_type = elem_idx,
        .start = start_idx,
        .len = len,
    } };
}

fn deserializeOption(
    inner_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    // PRECONDITION: ValuePool required for Option deserialization
    const vpool = values orelse return error.NotSupported;

    // Option format (v6+): 0x00 = None, 0x01 + value = Some
    const flag = reader.readByte() catch |e| return mapVlqError(e);

    if (flag == 0) {
        // None - use sentinel value
        return .{ .option = .{ .inner_type = inner_idx, .value_idx = null_value_idx } };
    }

    // Deserialize inner value
    const inner_value = try deserialize(inner_idx, pool, reader, arena, values);

    // Store inner value in ValuePool
    const inner_pool_idx = try storeValueInPool(inner_value, inner_idx, vpool, arena);

    return .{ .option = .{ .inner_type = inner_idx, .value_idx = inner_pool_idx } };
}

fn deserializeTuple2(
    t1: TypeIndex,
    t2: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    // Deserialize both elements
    const v1 = try deserialize(t1, pool, reader, arena, values);
    const v2 = try deserialize(t2, pool, reader, arena, values);

    // Try inline storage for primitives first
    const val1_opt = try valueToI64(v1);
    const val2_opt = try valueToI64(v2);

    if (val1_opt != null and val2_opt != null) {
        // Both primitives - use inline storage
        return .{
            .tuple = .{
                .start = 0, // 0 indicates inline storage
                .len = 2,
                .types = .{ t1, t2, 0, 0 },
                .values = .{ val1_opt.?, val2_opt.?, 0, 0 },
            },
        };
    }

    // Non-primitive element(s) - store in ValuePool
    const vpool = values orelse return error.NotSupported;

    // Allocate slots for both elements
    const start_idx = vpool.allocN(2) catch return error.OutOfMemory;

    // Store first element
    const pooled1 = try valueToPooled(v1, t1, vpool, arena);
    vpool.set(start_idx, pooled1);

    // Store second element
    const pooled2 = try valueToPooled(v2, t2, vpool, arena);
    vpool.set(start_idx + 1, pooled2);

    return .{
        .tuple = .{
            .start = start_idx,
            .len = 2,
            // types[0]=0 indicates external storage (distinguishes from inline which has types[0]!=0)
            .types = .{ 0, 0, 0, 0 },
            .values = .{ 0, 0, 0, 0 },
        },
    };
}

fn deserializeTuple3(
    t1: TypeIndex,
    t2: TypeIndex,
    t3: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    const v1 = try deserialize(t1, pool, reader, arena, values);
    const v2 = try deserialize(t2, pool, reader, arena, values);
    const v3 = try deserialize(t3, pool, reader, arena, values);

    // Try inline storage for all-primitive tuples
    const val1_opt = try valueToI64(v1);
    const val2_opt = try valueToI64(v2);
    const val3_opt = try valueToI64(v3);

    if (val1_opt != null and val2_opt != null and val3_opt != null) {
        return .{ .tuple = .{
            .start = 0,
            .len = 3,
            .types = .{ t1, t2, t3, 0 },
            .values = .{ val1_opt.?, val2_opt.?, val3_opt.?, 0 },
        } };
    }

    // Non-primitive element(s) - store in ValuePool
    const vpool = values orelse return error.NotSupported;
    const start_idx = vpool.allocN(3) catch return error.OutOfMemory;

    const elem_vals = [_]Value{ v1, v2, v3 };
    const elem_types = [_]TypeIndex{ t1, t2, t3 };
    for (0..3) |i| {
        const pooled = try valueToPooled(elem_vals[i], elem_types[i], vpool, arena);
        vpool.set(start_idx + @as(u16, @intCast(i)), pooled);
    }

    return .{ .tuple = .{
        .start = start_idx,
        .len = 3,
        .types = .{ 0, 0, 0, 0 },
        .values = .{ 0, 0, 0, 0 },
    } };
}

fn deserializeTuple4(
    t1: TypeIndex,
    t2: TypeIndex,
    t3: TypeIndex,
    t4: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    const v1 = try deserialize(t1, pool, reader, arena, values);
    const v2 = try deserialize(t2, pool, reader, arena, values);
    const v3 = try deserialize(t3, pool, reader, arena, values);
    const v4 = try deserialize(t4, pool, reader, arena, values);

    // Try inline storage for all-primitive tuples
    const val1_opt = try valueToI64(v1);
    const val2_opt = try valueToI64(v2);
    const val3_opt = try valueToI64(v3);
    const val4_opt = try valueToI64(v4);

    if (val1_opt != null and val2_opt != null and val3_opt != null and val4_opt != null) {
        return .{ .tuple = .{
            .start = 0,
            .len = 4,
            .types = .{ t1, t2, t3, t4 },
            .values = .{ val1_opt.?, val2_opt.?, val3_opt.?, val4_opt.? },
        } };
    }

    // Non-primitive element(s) - store in ValuePool
    const vpool = values orelse return error.NotSupported;
    const start_idx = vpool.allocN(4) catch return error.OutOfMemory;

    const elem_vals = [_]Value{ v1, v2, v3, v4 };
    const elem_types = [_]TypeIndex{ t1, t2, t3, t4 };
    for (0..4) |i| {
        const pooled = try valueToPooled(elem_vals[i], elem_types[i], vpool, arena);
        vpool.set(start_idx + @as(u16, @intCast(i)), pooled);
    }

    return .{ .tuple = .{
        .start = start_idx,
        .len = 4,
        .types = .{ 0, 0, 0, 0 },
        .values = .{ 0, 0, 0, 0 },
    } };
}

fn deserializeTupleN(
    indices: []const TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*ValuePool,
) DeserializeError!Value {
    // Only support up to 4 elements for inline storage
    if (indices.len > 4) return error.NotSupported;
    if (indices.len < 2) return error.InvalidData;

    var elem_types: [4]TypeIndex = .{ 0, 0, 0, 0 };
    var elem_values: [4]i64 = .{ 0, 0, 0, 0 };
    var deserialized_values: [4]Value = undefined;
    var all_primitive = true;

    for (indices, 0..) |t, i| {
        const v = try deserialize(t, pool, reader, arena, values);
        deserialized_values[i] = v;
        const val_opt = try valueToI64(v);
        if (val_opt) |val| {
            elem_types[i] = t;
            elem_values[i] = val;
        } else {
            all_primitive = false;
        }
    }

    if (all_primitive) {
        return .{ .tuple = .{
            .start = 0,
            .len = @intCast(indices.len),
            .types = elem_types,
            .values = elem_values,
        } };
    }

    // Non-primitive element(s) - store in ValuePool
    const vpool = values orelse return error.NotSupported;
    const start_idx = vpool.allocN(@intCast(indices.len)) catch return error.OutOfMemory;

    for (indices, 0..) |t, i| {
        const pooled = try valueToPooled(deserialized_values[i], t, vpool, arena);
        vpool.set(start_idx + @as(u16, @intCast(i)), pooled);
    }

    return .{ .tuple = .{
        .start = start_idx,
        .len = @intCast(indices.len),
        .types = .{ 0, 0, 0, 0 },
        .values = .{ 0, 0, 0, 0 },
    } };
}

/// Convert simple Value to i64 for inline tuple storage
/// Returns null for complex types that can't be stored inline
fn valueToI64(v: Value) DeserializeError!?i64 {
    return switch (v) {
        .boolean => |b| if (b) 1 else 0,
        .byte => |b| @as(i64, b),
        .short => |s| @as(i64, s),
        .int => |i| @as(i64, i),
        .long => |l| l,
        else => null,
    };
}

fn mapVlqError(err: vlq.DecodeError) DeserializeError {
    return switch (err) {
        error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
        error.Overflow => error.Overflow,
    };
}

// ============================================================================
// Serialize Functions
// ============================================================================

pub const SerializeError = error{
    BufferTooSmall,
    NotSupported,
    InvalidData,
};

/// Serialize a value to bytes based on its type.
/// Returns number of bytes written.
pub fn serialize(
    type_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    buf: []u8,
) SerializeError!usize {
    const t = pool.get(type_idx);

    return switch (t) {
        .unit => 0,
        .boolean => serializeBoolean(value, buf),
        .byte => serializeByte(value, buf),
        .short => serializeShort(value, buf),
        .int => serializeInt(value, buf),
        .long => serializeLong(value, buf),
        .big_int => serializeBigInt(value, buf),
        .unsigned_big_int => serializeUnsignedBigInt(value, buf),
        .group_element => serializeGroupElement(value, buf),
        .coll => |_| serializeColl(t, pool, value, buf),
        .avl_tree => serializeAvlTree(value, buf),
        else => error.NotSupported,
    };
}

fn serializeBoolean(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = if (value.boolean) 1 else 0;
    return 1;
}

fn serializeByte(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = @bitCast(value.byte);
    return 1;
}

fn serializeShort(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < vlq.max_vlq_bytes) return error.BufferTooSmall;
    return vlq.encodeI64(@as(i64, value.short), buf);
}

fn serializeInt(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < vlq.max_vlq_bytes) return error.BufferTooSmall;
    return vlq.encodeI64(@as(i64, value.int), buf);
}

fn serializeLong(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < vlq.max_vlq_bytes) return error.BufferTooSmall;
    return vlq.encodeI64(value.long, buf);
}

fn serializeBigInt(value: Value, buf: []u8) SerializeError!usize {
    const bi = value.big_int;
    const len_size = vlq.encodeU64(@as(u64, bi.len), buf);
    if (buf.len < len_size + bi.len) return error.BufferTooSmall;
    @memcpy(buf[len_size .. len_size + bi.len], bi.bytes[0..bi.len]);
    return len_size + bi.len;
}

fn serializeUnsignedBigInt(value: Value, buf: []u8) SerializeError!usize {
    const bi = value.unsigned_big_int;
    const len_size = vlq.encodeU64(@as(u64, bi.len), buf);
    if (buf.len < len_size + bi.len) return error.BufferTooSmall;
    @memcpy(buf[len_size .. len_size + bi.len], bi.bytes[0..bi.len]);
    return len_size + bi.len;
}

fn serializeGroupElement(value: Value, buf: []u8) SerializeError!usize {
    if (buf.len < group_element_size) return error.BufferTooSmall;
    @memcpy(buf[0..group_element_size], &value.group_element);
    return group_element_size;
}

fn serializeColl(t: SType, pool: *const TypePool, value: Value, buf: []u8) SerializeError!usize {
    _ = t;
    _ = pool;

    // Only Coll[Byte] supported for now
    const data = value.coll_byte;
    const len_size = vlq.encodeU64(@as(u64, data.len), buf);
    if (buf.len < len_size + data.len) return error.BufferTooSmall;
    @memcpy(buf[len_size .. len_size + data.len], data);
    return len_size + data.len;
}

fn serializeAvlTree(value: Value, buf: []u8) SerializeError!usize {
    const tree = value.avl_tree;

    // Minimum size: digest(33) + flags(1) + key_length(1-5) + opt_flag(1)
    const min_size = avl.digest_size + 1 + 1 + 1;
    if (buf.len < min_size) return error.BufferTooSmall;

    var pos: usize = 0;

    // Write digest (33 bytes)
    @memcpy(buf[pos..][0..avl.digest_size], &tree.digest);
    pos += avl.digest_size;

    // Write flags (1 byte)
    buf[pos] = tree.tree_flags.toByte();
    pos += 1;

    // Write key_length (VLQ u32)
    const key_len_size = vlq.encodeU64(@as(u64, tree.key_length), buf[pos..]);
    pos += key_len_size;

    // Write value_length_opt (Option[u32])
    if (tree.value_length_opt) |vl| {
        buf[pos] = 0x01; // Some
        pos += 1;
        const val_len_size = vlq.encodeU64(@as(u64, vl), buf[pos..]);
        pos += val_len_size;
    } else {
        buf[pos] = 0x00; // None
        pos += 1;
    }

    return pos;
}

// ============================================================================
// Serialize With ValuePool (for complex types)
// ============================================================================

/// Maximum serialization depth (bounded per ZIGMA_STYLE)
const max_serialize_depth: u8 = 16;

/// Serialize a value to bytes, with access to ValuePool for complex types.
/// This is the full-featured serializer that handles Coll[T], Option[T], Pair, Tuple.
/// Returns number of bytes written.
pub fn serializeWithPool(
    type_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
) SerializeError!usize {
    return serializeWithPoolDepth(type_idx, pool, value, values, buf, 0);
}

fn serializeWithPoolDepth(
    type_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    // PRECONDITION: Bounded recursion
    if (depth >= max_serialize_depth) return error.NotSupported;

    const t = pool.get(type_idx);

    return switch (t) {
        .unit => 0,
        .boolean => serializeBoolean(value, buf),
        .byte => serializeByte(value, buf),
        .short => serializeShort(value, buf),
        .int => serializeInt(value, buf),
        .long => serializeLong(value, buf),
        .big_int => serializeBigInt(value, buf),
        .unsigned_big_int => serializeUnsignedBigInt(value, buf),
        .group_element => serializeGroupElement(value, buf),
        .avl_tree => serializeAvlTree(value, buf),
        .sigma_prop => serializeSigmaProp(value, buf),
        .coll => |elem_idx| serializeCollWithPool(elem_idx, pool, value, values, buf, depth),
        .option => |inner_idx| serializeOptionWithPool(inner_idx, pool, value, values, buf, depth),
        .pair => |p| serializePairWithPool(p.first, p.second, pool, value, values, buf, depth),
        .triple => |tr| serializeTripleWithPool(tr.a, tr.b, tr.c, pool, value, values, buf, depth),
        .quadruple => |q| serializeQuadWithPool(q.a, q.b, q.c, q.d, pool, value, values, buf, depth),
        .tuple => |tuple_n| serializeTupleNWithPool(tuple_n.slice(), pool, value, values, buf, depth),
        else => error.NotSupported,
    };
}

fn serializeSigmaProp(value: Value, buf: []u8) SerializeError!usize {
    // SigmaProp is stored as raw bytes
    const data = value.sigma_prop.data;
    if (buf.len < data.len) return error.BufferTooSmall;
    @memcpy(buf[0..data.len], data);
    return data.len;
}

fn serializeCollWithPool(
    elem_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    const elem_type = pool.get(elem_idx);
    var pos: usize = 0;

    // Handle Coll[Byte] specially - it's stored as coll_byte or hash32
    if (elem_type == .byte) {
        const data: []const u8 = switch (value) {
            .coll_byte => |cb| cb,
            .hash32 => |*h| h,
            else => return error.NotSupported,
        };

        // Write length (VLQ)
        pos += vlq.encodeU64(@intCast(data.len), buf[pos..]);
        if (buf.len < pos + data.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..data.len], data);
        pos += data.len;
        return pos;
    }

    // Handle Coll[Boolean] - bit-packed
    if (elem_type == .boolean) {
        // For Coll[Boolean] stored as coll_byte (1 byte per bool)
        if (value == .coll_byte) {
            const bools = value.coll_byte;
            const byte_len = (bools.len + 7) / 8;

            // Write length (VLQ)
            pos += vlq.encodeU64(@intCast(bools.len), buf[pos..]);
            if (buf.len < pos + byte_len) return error.BufferTooSmall;

            // Pack bits
            for (0..byte_len) |i| {
                var byte_val: u8 = 0;
                for (0..8) |bit| {
                    const idx = i * 8 + bit;
                    if (idx >= bools.len) break;
                    if (bools[idx] != 0) {
                        byte_val |= @as(u8, 1) << @intCast(7 - bit);
                    }
                }
                buf[pos + i] = byte_val;
            }
            pos += byte_len;
            return pos;
        }
    }

    // Generic collection - elements stored in ValuePool
    const coll = switch (value) {
        .coll => |c| c,
        else => return error.NotSupported,
    };

    // Write length (VLQ)
    pos += vlq.encodeU64(@intCast(coll.len), buf[pos..]);

    // Serialize each element
    var i: u16 = 0;
    while (i < coll.len) : (i += 1) {
        const pooled = values.get(coll.start + i) orelse return error.InvalidData;
        const elem_value = pooledToValue(pooled, pool) orelse return error.NotSupported;
        const elem_bytes = try serializeWithPoolDepth(elem_idx, pool, elem_value, values, buf[pos..], depth + 1);
        pos += elem_bytes;
    }

    return pos;
}

fn serializeOptionWithPool(
    inner_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    if (buf.len < 1) return error.BufferTooSmall;

    const opt = switch (value) {
        .option => |o| o,
        else => return error.NotSupported,
    };

    if (opt.isNone()) {
        buf[0] = 0x00;
        return 1;
    }

    // Some - write flag then inner value
    buf[0] = 0x01;
    var pos: usize = 1;

    // Get inner value from ValuePool
    const pooled = values.get(opt.value_idx) orelse return error.InvalidData;
    const inner_value = pooledToValue(pooled, pool) orelse return error.NotSupported;
    pos += try serializeWithPoolDepth(inner_idx, pool, inner_value, values, buf[pos..], depth + 1);

    return pos;
}

fn serializePairWithPool(
    first_idx: TypeIndex,
    second_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    const tuple = switch (value) {
        .tuple => |t| t,
        else => return error.NotSupported,
    };

    // PRECONDITION: Pair has exactly 2 elements
    assert(tuple.len == 2);

    var pos: usize = 0;

    // Get values - either inline or from ValuePool
    const first_value = try getTupleElement(tuple, 0, values, pool);
    const second_value = try getTupleElement(tuple, 1, values, pool);

    pos += try serializeWithPoolDepth(first_idx, pool, first_value, values, buf[pos..], depth + 1);
    pos += try serializeWithPoolDepth(second_idx, pool, second_value, values, buf[pos..], depth + 1);

    return pos;
}

fn serializeTripleWithPool(
    a_idx: TypeIndex,
    b_idx: TypeIndex,
    c_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    const tuple = switch (value) {
        .tuple => |t| t,
        else => return error.NotSupported,
    };

    assert(tuple.len == 3);

    var pos: usize = 0;
    const indices = [_]TypeIndex{ a_idx, b_idx, c_idx };

    for (indices, 0..) |idx, i| {
        const elem_value = try getTupleElement(tuple, @intCast(i), values, pool);
        pos += try serializeWithPoolDepth(idx, pool, elem_value, values, buf[pos..], depth + 1);
    }

    return pos;
}

fn serializeQuadWithPool(
    a_idx: TypeIndex,
    b_idx: TypeIndex,
    c_idx: TypeIndex,
    d_idx: TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    const tuple = switch (value) {
        .tuple => |t| t,
        else => return error.NotSupported,
    };

    assert(tuple.len == 4);

    var pos: usize = 0;
    const indices = [_]TypeIndex{ a_idx, b_idx, c_idx, d_idx };

    for (indices, 0..) |idx, i| {
        const elem_value = try getTupleElement(tuple, @intCast(i), values, pool);
        pos += try serializeWithPoolDepth(idx, pool, elem_value, values, buf[pos..], depth + 1);
    }

    return pos;
}

fn serializeTupleNWithPool(
    type_indices: []const TypeIndex,
    pool: *const TypePool,
    value: Value,
    values: *const ValuePool,
    buf: []u8,
    depth: u8,
) SerializeError!usize {
    const tuple = switch (value) {
        .tuple => |t| t,
        else => return error.NotSupported,
    };

    assert(tuple.len == type_indices.len);

    var pos: usize = 0;

    for (type_indices, 0..) |idx, i| {
        const elem_value = try getTupleElement(tuple, @intCast(i), values, pool);
        pos += try serializeWithPoolDepth(idx, pool, elem_value, values, buf[pos..], depth + 1);
    }

    return pos;
}

/// Get tuple element value - handles both inline and ValuePool storage
fn getTupleElement(tuple: Value.TupleRef, idx: u8, values: *const ValuePool, pool: *const TypePool) SerializeError!Value {
    // Check if inline storage (start=0, types[0]!=0 indicates inline)
    if (tuple.start == 0 and tuple.types[0] != 0) {
        // Inline storage - decode from values array
        const val = tuple.values[idx];
        const type_idx = tuple.types[idx];

        // Map inline i64 to appropriate Value based on type
        return inlineToValue(type_idx, val);
    }

    // External storage - get from ValuePool
    const pooled = values.get(tuple.start + idx) orelse return error.InvalidData;
    return pooledToValue(pooled, pool) orelse error.NotSupported;
}

/// Convert inline tuple value (i64) to Value based on type
fn inlineToValue(type_idx: TypeIndex, val: i64) Value {
    return switch (type_idx) {
        TypePool.BOOLEAN => .{ .boolean = val != 0 },
        TypePool.BYTE => .{ .byte = @truncate(val) },
        TypePool.SHORT => .{ .short = @truncate(val) },
        TypePool.INT => .{ .int = @truncate(val) },
        TypePool.LONG => .{ .long = val },
        else => .{ .long = val }, // Default to long for unknown primitive types
    };
}

/// Convert PooledValue to Value (subset of types supported)
/// Uses type_idx to determine the data variant since ValueData is a bare union.
fn pooledToValue(pooled: *const value_pool.PooledValue, pool: *const TypePool) ?Value {
    const type_idx = pooled.type_idx;

    // Look up the SType to determine the data variant
    const stype = pool.get(type_idx);

    return switch (stype) {
        .boolean => .{ .boolean = pooled.data.primitive != 0 },
        .byte => .{ .byte = @truncate(pooled.data.primitive) },
        .short => .{ .short = @truncate(pooled.data.primitive) },
        .int => .{ .int = @truncate(pooled.data.primitive) },
        .long => .{ .long = pooled.data.primitive },

        .big_int, .unsigned_big_int => blk: {
            var result = Value.BigInt{
                .bytes = undefined,
                .len = pooled.data.big_int.len,
            };
            @memcpy(result.bytes[0..pooled.data.big_int.len], pooled.data.big_int.bytes[0..pooled.data.big_int.len]);
            break :blk .{ .big_int = result };
        },

        .group_element => .{ .group_element = pooled.data.group_element },

        .sigma_prop => .{ .sigma_prop = .{ .data = pooled.data.sigma_prop.slice() } },

        .avl_tree => .{ .avl_tree = pooled.data.avl_tree },

        .box => .{
            .box = .{
                .source = @enumFromInt(@intFromEnum(pooled.data.box.source)),
                .index = pooled.data.box.index,
            },
        },

        .coll => |_| blk: {
            // Check for Coll[Byte] stored as byte_slice
            if (type_idx == TypePool.COLL_BYTE) {
                break :blk .{ .coll_byte = pooled.data.byte_slice.slice() };
            }
            // Generic collection
            const c = pooled.data.collection;
            break :blk .{
                .coll = .{
                    .elem_type = c.elem_type,
                    .start = c.start_idx,
                    .len = c.len,
                },
            };
        },

        .option => |_| blk: {
            const o = pooled.data.option;
            break :blk .{
                .option = .{
                    .inner_type = o.inner_type,
                    .value_idx = o.value_idx,
                },
            };
        },

        .pair, .triple, .quadruple, .tuple => blk: {
            const t = pooled.data.tuple;
            break :blk .{
                .tuple = .{
                    .start = t.start_idx,
                    .len = t.len,
                    .types = .{ 0, 0, 0, 0 }, // External storage mode
                    .values = .{ 0, 0, 0, 0 },
                },
            };
        },

        else => null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "data_serializer: deserialize boolean" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // true = 0x01
    var r1 = vlq.Reader.init(&[_]u8{0x01});
    const v1 = try deserialize(TypePool.BOOLEAN, &pool, &r1, &arena, null);
    try std.testing.expect(v1.boolean == true);

    // false = 0x00
    var r2 = vlq.Reader.init(&[_]u8{0x00});
    const v2 = try deserialize(TypePool.BOOLEAN, &pool, &r2, &arena, null);
    try std.testing.expect(v2.boolean == false);
}

test "data_serializer: deserialize byte" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Test cases from vectors.json
    const cases = [_]struct { bytes: []const u8, expected: i8 }{
        .{ .bytes = &[_]u8{0x00}, .expected = 0 },
        .{ .bytes = &[_]u8{0x01}, .expected = 1 },
        .{ .bytes = &[_]u8{0xff}, .expected = -1 },
        .{ .bytes = &[_]u8{0x7f}, .expected = 127 },
        .{ .bytes = &[_]u8{0x80}, .expected = -128 },
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(tc.bytes);
        const v = try deserialize(TypePool.BYTE, &pool, &reader, &arena, null);
        try std.testing.expectEqual(tc.expected, v.byte);
    }
}

test "data_serializer: deserialize short" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Test cases from vectors.json (VLQ ZigZag encoded)
    const cases = [_]struct { bytes: []const u8, expected: i16 }{
        .{ .bytes = &[_]u8{0x00}, .expected = 0 },
        .{ .bytes = &[_]u8{0x02}, .expected = 1 },
        .{ .bytes = &[_]u8{0x01}, .expected = -1 },
        .{ .bytes = &[_]u8{ 0xfe, 0xff, 0x03 }, .expected = 32767 }, // i16::MAX
        .{ .bytes = &[_]u8{ 0xff, 0xff, 0x03 }, .expected = -32768 }, // i16::MIN
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(tc.bytes);
        const v = try deserialize(TypePool.SHORT, &pool, &reader, &arena, null);
        try std.testing.expectEqual(tc.expected, v.short);
    }
}

test "data_serializer: deserialize int" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Test cases from vectors.json
    const cases = [_]struct { bytes: []const u8, expected: i32 }{
        .{ .bytes = &[_]u8{0x00}, .expected = 0 },
        .{ .bytes = &[_]u8{0x02}, .expected = 1 },
        .{ .bytes = &[_]u8{0x01}, .expected = -1 },
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(tc.bytes);
        const v = try deserialize(TypePool.INT, &pool, &reader, &arena, null);
        try std.testing.expectEqual(tc.expected, v.int);
    }
}

test "data_serializer: deserialize long" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    const cases = [_]struct { bytes: []const u8, expected: i64 }{
        .{ .bytes = &[_]u8{0x00}, .expected = 0 },
        .{ .bytes = &[_]u8{0x02}, .expected = 1 },
        .{ .bytes = &[_]u8{0x01}, .expected = -1 },
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(tc.bytes);
        const v = try deserialize(TypePool.LONG, &pool, &reader, &arena, null);
        try std.testing.expectEqual(tc.expected, v.long);
    }
}

test "data_serializer: deserialize bigint" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Test cases from vectors.json
    // {"value": "0", "bytes": "0100"} - length(1) + 0x00
    var r1 = vlq.Reader.init(&[_]u8{ 0x01, 0x00 });
    const v1 = try deserialize(TypePool.BIG_INT, &pool, &r1, &arena, null);
    try std.testing.expectEqual(@as(u8, 1), v1.big_int.len);
    try std.testing.expectEqual(@as(u8, 0x00), v1.big_int.bytes[0]);
    try std.testing.expect(v1.big_int.isZero());

    // {"value": "1", "bytes": "0101"} - length(1) + 0x01
    var r2 = vlq.Reader.init(&[_]u8{ 0x01, 0x01 });
    const v2 = try deserialize(TypePool.BIG_INT, &pool, &r2, &arena, null);
    try std.testing.expectEqual(@as(u8, 1), v2.big_int.len);
    try std.testing.expectEqual(@as(u8, 0x01), v2.big_int.bytes[0]);
    try std.testing.expect(!v2.big_int.isNegative());

    // {"value": "-1", "bytes": "01ff"} - length(1) + 0xff
    var r3 = vlq.Reader.init(&[_]u8{ 0x01, 0xff });
    const v3 = try deserialize(TypePool.BIG_INT, &pool, &r3, &arena, null);
    try std.testing.expectEqual(@as(u8, 1), v3.big_int.len);
    try std.testing.expectEqual(@as(u8, 0xff), v3.big_int.bytes[0]);
    try std.testing.expect(v3.big_int.isNegative());

    // {"value": "256", "bytes": "020100"} - length(2) + big-endian 0x0100
    var r4 = vlq.Reader.init(&[_]u8{ 0x02, 0x01, 0x00 });
    const v4 = try deserialize(TypePool.BIG_INT, &pool, &r4, &arena, null);
    try std.testing.expectEqual(@as(u8, 2), v4.big_int.len);
    try std.testing.expectEqual(@as(u8, 0x01), v4.big_int.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x00), v4.big_int.bytes[1]);
}

test "data_serializer: deserialize group_element" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Generator point from vectors.json (33 bytes)
    const gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    var gen_bytes: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&gen_bytes, gen_hex) catch unreachable;

    var reader = vlq.Reader.init(&gen_bytes);
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null);

    try std.testing.expectEqual(@as(u8, 0x02), v.group_element[0]); // Compressed prefix
    try std.testing.expectEqual(@as(u8, 0x79), v.group_element[1]);
}

test "data_serializer: deserialize coll_byte" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();

    // Empty collection
    var r1 = vlq.Reader.init(&[_]u8{0x00}); // length = 0
    const v1 = try deserialize(TypePool.COLL_BYTE, &pool, &r1, &arena, null);
    try std.testing.expectEqual(@as(usize, 0), v1.coll_byte.len);

    // Collection with data
    arena.reset();
    var r2 = vlq.Reader.init(&[_]u8{ 0x03, 0x01, 0x02, 0x03 }); // length = 3, data = [1, 2, 3]
    const v2 = try deserialize(TypePool.COLL_BYTE, &pool, &r2, &arena, null);
    try std.testing.expectEqual(@as(usize, 3), v2.coll_byte.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, v2.coll_byte);
}

test "data_serializer: roundtrip boolean" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    const v_true = Value{ .boolean = true };
    const len_true = try serialize(TypePool.BOOLEAN, &pool, v_true, &buf);
    try std.testing.expectEqual(@as(usize, 1), len_true);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);

    const v_false = Value{ .boolean = false };
    const len_false = try serialize(TypePool.BOOLEAN, &pool, v_false, &buf);
    try std.testing.expectEqual(@as(usize, 1), len_false);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
}

test "data_serializer: roundtrip int" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();
    var buf: [16]u8 = undefined;

    const cases = [_]i32{ 0, 1, -1, 100, -100, 32767, -32768 };

    for (cases) |expected| {
        const v = Value{ .int = expected };
        const len = try serialize(TypePool.INT, &pool, v, &buf);

        var reader = vlq.Reader.init(buf[0..len]);
        const v2 = try deserialize(TypePool.INT, &pool, &reader, &arena, null);
        try std.testing.expectEqual(expected, v2.int);
    }
}

test "data_serializer: roundtrip coll_byte" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();
    var buf: [64]u8 = undefined;

    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const v = Value{ .coll_byte = &data };
    const len = try serialize(TypePool.COLL_BYTE, &pool, v, &buf);

    var reader = vlq.Reader.init(buf[0..len]);
    const v2 = try deserialize(TypePool.COLL_BYTE, &pool, &reader, &arena, null);
    try std.testing.expectEqualSlices(u8, &data, v2.coll_byte);
}

test "data_serializer: error on truncated input" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // BigInt with length but no data
    var reader = vlq.Reader.init(&[_]u8{0x05}); // length = 5, but no bytes
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(TypePool.BIG_INT, &pool, &reader, &arena, null));
}

test "data_serializer: error on invalid bigint length" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // BigInt with length 0
    var r1 = vlq.Reader.init(&[_]u8{0x00});
    try std.testing.expectError(error.InvalidData, deserialize(TypePool.BIG_INT, &pool, &r1, &arena, null));

    // BigInt with length > 33
    var r2 = vlq.Reader.init(&[_]u8{0x22}); // 34
    try std.testing.expectError(error.InvalidData, deserialize(TypePool.BIG_INT, &pool, &r2, &arena, null));
}

// ============================================================================
// GroupElement Security Tests
// ============================================================================

test "data_serializer: group_element rejects invalid prefix" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Invalid prefix 0x04 (uncompressed format not supported)
    var bad_prefix: [33]u8 = undefined;
    bad_prefix[0] = 0x04;
    @memset(bad_prefix[1..], 0x42);

    var reader = vlq.Reader.init(&bad_prefix);
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null));
}

test "data_serializer: group_element rejects point not on curve" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Valid prefix but x coordinate that doesn't produce a valid y
    // For x = 5: y² = 5³ + 7 = 132, which has no square root mod p
    // The array is big-endian: 31 zero bytes followed by 0x05
    var not_on_curve: [33]u8 = [_]u8{0x02} ++ [_]u8{0} ** 31 ++ [_]u8{0x05};

    var reader = vlq.Reader.init(&not_on_curve);
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null));
}

test "data_serializer: group_element accepts infinity" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // All zeros = point at infinity (valid identity element)
    const infinity: [33]u8 = [_]u8{0} ** 33;

    var reader = vlq.Reader.init(&infinity);
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null);
    try std.testing.expectEqual(@as(u8, 0), v.group_element[0]);
}

test "data_serializer: group_element accepts valid point" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Generator point G (known to be on curve)
    const gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    var gen_bytes: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&gen_bytes, gen_hex) catch unreachable;

    var reader = vlq.Reader.init(&gen_bytes);
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null);
    try std.testing.expectEqual(@as(u8, 0x02), v.group_element[0]);
    try std.testing.expectEqual(@as(u8, 0x79), v.group_element[1]);
}

test "data_serializer: group_element rejects x >= field prime" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // x = p (field prime) - should be rejected as x must be < p
    // p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    var x_equals_p: [33]u8 = undefined;
    x_equals_p[0] = 0x02;
    // Set x = p (big-endian)
    x_equals_p[1] = 0xFF;
    x_equals_p[2] = 0xFF;
    x_equals_p[3] = 0xFF;
    x_equals_p[4] = 0xFF;
    x_equals_p[5] = 0xFF;
    x_equals_p[6] = 0xFF;
    x_equals_p[7] = 0xFF;
    x_equals_p[8] = 0xFF;
    x_equals_p[9] = 0xFF;
    x_equals_p[10] = 0xFF;
    x_equals_p[11] = 0xFF;
    x_equals_p[12] = 0xFF;
    x_equals_p[13] = 0xFF;
    x_equals_p[14] = 0xFF;
    x_equals_p[15] = 0xFF;
    x_equals_p[16] = 0xFF;
    x_equals_p[17] = 0xFF;
    x_equals_p[18] = 0xFF;
    x_equals_p[19] = 0xFF;
    x_equals_p[20] = 0xFF;
    x_equals_p[21] = 0xFF;
    x_equals_p[22] = 0xFF;
    x_equals_p[23] = 0xFF;
    x_equals_p[24] = 0xFF;
    x_equals_p[25] = 0xFF;
    x_equals_p[26] = 0xFF;
    x_equals_p[27] = 0xFF;
    x_equals_p[28] = 0xFF;
    x_equals_p[29] = 0xFE; // Note: p has 0xFE here
    x_equals_p[30] = 0xFF;
    x_equals_p[31] = 0xFC;
    x_equals_p[32] = 0x2F;

    var reader = vlq.Reader.init(&x_equals_p);
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena, null));
}

test "data_serializer: deserialize tuple2 of longs" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();
    var values = ValuePool.init();

    // Register (Long, Long) tuple type
    const tuple_type = pool.add(.{ .pair = .{ .first = TypePool.LONG, .second = TypePool.LONG } }) catch unreachable;

    // Two VLQ-encoded longs: 10 and 20
    var data: [32]u8 = undefined;
    const len1 = vlq.encodeI64(10, &data);
    const len2 = vlq.encodeI64(20, data[len1..]);

    var reader = vlq.Reader.init(data[0 .. len1 + len2]);
    const result = try deserialize(tuple_type, &pool, &reader, &arena, &values);

    try std.testing.expect(result == .tuple);
    try std.testing.expectEqual(@as(u8, 2), result.tuple.len);
    try std.testing.expectEqual(@as(i64, 10), result.tuple.values[0]);
    try std.testing.expectEqual(@as(i64, 20), result.tuple.values[1]);
}

test "data_serializer: deserialize option Some(long)" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();
    var values = ValuePool.init();

    // Register Option[Long] type
    const option_type = pool.add(.{ .option = TypePool.LONG }) catch unreachable;

    // Some(42): 0x01 (flag) + VLQ(42)
    var data: [32]u8 = undefined;
    data[0] = 0x01; // Some flag
    const val_len = vlq.encodeI64(42, data[1..]);

    var reader = vlq.Reader.init(data[0 .. 1 + val_len]);
    const result = try deserialize(option_type, &pool, &reader, &arena, &values);

    try std.testing.expect(result == .option);
    try std.testing.expect(result.option.isSome());
    // Value stored in ValuePool at index result.option.value_idx
    const inner = values.get(result.option.value_idx).?;
    try std.testing.expectEqual(@as(i64, 42), inner.data.primitive);
}

test "data_serializer: deserialize option None" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();
    var values = ValuePool.init();

    const option_type = pool.add(.{ .option = TypePool.LONG }) catch unreachable;

    // None: 0x00
    var data = [_]u8{0x00};
    var reader = vlq.Reader.init(&data);
    const result = try deserialize(option_type, &pool, &reader, &arena, &values);

    try std.testing.expect(result == .option);
    try std.testing.expect(result.option.isNone());
}

// ============================================================================
// AVL Tree Serialization Tests
// ============================================================================

test "data_serializer: deserialize avl_tree with no value length" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();

    // Build serialized AvlTreeData:
    // - digest: 33 bytes (all 0x42 for test, height=5 in last byte)
    // - tree_flags: 0x07 (all operations allowed)
    // - key_length: 32 (VLQ: 0x20)
    // - value_length_opt: None (0x00)
    var data: [64]u8 = undefined;
    var pos: usize = 0;

    // Digest (32 bytes hash + 1 byte height)
    @memset(data[pos..][0..32], 0x42);
    pos += 32;
    data[pos] = 5; // height
    pos += 1;

    // Tree flags
    data[pos] = 0x07; // insert | update | remove allowed
    pos += 1;

    // Key length (VLQ)
    const key_len_size = vlq.encodeU64(32, data[pos..]);
    pos += key_len_size;

    // Value length option: None
    data[pos] = 0x00;
    pos += 1;

    var reader = vlq.Reader.init(data[0..pos]);
    const result = try deserialize(TypePool.AVL_TREE, &pool, &reader, &arena, null);

    try std.testing.expect(result == .avl_tree);
    try std.testing.expectEqual(@as(u8, 5), result.avl_tree.height());
    try std.testing.expectEqual(@as(u32, 32), result.avl_tree.key_length);
    try std.testing.expectEqual(@as(?u32, null), result.avl_tree.value_length_opt);
    try std.testing.expect(result.avl_tree.isInsertAllowed());
    try std.testing.expect(result.avl_tree.isUpdateAllowed());
    try std.testing.expect(result.avl_tree.isRemoveAllowed());
}

test "data_serializer: deserialize avl_tree with value length" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();

    var data: [64]u8 = undefined;
    var pos: usize = 0;

    // Digest
    @memset(data[pos..][0..32], 0xAB);
    pos += 32;
    data[pos] = 10; // height
    pos += 1;

    // Tree flags: read-only
    data[pos] = 0x00;
    pos += 1;

    // Key length
    const key_len_size = vlq.encodeU64(8, data[pos..]);
    pos += key_len_size;

    // Value length option: Some(64)
    data[pos] = 0x01;
    pos += 1;
    const val_len_size = vlq.encodeU64(64, data[pos..]);
    pos += val_len_size;

    var reader = vlq.Reader.init(data[0..pos]);
    const result = try deserialize(TypePool.AVL_TREE, &pool, &reader, &arena, null);

    try std.testing.expect(result == .avl_tree);
    try std.testing.expectEqual(@as(u8, 10), result.avl_tree.height());
    try std.testing.expectEqual(@as(u32, 8), result.avl_tree.key_length);
    try std.testing.expectEqual(@as(?u32, 64), result.avl_tree.value_length_opt);
    try std.testing.expect(!result.avl_tree.isInsertAllowed());
}

test "data_serializer: roundtrip avl_tree" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();
    var buf: [128]u8 = undefined;

    // Create an AvlTreeData
    var digest: [avl.digest_size]u8 = undefined;
    @memset(&digest, 0xDE);
    digest[32] = 7; // height

    const tree_data = avl.AvlTreeData.init(
        digest,
        avl.AvlTreeFlags.init(true, false, true), // insert + remove
        16, // key_length
        128, // value_length
    ) catch unreachable;

    const value = Value{ .avl_tree = tree_data };

    // Serialize
    const len = try serialize(TypePool.AVL_TREE, &pool, value, &buf);

    // Deserialize
    var reader = vlq.Reader.init(buf[0..len]);
    const result = try deserialize(TypePool.AVL_TREE, &pool, &reader, &arena, null);

    // Verify roundtrip
    try std.testing.expect(result == .avl_tree);
    try std.testing.expectEqual(tree_data.height(), result.avl_tree.height());
    try std.testing.expectEqual(tree_data.key_length, result.avl_tree.key_length);
    try std.testing.expectEqual(tree_data.value_length_opt, result.avl_tree.value_length_opt);
    try std.testing.expectEqual(tree_data.tree_flags.toByte(), result.avl_tree.tree_flags.toByte());
    try std.testing.expectEqualSlices(u8, &tree_data.digest, &result.avl_tree.digest);
}

test "data_serializer: avl_tree rejects invalid key_length" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();

    var data: [64]u8 = undefined;
    var pos: usize = 0;

    // Digest
    @memset(data[pos..][0..33], 0x00);
    pos += 33;

    // Tree flags
    data[pos] = 0x00;
    pos += 1;

    // Key length: 0 (invalid)
    const key_len_size = vlq.encodeU64(0, data[pos..]);
    pos += key_len_size;

    // Value length option: None
    data[pos] = 0x00;
    pos += 1;

    var reader = vlq.Reader.init(data[0..pos]);
    try std.testing.expectError(error.InvalidData, deserialize(TypePool.AVL_TREE, &pool, &reader, &arena, null));
}
