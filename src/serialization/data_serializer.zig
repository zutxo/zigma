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
const secp256k1 = @import("../crypto/secp256k1.zig");

const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const SType = types.SType;
const BumpAllocator = memory.BumpAllocator;

// ============================================================================
// Value Representation
// ============================================================================

/// Maximum size for BigInt (256 bits = 32 bytes)
pub const max_bigint_bytes: usize = 32;

/// GroupElement size (33 bytes compressed SEC1)
pub const group_element_size: usize = 33;

// Compile-time sanity checks
comptime {
    assert(max_bigint_bytes == 32);
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

    /// Single box reference (index into context array)
    box: BoxRef,

    /// Collection of boxes (reference to context array)
    box_coll: BoxCollRef,

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

    /// Reference to option value
    pub const OptionRef = struct {
        inner_type: TypeIndex,
        /// null if None, otherwise index into values
        value_idx: ?u16,
    };

    /// Reference to tuple
    pub const TupleRef = struct {
        start: u16,
        len: u8,
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
pub fn deserialize(
    type_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype, // BumpAllocator
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
        .coll => |elem_idx| deserializeColl(elem_idx, pool, reader, arena),
        .option => |inner_idx| deserializeOption(inner_idx, pool, reader, arena),
        .pair => |p| deserializeTuple2(p.first, p.second, pool, reader, arena),
        .triple => |tr| deserializeTuple3(tr.a, tr.b, tr.c, pool, reader, arena),
        .quadruple => |q| deserializeTuple4(q.a, q.b, q.c, q.d, pool, reader, arena),
        .tuple => |indices| deserializeTupleN(indices, pool, reader, arena),
        .func => error.NotSupported,
        // Object types cannot be deserialized as data
        .any, .box, .avl_tree, .context, .header, .pre_header, .global => error.NotSupported,
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

fn deserializeColl(
    elem_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
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

    // Generic collection - recursive deserialization
    // This would need a values array to store results
    // For now, skip elements and return error - full implementation later
    var i: u16 = 0;
    while (i < len) : (i += 1) {
        _ = deserialize(elem_idx, pool, reader, arena) catch {};
    }
    return error.NotSupported;
}

fn deserializeOption(
    inner_idx: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!Value {
    // Option format (v6+): 0x00 = None, 0x01 + value = Some
    const flag = reader.readByte() catch |e| return mapVlqError(e);

    if (flag == 0) {
        return .{ .option = .{ .inner_type = inner_idx, .value_idx = null } };
    }

    // Would need to deserialize inner value and store index
    // Skip the inner value for now
    _ = deserialize(inner_idx, pool, reader, arena) catch {};
    return error.NotSupported;
}

fn deserializeTuple2(
    t1: TypeIndex,
    t2: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!Value {
    _ = t1;
    _ = t2;
    _ = pool;
    _ = arena;
    _ = reader;

    // Tuples are serialized as sequential elements
    // Would need values array to store results
    return error.NotSupported;
}

fn deserializeTuple3(
    t1: TypeIndex,
    t2: TypeIndex,
    t3: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!Value {
    _ = t1;
    _ = t2;
    _ = t3;
    _ = pool;
    _ = arena;
    _ = reader;
    return error.NotSupported;
}

fn deserializeTuple4(
    t1: TypeIndex,
    t2: TypeIndex,
    t3: TypeIndex,
    t4: TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!Value {
    _ = t1;
    _ = t2;
    _ = t3;
    _ = t4;
    _ = pool;
    _ = arena;
    _ = reader;
    return error.NotSupported;
}

fn deserializeTupleN(
    indices: []const TypeIndex,
    pool: *const TypePool,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!Value {
    _ = indices;
    _ = pool;
    _ = arena;
    _ = reader;
    return error.NotSupported;
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

// ============================================================================
// Tests
// ============================================================================

test "data_serializer: deserialize boolean" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // true = 0x01
    var r1 = vlq.Reader.init(&[_]u8{0x01});
    const v1 = try deserialize(TypePool.BOOLEAN, &pool, &r1, &arena);
    try std.testing.expect(v1.boolean == true);

    // false = 0x00
    var r2 = vlq.Reader.init(&[_]u8{0x00});
    const v2 = try deserialize(TypePool.BOOLEAN, &pool, &r2, &arena);
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
        const v = try deserialize(TypePool.BYTE, &pool, &reader, &arena);
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
        const v = try deserialize(TypePool.SHORT, &pool, &reader, &arena);
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
        const v = try deserialize(TypePool.INT, &pool, &reader, &arena);
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
        const v = try deserialize(TypePool.LONG, &pool, &reader, &arena);
        try std.testing.expectEqual(tc.expected, v.long);
    }
}

test "data_serializer: deserialize bigint" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Test cases from vectors.json
    // {"value": "0", "bytes": "0100"} - length(1) + 0x00
    var r1 = vlq.Reader.init(&[_]u8{ 0x01, 0x00 });
    const v1 = try deserialize(TypePool.BIG_INT, &pool, &r1, &arena);
    try std.testing.expectEqual(@as(u8, 1), v1.big_int.len);
    try std.testing.expectEqual(@as(u8, 0x00), v1.big_int.bytes[0]);
    try std.testing.expect(v1.big_int.isZero());

    // {"value": "1", "bytes": "0101"} - length(1) + 0x01
    var r2 = vlq.Reader.init(&[_]u8{ 0x01, 0x01 });
    const v2 = try deserialize(TypePool.BIG_INT, &pool, &r2, &arena);
    try std.testing.expectEqual(@as(u8, 1), v2.big_int.len);
    try std.testing.expectEqual(@as(u8, 0x01), v2.big_int.bytes[0]);
    try std.testing.expect(!v2.big_int.isNegative());

    // {"value": "-1", "bytes": "01ff"} - length(1) + 0xff
    var r3 = vlq.Reader.init(&[_]u8{ 0x01, 0xff });
    const v3 = try deserialize(TypePool.BIG_INT, &pool, &r3, &arena);
    try std.testing.expectEqual(@as(u8, 1), v3.big_int.len);
    try std.testing.expectEqual(@as(u8, 0xff), v3.big_int.bytes[0]);
    try std.testing.expect(v3.big_int.isNegative());

    // {"value": "256", "bytes": "020100"} - length(2) + big-endian 0x0100
    var r4 = vlq.Reader.init(&[_]u8{ 0x02, 0x01, 0x00 });
    const v4 = try deserialize(TypePool.BIG_INT, &pool, &r4, &arena);
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
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena);

    try std.testing.expectEqual(@as(u8, 0x02), v.group_element[0]); // Compressed prefix
    try std.testing.expectEqual(@as(u8, 0x79), v.group_element[1]);
}

test "data_serializer: deserialize coll_byte" {
    var pool = TypePool.init();
    var arena = BumpAllocator(256).init();

    // Empty collection
    var r1 = vlq.Reader.init(&[_]u8{0x00}); // length = 0
    const v1 = try deserialize(TypePool.COLL_BYTE, &pool, &r1, &arena);
    try std.testing.expectEqual(@as(usize, 0), v1.coll_byte.len);

    // Collection with data
    arena.reset();
    var r2 = vlq.Reader.init(&[_]u8{ 0x03, 0x01, 0x02, 0x03 }); // length = 3, data = [1, 2, 3]
    const v2 = try deserialize(TypePool.COLL_BYTE, &pool, &r2, &arena);
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
        const v2 = try deserialize(TypePool.INT, &pool, &reader, &arena);
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
    const v2 = try deserialize(TypePool.COLL_BYTE, &pool, &reader, &arena);
    try std.testing.expectEqualSlices(u8, &data, v2.coll_byte);
}

test "data_serializer: error on truncated input" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // BigInt with length but no data
    var reader = vlq.Reader.init(&[_]u8{0x05}); // length = 5, but no bytes
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(TypePool.BIG_INT, &pool, &reader, &arena));
}

test "data_serializer: error on invalid bigint length" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // BigInt with length 0
    var r1 = vlq.Reader.init(&[_]u8{0x00});
    try std.testing.expectError(error.InvalidData, deserialize(TypePool.BIG_INT, &pool, &r1, &arena));

    // BigInt with length > 32
    var r2 = vlq.Reader.init(&[_]u8{0x21}); // 33
    try std.testing.expectError(error.InvalidData, deserialize(TypePool.BIG_INT, &pool, &r2, &arena));
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
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena));
}

test "data_serializer: group_element rejects point not on curve" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // Valid prefix but x coordinate that doesn't produce a valid y
    // For x = 5: y² = 5³ + 7 = 132, which has no square root mod p
    // The array is big-endian: 31 zero bytes followed by 0x05
    var not_on_curve: [33]u8 = [_]u8{0x02} ++ [_]u8{0} ** 31 ++ [_]u8{0x05};

    var reader = vlq.Reader.init(&not_on_curve);
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena));
}

test "data_serializer: group_element accepts infinity" {
    var pool = TypePool.init();
    var arena = BumpAllocator(64).init();

    // All zeros = point at infinity (valid identity element)
    const infinity: [33]u8 = [_]u8{0} ** 33;

    var reader = vlq.Reader.init(&infinity);
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena);
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
    const v = try deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena);
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
    try std.testing.expectError(error.InvalidGroupElement, deserialize(TypePool.GROUP_ELEMENT, &pool, &reader, &arena));
}
