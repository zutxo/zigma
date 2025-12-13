//! Type Serializer/Deserializer for ErgoTree
//!
//! Converts between type codes (bytes) and TypePool indices.
//! Uses TypeCodeInfo.parse() from types.zig for code decoding.
//!
//! Reference: TYPE_SYSTEM.md, Rust ergotree-ir/src/serialization/types.rs

const std = @import("std");
const assert = std.debug.assert;
const vlq = @import("vlq.zig");
const types = @import("../core/types.zig");

const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const TypeCodeInfo = types.TypeCodeInfo;
const TypeCode = types.TypeCode;
const PrimitiveCode = types.PrimitiveCode;
const SType = types.SType;

/// Maximum recursion depth for type parsing (bounded per ZIGMA_STYLE)
const max_type_depth: u8 = 8;

// Compile-time sanity checks
comptime {
    // Max depth should handle worst-case nesting like Coll[Coll[Coll[...]]]
    assert(max_type_depth >= 4);
    // But not too deep to prevent DoS
    assert(max_type_depth <= 16);
}

/// Errors that can occur during type deserialization
pub const DeserializeError = error{
    /// Input ended unexpectedly
    UnexpectedEndOfInput,
    /// VLQ value exceeded type bounds
    Overflow,
    /// Invalid type code
    InvalidTypeCode,
    /// Type pool is full
    PoolFull,
    /// Type nesting too deep
    NestingTooDeep,
    /// Tuple has invalid length
    InvalidTupleLength,
    /// Function domain too long (v6+)
    FuncDomainTooLong,
    /// Function has too many type params (v6+)
    FuncTpeParamsTooLong,
    /// Type variable name too long (v6+)
    TypeVarNameTooLong,
};

/// Deserialize a type from bytes into the TypePool.
/// Returns the TypeIndex of the deserialized type.
///
/// Depth parameter enables bounded recursion (per ZIGMA_STYLE: parsing can recurse with limits).
pub fn deserialize(
    pool: *TypePool,
    reader: *vlq.Reader,
) DeserializeError!TypeIndex {
    return deserializeWithDepth(pool, reader, 0);
}

fn deserializeWithDepth(
    pool: *TypePool,
    reader: *vlq.Reader,
    depth: u8,
) DeserializeError!TypeIndex {
    // PRECONDITION: Recursion depth bounded
    if (depth >= max_type_depth) {
        return error.NestingTooDeep;
    }

    // Read the type code byte
    const code = reader.readByte() catch |err| switch (err) {
        error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
        error.Overflow => return error.Overflow,
    };

    // Parse the type code structure
    const info = TypeCodeInfo.parse(code);

    // INVARIANT: We handle all valid type code patterns
    return switch (info) {
        .invalid => error.InvalidTypeCode,

        // Primitives: return pre-allocated index
        .primitive => |t| primitiveToIndex(t),

        // Objects: return pre-allocated index
        .object => |t| objectToIndex(t),

        // Coll[Primitive]: single-byte encoding
        .coll_primitive => |prim_code| blk: {
            const elem_idx = primitiveCodeToIndex(prim_code);
            break :blk pool.getColl(elem_idx) catch return error.PoolFull;
        },

        // Coll[Coll[Primitive]]: single-byte encoding
        .nested_coll_primitive => |prim_code| blk: {
            const inner_idx = primitiveCodeToIndex(prim_code);
            const coll_idx = pool.getColl(inner_idx) catch return error.PoolFull;
            break :blk pool.getColl(coll_idx) catch return error.PoolFull;
        },

        // Option[Primitive]: single-byte encoding
        .option_primitive => |prim_code| blk: {
            const elem_idx = primitiveCodeToIndex(prim_code);
            break :blk pool.getOption(elem_idx) catch return error.PoolFull;
        },

        // Option[Coll[Primitive]]: single-byte encoding
        .option_coll_primitive => |prim_code| blk: {
            const inner_idx = primitiveCodeToIndex(prim_code);
            const coll_idx = pool.getColl(inner_idx) catch return error.PoolFull;
            break :blk pool.getOption(coll_idx) catch return error.PoolFull;
        },

        // (T, T) symmetric pair: single-byte encoding
        .symmetric_pair_primitive => |prim_code| blk: {
            const elem_idx = primitiveCodeToIndex(prim_code);
            break :blk pool.getPair(elem_idx, elem_idx) catch return error.PoolFull;
        },

        // (Primitive, X): parse second type
        .pair1_primitive => |prim_code| blk: {
            const first_idx = primitiveCodeToIndex(prim_code);
            const second_idx = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.getPair(first_idx, second_idx) catch return error.PoolFull;
        },

        // (X, Primitive): parse first type
        .pair2_primitive => |prim_code| blk: {
            const second_idx = primitiveCodeToIndex(prim_code);
            const first_idx = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.getPair(first_idx, second_idx) catch return error.PoolFull;
        },

        // Coll[NonPrimitive]: generic collection
        .coll_generic => blk: {
            const elem_idx = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.getColl(elem_idx) catch return error.PoolFull;
        },

        // Option[NonPrimitive]: generic option
        .option_generic => blk: {
            const elem_idx = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.getOption(elem_idx) catch return error.PoolFull;
        },

        // Triple: parse 3 types
        .triple => blk: {
            const a = try deserializeWithDepth(pool, reader, depth + 1);
            const b = try deserializeWithDepth(pool, reader, depth + 1);
            const c = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.add(.{ .triple = .{ .a = a, .b = b, .c = c } }) catch return error.PoolFull;
        },

        // Quadruple: parse 4 types
        .quadruple => blk: {
            const a = try deserializeWithDepth(pool, reader, depth + 1);
            const b = try deserializeWithDepth(pool, reader, depth + 1);
            const c = try deserializeWithDepth(pool, reader, depth + 1);
            const d = try deserializeWithDepth(pool, reader, depth + 1);
            break :blk pool.add(.{ .quadruple = .{ .a = a, .b = b, .c = c, .d = d } }) catch return error.PoolFull;
        },

        // Tuple 5+: read length, parse N types
        .tuple5plus => blk: {
            const len = reader.readByte() catch |err| switch (err) {
                error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
                error.Overflow => return error.Overflow,
            };

            // Validate tuple length (5-max)
            if (len < 5) return error.InvalidTupleLength;
            if (len > types.max_tuple_elements) return error.InvalidTupleLength;

            // Parse element types
            var elements: [types.max_tuple_elements]types.TypeIndex = undefined;
            var i: u8 = 0;
            while (i < len) : (i += 1) {
                elements[i] = try deserializeWithDepth(pool, reader, depth + 1);
            }

            break :blk pool.getTupleN(elements[0..len]) catch return error.PoolFull;
        },

        // Function type (v6+)
        .func => blk: {
            // Read domain length
            const domain_len = reader.readByte() catch |err| switch (err) {
                error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
                error.Overflow => return error.Overflow,
            };
            if (domain_len > types.max_func_domain) return error.FuncDomainTooLong;

            // Read domain types
            var func_type = types.FuncType{
                .domain = undefined,
                .domain_len = domain_len,
                .range = undefined,
                .tpe_params = undefined,
                .tpe_params_len = 0,
            };
            var i: u8 = 0;
            while (i < domain_len) : (i += 1) {
                func_type.domain[i] = try deserializeWithDepth(pool, reader, depth + 1);
            }

            // Read range type
            func_type.range = try deserializeWithDepth(pool, reader, depth + 1);

            // Read type params length
            const tpe_params_len = reader.readByte() catch |err| switch (err) {
                error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
                error.Overflow => return error.Overflow,
            };
            if (tpe_params_len > types.max_func_tpe_params) return error.FuncTpeParamsTooLong;
            func_type.tpe_params_len = tpe_params_len;

            // Read type params (each is a type_var)
            i = 0;
            while (i < tpe_params_len) : (i += 1) {
                func_type.tpe_params[i] = try deserializeWithDepth(pool, reader, depth + 1);
            }

            break :blk pool.add(.{ .func = func_type }) catch return error.PoolFull;
        },

        // Type variable (v6+)
        .type_var => blk: {
            // Read name length
            const name_len = reader.readByte() catch |err| switch (err) {
                error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
                error.Overflow => return error.Overflow,
            };
            if (name_len > types.max_type_var_name) return error.TypeVarNameTooLong;
            if (name_len == 0) return error.InvalidTypeCode; // Name cannot be empty

            // Read name bytes
            var type_var = types.TypeVarType{
                .name = undefined,
                .name_len = name_len,
            };
            var j: u8 = 0;
            while (j < name_len) : (j += 1) {
                type_var.name[j] = reader.readByte() catch |err| switch (err) {
                    error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
                    error.Overflow => return error.Overflow,
                };
            }

            break :blk pool.add(.{ .type_var = type_var }) catch return error.PoolFull;
        },
    };
}

/// Map primitive SType to pre-allocated TypePool index
fn primitiveToIndex(t: SType) TypeIndex {
    return switch (t) {
        .boolean => TypePool.BOOLEAN,
        .byte => TypePool.BYTE,
        .short => TypePool.SHORT,
        .int => TypePool.INT,
        .long => TypePool.LONG,
        .big_int => TypePool.BIG_INT,
        .group_element => TypePool.GROUP_ELEMENT,
        .sigma_prop => TypePool.SIGMA_PROP,
        .unsigned_big_int => TypePool.UNSIGNED_BIG_INT,
        else => unreachable, // Caller ensures only primitives
    };
}

/// Map object SType to pre-allocated TypePool index
fn objectToIndex(t: SType) TypeIndex {
    return switch (t) {
        .any => TypePool.ANY,
        .unit => TypePool.UNIT,
        .box => TypePool.BOX,
        .avl_tree => TypePool.AVL_TREE,
        .context => TypePool.CONTEXT,
        .header => TypePool.HEADER,
        .pre_header => TypePool.PRE_HEADER,
        .global => TypePool.GLOBAL,
        else => unreachable, // Caller ensures only objects
    };
}

/// Map primitive code (1-9) to pre-allocated TypePool index
fn primitiveCodeToIndex(code: u8) TypeIndex {
    // PRECONDITION: Code is valid primitive code
    assert(PrimitiveCode.isEmbeddable(code));

    return switch (code) {
        1 => TypePool.BOOLEAN,
        2 => TypePool.BYTE,
        3 => TypePool.SHORT,
        4 => TypePool.INT,
        5 => TypePool.LONG,
        6 => TypePool.BIG_INT,
        7 => TypePool.GROUP_ELEMENT,
        8 => TypePool.SIGMA_PROP,
        9 => TypePool.UNSIGNED_BIG_INT,
        else => unreachable,
    };
}

/// Serialize a type from TypePool to bytes.
/// Returns number of bytes written.
pub fn serialize(
    pool: *const TypePool,
    type_idx: TypeIndex,
    buf: []u8,
) error{BufferTooSmall}!usize {
    return serializeWithDepth(pool, type_idx, buf, 0);
}

fn serializeWithDepth(
    pool: *const TypePool,
    type_idx: TypeIndex,
    buf: []u8,
    depth: u8,
) error{BufferTooSmall}!usize {
    // PRECONDITION: Recursion depth bounded
    assert(depth < max_type_depth);

    if (buf.len == 0) return error.BufferTooSmall;

    const t = pool.get(type_idx);

    // Handle non-composite types with direct type codes
    const direct_code = t.typeCode();
    if (direct_code != 0) {
        buf[0] = direct_code;
        return 1;
    }

    // Handle composite types
    switch (t) {
        .coll => |elem_idx| {
            const code = pool.getTypeCode(type_idx);
            buf[0] = code;

            // If generic (code == 12), serialize element type
            if (code == types.TypeConstrCode.coll_generic) {
                const elem_len = try serializeWithDepth(pool, elem_idx, buf[1..], depth + 1);
                return 1 + elem_len;
            }
            return 1;
        },
        .option => |elem_idx| {
            const code = pool.getTypeCode(type_idx);
            buf[0] = code;

            // If generic (code == 36), serialize element type
            if (code == types.TypeConstrCode.option_generic) {
                const elem_len = try serializeWithDepth(pool, elem_idx, buf[1..], depth + 1);
                return 1 + elem_len;
            }
            return 1;
        },
        .pair => |p| {
            const code = pool.getTypeCode(type_idx);
            buf[0] = code;

            const first = pool.get(p.first);
            const second = pool.get(p.second);

            // Symmetric pair (T, T) where T is embeddable: single byte
            if (p.first == p.second and first.embeddableCode() != null) {
                return 1;
            }

            // (Primitive, X): serialize X
            if (first.embeddableCode() != null) {
                const second_len = try serializeWithDepth(pool, p.second, buf[1..], depth + 1);
                return 1 + second_len;
            }

            // (X, Primitive): serialize X
            if (second.embeddableCode() != null) {
                const first_len = try serializeWithDepth(pool, p.first, buf[1..], depth + 1);
                return 1 + first_len;
            }

            // Generic pair: serialize both (not handled by single-byte encoding)
            // Use Pair1 encoding (60 + 0) + first + second
            buf[0] = types.TypeConstrCode.pair1_base;
            var written: usize = 1;
            written += try serializeWithDepth(pool, p.first, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, p.second, buf[written..], depth + 1);
            return written;
        },
        .triple => |tr| {
            if (buf.len < 4) return error.BufferTooSmall;
            buf[0] = types.TypeConstrCode.triple;
            var written: usize = 1;
            written += try serializeWithDepth(pool, tr.a, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, tr.b, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, tr.c, buf[written..], depth + 1);
            return written;
        },
        .quadruple => |q| {
            if (buf.len < 5) return error.BufferTooSmall;
            buf[0] = types.TypeConstrCode.quadruple;
            var written: usize = 1;
            written += try serializeWithDepth(pool, q.a, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, q.b, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, q.c, buf[written..], depth + 1);
            written += try serializeWithDepth(pool, q.d, buf[written..], depth + 1);
            return written;
        },
        .tuple => |tuple_n| {
            if (buf.len < 2) return error.BufferTooSmall;
            buf[0] = types.TypeConstrCode.tuple5plus;
            buf[1] = tuple_n.len;
            var written: usize = 2;
            for (tuple_n.slice()) |idx| {
                written += try serializeWithDepth(pool, idx, buf[written..], depth + 1);
            }
            return written;
        },
        .func => |f| {
            // Function type: code + domain_len + domains + range + tpe_params_len + tpe_params
            if (buf.len < 3) return error.BufferTooSmall;
            buf[0] = types.ObjectCode.func;
            buf[1] = f.domain_len;
            var written: usize = 2;

            // Serialize domain types
            for (f.domainSlice()) |domain_idx| {
                written += try serializeWithDepth(pool, domain_idx, buf[written..], depth + 1);
            }

            // Serialize range type
            written += try serializeWithDepth(pool, f.range, buf[written..], depth + 1);

            // Serialize type params
            if (buf.len <= written) return error.BufferTooSmall;
            buf[written] = f.tpe_params_len;
            written += 1;

            for (f.tpeParamsSlice()) |tpe_idx| {
                written += try serializeWithDepth(pool, tpe_idx, buf[written..], depth + 1);
            }

            return written;
        },
        .type_var => |tv| {
            // Type variable: code + name_len + name_bytes
            const needed = 2 + tv.name_len;
            if (buf.len < needed) return error.BufferTooSmall;
            buf[0] = types.ObjectCode.type_var;
            buf[1] = tv.name_len;
            @memcpy(buf[2 .. 2 + tv.name_len], tv.nameSlice());
            return needed;
        },
        else => unreachable, // All composite types handled
    }
}

// ============================================================================
// Tests
// ============================================================================

test "type_serializer: deserialize primitives" {
    var pool = TypePool.init();

    // Boolean (0x01)
    var r1 = vlq.Reader.init(&[_]u8{0x01});
    try std.testing.expectEqual(TypePool.BOOLEAN, try deserialize(&pool, &r1));

    // Byte (0x02)
    var r2 = vlq.Reader.init(&[_]u8{0x02});
    try std.testing.expectEqual(TypePool.BYTE, try deserialize(&pool, &r2));

    // Int (0x04)
    var r3 = vlq.Reader.init(&[_]u8{0x04});
    try std.testing.expectEqual(TypePool.INT, try deserialize(&pool, &r3));

    // Long (0x05)
    var r4 = vlq.Reader.init(&[_]u8{0x05});
    try std.testing.expectEqual(TypePool.LONG, try deserialize(&pool, &r4));

    // BigInt (0x06)
    var r5 = vlq.Reader.init(&[_]u8{0x06});
    try std.testing.expectEqual(TypePool.BIG_INT, try deserialize(&pool, &r5));

    // GroupElement (0x07)
    var r6 = vlq.Reader.init(&[_]u8{0x07});
    try std.testing.expectEqual(TypePool.GROUP_ELEMENT, try deserialize(&pool, &r6));

    // SigmaProp (0x08)
    var r7 = vlq.Reader.init(&[_]u8{0x08});
    try std.testing.expectEqual(TypePool.SIGMA_PROP, try deserialize(&pool, &r7));
}

test "type_serializer: deserialize objects" {
    var pool = TypePool.init();

    // SAny (0x61 = 97)
    var r1 = vlq.Reader.init(&[_]u8{0x61});
    try std.testing.expectEqual(TypePool.ANY, try deserialize(&pool, &r1));

    // SUnit (0x62 = 98)
    var r2 = vlq.Reader.init(&[_]u8{0x62});
    try std.testing.expectEqual(TypePool.UNIT, try deserialize(&pool, &r2));

    // SBox (0x63 = 99)
    var r3 = vlq.Reader.init(&[_]u8{0x63});
    try std.testing.expectEqual(TypePool.BOX, try deserialize(&pool, &r3));

    // SAvlTree (0x64 = 100)
    var r4 = vlq.Reader.init(&[_]u8{0x64});
    try std.testing.expectEqual(TypePool.AVL_TREE, try deserialize(&pool, &r4));
}

test "type_serializer: deserialize Coll[Primitive]" {
    var pool = TypePool.init();

    // Coll[Boolean] = 0x0d (1 + 12 = 13)
    var r1 = vlq.Reader.init(&[_]u8{0x0d});
    const coll_bool = try deserialize(&pool, &r1);
    try std.testing.expect(pool.get(coll_bool) == .coll);
    try std.testing.expectEqual(TypePool.BOOLEAN, pool.get(coll_bool).coll);

    // Coll[Byte] = 0x0e (2 + 12 = 14)
    var r2 = vlq.Reader.init(&[_]u8{0x0e});
    try std.testing.expectEqual(TypePool.COLL_BYTE, try deserialize(&pool, &r2));

    // Coll[Int] = 0x10 (4 + 12 = 16)
    var r3 = vlq.Reader.init(&[_]u8{0x10});
    try std.testing.expectEqual(TypePool.COLL_INT, try deserialize(&pool, &r3));

    // Coll[Long] = 0x11 (5 + 12 = 17)
    var r4 = vlq.Reader.init(&[_]u8{0x11});
    try std.testing.expectEqual(TypePool.COLL_LONG, try deserialize(&pool, &r4));
}

test "type_serializer: deserialize Coll[Coll[Primitive]]" {
    var pool = TypePool.init();

    // Coll[Coll[Byte]] = 0x1a (2 + 24 = 26)
    var r1 = vlq.Reader.init(&[_]u8{0x1a});
    try std.testing.expectEqual(TypePool.COLL_COLL_BYTE, try deserialize(&pool, &r1));
}

test "type_serializer: deserialize Option[Primitive]" {
    var pool = TypePool.init();

    // Option[Boolean] = 0x25 (1 + 36 = 37)
    var r1 = vlq.Reader.init(&[_]u8{0x25});
    const opt_bool = try deserialize(&pool, &r1);
    try std.testing.expect(pool.get(opt_bool) == .option);
    try std.testing.expectEqual(TypePool.BOOLEAN, pool.get(opt_bool).option);

    // Option[Int] = 0x28 (4 + 36 = 40)
    var r2 = vlq.Reader.init(&[_]u8{0x28});
    try std.testing.expectEqual(TypePool.OPTION_INT, try deserialize(&pool, &r2));

    // Option[Long] = 0x29 (5 + 36 = 41)
    var r3 = vlq.Reader.init(&[_]u8{0x29});
    try std.testing.expectEqual(TypePool.OPTION_LONG, try deserialize(&pool, &r3));
}

test "type_serializer: deserialize Option[Coll[Primitive]]" {
    var pool = TypePool.init();

    // Option[Coll[Byte]] = 0x32 (2 + 48 = 50)
    var r1 = vlq.Reader.init(&[_]u8{0x32});
    try std.testing.expectEqual(TypePool.OPTION_COLL_BYTE, try deserialize(&pool, &r1));
}

test "type_serializer: deserialize symmetric pairs" {
    var pool = TypePool.init();

    // (Int, Int) = 0x58 (4 + 84 = 88)
    var r1 = vlq.Reader.init(&[_]u8{0x58});
    const pair_idx = try deserialize(&pool, &r1);
    const pair_type = pool.get(pair_idx);
    try std.testing.expect(pair_type == .pair);
    try std.testing.expectEqual(TypePool.INT, pair_type.pair.first);
    try std.testing.expectEqual(TypePool.INT, pair_type.pair.second);

    // (Byte, Byte) = 0x56 (2 + 84 = 86)
    var r2 = vlq.Reader.init(&[_]u8{0x56});
    const pair2_idx = try deserialize(&pool, &r2);
    const pair2_type = pool.get(pair2_idx);
    try std.testing.expect(pair2_type == .pair);
    try std.testing.expectEqual(TypePool.BYTE, pair2_type.pair.first);
    try std.testing.expectEqual(TypePool.BYTE, pair2_type.pair.second);
}

test "type_serializer: deserialize Pair1 (Primitive, X)" {
    var pool = TypePool.init();

    // (Int, Box) = 0x40 + 0x63 = Pair1(4) + Box
    var r1 = vlq.Reader.init(&[_]u8{ 0x40, 0x63 });
    const pair_idx = try deserialize(&pool, &r1);
    const pair_type = pool.get(pair_idx);
    try std.testing.expect(pair_type == .pair);
    try std.testing.expectEqual(TypePool.INT, pair_type.pair.first);
    try std.testing.expectEqual(TypePool.BOX, pair_type.pair.second);
}

test "type_serializer: deserialize Pair2 (X, Primitive)" {
    var pool = TypePool.init();

    // (Box, Int) = 0x4c + 0x63 = Pair2(4) + Box
    var r1 = vlq.Reader.init(&[_]u8{ 0x4c, 0x63 });
    const pair_idx = try deserialize(&pool, &r1);
    const pair_type = pool.get(pair_idx);
    try std.testing.expect(pair_type == .pair);
    try std.testing.expectEqual(TypePool.BOX, pair_type.pair.first);
    try std.testing.expectEqual(TypePool.INT, pair_type.pair.second);
}

test "type_serializer: deserialize generic Coll[Box]" {
    var pool = TypePool.init();

    // Coll[Box] = 0x0c + 0x63 = CollGeneric + Box
    var r1 = vlq.Reader.init(&[_]u8{ 0x0c, 0x63 });
    const coll_idx = try deserialize(&pool, &r1);
    const coll_type = pool.get(coll_idx);
    try std.testing.expect(coll_type == .coll);
    try std.testing.expectEqual(TypePool.BOX, coll_type.coll);
}

test "type_serializer: deserialize generic Option[Box]" {
    var pool = TypePool.init();

    // Option[Box] = 0x24 + 0x63 = OptionGeneric + Box
    var r1 = vlq.Reader.init(&[_]u8{ 0x24, 0x63 });
    const opt_idx = try deserialize(&pool, &r1);
    const opt_type = pool.get(opt_idx);
    try std.testing.expect(opt_type == .option);
    try std.testing.expectEqual(TypePool.BOX, opt_type.option);
}

test "type_serializer: deserialize triple" {
    var pool = TypePool.init();

    // (Int, Int, Int) = 0x48 + 0x04 + 0x04 + 0x04
    var r1 = vlq.Reader.init(&[_]u8{ 0x48, 0x04, 0x04, 0x04 });
    const triple_idx = try deserialize(&pool, &r1);
    const triple_type = pool.get(triple_idx);
    try std.testing.expect(triple_type == .triple);
    try std.testing.expectEqual(TypePool.INT, triple_type.triple.a);
    try std.testing.expectEqual(TypePool.INT, triple_type.triple.b);
    try std.testing.expectEqual(TypePool.INT, triple_type.triple.c);
}

test "type_serializer: deserialize quadruple" {
    var pool = TypePool.init();

    // (Int, Int, Int, Int) = 0x54 + 0x04 + 0x04 + 0x04 + 0x04
    var r1 = vlq.Reader.init(&[_]u8{ 0x54, 0x04, 0x04, 0x04, 0x04 });
    const quad_idx = try deserialize(&pool, &r1);
    const quad_type = pool.get(quad_idx);
    try std.testing.expect(quad_type == .quadruple);
    try std.testing.expectEqual(TypePool.INT, quad_type.quadruple.a);
    try std.testing.expectEqual(TypePool.INT, quad_type.quadruple.b);
    try std.testing.expectEqual(TypePool.INT, quad_type.quadruple.c);
    try std.testing.expectEqual(TypePool.INT, quad_type.quadruple.d);
}

test "type_serializer: deserialize tuple5plus" {
    var pool = TypePool.init();

    // (Int, Int, Int, Int, Int) = 0x60 (tuple5plus) + 0x05 (len) + 5x 0x04 (Int)
    var r1 = vlq.Reader.init(&[_]u8{ 0x60, 0x05, 0x04, 0x04, 0x04, 0x04, 0x04 });
    const tuple_idx = try deserialize(&pool, &r1);
    const tuple_type = pool.get(tuple_idx);
    try std.testing.expect(tuple_type == .tuple);
    try std.testing.expectEqual(@as(u8, 5), tuple_type.tuple.len);
    for (0..5) |i| {
        try std.testing.expectEqual(TypePool.INT, tuple_type.tuple.get(i));
    }
}

test "type_serializer: roundtrip tuple5plus" {
    var pool = TypePool.init();
    var buf: [32]u8 = undefined;

    // Create a 5-tuple of Ints
    const elements = [_]types.TypeIndex{ TypePool.INT, TypePool.LONG, TypePool.BYTE, TypePool.SHORT, TypePool.BOOLEAN };
    const tuple_idx = try pool.getTupleN(&elements);

    // Serialize
    const len = try serialize(&pool, tuple_idx, &buf);
    try std.testing.expectEqual(@as(usize, 7), len); // 1 (code) + 1 (len) + 5 (elements)
    try std.testing.expectEqual(@as(u8, types.TypeConstrCode.tuple5plus), buf[0]);
    try std.testing.expectEqual(@as(u8, 5), buf[1]); // length

    // Deserialize and verify
    var reader = vlq.Reader.init(buf[0..len]);
    const result_idx = try deserialize(&pool, &reader);
    const result_type = pool.get(result_idx);
    try std.testing.expect(result_type == .tuple);
    try std.testing.expectEqual(@as(u8, 5), result_type.tuple.len);
}

test "type_serializer: tuple5plus too large" {
    var pool = TypePool.init();

    // Length 11 (exceeds max 10)
    var r1 = vlq.Reader.init(&[_]u8{ 0x60, 0x0B, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 });
    try std.testing.expectError(error.InvalidTupleLength, deserialize(&pool, &r1));
}

test "type_serializer: roundtrip primitives" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    // Int
    const len = try serialize(&pool, TypePool.INT, &buf);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x04), buf[0]);

    var reader = vlq.Reader.init(buf[0..len]);
    try std.testing.expectEqual(TypePool.INT, try deserialize(&pool, &reader));
}

test "type_serializer: roundtrip Coll[Byte]" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    const len = try serialize(&pool, TypePool.COLL_BYTE, &buf);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x0e), buf[0]);

    var reader = vlq.Reader.init(buf[0..len]);
    try std.testing.expectEqual(TypePool.COLL_BYTE, try deserialize(&pool, &reader));
}

test "type_serializer: roundtrip (Int, Int)" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    const pair_idx = try pool.getPair(TypePool.INT, TypePool.INT);
    const len = try serialize(&pool, pair_idx, &buf);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x58), buf[0]);

    var reader = vlq.Reader.init(buf[0..len]);
    const result = try deserialize(&pool, &reader);
    try std.testing.expectEqual(pair_idx, result);
}

test "type_serializer: roundtrip Coll[Box]" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    const coll_box_idx = try pool.getColl(TypePool.BOX);
    const len = try serialize(&pool, coll_box_idx, &buf);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0x63 }, buf[0..len]);

    var reader = vlq.Reader.init(buf[0..len]);
    const result = try deserialize(&pool, &reader);
    try std.testing.expectEqual(coll_box_idx, result);
}

test "type_serializer: error on invalid type code" {
    var pool = TypePool.init();

    // Type code 0 is invalid
    var r1 = vlq.Reader.init(&[_]u8{0x00});
    try std.testing.expectError(error.InvalidTypeCode, deserialize(&pool, &r1));
}

test "type_serializer: error on truncated input" {
    var pool = TypePool.init();

    // Generic collection without element type
    var r1 = vlq.Reader.init(&[_]u8{0x0c});
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(&pool, &r1));
}

test "type_serializer: error on empty input" {
    var pool = TypePool.init();

    var r1 = vlq.Reader.init(&[_]u8{});
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(&pool, &r1));
}

test "type_serializer: spec vectors - all primitive bytes" {
    // From vectors.json type_serialization.primitives
    var pool = TypePool.init();

    const cases = [_]struct { code: u8, expected: TypeIndex }{
        .{ .code = 0x01, .expected = TypePool.BOOLEAN },
        .{ .code = 0x02, .expected = TypePool.BYTE },
        .{ .code = 0x03, .expected = TypePool.SHORT },
        .{ .code = 0x04, .expected = TypePool.INT },
        .{ .code = 0x05, .expected = TypePool.LONG },
        .{ .code = 0x06, .expected = TypePool.BIG_INT },
        .{ .code = 0x07, .expected = TypePool.GROUP_ELEMENT },
        .{ .code = 0x08, .expected = TypePool.SIGMA_PROP },
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(&[_]u8{tc.code});
        const result = try deserialize(&pool, &reader);
        try std.testing.expectEqual(tc.expected, result);
    }
}

test "type_serializer: spec vectors - all object bytes" {
    // From vectors.json type_serialization.objects
    var pool = TypePool.init();

    const cases = [_]struct { code: u8, expected: TypeIndex }{
        .{ .code = 0x61, .expected = TypePool.ANY },
        .{ .code = 0x62, .expected = TypePool.UNIT },
        .{ .code = 0x63, .expected = TypePool.BOX },
        .{ .code = 0x64, .expected = TypePool.AVL_TREE },
        .{ .code = 0x65, .expected = TypePool.CONTEXT },
        .{ .code = 0x68, .expected = TypePool.HEADER },
        .{ .code = 0x69, .expected = TypePool.PRE_HEADER },
        .{ .code = 0x6a, .expected = TypePool.GLOBAL },
    };

    for (cases) |tc| {
        var reader = vlq.Reader.init(&[_]u8{tc.code});
        const result = try deserialize(&pool, &reader);
        try std.testing.expectEqual(tc.expected, result);
    }
}

// ============================================================================
// v6+ Function Type Tests
// ============================================================================

test "type_serializer: deserialize type_var" {
    var pool = TypePool.init();

    // TypeVar "T" = 0x67 (103) + 0x01 (len) + 'T'
    var r1 = vlq.Reader.init(&[_]u8{ 0x67, 0x01, 'T' });
    const tv_idx = try deserialize(&pool, &r1);
    const tv_type = pool.get(tv_idx);
    try std.testing.expect(tv_type == .type_var);
    try std.testing.expectEqual(@as(u8, 1), tv_type.type_var.name_len);
    try std.testing.expectEqualSlices(u8, "T", tv_type.type_var.nameSlice());
}

test "type_serializer: roundtrip type_var" {
    var pool = TypePool.init();
    var buf: [32]u8 = undefined;

    // Create a type_var "IV"
    var tv = types.TypeVarType{
        .name = undefined,
        .name_len = 2,
    };
    tv.name[0] = 'I';
    tv.name[1] = 'V';
    const tv_idx = try pool.add(.{ .type_var = tv });

    // Serialize
    const len = try serialize(&pool, tv_idx, &buf);
    try std.testing.expectEqual(@as(usize, 4), len); // code + len + "IV"
    try std.testing.expectEqual(@as(u8, 0x67), buf[0]); // type_var code
    try std.testing.expectEqual(@as(u8, 2), buf[1]); // name length
    try std.testing.expectEqualSlices(u8, "IV", buf[2..4]);

    // Deserialize and verify
    var reader = vlq.Reader.init(buf[0..len]);
    const result_idx = try deserialize(&pool, &reader);
    const result_type = pool.get(result_idx);
    try std.testing.expect(result_type == .type_var);
    try std.testing.expectEqualSlices(u8, "IV", result_type.type_var.nameSlice());
}

test "type_serializer: deserialize func (Int => Long)" {
    var pool = TypePool.init();

    // SFunc(Int => Long) = 0x70 (112) + 0x01 (domain len) + 0x04 (Int) + 0x05 (Long) + 0x00 (no tpe params)
    var r1 = vlq.Reader.init(&[_]u8{ 0x70, 0x01, 0x04, 0x05, 0x00 });
    const func_idx = try deserialize(&pool, &r1);
    const func_type = pool.get(func_idx);
    try std.testing.expect(func_type == .func);
    try std.testing.expectEqual(@as(u8, 1), func_type.func.domain_len);
    try std.testing.expectEqual(TypePool.INT, func_type.func.domain[0]);
    try std.testing.expectEqual(TypePool.LONG, func_type.func.range);
    try std.testing.expectEqual(@as(u8, 0), func_type.func.tpe_params_len);
}

test "type_serializer: roundtrip func ((Int, Long) => Boolean)" {
    var pool = TypePool.init();
    var buf: [32]u8 = undefined;

    // Create SFunc((Int, Long) => Boolean)
    var func_type = types.FuncType{
        .domain = undefined,
        .domain_len = 2,
        .range = TypePool.BOOLEAN,
        .tpe_params = undefined,
        .tpe_params_len = 0,
    };
    func_type.domain[0] = TypePool.INT;
    func_type.domain[1] = TypePool.LONG;
    const func_idx = try pool.add(.{ .func = func_type });

    // Serialize
    const len = try serialize(&pool, func_idx, &buf);
    try std.testing.expectEqual(@as(usize, 6), len); // code + dom_len + Int + Long + Boolean + tpe_len
    try std.testing.expectEqual(@as(u8, 0x70), buf[0]); // func code (112)
    try std.testing.expectEqual(@as(u8, 2), buf[1]); // domain length
    try std.testing.expectEqual(@as(u8, 0x04), buf[2]); // Int
    try std.testing.expectEqual(@as(u8, 0x05), buf[3]); // Long
    try std.testing.expectEqual(@as(u8, 0x01), buf[4]); // Boolean (range)
    try std.testing.expectEqual(@as(u8, 0x00), buf[5]); // no type params

    // Deserialize and verify
    var reader = vlq.Reader.init(buf[0..len]);
    const result_idx = try deserialize(&pool, &reader);
    const result_type = pool.get(result_idx);
    try std.testing.expect(result_type == .func);
    try std.testing.expectEqual(@as(u8, 2), result_type.func.domain_len);
    try std.testing.expectEqual(TypePool.INT, result_type.func.domain[0]);
    try std.testing.expectEqual(TypePool.LONG, result_type.func.domain[1]);
    try std.testing.expectEqual(TypePool.BOOLEAN, result_type.func.range);
}

test "type_serializer: roundtrip func with type params" {
    var pool = TypePool.init();
    var buf: [64]u8 = undefined;

    // Create type var "T"
    var tv = types.TypeVarType{
        .name = undefined,
        .name_len = 1,
    };
    tv.name[0] = 'T';
    const tv_idx = try pool.add(.{ .type_var = tv });

    // Create SFunc(T => Coll[T]) with type param T
    // For simplicity, use Int for domain/range in this test
    var func_type = types.FuncType{
        .domain = undefined,
        .domain_len = 1,
        .range = TypePool.COLL_INT,
        .tpe_params = undefined,
        .tpe_params_len = 1,
    };
    func_type.domain[0] = TypePool.INT;
    func_type.tpe_params[0] = tv_idx;
    const func_idx = try pool.add(.{ .func = func_type });

    // Serialize
    const len = try serialize(&pool, func_idx, &buf);
    // code(1) + dom_len(1) + Int(1) + Coll[Int](1) + tpe_len(1) + TypeVar(3) = 8 bytes
    try std.testing.expectEqual(@as(usize, 8), len);

    // Deserialize and verify
    var reader = vlq.Reader.init(buf[0..len]);
    const result_idx = try deserialize(&pool, &reader);
    const result_type = pool.get(result_idx);
    try std.testing.expect(result_type == .func);
    try std.testing.expectEqual(@as(u8, 1), result_type.func.domain_len);
    try std.testing.expectEqual(@as(u8, 1), result_type.func.tpe_params_len);

    // Verify the type param is a type_var
    const tpe_param_idx = result_type.func.tpe_params[0];
    const tpe_param = pool.get(tpe_param_idx);
    try std.testing.expect(tpe_param == .type_var);
    try std.testing.expectEqualSlices(u8, "T", tpe_param.type_var.nameSlice());
}

test "type_serializer: func domain too long" {
    var pool = TypePool.init();

    // Domain length 9 (exceeds max 8)
    var r1 = vlq.Reader.init(&[_]u8{ 0x70, 0x09 });
    try std.testing.expectError(error.FuncDomainTooLong, deserialize(&pool, &r1));
}

test "type_serializer: type_var name too long" {
    var pool = TypePool.init();

    // Name length 17 (exceeds max 16)
    var r1 = vlq.Reader.init(&[_]u8{ 0x67, 0x11 });
    try std.testing.expectError(error.TypeVarNameTooLong, deserialize(&pool, &r1));
}

test "type_serializer: type_var empty name" {
    var pool = TypePool.init();

    // Name length 0 (invalid)
    var r1 = vlq.Reader.init(&[_]u8{ 0x67, 0x00 });
    try std.testing.expectError(error.InvalidTypeCode, deserialize(&pool, &r1));
}
