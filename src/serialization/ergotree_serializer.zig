//! ErgoTree Serializer/Deserializer
//!
//! Parses the ErgoTree envelope: header byte, optional size, constants, and root expression.
//!
//! Header byte layout:
//!   Bits 0-2: Version (0-7)
//!   Bit 3: Has size field
//!   Bit 4: Constant segregation enabled
//!   Bits 5-7: Reserved
//!
//! Reference: Rust ergotree-ir/src/ergo_tree.rs, tree_header.rs

const std = @import("std");
const assert = std.debug.assert;
const vlq = @import("vlq.zig");
const types = @import("../core/types.zig");
const type_serializer = @import("type_serializer.zig");
const data_serializer = @import("data_serializer.zig");
const expr_serializer = @import("expr_serializer.zig");
const memory = @import("../interpreter/memory.zig");

const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const Value = data_serializer.Value;
const ExprTree = expr_serializer.ExprTree;
const BumpAllocator = memory.BumpAllocator;

// ============================================================================
// ErgoTree Header
// ============================================================================

/// Header byte flag masks
pub const HeaderFlags = struct {
    pub const version_mask: u8 = 0x07; // Bits 0-2
    pub const has_size: u8 = 0x08; // Bit 3
    pub const constant_segregation: u8 = 0x10; // Bit 4
    pub const has_more_bytes: u8 = 0x80; // Bit 7 (reserved for extension)
    pub const reserved_mask: u8 = 0x60; // Bits 5-6
};

/// ErgoTree version
pub const ErgoTreeVersion = enum(u3) {
    v0 = 0, // Pre-4.0
    v1 = 1, // Post-4.0 (size mandatory)
    v2 = 2, // 5.0 JIT
    v3 = 3, // 6.0 Evolution
};

/// Parsed ErgoTree header
pub const ErgoTreeHeader = struct {
    version: ErgoTreeVersion,
    has_size: bool,
    constant_segregation: bool,

    /// Parse from header byte
    pub fn parse(byte: u8) error{InvalidVersion}!ErgoTreeHeader {
        const version = std.meta.intToEnum(ErgoTreeVersion, byte & HeaderFlags.version_mask) catch {
            return error.InvalidVersion;
        };
        return .{
            .version = version,
            .has_size = byte & HeaderFlags.has_size != 0,
            .constant_segregation = byte & HeaderFlags.constant_segregation != 0,
        };
    }

    /// Serialize to header byte
    pub fn toByte(self: ErgoTreeHeader) u8 {
        var byte: u8 = @intFromEnum(self.version);
        if (self.has_size) byte |= HeaderFlags.has_size;
        if (self.constant_segregation) byte |= HeaderFlags.constant_segregation;
        return byte;
    }

    /// Create v0 header
    pub fn v0(constant_segregation: bool) ErgoTreeHeader {
        return .{
            .version = .v0,
            .has_size = false,
            .constant_segregation = constant_segregation,
        };
    }

    /// Create v1 header (size is mandatory for v1+)
    pub fn v1(constant_segregation: bool) ErgoTreeHeader {
        return .{
            .version = .v1,
            .has_size = true,
            .constant_segregation = constant_segregation,
        };
    }
};

// Compile-time sanity checks
comptime {
    // Header flags don't overlap incorrectly
    assert(HeaderFlags.version_mask & HeaderFlags.has_size == 0);
    assert(HeaderFlags.has_size & HeaderFlags.constant_segregation == 0);
}

// ============================================================================
// Complete ErgoTree
// ============================================================================

/// Maximum number of constants in an ErgoTree
pub const max_constants: usize = 4096;

/// Maximum size of serialized ErgoTree in bytes (4KB protocol limit)
/// Reference: Ergo protocol enforces this to prevent DoS via oversized scripts
pub const max_ergo_tree_size: usize = 4096;

/// Parsed ErgoTree
pub const ErgoTree = struct {
    /// Parsed header
    header: ErgoTreeHeader,

    /// Tree size (if has_size flag set)
    size: ?u32 = null,

    /// Segregated constants (types and values)
    constant_types: [max_constants]TypeIndex = undefined,
    constant_values: [max_constants]Value = undefined,
    constant_count: u16 = 0,

    /// Parsed expression tree
    expr_tree: ExprTree,

    /// Type pool shared with expression tree
    type_pool: *TypePool,

    pub fn init(type_pool: *TypePool) ErgoTree {
        return .{
            .header = ErgoTreeHeader.v0(false),
            .expr_tree = ExprTree.init(),
            .type_pool = type_pool,
        };
    }

    pub fn reset(self: *ErgoTree) void {
        self.header = ErgoTreeHeader.v0(false);
        self.size = null;
        self.constant_count = 0;
        self.expr_tree.reset();
    }

    pub fn getConstant(self: *const ErgoTree, idx: u16) ?Value {
        if (idx >= self.constant_count) return null;
        return self.constant_values[idx];
    }

    pub fn getConstantType(self: *const ErgoTree, idx: u16) ?TypeIndex {
        if (idx >= self.constant_count) return null;
        return self.constant_types[idx];
    }
};

// ============================================================================
// Deserialize Error
// ============================================================================

pub const DeserializeError = error{
    UnexpectedEndOfInput,
    Overflow,
    InvalidTypeCode,
    PoolFull,
    NestingTooDeep,
    InvalidTupleLength,
    InvalidData,
    OutOfMemory,
    TypeMismatch,
    NotSupported,
    ExpressionTooComplex,
    InvalidOpcode,
    TooManyConstants,
    InvalidHeader,
    SizeMismatch,
    /// ErgoTree exceeds maximum allowed size (4KB protocol limit)
    TreeTooBig,
};

// ============================================================================
// Deserialization Diagnostics
// ============================================================================

/// Phase of deserialization where an error occurred
pub const DeserializePhase = enum {
    header,
    constants,
    constant_type,
    constant_value,
    expression,
};

/// Diagnostic information for deserialization failures.
/// Captures context to help identify the root cause of errors.
pub const DeserializeDiagnostics = struct {
    /// The error that occurred
    err: DeserializeError,
    /// Byte offset where the error occurred
    byte_offset: u32,
    /// The byte value at the error location (if available)
    failed_byte: ?u8,
    /// Phase of deserialization
    phase: DeserializePhase,
    /// Index of the constant being parsed (if in constants phase)
    constant_index: ?u16,
    /// Type index of the constant (if in constant_value phase)
    type_idx: ?types.TypeIndex,
    /// Pointer to type pool for type name lookup
    type_pool: ?*const types.TypePool,

    /// Format diagnostics as a human-readable string
    pub fn format(self: DeserializeDiagnostics, buf: []u8) []const u8 {
        const phase_str = switch (self.phase) {
            .header => "header",
            .constants => "constants",
            .constant_type => "constant_type",
            .constant_value => "constant_value",
            .expression => "expression",
        };

        const err_str = @errorName(self.err);

        return if (self.failed_byte) |byte|
            std.fmt.bufPrint(buf, "{s} at offset {d} (byte 0x{X:0>2}) in {s}", .{
                err_str,
                self.byte_offset,
                byte,
                phase_str,
            }) catch "format error"
        else
            std.fmt.bufPrint(buf, "{s} at offset {d} in {s}", .{
                err_str,
                self.byte_offset,
                phase_str,
            }) catch "format error";
    }

    /// Get type name string for debugging
    pub fn typeName(self: DeserializeDiagnostics) []const u8 {
        if (self.type_idx == null or self.type_pool == null) return "unknown";
        const pool = self.type_pool.?;
        const t = pool.get(self.type_idx.?);
        return typeNameInner(pool, t);
    }

    fn typeNameInner(pool: *const types.TypePool, t: types.SType) []const u8 {
        return switch (t) {
            .boolean => "Boolean",
            .byte => "Byte",
            .short => "Short",
            .int => "Int",
            .long => "Long",
            .big_int => "BigInt",
            .group_element => "GroupElement",
            .sigma_prop => "SigmaProp",
            .unsigned_big_int => "UnsignedBigInt",
            .coll => |elem_idx| blk: {
                const elem = pool.get(elem_idx);
                break :blk switch (elem) {
                    .byte => "Coll[Byte]",
                    .boolean => "Coll[Boolean]",
                    .short => "Coll[Short]",
                    .int => "Coll[Int]",
                    .long => "Coll[Long]",
                    .big_int => "Coll[BigInt]",
                    .group_element => "Coll[GroupElement]",
                    .sigma_prop => "Coll[SigmaProp]",
                    .box => "Coll[Box]",
                    .header => "Coll[Header]",
                    .avl_tree => "Coll[AvlTree]",
                    .coll => "Coll[Coll[...]]",
                    .option => "Coll[Option[...]]",
                    .pair => "Coll[(T,T)]",
                    else => "Coll[?]",
                };
            },
            .option => |inner_idx| blk: {
                const inner = pool.get(inner_idx);
                break :blk switch (inner) {
                    .byte => "Option[Byte]",
                    .int => "Option[Int]",
                    .long => "Option[Long]",
                    .box => "Option[Box]",
                    .coll => "Option[Coll[...]]",
                    else => "Option[?]",
                };
            },
            .pair => "(T,T)",
            .triple => "(T,T,T)",
            .quadruple => "(T,T,T,T)",
            .tuple => "Tuple",
            .avl_tree => "AvlTree",
            .func => "Func",
            .any => "Any",
            .unit => "Unit",
            .box => "Box",
            .context => "Context",
            .header => "Header",
            .pre_header => "PreHeader",
            .global => "Global",
            .type_var => "TypeVar",
        };
    }
};

// ============================================================================
// Deserialize Functions
// ============================================================================

/// Deserialize an ErgoTree from bytes
pub fn deserialize(
    tree: *ErgoTree,
    data: []const u8,
    arena: anytype,
) DeserializeError!void {
    // SECURITY: Enforce 4KB size limit to prevent DoS via oversized scripts
    // Reference: Ergo protocol limit, enforced at deserialization time
    if (data.len > max_ergo_tree_size) {
        return error.TreeTooBig;
    }

    var reader = vlq.Reader.init(data);

    // Parse header byte
    const header_byte = reader.readByte() catch return error.UnexpectedEndOfInput;

    // Check for reserved bits
    if (header_byte & HeaderFlags.reserved_mask != 0) {
        return error.InvalidHeader;
    }

    tree.header = ErgoTreeHeader.parse(header_byte) catch return error.InvalidHeader;

    // Parse optional size field
    if (tree.header.has_size) {
        tree.size = reader.readU32() catch |e| return mapVlqError(e);
    }

    // Parse constants if segregation enabled
    // ValuePool required for Coll[Int]/Coll[Long]/etc. constants
    var value_pool = data_serializer.ValuePool.init();
    if (tree.header.constant_segregation) {
        try parseConstants(tree, &reader, arena, &value_pool);
    }

    // Copy constants to expression tree for ConstantPlaceholder resolution
    for (0..tree.constant_count) |i| {
        tree.expr_tree.constants[i] = tree.constant_values[i];
    }
    tree.expr_tree.constant_count = tree.constant_count;

    // Parse root expression
    try expr_serializer.deserialize(&tree.expr_tree, &reader, arena);

    // Verify size field matches bytes read (if size was specified)
    // Note: size field indicates tree content size after header
    _ = tree.size; // Size verification deferred to full implementation

    // Check all bytes consumed
    if (!reader.isEmpty()) {
        // Extra bytes - could be padding or error
        // For now, don't fail - some trees may have padding
    }
}

/// Deserialize an ErgoTree with detailed diagnostics on failure.
/// Use this for debugging deserialization errors - provides byte offset,
/// failed byte value, and phase information.
/// The `values` parameter is required for Coll[Int]/Coll[Long]/etc. constants.
pub fn deserializeWithDiagnostics(
    tree: *ErgoTree,
    data: []const u8,
    arena: anytype,
    values: ?*data_serializer.ValuePool,
    diag: *?DeserializeDiagnostics,
) DeserializeError!void {
    diag.* = null;

    // SECURITY: Enforce 4KB size limit
    if (data.len > max_ergo_tree_size) {
        diag.* = .{
            .err = error.TreeTooBig,
            .byte_offset = 0,
            .failed_byte = if (data.len > 0) data[0] else null,
            .phase = .header,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return error.TreeTooBig;
    }

    var reader = vlq.Reader.init(data);

    // Parse header byte
    const header_byte = reader.readByte() catch {
        diag.* = .{
            .err = error.UnexpectedEndOfInput,
            .byte_offset = @intCast(reader.pos),
            .failed_byte = null,
            .phase = .header,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return error.UnexpectedEndOfInput;
    };

    // Check for reserved bits
    if (header_byte & HeaderFlags.reserved_mask != 0) {
        diag.* = .{
            .err = error.InvalidHeader,
            .byte_offset = 0,
            .failed_byte = header_byte,
            .phase = .header,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return error.InvalidHeader;
    }

    tree.header = ErgoTreeHeader.parse(header_byte) catch {
        diag.* = .{
            .err = error.InvalidHeader,
            .byte_offset = 0,
            .failed_byte = header_byte,
            .phase = .header,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return error.InvalidHeader;
    };

    // Parse optional size field
    if (tree.header.has_size) {
        tree.size = reader.readU32() catch |e| {
            const err = mapVlqError(e);
            diag.* = .{
                .err = err,
                .byte_offset = @intCast(reader.pos),
                .failed_byte = if (reader.pos < data.len) data[reader.pos] else null,
                .phase = .header,
                .constant_index = null,
                .type_idx = null,
                .type_pool = null,
            };
            return err;
        };
    }

    // Parse constants if segregation enabled
    if (tree.header.constant_segregation) {
        parseConstantsWithDiagnostics(tree, &reader, arena, values, data, diag) catch |e| {
            return e;
        };
    }

    // Copy constants to expression tree for ConstantPlaceholder resolution
    for (0..tree.constant_count) |i| {
        tree.expr_tree.constants[i] = tree.constant_values[i];
    }
    tree.expr_tree.constant_count = tree.constant_count;

    // Parse root expression
    const expr_start = reader.pos;
    expr_serializer.deserialize(&tree.expr_tree, &reader, arena) catch |e| {
        const err: DeserializeError = switch (e) {
            error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
            error.Overflow => error.Overflow,
            error.InvalidOpcode => error.InvalidOpcode,
            error.ExpressionTooComplex => error.ExpressionTooComplex,
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            error.InvalidData => error.InvalidData,
            error.TypeMismatch => error.TypeMismatch,
            error.NotSupported => error.NotSupported,
        };
        diag.* = .{
            .err = err,
            .byte_offset = @intCast(reader.pos),
            .failed_byte = if (reader.pos < data.len) data[reader.pos] else null,
            .phase = .expression,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        _ = expr_start;
        return err;
    };
}

fn parseConstantsWithDiagnostics(
    tree: *ErgoTree,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*data_serializer.ValuePool,
    data: []const u8,
    diag: *?DeserializeDiagnostics,
) DeserializeError!void {
    // Read constant count (VLQ u32)
    const count = reader.readU32() catch |e| {
        const err = mapVlqError(e);
        diag.* = .{
            .err = err,
            .byte_offset = @intCast(reader.pos),
            .failed_byte = if (reader.pos < data.len) data[reader.pos] else null,
            .phase = .constants,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return err;
    };

    if (count > max_constants) {
        diag.* = .{
            .err = error.TooManyConstants,
            .byte_offset = @intCast(reader.pos),
            .failed_byte = if (reader.pos < data.len) data[reader.pos] else null,
            .phase = .constants,
            .constant_index = null,
            .type_idx = null,
            .type_pool = null,
        };
        return error.TooManyConstants;
    }

    // Parse each constant: type + value
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const type_start = reader.pos;

        // Parse type
        const type_idx = type_serializer.deserialize(tree.type_pool, reader) catch |e| {
            const err: DeserializeError = switch (e) {
                error.InvalidTypeCode => error.InvalidTypeCode,
                error.PoolFull => error.PoolFull,
                error.NestingTooDeep => error.NestingTooDeep,
                error.InvalidTupleLength => error.InvalidTupleLength,
                else => error.InvalidData,
            };
            diag.* = .{
                .err = err,
                .byte_offset = @intCast(type_start),
                .failed_byte = if (type_start < data.len) data[type_start] else null,
                .phase = .constant_type,
                .constant_index = i,
                .type_idx = null,
                .type_pool = null,
            };
            return err;
        };

        const value_start = reader.pos;

        // Parse value (pass values for Coll[Int] etc.)
        const value = data_serializer.deserialize(type_idx, tree.type_pool, reader, arena, values) catch |e| {
            const err: DeserializeError = switch (e) {
                error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
                error.Overflow => error.Overflow,
                error.InvalidData, error.InvalidGroupElement => error.InvalidData,
                error.OutOfMemory => error.OutOfMemory,
                error.TypeMismatch => error.TypeMismatch,
                error.NotSupported => error.NotSupported,
            };
            diag.* = .{
                .err = err,
                .byte_offset = @intCast(value_start),
                .failed_byte = if (value_start < data.len) data[value_start] else null,
                .phase = .constant_value,
                .constant_index = i,
                .type_idx = type_idx,
                .type_pool = tree.type_pool,
            };
            return err;
        };

        tree.constant_types[i] = type_idx;
        tree.constant_values[i] = value;
    }

    tree.constant_count = @truncate(count);
}

fn parseConstants(
    tree: *ErgoTree,
    reader: *vlq.Reader,
    arena: anytype,
    values: ?*data_serializer.ValuePool,
) DeserializeError!void {
    // Read constant count (VLQ u32)
    const count = reader.readU32() catch |e| return mapVlqError(e);

    if (count > max_constants) {
        return error.TooManyConstants;
    }

    // Parse each constant: type + value
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        // Parse type
        const type_idx = type_serializer.deserialize(tree.type_pool, reader) catch |e| {
            return switch (e) {
                error.InvalidTypeCode => error.InvalidTypeCode,
                error.PoolFull => error.PoolFull,
                error.NestingTooDeep => error.NestingTooDeep,
                error.InvalidTupleLength => error.InvalidTupleLength,
                else => error.InvalidData,
            };
        };

        // Parse value (pass ValuePool for Coll[Int]/Coll[Long]/etc. constants)
        const value = data_serializer.deserialize(type_idx, tree.type_pool, reader, arena, values) catch |e| {
            return switch (e) {
                error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
                error.Overflow => error.Overflow,
                error.InvalidData, error.InvalidGroupElement => error.InvalidData,
                error.OutOfMemory => error.OutOfMemory,
                error.TypeMismatch => error.TypeMismatch,
                error.NotSupported => error.NotSupported,
            };
        };

        tree.constant_types[i] = type_idx;
        tree.constant_values[i] = value;
    }

    tree.constant_count = @truncate(count);
}

fn mapVlqError(err: vlq.DecodeError) DeserializeError {
    return switch (err) {
        error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
        error.Overflow => error.Overflow,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "ergotree: parse header byte v0" {
    const header = try ErgoTreeHeader.parse(0x00);
    try std.testing.expectEqual(ErgoTreeVersion.v0, header.version);
    try std.testing.expect(!header.has_size);
    try std.testing.expect(!header.constant_segregation);
}

test "ergotree: parse header byte v1 with size" {
    const header = try ErgoTreeHeader.parse(0x09); // v1 + has_size
    try std.testing.expectEqual(ErgoTreeVersion.v1, header.version);
    try std.testing.expect(header.has_size);
    try std.testing.expect(!header.constant_segregation);
}

test "ergotree: parse header byte v0 with segregation" {
    const header = try ErgoTreeHeader.parse(0x10); // v0 + constant_segregation
    try std.testing.expectEqual(ErgoTreeVersion.v0, header.version);
    try std.testing.expect(!header.has_size);
    try std.testing.expect(header.constant_segregation);
}

test "ergotree: parse header byte v1 full" {
    const header = try ErgoTreeHeader.parse(0x19); // v1 + has_size + constant_segregation
    try std.testing.expectEqual(ErgoTreeVersion.v1, header.version);
    try std.testing.expect(header.has_size);
    try std.testing.expect(header.constant_segregation);
}

test "ergotree: parse invalid version" {
    // Version 4-7 are not defined in ErgoTreeVersion enum
    try std.testing.expectError(error.InvalidVersion, ErgoTreeHeader.parse(0x04));
    try std.testing.expectError(error.InvalidVersion, ErgoTreeHeader.parse(0x05));
    try std.testing.expectError(error.InvalidVersion, ErgoTreeHeader.parse(0x06));
    try std.testing.expectError(error.InvalidVersion, ErgoTreeHeader.parse(0x07));
}

test "ergotree: header roundtrip" {
    const h1 = ErgoTreeHeader.v0(false);
    try std.testing.expectEqual(h1, try ErgoTreeHeader.parse(h1.toByte()));

    const h2 = ErgoTreeHeader.v0(true);
    try std.testing.expectEqual(h2, try ErgoTreeHeader.parse(h2.toByte()));

    const h3 = ErgoTreeHeader.v1(false);
    try std.testing.expectEqual(h3, try ErgoTreeHeader.parse(h3.toByte()));

    const h4 = ErgoTreeHeader.v1(true);
    try std.testing.expectEqual(h4, try ErgoTreeHeader.parse(h4.toByte()));
}

test "ergotree: deserialize simple TrueLeaf" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // Header v0 (no segregation) + TrueLeaf
    // 0x00 (header) + 0x7F (TrueLeaf)
    const data = [_]u8{ 0x00, 0x7F };
    try deserialize(&tree, &data, &arena);

    try std.testing.expectEqual(ErgoTreeVersion.v0, tree.header.version);
    try std.testing.expect(!tree.header.constant_segregation);
    try std.testing.expectEqual(@as(u16, 0), tree.constant_count);
    try std.testing.expectEqual(@as(u16, 1), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.true_leaf, tree.expr_tree.nodes[0].tag);
}

test "ergotree: deserialize FalseLeaf" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // 0x00 (header) + 0x80 (FalseLeaf)
    const data = [_]u8{ 0x00, 0x80 };
    try deserialize(&tree, &data, &arena);

    try std.testing.expectEqual(expr_serializer.ExprTag.false_leaf, tree.expr_tree.nodes[0].tag);
}

test "ergotree: deserialize HEIGHT > 100" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // Header v0 + GT(HEIGHT, Int(100))
    // 0x00 + 0x91 + 0xA3 + 0x04 + 0xC8 + 0x01
    const data = [_]u8{ 0x00, 0x91, 0xA3, 0x04, 0xC8, 0x01 };
    try deserialize(&tree, &data, &arena);

    try std.testing.expectEqual(@as(u16, 3), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.bin_op, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.height, tree.expr_tree.nodes[1].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.constant, tree.expr_tree.nodes[2].tag);
}

test "ergotree: deserialize with constant segregation" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // Header v0 with segregation + 1 constant (Int 100) + expression using placeholder
    // 0x10 (header with segregation)
    // 0x01 (1 constant)
    // 0x04 0xC8 0x01 (Int 100)
    // 0x76 0x00 (ConstantPlaceholder index 0)
    const data = [_]u8{ 0x10, 0x01, 0x04, 0xC8, 0x01, 0x76, 0x00 };
    try deserialize(&tree, &data, &arena);

    try std.testing.expect(tree.header.constant_segregation);
    try std.testing.expectEqual(@as(u16, 1), tree.constant_count);
    try std.testing.expectEqual(@as(i32, 100), tree.constant_values[0].int);
    try std.testing.expectEqual(TypePool.INT, tree.constant_types[0]);
}

test "ergotree: error on empty input" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    const data = [_]u8{};
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(&tree, &data, &arena));
}

test "ergotree: error on reserved bits" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // Header with reserved bits set
    const data = [_]u8{ 0x20, 0x7F }; // Bit 5 set (reserved)
    try std.testing.expectError(error.InvalidHeader, deserialize(&tree, &data, &arena));
}

test "ergotree: 4KB size limit - exactly 4096 bytes succeeds" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(8192).init();

    // Create a 4096-byte buffer with valid header + TrueLeaf + padding
    var data: [max_ergo_tree_size]u8 = undefined;
    data[0] = 0x00; // Header v0
    data[1] = 0x7F; // TrueLeaf
    // Rest is padding (will be ignored after TrueLeaf)
    @memset(data[2..], 0x00);

    // Should succeed - exactly at limit
    try deserialize(&tree, &data, &arena);
    try std.testing.expectEqual(expr_serializer.ExprTag.true_leaf, tree.expr_tree.nodes[0].tag);
}

test "ergotree: 4KB size limit - 4097 bytes fails with TreeTooBig" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(8192).init();

    // Create a 4097-byte buffer (one byte over limit)
    var data: [max_ergo_tree_size + 1]u8 = undefined;
    data[0] = 0x00; // Header v0
    data[1] = 0x7F; // TrueLeaf
    @memset(data[2..], 0x00);

    // Should fail - exceeds limit
    try std.testing.expectError(error.TreeTooBig, deserialize(&tree, &data, &arena));
}

test "ergotree: 4KB size limit - large input rejected immediately" {
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    // Create a much larger buffer (8KB)
    var data: [8192]u8 = undefined;
    data[0] = 0x00;
    data[1] = 0x7F;
    @memset(data[2..], 0x00);

    // Should fail immediately with TreeTooBig (before attempting to parse)
    try std.testing.expectError(error.TreeTooBig, deserialize(&tree, &data, &arena));
}

// ============================================================================
// Conformance Tests (end-to-end)
// ============================================================================

const evaluator = @import("../interpreter/evaluator.zig");
const context = @import("../interpreter/context.zig");

test "conformance: HEIGHT > 100 evaluates true at height 500" {
    // This is the first end-to-end conformance test!
    // ErgoTree bytes for: HEIGHT > 100
    const ergo_tree_bytes = [_]u8{
        0x00, // Header: v0, no size, no segregation
        0x91, // GT opcode (0x90 + 0x01 for SInt type info)
        0xA3, // HEIGHT opcode
        0x04, // Type: SInt
        0xC8, 0x01, // VLQ-encoded 100 (zigzag: 200)
    };

    // Step 1: Deserialize the ErgoTree
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    // Verify deserialization
    try std.testing.expectEqual(ErgoTreeVersion.v0, tree.header.version);
    try std.testing.expect(!tree.header.constant_segregation);
    try std.testing.expectEqual(@as(u16, 3), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.bin_op, tree.expr_tree.nodes[0].tag);

    // Step 2: Set up evaluation context
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = context.Context.forHeight(500, &inputs);
    try ctx.validate();

    // Step 3: Evaluate the expression
    var eval = evaluator.Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    // Step 4: Verify result
    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true); // 500 > 100 = true
}

test "conformance: HEIGHT > 100 evaluates false at height 50" {
    const ergo_tree_bytes = [_]u8{
        0x00, // Header: v0, no size, no segregation
        0x91, // GT opcode
        0xA3, // HEIGHT opcode
        0x04, // Type: SInt
        0xC8, 0x01, // VLQ-encoded 100
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = context.Context.forHeight(50, &inputs);

    var eval = evaluator.Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false); // 50 > 100 = false
}

test "conformance: HEIGHT > 100 boundary at height 100" {
    const ergo_tree_bytes = [_]u8{
        0x00, 0x91, 0xA3, 0x04, 0xC8, 0x01,
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = context.Context.forHeight(100, &inputs);

    var eval = evaluator.Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false); // 100 > 100 = false (GT, not GE)
}

test "conformance: TrueLeaf always passes" {
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0x7F, // TrueLeaf (SigmaPropConstant true)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = context.Context.forHeight(1, &inputs);

    var eval = evaluator.Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "conformance: FalseLeaf always fails" {
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0x80, // FalseLeaf (SigmaPropConstant false)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = context.Context.forHeight(1, &inputs);

    var eval = evaluator.Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

// ============================================================================
// Golden Tests (Serialization Conformance)
// ============================================================================
// These tests verify deserialization produces expected structures for
// known-good byte sequences from the Ergo protocol.

test "golden: proveDlog with generator G" {
    // ProveDlog(G) - prove discrete log of generator point
    // 0x00 header v0 + 0xCD ProveDlog + 0x07 GroupElement + compressed G
    const G_compressed = [_]u8{
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };

    var bytes: [36]u8 = undefined;
    bytes[0] = 0x00; // Header v0
    bytes[1] = 0xCD; // ProveDlog opcode
    bytes[2] = 0x07; // GroupElement type code
    @memcpy(bytes[3..36], &G_compressed);

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &bytes, &arena);

    try std.testing.expectEqual(ErgoTreeVersion.v0, tree.header.version);
    try std.testing.expectEqual(@as(u16, 2), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.prove_dlog, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.constant, tree.expr_tree.nodes[1].tag);
}

test "golden: ExtractAmount from SELF" {
    // SELF.value (extract nanoErgs from SELF box)
    // ExtractAmount = 193 = 0xC1, Self = 167 = 0xA7
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0xC1, // ExtractAmount (opcode 193)
        0xA7, // Self (opcode 167)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 2), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.extract_amount, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.self_box, tree.expr_tree.nodes[1].tag);
}

test "golden: ExtractId from SELF" {
    // SELF.id (get box ID)
    // ExtractId = 197 = 0xC5, Self = 167 = 0xA7
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0xC5, // ExtractId (opcode 197)
        0xA7, // Self (opcode 167)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 2), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.extract_id, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.self_box, tree.expr_tree.nodes[1].tag);
}

test "golden: header v1 with size field" {
    // v1 header + size=2 + TrueLeaf (minimal valid v1 tree)
    const ergo_tree_bytes = [_]u8{
        0x09, // Header: v1 + has_size
        0x01, // Size: 1 byte for expression
        0x7F, // TrueLeaf
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(ErgoTreeVersion.v1, tree.header.version);
    try std.testing.expect(tree.header.has_size);
    try std.testing.expectEqual(@as(?u32, 1), tree.size);
    try std.testing.expectEqual(expr_serializer.ExprTag.true_leaf, tree.expr_tree.nodes[0].tag);
}

test "golden: constant segregation with single constant" {
    // Header with segregation + 1 constant (Int 42) + ConstantPlaceholder
    const ergo_tree_bytes = [_]u8{
        0x10, // Header: v0 + constant_segregation
        0x01, // 1 constant
        // Constant 0: Int 42
        0x04, // Int type
        0x54, // VLQ zigzag 42 (42 * 2 = 84 = 0x54)
        // Expression: ConstantPlaceholder(0)
        0x76, 0x00, // ConstantPlaceholder index 0
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expect(tree.header.constant_segregation);
    try std.testing.expectEqual(@as(u16, 1), tree.constant_count);
    try std.testing.expectEqual(@as(i32, 42), tree.constant_values[0].int);
}

test "golden: Blake2b256 hash of SELF.id" {
    // CalcBlake2b256(SELF.id) - common pattern for box ID hashing
    // CalcBlake2b256 = 203 = 0xCB, ExtractId = 197 = 0xC5, Self = 167 = 0xA7
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0xCB, // CalcBlake2b256 (opcode 203)
        0xC5, // ExtractId (opcode 197)
        0xA7, // Self (opcode 167)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 3), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.calc_blake2b256, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.extract_id, tree.expr_tree.nodes[1].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.self_box, tree.expr_tree.nodes[2].tag);
}

test "golden: GroupGenerator constant" {
    // Get secp256k1 generator G
    // GroupGenerator = 130 = 0x82
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0x82, // GroupGenerator (opcode 130)
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.group_generator, tree.expr_tree.nodes[0].tag);
}

test "golden: SizeOf collection" {
    // SizeOf(INPUTS) - get count of input boxes
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0xB1, // SizeOf (opcode 177)
        0xA4, // INPUTS
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 2), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.size_of, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.inputs, tree.expr_tree.nodes[1].tag);
}

test "golden: negation operator" {
    // -HEIGHT (negate height value)
    const ergo_tree_bytes = [_]u8{
        0x00, // Header v0
        0xF0, // Negation (opcode 240)
        0xA3, // HEIGHT
    };

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    try deserialize(&tree, &ergo_tree_bytes, &arena);

    try std.testing.expectEqual(@as(u16, 2), tree.expr_tree.node_count);
    try std.testing.expectEqual(expr_serializer.ExprTag.negation, tree.expr_tree.nodes[0].tag);
    try std.testing.expectEqual(expr_serializer.ExprTag.height, tree.expr_tree.nodes[1].tag);
}

// ============================================================================
// Type Serializer Roundtrip Conformance
// ============================================================================

test "type_roundtrip: all primitive types" {
    var pool = TypePool.init();
    var buf: [16]u8 = undefined;

    // Test all primitive types roundtrip correctly
    const primitives = [_]TypeIndex{
        TypePool.BOOLEAN,
        TypePool.BYTE,
        TypePool.SHORT,
        TypePool.INT,
        TypePool.LONG,
        TypePool.BIG_INT,
        TypePool.GROUP_ELEMENT,
        TypePool.SIGMA_PROP,
        TypePool.UNIT,
        TypePool.BOX,
        TypePool.AVL_TREE,
    };

    for (primitives) |type_idx| {
        const len = try type_serializer.serialize(&pool, type_idx, &buf);
        var reader = vlq.Reader.init(buf[0..len]);
        const result = try type_serializer.deserialize(&pool, &reader);
        try std.testing.expectEqual(type_idx, result);
    }
}

test "type_roundtrip: Coll[Coll[Byte]]" {
    var pool = TypePool.init();

    // Create Coll[Coll[Byte]]
    const inner = pool.add(.{ .coll = TypePool.BYTE }) catch unreachable;
    const outer = pool.add(.{ .coll = inner }) catch unreachable;

    var buf: [16]u8 = undefined;
    const len = try type_serializer.serialize(&pool, outer, &buf);

    var reader = vlq.Reader.init(buf[0..len]);
    const result = try type_serializer.deserialize(&pool, &reader);

    // Verify structure
    const outer_type = pool.get(result);
    try std.testing.expect(outer_type == .coll);
    const inner_type = pool.get(outer_type.coll);
    try std.testing.expect(inner_type == .coll);
    try std.testing.expectEqual(TypePool.BYTE, inner_type.coll);
}

test "type_roundtrip: Option[GroupElement]" {
    var pool = TypePool.init();

    const opt_ge = pool.add(.{ .option = TypePool.GROUP_ELEMENT }) catch unreachable;

    var buf: [16]u8 = undefined;
    const len = try type_serializer.serialize(&pool, opt_ge, &buf);

    var reader = vlq.Reader.init(buf[0..len]);
    const result = try type_serializer.deserialize(&pool, &reader);

    const t = pool.get(result);
    try std.testing.expect(t == .option);
    try std.testing.expectEqual(TypePool.GROUP_ELEMENT, t.option);
}

test "type_roundtrip: (Int, Long, Boolean)" {
    var pool = TypePool.init();

    const triple = pool.add(.{ .triple = .{
        .a = TypePool.INT,
        .b = TypePool.LONG,
        .c = TypePool.BOOLEAN,
    } }) catch unreachable;

    var buf: [16]u8 = undefined;
    const len = try type_serializer.serialize(&pool, triple, &buf);

    var reader = vlq.Reader.init(buf[0..len]);
    const result = try type_serializer.deserialize(&pool, &reader);

    const t = pool.get(result);
    try std.testing.expect(t == .triple);
    try std.testing.expectEqual(TypePool.INT, t.triple.a);
    try std.testing.expectEqual(TypePool.LONG, t.triple.b);
    try std.testing.expectEqual(TypePool.BOOLEAN, t.triple.c);
}
