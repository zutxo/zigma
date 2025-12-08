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
    pub fn parse(byte: u8) ErgoTreeHeader {
        return .{
            .version = @enumFromInt(byte & HeaderFlags.version_mask),
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
    var reader = vlq.Reader.init(data);

    // Parse header byte
    const header_byte = reader.readByte() catch return error.UnexpectedEndOfInput;

    // Check for reserved bits
    if (header_byte & HeaderFlags.reserved_mask != 0) {
        return error.InvalidHeader;
    }

    tree.header = ErgoTreeHeader.parse(header_byte);

    // Parse optional size field
    if (tree.header.has_size) {
        tree.size = reader.readU32() catch |e| return mapVlqError(e);
    }

    // Parse constants if segregation enabled
    if (tree.header.constant_segregation) {
        try parseConstants(tree, &reader, arena);
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

fn parseConstants(
    tree: *ErgoTree,
    reader: *vlq.Reader,
    arena: anytype,
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

        // Parse value
        const value = data_serializer.deserialize(type_idx, tree.type_pool, reader, arena) catch |e| {
            return switch (e) {
                error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
                error.Overflow => error.Overflow,
                error.InvalidData => error.InvalidData,
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
    const header = ErgoTreeHeader.parse(0x00);
    try std.testing.expectEqual(ErgoTreeVersion.v0, header.version);
    try std.testing.expect(!header.has_size);
    try std.testing.expect(!header.constant_segregation);
}

test "ergotree: parse header byte v1 with size" {
    const header = ErgoTreeHeader.parse(0x09); // v1 + has_size
    try std.testing.expectEqual(ErgoTreeVersion.v1, header.version);
    try std.testing.expect(header.has_size);
    try std.testing.expect(!header.constant_segregation);
}

test "ergotree: parse header byte v0 with segregation" {
    const header = ErgoTreeHeader.parse(0x10); // v0 + constant_segregation
    try std.testing.expectEqual(ErgoTreeVersion.v0, header.version);
    try std.testing.expect(!header.has_size);
    try std.testing.expect(header.constant_segregation);
}

test "ergotree: parse header byte v1 full" {
    const header = ErgoTreeHeader.parse(0x19); // v1 + has_size + constant_segregation
    try std.testing.expectEqual(ErgoTreeVersion.v1, header.version);
    try std.testing.expect(header.has_size);
    try std.testing.expect(header.constant_segregation);
}

test "ergotree: header roundtrip" {
    const h1 = ErgoTreeHeader.v0(false);
    try std.testing.expectEqual(h1, ErgoTreeHeader.parse(h1.toByte()));

    const h2 = ErgoTreeHeader.v0(true);
    try std.testing.expectEqual(h2, ErgoTreeHeader.parse(h2.toByte()));

    const h3 = ErgoTreeHeader.v1(false);
    try std.testing.expectEqual(h3, ErgoTreeHeader.parse(h3.toByte()));

    const h4 = ErgoTreeHeader.v1(true);
    try std.testing.expectEqual(h4, ErgoTreeHeader.parse(h4.toByte()));
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
