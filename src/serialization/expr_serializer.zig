//! Expression Serializer/Deserializer for ErgoTree
//!
//! Minimal implementation supporting HEIGHT > 100 expression.
//! Uses explicit work stack instead of recursion per ZIGMA_STYLE.
//!
//! Reference: Rust ergotree-ir/src/serialization/expr.rs

const std = @import("std");
const assert = std.debug.assert;
const vlq = @import("vlq.zig");
const types = @import("../core/types.zig");
const opcodes = @import("../core/opcodes.zig");
const data_serializer = @import("data_serializer.zig");
const type_serializer = @import("type_serializer.zig");
const memory = @import("../interpreter/memory.zig");

const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const OpCode = opcodes.OpCode;
const Value = data_serializer.Value;
const BumpAllocator = memory.BumpAllocator;

// ============================================================================
// Expression Node
// ============================================================================

/// Maximum expression tree depth
const max_expr_depth: u8 = 64;

/// Maximum number of constants in an ErgoTree
pub const max_constants: usize = 256;

// Compile-time sanity checks
comptime {
    assert(max_expr_depth >= 16);
    assert(max_expr_depth <= 128);
    assert(max_constants <= 1024);
}

/// Expression node types
pub const ExprTag = enum(u8) {
    /// Constant value
    constant,
    /// Reference to constant in pool
    constant_placeholder,
    /// Boolean true literal
    true_leaf,
    /// Boolean false literal
    false_leaf,
    /// Context height access
    height,
    /// Binary operation (GT, LT, EQ, Plus, etc.)
    bin_op,
    /// Unit constant
    unit,
    /// Inputs collection
    inputs,
    /// Outputs collection
    outputs,
    /// Self box
    self_box,
    /// If-then-else
    if_then_else,
    /// Unsupported opcode
    unsupported,
};

/// Binary operation kind
pub const BinOpKind = enum(u8) {
    // Comparison
    lt,
    le,
    gt,
    ge,
    eq,
    neq,
    // Arithmetic
    plus,
    minus,
    multiply,
    divide,
    modulo,
    // Logical
    and_op,
    or_op,
    xor_op,
};

/// Expression node (compact representation)
pub const ExprNode = struct {
    /// Node type
    tag: ExprTag,
    /// Associated data (interpretation depends on tag)
    /// - constant: index into values array
    /// - constant_placeholder: index into constants pool
    /// - bin_op: BinOpKind as u8, children are next 2 nodes
    /// - if_then_else: children are next 3 nodes (condition, then, else)
    data: u16 = 0,
    /// Type of expression result
    result_type: TypeIndex = TypePool.BOOLEAN,

    pub fn isConstant(self: ExprNode) bool {
        return self.tag == .constant or
            self.tag == .constant_placeholder or
            self.tag == .true_leaf or
            self.tag == .false_leaf or
            self.tag == .unit;
    }

    pub fn isBinOp(self: ExprNode) bool {
        return self.tag == .bin_op;
    }

    pub fn binOpKind(self: ExprNode) ?BinOpKind {
        if (self.tag != .bin_op) return null;
        return @enumFromInt(self.data & 0xFF);
    }
};

// ============================================================================
// Deserializer State
// ============================================================================

/// Deserialized expression tree
pub const ExprTree = struct {
    /// Expression nodes in pre-order (depth-first)
    nodes: [max_constants]ExprNode = undefined,
    node_count: u16 = 0,

    /// Constant values
    values: [max_constants]Value = undefined,
    value_count: u16 = 0,

    /// Constants pool (from ErgoTree header)
    constants: [max_constants]Value = undefined,
    constant_count: u16 = 0,

    /// Type pool
    type_pool: TypePool = TypePool.init(),

    pub fn init() ExprTree {
        return .{};
    }

    pub fn reset(self: *ExprTree) void {
        self.node_count = 0;
        self.value_count = 0;
        self.constant_count = 0;
        self.type_pool.reset();
    }

    pub fn addNode(self: *ExprTree, node: ExprNode) error{ExpressionTooComplex}!u16 {
        if (self.node_count >= max_constants) return error.ExpressionTooComplex;
        const idx = self.node_count;
        self.nodes[idx] = node;
        self.node_count += 1;
        return idx;
    }

    pub fn addValue(self: *ExprTree, value: Value) error{ExpressionTooComplex}!u16 {
        if (self.value_count >= max_constants) return error.ExpressionTooComplex;
        const idx = self.value_count;
        self.values[idx] = value;
        self.value_count += 1;
        return idx;
    }

    pub fn addConstant(self: *ExprTree, value: Value) error{ExpressionTooComplex}!u16 {
        if (self.constant_count >= max_constants) return error.ExpressionTooComplex;
        const idx = self.constant_count;
        self.constants[idx] = value;
        self.constant_count += 1;
        return idx;
    }

    pub fn root(self: *const ExprTree) ?ExprNode {
        if (self.node_count == 0) return null;
        return self.nodes[0];
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
};

// ============================================================================
// Deserialize Functions
// ============================================================================

/// Deserialize an expression from bytes.
/// Uses bounded recursion (depth limited per ZIGMA_STYLE).
pub fn deserialize(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
) DeserializeError!void {
    try deserializeWithDepth(tree, reader, arena, 0);
}

fn deserializeWithDepth(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITION: Bounded recursion
    if (depth >= max_expr_depth) {
        return error.ExpressionTooComplex;
    }

    // Read opcode/type tag
    const tag = reader.readByte() catch |e| return mapVlqError(e);

    // Dispatch based on tag value
    if (tag <= opcodes.constant_last) {
        // Type code (1-111) - this is a constant
        try deserializeConstant(tree, reader, arena, tag);
    } else {
        // Operation opcode
        switch (tag) {
            opcodes.TrueLeaf => {
                _ = try tree.addNode(.{
                    .tag = .true_leaf,
                    .result_type = TypePool.BOOLEAN,
                });
            },
            opcodes.FalseLeaf => {
                _ = try tree.addNode(.{
                    .tag = .false_leaf,
                    .result_type = TypePool.BOOLEAN,
                });
            },
            opcodes.UnitConstant => {
                _ = try tree.addNode(.{
                    .tag = .unit,
                    .result_type = TypePool.UNIT,
                });
            },
            opcodes.ConstantPlaceholder => {
                const idx = reader.readByte() catch |e| return mapVlqError(e);
                _ = try tree.addNode(.{
                    .tag = .constant_placeholder,
                    .data = idx,
                    // Type comes from constants pool
                });
            },
            opcodes.Height => {
                _ = try tree.addNode(.{
                    .tag = .height,
                    .result_type = TypePool.INT,
                });
            },
            opcodes.Inputs => {
                _ = try tree.addNode(.{
                    .tag = .inputs,
                    // result_type is Coll[Box]
                });
            },
            opcodes.Outputs => {
                _ = try tree.addNode(.{
                    .tag = .outputs,
                    // result_type is Coll[Box]
                });
            },
            opcodes.Self => {
                _ = try tree.addNode(.{
                    .tag = .self_box,
                    .result_type = TypePool.BOX,
                });
            },
            // Comparison operations
            opcodes.LT => try deserializeBinOp(tree, reader, arena, .lt, depth),
            opcodes.LE => try deserializeBinOp(tree, reader, arena, .le, depth),
            opcodes.GT => try deserializeBinOp(tree, reader, arena, .gt, depth),
            opcodes.GE => try deserializeBinOp(tree, reader, arena, .ge, depth),
            opcodes.EQ => try deserializeBinOp(tree, reader, arena, .eq, depth),
            opcodes.NEQ => try deserializeBinOp(tree, reader, arena, .neq, depth),
            // Arithmetic operations
            opcodes.Plus => try deserializeBinOp(tree, reader, arena, .plus, depth),
            opcodes.Minus => try deserializeBinOp(tree, reader, arena, .minus, depth),
            opcodes.Multiply => try deserializeBinOp(tree, reader, arena, .multiply, depth),
            opcodes.Division => try deserializeBinOp(tree, reader, arena, .divide, depth),
            opcodes.Modulo => try deserializeBinOp(tree, reader, arena, .modulo, depth),
            // Logical operations
            opcodes.AND => try deserializeBinOp(tree, reader, arena, .and_op, depth),
            opcodes.OR => try deserializeBinOp(tree, reader, arena, .or_op, depth),
            // If-then-else
            opcodes.If => try deserializeIf(tree, reader, arena, depth),
            else => {
                // Unsupported opcode - record it but don't fail
                _ = try tree.addNode(.{
                    .tag = .unsupported,
                    .data = tag,
                });
            },
        }
    }
}

fn deserializeConstant(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    first_byte: u8,
) DeserializeError!void {
    // Parse type from first byte + any additional bytes
    // Put the first byte back for the type deserializer
    var type_buf: [16]u8 = undefined;
    type_buf[0] = first_byte;

    // Read more bytes if needed for generic types
    var type_len: usize = 1;
    const info = types.TypeCodeInfo.parse(first_byte);
    if (info == .coll_generic or info == .option_generic or
        info == .pair1_primitive or info == .pair2_primitive or
        info == .triple or info == .quadruple or info == .tuple5plus)
    {
        // Need to read more type bytes
        // For now, just read one more byte for generic cases
        const next_byte = reader.readByte() catch |e| return mapVlqError(e);
        type_buf[type_len] = next_byte;
        type_len += 1;
    }

    // Parse the type
    var type_reader = vlq.Reader.init(type_buf[0..type_len]);
    const type_idx = type_serializer.deserialize(&tree.type_pool, &type_reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Parse the value
    const value = data_serializer.deserialize(type_idx, &tree.type_pool, reader, arena) catch |e| {
        return switch (e) {
            error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
            error.Overflow => error.Overflow,
            error.InvalidData, error.InvalidGroupElement => error.InvalidData,
            error.OutOfMemory => error.OutOfMemory,
            error.TypeMismatch => error.TypeMismatch,
            error.NotSupported => error.NotSupported,
        };
    };

    // Store value and create node
    const value_idx = try tree.addValue(value);
    _ = try tree.addNode(.{
        .tag = .constant,
        .data = value_idx,
        .result_type = type_idx,
    });
}

fn deserializeBinOp(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    kind: BinOpKind,
    depth: u8,
) DeserializeError!void {
    // Add the bin_op node first (pre-order)
    _ = try tree.addNode(.{
        .tag = .bin_op,
        .data = @intFromEnum(kind),
        .result_type = TypePool.BOOLEAN, // Most bin ops return boolean
    });

    // Recursively parse left operand
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Recursively parse right operand
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeIf(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Add the if node first
    _ = try tree.addNode(.{
        .tag = .if_then_else,
    });

    // Parse condition
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse then branch
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse else branch
    try deserializeWithDepth(tree, reader, arena, depth + 1);
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

test "expr_serializer: deserialize TrueLeaf" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // TrueLeaf = 0x7F
    var reader = vlq.Reader.init(&[_]u8{0x7F});
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.true_leaf, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.BOOLEAN, tree.nodes[0].result_type);
}

test "expr_serializer: deserialize FalseLeaf" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // FalseLeaf = 0x80
    var reader = vlq.Reader.init(&[_]u8{0x80});
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.false_leaf, tree.nodes[0].tag);
}

test "expr_serializer: deserialize Height" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // Height = 0xA3
    var reader = vlq.Reader.init(&[_]u8{0xA3});
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.height, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.INT, tree.nodes[0].result_type);
}

test "expr_serializer: deserialize Int constant" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // Int constant 100: type code 0x04 (Int) + value 100 (ZigZag = 0xC8, 0x01)
    var reader = vlq.Reader.init(&[_]u8{ 0x04, 0xC8, 0x01 });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.INT, tree.nodes[0].result_type);
    try std.testing.expectEqual(@as(u16, 1), tree.value_count);
    try std.testing.expectEqual(@as(i32, 100), tree.values[0].int);
}

test "expr_serializer: deserialize HEIGHT > 100" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // GT(HEIGHT, Int(100)):
    // 0x91 (GT)
    //   0xA3 (HEIGHT)
    //   0x04 0xC8 0x01 (Int 100)
    var reader = vlq.Reader.init(&[_]u8{ 0x91, 0xA3, 0x04, 0xC8, 0x01 });
    try deserialize(&tree, &reader, &arena);

    // Should have 3 nodes: GT, HEIGHT, constant
    try std.testing.expectEqual(@as(u16, 3), tree.node_count);

    // Root is GT
    try std.testing.expectEqual(ExprTag.bin_op, tree.nodes[0].tag);
    try std.testing.expectEqual(BinOpKind.gt, tree.nodes[0].binOpKind().?);

    // Left operand is HEIGHT
    try std.testing.expectEqual(ExprTag.height, tree.nodes[1].tag);

    // Right operand is constant
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[2].tag);
    try std.testing.expectEqual(@as(i32, 100), tree.values[0].int);
}

test "expr_serializer: deserialize nested binary ops" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // AND(GT(HEIGHT, 100), TRUE):
    // 0xC0 (AND)
    //   0x91 (GT)
    //     0xA3 (HEIGHT)
    //     0x04 0xC8 0x01 (Int 100)
    //   0x7F (TRUE)
    var reader = vlq.Reader.init(&[_]u8{ 0xC0, 0x91, 0xA3, 0x04, 0xC8, 0x01, 0x7F });
    try deserialize(&tree, &reader, &arena);

    // Should have 5 nodes: AND, GT, HEIGHT, constant, TRUE
    try std.testing.expectEqual(@as(u16, 5), tree.node_count);

    // Root is AND
    try std.testing.expectEqual(ExprTag.bin_op, tree.nodes[0].tag);
    try std.testing.expectEqual(BinOpKind.and_op, tree.nodes[0].binOpKind().?);

    // Second node is GT
    try std.testing.expectEqual(ExprTag.bin_op, tree.nodes[1].tag);
    try std.testing.expectEqual(BinOpKind.gt, tree.nodes[1].binOpKind().?);
}

test "expr_serializer: deserialize ConstantPlaceholder" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // ConstantPlaceholder with index 0: 0x76 0x00
    var reader = vlq.Reader.init(&[_]u8{ 0x76, 0x00 });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.constant_placeholder, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 0), tree.nodes[0].data);
}

test "expr_serializer: error on empty input" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    var reader = vlq.Reader.init(&[_]u8{});
    try std.testing.expectError(error.UnexpectedEndOfInput, deserialize(&tree, &reader, &arena));
}
