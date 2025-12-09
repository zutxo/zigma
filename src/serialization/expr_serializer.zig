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
    /// CalcBlake2b256 hash (opcode 0xCB)
    calc_blake2b256,
    /// CalcSha256 hash (opcode 0xCC)
    calc_sha256,
    /// Variable reference (opcode 0x72) - data = varId
    val_use,
    /// Variable definition (opcode 0x73) - data = varId
    val_def,
    /// Block with let bindings (opcode 0x74) - data = item count
    block_value,
    /// Function value / lambda (opcode for func expressions)
    func_value,
    /// Function application (opcode 0xF5)
    apply,
    /// Get value from Option (opcode 0xBA) - errors if None
    option_get,
    /// Check if Option is defined (opcode 0xBB) - returns boolean
    option_is_defined,
    /// Get value from Option or default (opcode 0xBC)
    option_get_or_else,
    /// Convert Long to Coll[Byte] (opcode 0x78)
    long_to_byte_array,
    /// Convert Coll[Byte] to BigInt (opcode 0x79)
    byte_array_to_bigint,
    /// Convert Coll[Byte] to Long (opcode 0x7A)
    byte_array_to_long,
    /// Decode point from bytes (opcode 0xD0) - Coll[Byte] → GroupElement
    decode_point,
    /// Get group generator G (opcode 0xD2) - → GroupElement
    group_generator,
    /// Scalar multiplication (opcode 0xD3) - GroupElement, BigInt → GroupElement
    exponentiate,
    /// Point multiplication/addition (opcode 0xD4) - GroupElement, GroupElement → GroupElement
    multiply_group,
    /// Select field from tuple (opcode 0xBD) - Tuple → element type
    select_field,
    /// Generic tuple constructor (opcode 0xBE) - n elements → Tuple
    tuple_construct,
    /// Pair constructor (opcode 0xDD) - 2 elements → Pair
    pair_construct,
    /// Triple constructor (opcode 0xDE) - 3 elements → Triple
    triple_construct,
    /// Upcast to larger type (opcode 0xE4) - e.g., Int → Long
    upcast,
    /// Downcast to smaller type (opcode 0xE5) - e.g., Long → Int, may overflow
    downcast,
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

/// Maximum number of variable definitions in a block
const max_val_defs: usize = 64;

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

    /// ValDef type store: maps varId -> TypeIndex
    /// Used during deserialization so ValUse can look up types
    val_def_types: [max_val_defs]TypeIndex = [_]TypeIndex{TypePool.UNIT} ** max_val_defs,

    pub fn init() ExprTree {
        return .{};
    }

    pub fn reset(self: *ExprTree) void {
        self.node_count = 0;
        self.value_count = 0;
        self.constant_count = 0;
        self.type_pool.reset();
        self.val_def_types = [_]TypeIndex{TypePool.UNIT} ** max_val_defs;
    }

    /// Register a ValDef type for later ValUse lookups
    pub fn setValDefType(self: *ExprTree, var_id: u16, type_idx: TypeIndex) void {
        if (var_id < max_val_defs) {
            self.val_def_types[var_id] = type_idx;
        }
    }

    /// Get the type of a ValDef by varId
    pub fn getValDefType(self: *const ExprTree, var_id: u16) TypeIndex {
        if (var_id < max_val_defs) {
            return self.val_def_types[var_id];
        }
        return TypePool.UNIT; // Fallback
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
            // Crypto hash operations (unary: input -> Coll[Byte])
            opcodes.CalcBlake2b256 => try deserializeUnaryOp(tree, reader, arena, .calc_blake2b256, depth),
            opcodes.CalcSha256 => try deserializeUnaryOp(tree, reader, arena, .calc_sha256, depth),
            // Variable operations
            opcodes.ValUse => try deserializeValUse(tree, reader),
            opcodes.ValDef => try deserializeValDef(tree, reader, arena, depth),
            opcodes.BlockValue => try deserializeBlockValue(tree, reader, arena, depth),
            // Function application
            opcodes.Apply => try deserializeApply(tree, reader, arena, depth),
            // Option operations
            opcodes.OptionGet => try deserializeUnaryOp(tree, reader, arena, .option_get, depth),
            opcodes.OptionIsDefined => try deserializeUnaryOp(tree, reader, arena, .option_is_defined, depth),
            opcodes.OptionGetOrElse => try deserializeOptionGetOrElse(tree, reader, arena, depth),
            // Type conversion operations
            opcodes.LongToByteArray => try deserializeUnaryOp(tree, reader, arena, .long_to_byte_array, depth),
            opcodes.ByteArrayToBigInt => try deserializeUnaryOp(tree, reader, arena, .byte_array_to_bigint, depth),
            opcodes.ByteArrayToLong => try deserializeUnaryOp(tree, reader, arena, .byte_array_to_long, depth),
            // Group element crypto operations
            opcodes.DecodePoint => try deserializeUnaryOp(tree, reader, arena, .decode_point, depth),
            opcodes.GroupGenerator => {
                // Nullary operation - just add the node
                _ = try tree.addNode(.{
                    .tag = .group_generator,
                    .result_type = TypePool.GROUP_ELEMENT,
                });
            },
            opcodes.Exponentiate => try deserializeBinaryGroupOp(tree, reader, arena, .exponentiate, depth),
            opcodes.MultiplyGroup => try deserializeBinaryGroupOp(tree, reader, arena, .multiply_group, depth),
            // Tuple operations
            opcodes.SelectField => try deserializeSelectField(tree, reader, arena, depth),
            opcodes.Tuple => try deserializeTuple(tree, reader, arena, depth),
            opcodes.PairConstructor => try deserializePairConstructor(tree, reader, arena, depth),
            opcodes.TripleConstructor => try deserializeTripleConstructor(tree, reader, arena, depth),
            // Type conversion operations
            opcodes.Upcast => try deserializeUpcast(tree, reader, arena, depth),
            opcodes.Downcast => try deserializeDowncast(tree, reader, arena, depth),
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

fn deserializeUnaryOp(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // PRECONDITION: tag is a valid unary operation
    assert(tag == .calc_blake2b256 or tag == .calc_sha256 or
        tag == .option_get or tag == .option_is_defined or
        tag == .long_to_byte_array or tag == .byte_array_to_bigint or
        tag == .byte_array_to_long or tag == .decode_point);

    // Determine result type based on operation
    const result_type: TypeIndex = switch (tag) {
        .calc_blake2b256, .calc_sha256, .long_to_byte_array => TypePool.COLL_BYTE,
        .option_is_defined => TypePool.BOOLEAN,
        .option_get => TypePool.ANY, // Will be inner type of option at runtime
        .byte_array_to_long => TypePool.LONG,
        .byte_array_to_bigint => TypePool.BIG_INT,
        .decode_point => TypePool.GROUP_ELEMENT,
        else => TypePool.ANY,
    };

    // Add the unary op node first (pre-order)
    _ = try tree.addNode(.{
        .tag = tag,
        .result_type = result_type,
    });

    // Parse the single operand
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeBinaryGroupOp(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // PRECONDITION: tag is a valid binary group operation
    assert(tag == .exponentiate or tag == .multiply_group);

    // Add the binary op node first (pre-order)
    _ = try tree.addNode(.{
        .tag = tag,
        .result_type = TypePool.GROUP_ELEMENT,
    });

    // Parse left operand (GroupElement for both ops)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse right operand (BigInt for exponentiate, GroupElement for multiply)
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeValUse(
    tree: *ExprTree,
    reader: *vlq.Reader,
) DeserializeError!void {
    // ValUse format: just the varId (VLQ)
    // Type is looked up from val_def_types store
    const var_id = reader.readU32() catch |e| return mapVlqError(e);

    // Look up the type from the ValDef store
    const result_type = tree.getValDefType(@truncate(var_id));

    _ = try tree.addNode(.{
        .tag = .val_use,
        .data = @truncate(var_id),
        .result_type = result_type,
    });
}

fn deserializeValDef(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // ValDef format: varId (VLQ) + optional tpeArgs + rhs expression
    const var_id = reader.readU32() catch |e| return mapVlqError(e);

    // Record the node index for this ValDef
    const node_idx = try tree.addNode(.{
        .tag = .val_def,
        .data = @truncate(var_id),
    });

    // Parse the right-hand side expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // The rhs node is at node_idx + 1 in pre-order layout
    // Store its type for later ValUse lookups
    if (node_idx + 1 < tree.node_count) {
        const rhs_type = tree.nodes[node_idx + 1].result_type;
        tree.setValDefType(@truncate(var_id), rhs_type);
        // Update the ValDef's result_type to match rhs
        tree.nodes[node_idx].result_type = rhs_type;
    }
}

fn deserializeBlockValue(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // BlockValue format: item_count (VLQ) + items (ValDef/FunDef) + result expression
    const item_count = reader.readU32() catch |e| return mapVlqError(e);

    // Add the block node first (pre-order)
    const block_idx = try tree.addNode(.{
        .tag = .block_value,
        .data = @truncate(item_count),
    });

    // Parse each item (ValDef or FunDef)
    var i: u32 = 0;
    while (i < item_count) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }

    // Parse the result expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Update block's result type from the result expression
    // Result is the last parsed expression
    if (tree.node_count > block_idx + 1) {
        const result_node_idx = tree.node_count - 1;
        // Walk back to find the result expression (after all ValDefs)
        tree.nodes[block_idx].result_type = tree.nodes[result_node_idx].result_type;
    }
}

fn deserializeApply(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Apply format: func expression + args count (VLQ) + args expressions
    // Note: In v5.x only single-argument functions are supported

    // Add the apply node first (pre-order)
    _ = try tree.addNode(.{
        .tag = .apply,
    });

    // Parse function expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse args count (should be 1 in practice)
    const arg_count = reader.readU32() catch |e| return mapVlqError(e);

    // Parse each argument
    var i: u32 = 0;
    while (i < arg_count) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }
}

fn deserializeOptionGetOrElse(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // OptionGetOrElse format: option expression + default expression
    // Returns the value if Some, or the default if None

    // Add the option_get_or_else node first (pre-order)
    _ = try tree.addNode(.{
        .tag = .option_get_or_else,
        .result_type = TypePool.ANY, // Will be type of default/inner at runtime
    });

    // Parse the option expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse the default expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeSelectField(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // SelectField format: tuple expression + field index (VLQ)
    // Note: some serializations have field index before the expression

    // For now, assume format: SelectField(fieldIdx, tupleExpr)
    // Field index is 1-based in ErgoTree
    const field_idx = reader.readU32() catch |e| return mapVlqError(e);

    // Add the select_field node first (pre-order)
    // Store field index in data (convert to 0-based)
    _ = try tree.addNode(.{
        .tag = .select_field,
        .data = @truncate(field_idx -| 1), // Convert 1-based to 0-based, saturating
        .result_type = TypePool.ANY, // Determined at runtime from tuple type
    });

    // Parse the tuple expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeTuple(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Tuple format: element count (VLQ) + n element expressions

    const elem_count = reader.readU32() catch |e| return mapVlqError(e);
    if (elem_count > 255) return error.InvalidData;

    // Add the tuple_construct node first (pre-order)
    // Store element count in data
    _ = try tree.addNode(.{
        .tag = .tuple_construct,
        .data = @truncate(elem_count),
        .result_type = TypePool.ANY, // Determined at runtime
    });

    // Parse each element expression
    var i: u32 = 0;
    while (i < elem_count) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }
}

fn deserializePairConstructor(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PairConstructor format: first expression + second expression

    // Add the pair_construct node first (pre-order)
    // Store element count (2) in data
    _ = try tree.addNode(.{
        .tag = .pair_construct,
        .data = 2, // Fixed: 2 elements
        .result_type = TypePool.ANY, // Determined at runtime
    });

    // Parse first element
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse second element
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeTripleConstructor(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // TripleConstructor format: three expressions

    // Add the triple_construct node first (pre-order)
    // Store element count (3) in data
    _ = try tree.addNode(.{
        .tag = .triple_construct,
        .data = 3, // Fixed: 3 elements
        .result_type = TypePool.ANY, // Determined at runtime
    });

    // Parse first element
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse second element
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse third element
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeUpcast(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Upcast format: target type + input expression
    // Reads target type code, then the expression to upcast

    const target_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Store target type in data field (u16 index)
    _ = try tree.addNode(.{
        .tag = .upcast,
        .data = target_type,
        .result_type = target_type,
    });

    // Parse the input expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeDowncast(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Downcast format: target type + input expression
    // Reads target type code, then the expression to downcast

    const target_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Store target type in data field (u16 index)
    _ = try tree.addNode(.{
        .tag = .downcast,
        .data = target_type,
        .result_type = target_type,
    });

    // Parse the input expression
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
