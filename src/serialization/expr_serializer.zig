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
    /// Miner public key from pre-header (opcode 0xAA)
    miner_pk,
    /// Last block UTXO root hash from headers (opcode 0xA6)
    last_block_utxo_root,
    /// Context object (opcode 0xFE/254) - provides access to context methods
    context,
    /// Global object (opcode 0xDD/221) - provides access to global methods
    global,
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
    /// Concrete collection literal (opcode 0xDC) - Coll[T](item_0, item_1, ...)
    concrete_collection,

    // Collection higher-order functions (opcodes 0xAD-0xB5)
    /// Map: Coll[A] × (A → B) → Coll[B] (opcode 0xAD)
    map_collection,
    /// Exists: Coll[A] × (A → Boolean) → Boolean (opcode 0xAE)
    exists,
    /// ForAll: Coll[A] × (A → Boolean) → Boolean (opcode 0xAF)
    for_all,
    /// Fold: Coll[A] × B × ((B,A) → B) → B (opcode 0xB0)
    fold,
    /// Filter: Coll[A] × (A → Boolean) → Coll[A] (opcode 0xB5)
    filter,
    /// FlatMap: Coll[A] × (A → Coll[B]) → Coll[B] (opcode 0xB8)
    flat_map,

    // Logical operations on collections of booleans (unary: Coll[Boolean] → Boolean)
    /// AND: all elements in collection are true (opcode 0x96)
    logical_and,
    /// OR: at least one element in collection is true (opcode 0x97)
    logical_or,

    // Sigma proposition connectives (opcodes 0xEA-0xEB after shift)
    /// SigmaAnd: all child propositions must be proven (opcode 0xEA)
    sigma_and,
    /// SigmaOr: at least one child proposition must be proven (opcode 0xEB)
    sigma_or,
    /// Binary AND of two SigmaBoolean propositions (opcode 0xED/237)
    bin_and,
    /// Binary OR of two SigmaBoolean propositions (opcode 0xEC/236)
    bin_or,
    /// Binary XOR of two SigmaBoolean propositions (opcode 0xF4/244)
    bin_xor,

    // Header field extraction opcodes (0xE9-0xF2)
    /// Extract version byte from Header (opcode 0xE9)
    extract_version,
    /// Extract parent block ID from Header (opcode 0xEA)
    extract_parent_id,
    /// Extract AD proofs root from Header (opcode 0xEB)
    extract_ad_proofs_root,
    /// Extract state root (AVL+ digest) from Header (opcode 0xEC)
    extract_state_root,
    /// Extract transactions root from Header (opcode 0xED)
    extract_txs_root,
    /// Extract timestamp from Header (opcode 0xEE)
    extract_timestamp,
    /// Extract nBits (difficulty target) from Header (opcode 0xEF)
    extract_n_bits,
    /// Extract difficulty as BigInt from Header (opcode 0xF0)
    extract_difficulty,
    /// Extract votes from Header (opcode 0xF1)
    extract_votes,
    /// Extract miner rewards pubkey from Header (opcode 0xF2)
    extract_miner_rewards,

    /// Method call (opcode 0xDC/220) - obj.method(args)
    /// data: low 8 bits = type_code, high 8 bits = method_id
    method_call,

    /// Property call (opcode 0xDB/219) - obj.property (no args)
    /// data: low 8 bits = type_code, high 8 bits = property_id
    property_call,

    // AVL tree operations (opcodes 0xB6-0xB7 / 182-183)
    /// Create AVL tree (opcode 0xB6/182) - flags, digest, key_len, opt_value_len → AvlTree
    create_avl_tree,
    /// Tree lookup (opcode 0xB7/183) - tree, key, proof → Option[Coll[Byte]]
    tree_lookup,

    // Box extraction operations (opcodes 0xC5-0xC9 / 193-201)
    /// Extract register value from box (opcode 0xC7/199) - Box, regId, type → Option[T]
    /// data: low 4 bits = register_id (0-9), rest = type_idx for inner type
    extract_register_as,

    // Context variable access (opcode 0xE3 / 227)
    /// GetVar: access context extension variable (opcode 0xE3/227) - varId, type → Option[T]
    /// data: low 8 bits = var_id, high 8 bits = type_idx for expected type
    get_var,

    // Modular arithmetic mod secp256k1 group order (opcodes 0xE7-0xE9 / 231-233)
    /// ModQ: reduce BigInt mod q (opcode 0xE7/231) - BigInt → BigInt
    mod_q,
    /// PlusModQ: (a + b) mod q (opcode 0xE8/232) - BigInt, BigInt → BigInt
    plus_mod_q,
    /// MinusModQ: (a - b) mod q (opcode 0xE9/233) - BigInt, BigInt → BigInt
    minus_mod_q,

    // Bitwise unary operation (v3+)
    /// Bitwise inversion/complement (opcode 0xF1/241) - T → T
    bit_inversion,

    // Special operations
    /// SubstConstants: substitute constants in serialized ErgoTree (opcode 0x74/116)
    /// 3 children: script_bytes (Coll[Byte]), positions (Coll[Int]), newValues (Coll[T])
    /// Returns: Coll[Byte] with substituted constants
    subst_constants,

    /// DeserializeContext: execute script from context variable (opcode 0xD4/212)
    /// data: type_idx(16) | var_id(8) | unused(8)
    /// Returns: T where T is the expected type
    deserialize_context,

    /// DeserializeRegister: execute script from SELF register (opcode 0xD5/213)
    /// data: type_idx(16) | reg_id(8) | has_default(8)
    /// Optional child: default expression if has_default == 1
    /// Returns: T where T is the expected type
    deserialize_register,

    /// BoolToSigmaProp: convert boolean to SigmaProp (opcode 0xD1/209)
    /// Wraps a Boolean expression as a SigmaProp (trivial proposition)
    /// 1 child: Boolean expression
    /// Returns: SigmaProp
    bool_to_sigma_prop,

    // Additional unary operations
    /// SizeOf: get collection length (opcode 0xB1/177) - Coll[T] → Int
    size_of,
    /// Negation: arithmetic negation (opcode 0xF0/240) - T → T
    negation,
    /// LogicalNot: boolean negation (opcode 0xEF/239) - Boolean → Boolean
    logical_not,

    // Additional box operations (opcodes 0xC1-0xC7 / 193-199)
    /// ExtractAmount: get box value in nanoERGs (opcode 0xC1/193) - Box → Long
    extract_amount,
    /// ExtractScriptBytes: get box script as bytes (opcode 0xC2/194) - Box → Coll[Byte]
    extract_script_bytes,
    /// ExtractBytes: get box serialized bytes (opcode 0xC3/195) - Box → Coll[Byte]
    extract_bytes,
    /// ExtractBytesWithNoRef: box bytes without transaction ref (opcode 0xC4/196) - Box → Coll[Byte]
    extract_bytes_with_no_ref,
    /// ExtractId: get 32-byte box ID (opcode 0xC5/197) - Box → Coll[Byte]
    extract_id,
    /// ExtractCreationInfo: get (height, txId) (opcode 0xC7/199) - Box → (Int, Coll[Byte])
    extract_creation_info,

    // Sigma proposition literals
    /// TrivialPropTrue: always-true proposition (opcode 0xD3/211)
    trivial_prop_true,
    /// TrivialPropFalse: always-false proposition (opcode 0xD2/210)
    trivial_prop_false,

    // Sigma protocol constructors
    /// ProveDlog: Schnorr signature (opcode 0xCD/205) - GroupElement → SigmaProp
    prove_dlog,
    /// ProveDHTuple: DH tuple (opcode 0xCE/206) - 4 GroupElements → SigmaProp
    prove_dh_tuple,
    /// SigmaPropBytes: get proposition bytes (opcode 0xD0/208) - SigmaProp → Coll[Byte]
    sigma_prop_bytes,

    // Collection slice (ternary operation)
    /// Slice: collection.slice(from, until) (opcode 0xB4/180)
    /// 3 children: collection, from, until
    slice,

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
    // Bitwise (v3+)
    bit_or,
    bit_and,
    bit_xor,
    bit_shift_right, // arithmetic (sign-extending)
    bit_shift_left,
    bit_shift_right_zeroed, // logical (zero-extending)
    // Collection operations
    by_index, // collection[index]
    append, // collection ++ collection
    min, // min(a, b)
    max, // max(a, b)
    xor_byte_array, // byte array XOR
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
        return std.meta.intToEnum(BinOpKind, self.data & 0xFF) catch null;
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
    const start_pos = reader.pos;
    const tag = reader.readByte() catch |e| {
        std.debug.print("EOF at pos {d}, depth {d}, total_len {d}\n", .{ start_pos, depth, reader.data.len });
        return mapVlqError(e);
    };

    // Dispatch based on tag value
    if (tag >= opcodes.constant_first and tag <= opcodes.constant_last) {
        // Type code (1-111) - this is an inline constant
        // Skip reserved type codes 10-11 (between primitives 1-9 and Coll at 12+)
        if (tag == 10 or tag == 11) {
            return error.InvalidTypeCode;
        }
        try deserializeConstant(tree, reader, arena, tag);
    } else if (tag == 0) {
        // Opcode 0 is reserved/invalid
        return error.InvalidOpcode;
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
                // Index is VLQ u32, not a single byte
                // Reference: Rust constant_placeholder.rs: r.get_u32()
                const idx = reader.readU32() catch |e| return mapVlqError(e);
                _ = try tree.addNode(.{
                    .tag = .constant_placeholder,
                    .data = @truncate(idx),
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
            opcodes.MinerPubKey => {
                _ = try tree.addNode(.{
                    .tag = .miner_pk,
                    .result_type = TypePool.GROUP_ELEMENT,
                });
            },
            opcodes.LastBlockUtxoRootHash => {
                _ = try tree.addNode(.{
                    .tag = .last_block_utxo_root,
                    .result_type = TypePool.AVL_TREE,
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
            // Note: AND/OR (0x96/0x97) take a SINGLE collection input (unary),
            // not two expressions like binary operators. Reference: Rust and.rs, or.rs
            opcodes.AND => try deserializeUnaryOp(tree, reader, arena, .logical_and, depth),
            opcodes.OR => try deserializeUnaryOp(tree, reader, arena, .logical_or, depth),
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
            // Context and Global objects (nullary)
            opcodes.Context => {
                _ = try tree.addNode(.{
                    .tag = .context,
                    .result_type = TypePool.ANY, // Context type
                });
            },
            opcodes.Global => {
                _ = try tree.addNode(.{
                    .tag = .global,
                    .result_type = TypePool.ANY, // Global type
                });
            },
            opcodes.Exponentiate => try deserializeBinaryGroupOp(tree, reader, arena, .exponentiate, depth),
            opcodes.MultiplyGroup => try deserializeBinaryGroupOp(tree, reader, arena, .multiply_group, depth),
            // Tuple operations
            opcodes.SelectField => try deserializeSelectField(tree, reader, arena, depth),
            opcodes.Select1 => try deserializeSelectN(tree, reader, arena, 0, depth),
            opcodes.Select2 => try deserializeSelectN(tree, reader, arena, 1, depth),
            opcodes.Select3 => try deserializeSelectN(tree, reader, arena, 2, depth),
            opcodes.Select4 => try deserializeSelectN(tree, reader, arena, 3, depth),
            opcodes.Select5 => try deserializeSelectN(tree, reader, arena, 4, depth),
            opcodes.Tuple => try deserializeTuple(tree, reader, arena, depth),
            // NOTE: PairConstructor/TripleConstructor not in canonical Scala opcodes
            // Tuple construction uses the Tuple opcode with element count from type
            // Type conversion operations
            opcodes.Upcast => try deserializeUpcast(tree, reader, arena, depth),
            opcodes.Downcast => try deserializeDowncast(tree, reader, arena, depth),
            // Collection constructors
            opcodes.ConcreteCollection => try deserializeConcreteCollection(tree, reader, arena, depth),
            // Collection higher-order functions
            opcodes.MapCollection => try deserializeCollectionHOF(tree, reader, arena, .map_collection, depth),
            opcodes.Exists => try deserializeCollectionHOF(tree, reader, arena, .exists, depth),
            opcodes.ForAll => try deserializeCollectionHOF(tree, reader, arena, .for_all, depth),
            opcodes.Fold => try deserializeFold(tree, reader, arena, depth),
            opcodes.Filter => try deserializeCollectionHOF(tree, reader, arena, .filter, depth),
            opcodes.FlatMapCollection => try deserializeCollectionHOF(tree, reader, arena, .flat_map, depth),
            // Collection operations with optional default
            opcodes.ByIndex => try deserializeByIndex(tree, reader, arena, depth),
            opcodes.Append => try deserializeBinOp(tree, reader, arena, .append, depth),
            opcodes.Slice => try deserializeSlice(tree, reader, arena, depth),
            // Collection unary operations
            opcodes.SizeOf => try deserializeUnaryOp(tree, reader, arena, .size_of, depth),
            // Arithmetic binary ops
            opcodes.Min => try deserializeBinOp(tree, reader, arena, .min, depth),
            opcodes.Max => try deserializeBinOp(tree, reader, arena, .max, depth),
            opcodes.Xor => try deserializeBinOp(tree, reader, arena, .xor_byte_array, depth),
            // Unary operations
            opcodes.Negation => try deserializeUnaryOp(tree, reader, arena, .negation, depth),
            opcodes.LogicalNot => try deserializeUnaryOp(tree, reader, arena, .logical_not, depth),
            // Box extraction operations
            opcodes.ExtractAmount => try deserializeUnaryOp(tree, reader, arena, .extract_amount, depth),
            opcodes.ExtractScriptBytes => try deserializeUnaryOp(tree, reader, arena, .extract_script_bytes, depth),
            opcodes.ExtractBytes => try deserializeUnaryOp(tree, reader, arena, .extract_bytes, depth),
            opcodes.ExtractBytesWithNoRef => try deserializeUnaryOp(tree, reader, arena, .extract_bytes_with_no_ref, depth),
            opcodes.ExtractId => try deserializeUnaryOp(tree, reader, arena, .extract_id, depth),
            opcodes.ExtractCreationInfo => try deserializeUnaryOp(tree, reader, arena, .extract_creation_info, depth),
            // Sigma proposition constructors
            opcodes.ProveDlog => try deserializeUnaryOp(tree, reader, arena, .prove_dlog, depth),
            opcodes.ProveDHTuple => try deserializeProveDHTuple(tree, reader, arena, depth),
            opcodes.SigmaPropBytes => try deserializeUnaryOp(tree, reader, arena, .sigma_prop_bytes, depth),
            // Trivial propositions (nullary)
            opcodes.TrivialPropTrue => {
                _ = try tree.addNode(.{
                    .tag = .trivial_prop_true,
                    .result_type = TypePool.SIGMA_PROP,
                });
            },
            opcodes.TrivialPropFalse => {
                _ = try tree.addNode(.{
                    .tag = .trivial_prop_false,
                    .result_type = TypePool.SIGMA_PROP,
                });
            },
            // FuncValue
            opcodes.FuncValue => try deserializeFuncValue(tree, reader, arena, depth),
            // Sigma proposition connectives
            opcodes.SigmaAnd => try deserializeSigmaConnective(tree, reader, arena, .sigma_and, depth),
            opcodes.SigmaOr => try deserializeSigmaConnective(tree, reader, arena, .sigma_or, depth),
            // Binary sigma proposition operations (2 children each)
            opcodes.BinAnd => try deserializeBinarySigmaOp(tree, reader, arena, .bin_and, depth),
            opcodes.BinOr => try deserializeBinarySigmaOp(tree, reader, arena, .bin_or, depth),
            opcodes.BinXor => try deserializeBinarySigmaOp(tree, reader, arena, .bin_xor, depth),
            // BoolToSigmaProp: wrap Boolean as SigmaProp (trivial proposition)
            opcodes.BoolToSigmaProp => try deserializeUnaryOp(tree, reader, arena, .bool_to_sigma_prop, depth),
            // Method call (collection methods like zip, indices, etc.)
            opcodes.MethodCall => try deserializeMethodCall(tree, reader, arena, depth),
            // Property call (property access like box.value, context.dataInputs)
            opcodes.PropertyCall => try deserializePropertyCall(tree, reader, arena, depth),
            // AVL tree operations
            opcodes.AvlTree => try deserializeCreateAvlTree(tree, reader, arena, depth),
            opcodes.AvlTreeGet => try deserializeTreeLookup(tree, reader, arena, depth),
            // Box extraction operations
            opcodes.ExtractRegisterAs => try deserializeExtractRegisterAs(tree, reader, arena, depth),
            // Context variable access
            opcodes.GetVar => try deserializeGetVar(tree, reader, depth),
            // Modular arithmetic mod secp256k1 group order
            opcodes.ModQ => try deserializeUnaryOp(tree, reader, arena, .mod_q, depth),
            opcodes.PlusModQ => try deserializeBinaryModQOp(tree, reader, arena, .plus_mod_q, depth),
            opcodes.MinusModQ => try deserializeBinaryModQOp(tree, reader, arena, .minus_mod_q, depth),
            // Bitwise operations (v3+)
            opcodes.BitInversion => try deserializeUnaryOp(tree, reader, arena, .bit_inversion, depth),
            opcodes.BitOr => try deserializeBinOp(tree, reader, arena, .bit_or, depth),
            opcodes.BitAnd => try deserializeBinOp(tree, reader, arena, .bit_and, depth),
            opcodes.BitXor => try deserializeBinOp(tree, reader, arena, .bit_xor, depth),
            opcodes.BitShiftRight => try deserializeBinOp(tree, reader, arena, .bit_shift_right, depth),
            opcodes.BitShiftLeft => try deserializeBinOp(tree, reader, arena, .bit_shift_left, depth),
            opcodes.BitShiftRightZeroed => try deserializeBinOp(tree, reader, arena, .bit_shift_right_zeroed, depth),
            // Special operations
            opcodes.SubstConstants => try deserializeSubstConstants(tree, reader, arena, depth),
            opcodes.DeserializeContext => try deserializeDeserializeContext(tree, reader, depth),
            opcodes.DeserializeRegister => try deserializeDeserializeRegister(tree, reader, arena, depth),
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

    // Parse the value (pass null for value_pool - not needed during deserialization)
    const value = data_serializer.deserialize(type_idx, &tree.type_pool, reader, arena, null) catch |e| {
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

/// Deserialize ByIndex (opcode 0xB2/178)
/// Serialization format: input_collection + index + Option[default]
/// Reference: Rust coll_by_index.rs - has optional default for getOrElse
fn deserializeByIndex(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Add the bin_op node first (pre-order)
    // We treat ByIndex as a binary op since we don't handle the default yet
    _ = try tree.addNode(.{
        .tag = .bin_op,
        .data = @intFromEnum(BinOpKind.by_index),
        .result_type = TypePool.ANY, // Element type depends on collection
    });

    // Parse input collection
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse index
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Read optional default value (0 = None, 1 = Some + expression)
    const has_default = reader.readByte() catch |e| return mapVlqError(e);
    if (has_default != 0) {
        // Has default value - parse it (but we don't use it currently)
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }
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

/// Deserialize Slice (opcode 0xB4/180)
/// Serialization format: collection, from, until (3 children)
fn deserializeSlice(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Add the slice node first
    _ = try tree.addNode(.{
        .tag = .slice,
    });

    // Parse collection
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse from index
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse until index
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

/// Deserialize ProveDHTuple (opcode 0xCE/206)
/// Serialization format: g, h, u, v (4 GroupElement children)
fn deserializeProveDHTuple(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Add the node first
    _ = try tree.addNode(.{
        .tag = .prove_dh_tuple,
        .result_type = TypePool.SIGMA_PROP,
    });

    // Parse 4 GroupElement expressions: g, h, u, v
    try deserializeWithDepth(tree, reader, arena, depth + 1);
    try deserializeWithDepth(tree, reader, arena, depth + 1);
    try deserializeWithDepth(tree, reader, arena, depth + 1);
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
        tag == .byte_array_to_long or tag == .decode_point or
        tag == .mod_q or tag == .bool_to_sigma_prop or
        tag == .bit_inversion or
        // Box extraction operations
        tag == .extract_amount or tag == .extract_script_bytes or
        tag == .extract_bytes or tag == .extract_bytes_with_no_ref or
        tag == .extract_id or tag == .extract_creation_info or
        // Additional unary operations
        tag == .size_of or tag == .negation or tag == .logical_not or
        // Logical AND/OR on collections (unary: Coll[Boolean] → Boolean)
        tag == .logical_and or tag == .logical_or or
        // Sigma proposition operations
        tag == .prove_dlog or tag == .sigma_prop_bytes);

    // Determine result type based on operation
    const result_type: TypeIndex = switch (tag) {
        .calc_blake2b256, .calc_sha256, .long_to_byte_array => TypePool.COLL_BYTE,
        .option_is_defined, .logical_and, .logical_or => TypePool.BOOLEAN,
        .option_get => TypePool.ANY, // Will be inner type of option at runtime
        .byte_array_to_long => TypePool.LONG,
        .byte_array_to_bigint, .mod_q => TypePool.BIG_INT,
        .decode_point => TypePool.GROUP_ELEMENT,
        .bool_to_sigma_prop => TypePool.SIGMA_PROP, // Boolean -> SigmaProp
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

fn deserializeBinaryModQOp(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // PRECONDITION: tag is a valid binary ModQ operation
    assert(tag == .plus_mod_q or tag == .minus_mod_q);

    // Add the binary op node first (pre-order)
    _ = try tree.addNode(.{
        .tag = tag,
        .result_type = TypePool.BIG_INT,
    });

    // Parse left operand (BigInt)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse right operand (BigInt)
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

/// Deserialize binary sigma operations (BinAnd, BinOr, BinXor)
/// Format: opcode + left_child + right_child
fn deserializeBinarySigmaOp(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // Add the node first (pre-order)
    _ = try tree.addNode(.{
        .tag = tag,
        .result_type = TypePool.SIGMA_PROP,
    });

    // Parse two children
    try deserializeWithDepth(tree, reader, arena, depth + 1);
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

/// Type codes for methods with explicit type arguments
const ContextTypeCode: u8 = 101; // SContext
const BoxTypeCode: u8 = 99; // SBox

/// Method IDs that require explicit type arguments
const ContextMethodId = struct {
    const get_var_from_input: u8 = 12; // getVarFromInput[T](Short, Byte): Option[T]
};
const BoxMethodId = struct {
    const get_reg: u8 = 7; // getReg[T](Int): Option[T]
};

/// Check if a method requires explicit type arguments
fn methodNeedsExplicitTypeArg(type_code: u8, method_id: u8) bool {
    // Context.getVarFromInput[T]
    if (type_code == ContextTypeCode and method_id == ContextMethodId.get_var_from_input) return true;
    // Box.getReg[T]
    if (type_code == BoxTypeCode and method_id == BoxMethodId.get_reg) return true;
    return false;
}

fn deserializeMethodCall(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // MethodCall format: type_code + method_id + obj + args[] + explicit_type_args[]
    // Reference: Rust ergotree-ir/src/serialization/method_call.rs
    //
    // For methods with explicit type args (like getVarFromInput[T]):
    //   - Type args are serialized AFTER the arguments
    //   - We store the inner type T in result_type for later use

    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Read type code (1 byte) and method_id (1 byte)
    const type_code = reader.readByte() catch |e| return mapVlqError(e);
    const method_id = reader.readByte() catch |e| return mapVlqError(e);

    // INVARIANT: valid type code range
    assert(type_code > 0 or method_id > 0); // At least one must be non-zero

    // Pack type_code and method_id into data field
    // low 8 bits = type_code, high 8 bits = method_id
    const data: u16 = @as(u16, method_id) << 8 | @as(u16, type_code);

    // Add the method_call node first (pre-order)
    const node_idx = try tree.addNode(.{
        .tag = .method_call,
        .data = data,
        .result_type = TypePool.ANY, // Will be updated if explicit type arg present
    });

    // POSTCONDITION: Node was added
    assert(node_idx < tree.node_count);

    // Parse object expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse args count
    const arg_count = reader.readU32() catch |e| return mapVlqError(e);

    // INVARIANT: Reasonable arg count
    if (arg_count > 8) return error.InvalidData;

    // Parse each argument
    var i: u32 = 0;
    while (i < arg_count) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }

    // Parse explicit type arguments if method requires them
    // For methods like getVarFromInput[T] and getReg[T], there's 1 type arg (T)
    // We store T in result_type so evaluation can use it for deserialization
    if (methodNeedsExplicitTypeArg(type_code, method_id)) {
        const inner_type_idx = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
            return switch (e) {
                error.InvalidTypeCode => error.InvalidTypeCode,
                error.PoolFull => error.PoolFull,
                error.NestingTooDeep => error.NestingTooDeep,
                error.InvalidTupleLength => error.InvalidTupleLength,
                else => error.InvalidData,
            };
        };
        // Store inner type T in result_type
        // The actual result type is Option[T], but we need T for deserialization
        tree.nodes[node_idx].result_type = inner_type_idx;
    }
}

/// Deserialize PropertyCall operation (opcode 0xDB/219)
/// Format: type_code + property_id + obj
/// Reference: Rust ergotree-ir/src/serialization/property_call.rs
fn deserializePropertyCall(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Read type code (1 byte) and property_id (1 byte)
    const type_code = reader.readByte() catch |e| return mapVlqError(e);
    const property_id = reader.readByte() catch |e| return mapVlqError(e);

    // INVARIANT: valid type code range
    assert(type_code > 0 or property_id > 0); // At least one must be non-zero

    // Pack type_code and property_id into data field
    // low 8 bits = type_code, high 8 bits = property_id
    const data: u16 = @as(u16, property_id) << 8 | @as(u16, type_code);

    // Add the property_call node first (pre-order)
    const node_idx = try tree.addNode(.{
        .tag = .property_call,
        .data = data,
        .result_type = TypePool.ANY,
    });

    // POSTCONDITION: Node was added
    assert(node_idx < tree.node_count);

    // Parse object expression (no args unlike MethodCall)
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

/// Deserialize CreateAvlTree operation (opcode 0xB6/182)
/// Format: flags_expr + digest_expr + key_length_expr + Option[value_length_expr]
/// Returns: AvlTree
fn deserializeCreateAvlTree(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Add the create_avl_tree node first (pre-order)
    const node_idx = try tree.addNode(.{
        .tag = .create_avl_tree,
        .result_type = TypePool.AVL_TREE,
    });

    // POSTCONDITION: Node was added
    assert(node_idx < tree.node_count);

    // Parse flags expression (Byte)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse digest expression (Coll[Byte])
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse key_length expression (Int)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse optional value_length expression (Option[Int])
    // Format: 0x00 = None, 0x01 + expr = Some
    const opt_flag = reader.readByte() catch |e| return mapVlqError(e);
    if (opt_flag != 0) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }

    // Update node data to indicate if value_length is present
    // data = 1 if value_length present, 0 if not
    tree.nodes[node_idx].data = if (opt_flag != 0) 1 else 0;
}

/// Deserialize TreeLookup operation (opcode 0xB7/183)
/// Format: tree_expr + key_expr + proof_expr
/// Returns: Option[Coll[Byte]]
fn deserializeTreeLookup(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Get Option[Coll[Byte]] type for result
    const coll_byte_idx = TypePool.COLL_BYTE;
    const opt_coll_byte_idx = tree.type_pool.getOption(coll_byte_idx) catch TypePool.ANY;

    // Add the tree_lookup node first (pre-order)
    const node_idx = try tree.addNode(.{
        .tag = .tree_lookup,
        .result_type = opt_coll_byte_idx,
    });

    // POSTCONDITION: Node was added
    assert(node_idx < tree.node_count);

    // Parse tree expression (AvlTree)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse key expression (Coll[Byte])
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse proof expression (Coll[Byte])
    try deserializeWithDepth(tree, reader, arena, depth + 1);
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
    // SelectField format (Rust): input expression FIRST, then field_index (1 byte)
    // Field index is 1-based in ErgoTree

    // Add the select_field node first (pre-order) with placeholder
    const node_idx = try tree.addNode(.{
        .tag = .select_field,
        .data = 0, // Placeholder, updated after reading field_index
        .result_type = TypePool.ANY, // Determined at runtime from tuple type
    });

    // Parse the tuple expression FIRST
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Read field_index SECOND (1 byte, 1-based)
    const field_idx = reader.readByte() catch return error.UnexpectedEndOfInput;

    // Update node with field index (convert to 0-based)
    tree.nodes[node_idx].data = field_idx -| 1; // Saturating subtract for 0-based
}

/// Deserialize Select1-5 (fixed field index, no VLQ)
fn deserializeSelectN(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    field_idx: u16,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(field_idx < 5); // Select1-5 only (0-4)
    assert(depth < max_expr_depth); // Depth not exceeded
    assert(tree.node_count < tree.nodes.len); // Space available in tree

    // Select1-5 format: just the tuple expression (field index is implicit from opcode)

    // Add the select_field node first (pre-order)
    const node_idx = try tree.addNode(.{
        .tag = .select_field,
        .data = field_idx, // Already 0-based (Select1 = 0, Select2 = 1, etc.)
        .result_type = TypePool.ANY, // Determined at runtime from tuple type
    });

    // POSTCONDITION: Node was added
    assert(node_idx < tree.node_count);

    // Parse the tuple expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

/// Deserialize ExtractRegisterAs (opcode 0xC7 / 199)
/// Serialization format (per Rust): box_expr + register_id (i8) + elem_type
/// We add the node first (pre-order), then parse child, then read trailing metadata
fn deserializeExtractRegisterAs(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Add the extract_register_as node first (pre-order) with placeholder data
    const node_idx = try tree.addNode(.{
        .tag = .extract_register_as,
        .data = 0, // Placeholder, will be filled after parsing child
        .result_type = TypePool.ANY, // Returns Option[T], type known at runtime
    });

    // Parse the box expression (child node)
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Now read the trailing metadata: register_id and elem_type
    // Read register ID (i8 in Rust, but we treat as unsigned 0-9)
    const register_id_byte = reader.readByte() catch |e| return mapVlqError(e);
    const register_id: u4 = @truncate(register_id_byte);

    // INVARIANT: Register ID must be 0-9
    if (register_id > 9) return error.InvalidData;

    // Read the element type (inner type of Option[T])
    const type_idx = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Pack register_id (4 bits) and type_idx (12 bits) into data field
    // data = (type_idx << 4) | register_id
    const data: u16 = (@as(u16, type_idx) << 4) | @as(u16, register_id);

    // Update the node with actual data
    tree.nodes[node_idx].data = data;

    // POSTCONDITION: Node has valid data
    assert(tree.nodes[node_idx].tag == .extract_register_as);
}

/// Deserialize GetVar (opcode 0xE3 / 227)
/// Serialization format: var_id (u8) + var_tpe (type)
/// Returns Option[T] where T is the expected type
fn deserializeGetVar(
    tree: *ExprTree,
    reader: *vlq.Reader,
    depth: u8,
) DeserializeError!void {
    _ = depth; // GetVar is a leaf node, no recursion needed

    // Read var_id (1 byte)
    const var_id = reader.readByte() catch |e| return mapVlqError(e);

    // Read expected type
    const type_idx = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Pack var_id (8 bits) and type_idx (8 bits) into data field
    // data = (type_idx << 8) | var_id
    const data: u16 = (@as(u16, type_idx) << 8) | @as(u16, var_id);

    // Add the get_var node
    _ = try tree.addNode(.{
        .tag = .get_var,
        .data = data,
        .result_type = TypePool.ANY, // Returns Option[T], resolved at runtime
    });
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
    // Upcast format (from Rust): input expression + target type
    // Reference: sigma-rust/ergotree-ir/src/mir/upcast.rs

    // Add the upcast node first (pre-order) with placeholder type
    const node_idx = try tree.addNode(.{
        .tag = .upcast,
        .data = 0,
        .result_type = TypePool.ANY,
    });

    // Parse the input expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Now read the target type
    const target_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Update the node with the actual target type
    tree.nodes[node_idx].data = target_type;
    tree.nodes[node_idx].result_type = target_type;
}

fn deserializeDowncast(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Downcast format (from Rust): input expression + target type
    // Reference: sigma-rust/ergotree-ir/src/mir/downcast.rs

    // Add the downcast node first (pre-order) with placeholder type
    const node_idx = try tree.addNode(.{
        .tag = .downcast,
        .data = 0,
        .result_type = TypePool.ANY,
    });

    // Parse the input expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Now read the target type
    const target_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Update the node with the actual target type
    tree.nodes[node_idx].data = target_type;
    tree.nodes[node_idx].result_type = target_type;
}

fn deserializeConcreteCollection(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // ConcreteCollection format: numItems (u16 VLQ) + elementType + items
    // Format from Scala: w.putUShort(cc.items.size); w.putType(cc.tpe.elemType); items...

    // PRECONDITION: depth check already done in deserializeWithDepth
    assert(depth < max_expr_depth);

    // Read item count (unsigned short)
    const num_items = reader.readU16() catch |e| return mapVlqError(e);

    // INVARIANT: collection size is bounded
    if (num_items > max_constants) return error.ExpressionTooComplex;

    // Read element type
    const elem_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.NestingTooDeep,
            error.InvalidTupleLength => error.InvalidTupleLength,
            else => error.InvalidData,
        };
    };

    // Get or create the Coll[T] type
    const coll_type = tree.type_pool.getColl(elem_type) catch return error.PoolFull;

    // Add the concrete_collection node first (pre-order)
    // Store item count in data
    _ = try tree.addNode(.{
        .tag = .concrete_collection,
        .data = num_items,
        .result_type = coll_type,
    });

    // Parse each item expression
    var i: u16 = 0;
    while (i < num_items) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }

    // POSTCONDITION: all items parsed
    // (node count increased by 1 + sum of all child nodes)
}

fn deserializeCollectionHOF(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // Collection HOF format: [collection_expr] [lambda_func]
    // For Map, Exists, ForAll, Filter
    // PRECONDITION: tag is a valid collection HOF
    assert(tag == .map_collection or tag == .exists or tag == .for_all or tag == .filter);

    // Determine result type
    const result_type: TypeIndex = switch (tag) {
        .exists, .for_all => TypePool.BOOLEAN,
        .map_collection, .filter => TypePool.ANY, // Determined at runtime
        else => TypePool.ANY,
    };

    // Add the HOF node first (pre-order)
    _ = try tree.addNode(.{
        .tag = tag,
        .result_type = result_type,
    });

    // Parse collection expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse lambda function expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeFold(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // Fold format: [collection_expr] [zero_expr] [fold_op_func]
    // Fold: Coll[A] × B × ((B,A) → B) → B

    // Add the fold node first (pre-order)
    _ = try tree.addNode(.{
        .tag = .fold,
        .result_type = TypePool.ANY, // Type of zero/result
    });

    // Parse collection expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse zero (initial accumulator) expression
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // Parse fold operation (lambda: (acc, elem) -> acc)
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn deserializeFuncValue(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // FuncValue format: numArgs (VLQ) + args [(id, type)...] + body expr
    // Reference: Scala FuncValueSerializer.scala

    const num_args = reader.readU32() catch |e| return mapVlqError(e);
    if (num_args > 32) return error.InvalidData; // Reasonable limit

    // Read argument definitions and register types
    var i: u32 = 0;
    while (i < num_args) : (i += 1) {
        const var_id = reader.readU32() catch |e| return mapVlqError(e);
        const arg_type = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
            return switch (e) {
                error.InvalidTypeCode => error.InvalidTypeCode,
                error.PoolFull => error.PoolFull,
                error.NestingTooDeep => error.NestingTooDeep,
                error.InvalidTupleLength => error.InvalidTupleLength,
                else => error.InvalidData,
            };
        };
        // Register the argument type for ValUse lookups
        tree.setValDefType(@truncate(var_id), arg_type);
    }

    // Add the func_value node (stores num_args in data)
    _ = try tree.addNode(.{
        .tag = .func_value,
        .data = @truncate(num_args),
        .result_type = TypePool.ANY, // Function type determined by body
    });

    // Parse function body
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

fn mapVlqError(err: vlq.DecodeError) DeserializeError {
    return switch (err) {
        error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
        error.Overflow => error.Overflow,
    };
}

/// Deserialize SigmaAnd or SigmaOr connective
/// Format: item_count (VLQ) + item_count × SigmaProp children
/// Reference: Scala SigmaTransformerSerializer.scala
fn deserializeSigmaConnective(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    comptime tag: ExprTag,
    depth: u8,
) DeserializeError!void {
    // PRECONDITION: tag is sigma_and or sigma_or
    comptime assert(tag == .sigma_and or tag == .sigma_or);

    // Read item count
    const item_count = reader.readU32() catch |e| return mapVlqError(e);

    // INVARIANT: Reasonable limit on children
    if (item_count > max_children) return error.InvalidData;
    if (item_count < 2) return error.InvalidData; // AND/OR must have at least 2 children

    // Add the connective node
    // data stores the child count
    _ = try tree.addNode(.{
        .tag = tag,
        .data = @truncate(item_count),
        .result_type = TypePool.SIGMA_PROP,
    });

    // Deserialize each child SigmaProp expression
    var i: u32 = 0;
    while (i < item_count) : (i += 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }
}

/// Maximum children for AND/OR/THRESHOLD
const max_children: u32 = 255;

/// Deserialize SubstConstants (opcode 0x74 / 116)
/// Format: script_bytes_expr + positions_expr + new_values_expr
/// Reference: Scala SubstConstantsSerializer.scala
fn deserializeSubstConstants(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Add the subst_constants node first (pre-order)
    // Returns Coll[Byte] (the modified serialized ErgoTree)
    _ = try tree.addNode(.{
        .tag = .subst_constants,
        .result_type = TypePool.COLL_BYTE,
    });

    // Parse 3 child expressions in order:
    // 1. script_bytes: Coll[Byte] - the serialized ErgoTree
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // 2. positions: Coll[Int] - indices of constants to replace
    try deserializeWithDepth(tree, reader, arena, depth + 1);

    // 3. new_values: Coll[T] - new values to substitute
    try deserializeWithDepth(tree, reader, arena, depth + 1);
}

/// Deserialize DeserializeContext (opcode 0xD4 / 212)
/// Format: [type T] [id: byte]
/// Reference: Scala DeserializeContextSerializer.scala
fn deserializeDeserializeContext(
    tree: *ExprTree,
    reader: *vlq.Reader,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Read expected type T
    const type_idx = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.ExpressionTooComplex,
            error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
            error.Overflow => error.InvalidData,
            error.InvalidTupleLength, error.FuncDomainTooLong, error.FuncTpeParamsTooLong, error.TypeVarNameTooLong => error.InvalidData,
        };
    };

    // Read context variable id (single byte)
    const var_id = reader.readByte() catch return error.UnexpectedEndOfInput;

    // Store var_id in data, type_idx in result_type
    _ = try tree.addNode(.{
        .tag = .deserialize_context,
        .result_type = type_idx,
        .data = var_id,
    });
}

/// Deserialize DeserializeRegister (opcode 0xD5 / 213)
/// Format: [reg_id: byte] [type T] [default: Option<Expr>]
/// Reference: Scala DeserializeRegisterSerializer.scala
fn deserializeDeserializeRegister(
    tree: *ExprTree,
    reader: *vlq.Reader,
    arena: anytype,
    depth: u8,
) DeserializeError!void {
    // PRECONDITIONS
    assert(depth < max_expr_depth);
    assert(tree.node_count < tree.nodes.len);

    // Read register id (0-9 for R0-R9)
    const reg_id = reader.readByte() catch return error.UnexpectedEndOfInput;
    if (reg_id > 9) return error.InvalidData;

    // Read expected type T
    const type_idx = type_serializer.deserialize(&tree.type_pool, reader) catch |e| {
        return switch (e) {
            error.InvalidTypeCode => error.InvalidTypeCode,
            error.PoolFull => error.PoolFull,
            error.NestingTooDeep => error.ExpressionTooComplex,
            error.UnexpectedEndOfInput => error.UnexpectedEndOfInput,
            error.Overflow => error.InvalidData,
            error.InvalidTupleLength, error.FuncDomainTooLong, error.FuncTpeParamsTooLong, error.TypeVarNameTooLong => error.InvalidData,
        };
    };

    // Read Option<Expr> for default value
    // Option encoding: 0x00 = None, 0x01 = Some followed by expression
    const has_default = reader.readByte() catch return error.UnexpectedEndOfInput;
    if (has_default != 0 and has_default != 1) return error.InvalidData;

    // Pack: reg_id(8 high) | has_default(8 low), type_idx in result_type
    const data: u16 = (@as(u16, reg_id) << 8) | @as(u16, has_default);

    _ = try tree.addNode(.{
        .tag = .deserialize_register,
        .result_type = type_idx,
        .data = data,
    });

    // If has default, deserialize the default expression
    if (has_default == 1) {
        try deserializeWithDepth(tree, reader, arena, depth + 1);
    }
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

    // EQ(GT(HEIGHT, 100), TRUE):
    // 0x93 (EQ = 147 = 112 + 35)
    //   0x91 (GT = 145 = 112 + 33)
    //     0xA3 (HEIGHT = 163 = 112 + 51)
    //     0x04 0xC8 0x01 (Int 100)
    //   0x7F (TRUE = 127 = 112 + 15)
    var reader = vlq.Reader.init(&[_]u8{ 0x93, 0x91, 0xA3, 0x04, 0xC8, 0x01, 0x7F });
    try deserialize(&tree, &reader, &arena);

    // Should have 5 nodes: EQ, GT, HEIGHT, constant, TRUE
    try std.testing.expectEqual(@as(u16, 5), tree.node_count);

    // Root is EQ
    try std.testing.expectEqual(ExprTag.bin_op, tree.nodes[0].tag);
    try std.testing.expectEqual(BinOpKind.eq, tree.nodes[0].binOpKind().?);

    // Second node is GT
    try std.testing.expectEqual(ExprTag.bin_op, tree.nodes[1].tag);
    try std.testing.expectEqual(BinOpKind.gt, tree.nodes[1].binOpKind().?);
}

test "expr_serializer: deserialize ConstantPlaceholder" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // ConstantPlaceholder with index 0: 0x73 (115 = 112 + 3) 0x00
    var reader = vlq.Reader.init(&[_]u8{ 0x73, 0x00 });
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

test "expr_serializer: deserialize ConcreteCollection empty" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // ConcreteCollection[Int]():
    // 0x83 (ConcreteCollection = 131 = 112 + 19)
    // 0x00 (numItems = 0)
    // 0x04 (element type = Int)
    var reader = vlq.Reader.init(&[_]u8{ 0x83, 0x00, 0x04 });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.concrete_collection, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 0), tree.nodes[0].data); // 0 elements
}

test "expr_serializer: deserialize ConcreteCollection with Int elements" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // ConcreteCollection[Int](1, 2, 3):
    // 0x83 (ConcreteCollection = 131 = 112 + 19)
    // 0x03 (numItems = 3)
    // 0x04 (element type = Int)
    // 0x04 0x02 (Int 1)
    // 0x04 0x04 (Int 2)
    // 0x04 0x06 (Int 3)
    var reader = vlq.Reader.init(&[_]u8{
        0x83, 0x03, 0x04, // ConcreteCollection(3, Int)
        0x04, 0x02, // Int(1)
        0x04, 0x04, // Int(2)
        0x04, 0x06, // Int(3)
    });
    try deserialize(&tree, &reader, &arena);

    // Should have 4 nodes: ConcreteCollection + 3 Int constants
    try std.testing.expectEqual(@as(u16, 4), tree.node_count);
    try std.testing.expectEqual(ExprTag.concrete_collection, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 3), tree.nodes[0].data); // 3 elements

    // Check individual elements
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[1].tag);
    try std.testing.expectEqual(@as(i32, 1), tree.values[0].int);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[2].tag);
    try std.testing.expectEqual(@as(i32, 2), tree.values[1].int);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[3].tag);
    try std.testing.expectEqual(@as(i32, 3), tree.values[2].int);
}

test "expr_serializer: deserialize nested ConcreteCollection" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // ConcreteCollection[Coll[Byte]](single element Coll[Byte]):
    // 0x83 (ConcreteCollection = 131 = 112 + 19)
    // 0x01 (numItems = 1)
    // 0x0E (element type = Coll[Byte] = 12 + 2)
    // Nested: 0x0E 0x02 0xAB 0xCD (Coll[Byte] with 2 bytes)
    var reader = vlq.Reader.init(&[_]u8{
        0x83, 0x01, 0x0E, // ConcreteCollection(1, Coll[Byte])
        0x0E, 0x02, 0xAB, 0xCD, // Coll[Byte] constant: 2 bytes, 0xAB 0xCD
    });
    try deserialize(&tree, &reader, &arena);

    // Should have 2 nodes: ConcreteCollection + 1 Coll[Byte] constant
    try std.testing.expectEqual(@as(u16, 2), tree.node_count);
    try std.testing.expectEqual(ExprTag.concrete_collection, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 1), tree.nodes[0].data); // 1 element

    // Check nested collection constant
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[1].tag);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAB, 0xCD }, tree.values[0].coll_byte);
}

test "expr_serializer: deserialize SigmaAnd with TrueLeaf children" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // SigmaAnd opcode = 234 (shift 122)
    // Format: opcode + child_count (VLQ) + children
    // Children: 2x TrueLeaf (0x7F)
    var reader = vlq.Reader.init(&[_]u8{
        234, // SigmaAnd opcode
        0x02, // 2 children (VLQ)
        0x7F, // TrueLeaf
        0x7F, // TrueLeaf
    });
    try deserialize(&tree, &reader, &arena);

    // Should have 3 nodes: SigmaAnd + 2 TrueLeaf
    try std.testing.expectEqual(@as(u16, 3), tree.node_count);
    try std.testing.expectEqual(ExprTag.sigma_and, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 2), tree.nodes[0].data); // 2 children
    try std.testing.expectEqual(ExprTag.true_leaf, tree.nodes[1].tag);
    try std.testing.expectEqual(ExprTag.true_leaf, tree.nodes[2].tag);
}

test "expr_serializer: deserialize SigmaOr with boolean children" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // SigmaOr opcode = 235 (shift 123)
    // Format: opcode + child_count (VLQ) + children
    // Children: TrueLeaf + FalseLeaf
    var reader = vlq.Reader.init(&[_]u8{
        235, // SigmaOr opcode
        0x02, // 2 children (VLQ)
        0x7F, // TrueLeaf
        0x80, // FalseLeaf
    });
    try deserialize(&tree, &reader, &arena);

    // Should have 3 nodes: SigmaOr + TrueLeaf + FalseLeaf
    try std.testing.expectEqual(@as(u16, 3), tree.node_count);
    try std.testing.expectEqual(ExprTag.sigma_or, tree.nodes[0].tag);
    try std.testing.expectEqual(@as(u16, 2), tree.nodes[0].data); // 2 children
    try std.testing.expectEqual(ExprTag.true_leaf, tree.nodes[1].tag);
    try std.testing.expectEqual(ExprTag.false_leaf, tree.nodes[2].tag);
}

test "expr_serializer: deserialize SubstConstants with 3 children" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(512).init();

    // SubstConstants opcode = 116 (0x74)
    // Format: opcode + 3 child expressions
    // Child 1: Coll[Byte] constant (script bytes placeholder)
    // Child 2: Coll[Int] constant (positions)
    // Child 3: Coll[Int] constant (new values)
    //
    // For this test, use simple inline constants:
    // - Coll[Byte] with 2 bytes: 0x0E (Coll[Byte] type), 0x02, 0xAB, 0xCD
    // - Two Int constants for positions and values
    var reader = vlq.Reader.init(&[_]u8{
        0x74, // SubstConstants opcode (116)
        // Child 1: Coll[Byte] constant
        0x0E, // Type code for Coll[Byte]
        0x02, // Length 2
        0xAB,
        0xCD, // Bytes
        // Child 2: Int constant (position 0)
        0x04, // Int type
        0x00, // Value 0 (ZigZag encoded)
        // Child 3: Int constant (value 100)
        0x04, // Int type
        0xC8,
        0x01, // Value 100 (ZigZag encoded)
    });
    try deserialize(&tree, &reader, &arena);

    // Should have 4 nodes: SubstConstants + 3 constants
    try std.testing.expectEqual(@as(u16, 4), tree.node_count);
    try std.testing.expectEqual(ExprTag.subst_constants, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.COLL_BYTE, tree.nodes[0].result_type);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[1].tag);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[2].tag);
    try std.testing.expectEqual(ExprTag.constant, tree.nodes[3].tag);
}

test "expr_serializer: deserialize DeserializeContext" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // DeserializeContext opcode = 212 (0xD4)
    // Format: [opcode] [type T] [id: byte]
    var reader = vlq.Reader.init(&[_]u8{
        212, // DeserializeContext opcode
        0x01, // Type = Boolean (type code 1)
        0x05, // Context variable id = 5
    });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.deserialize_context, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.BOOLEAN, tree.nodes[0].result_type);
    // var_id stored in data, type in result_type
    try std.testing.expectEqual(@as(u16, 5), tree.nodes[0].data);
}

test "expr_serializer: deserialize DeserializeRegister without default" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // DeserializeRegister opcode = 213 (0xD5)
    // Format: [opcode] [reg_id] [type T] [has_default=0]
    var reader = vlq.Reader.init(&[_]u8{
        213, // DeserializeRegister opcode
        0x04, // Register id = R4
        0x04, // Type = Int (type code 4)
        0x00, // No default value
    });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 1), tree.node_count);
    try std.testing.expectEqual(ExprTag.deserialize_register, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.INT, tree.nodes[0].result_type);
    // Data format: reg_id(8 high) | has_default(8 low)
    const data = tree.nodes[0].data;
    const reg_id: u8 = @truncate(data >> 8);
    const has_default: u8 = @truncate(data);
    try std.testing.expectEqual(@as(u8, 4), reg_id);
    try std.testing.expectEqual(@as(u8, 0), has_default);
}

test "expr_serializer: deserialize DeserializeRegister with default" {
    var tree = ExprTree.init();
    var arena = BumpAllocator(256).init();

    // DeserializeRegister opcode = 213 (0xD5)
    // Format: [opcode] [reg_id] [type T] [has_default=1] [default_expr]
    var reader = vlq.Reader.init(&[_]u8{
        213, // DeserializeRegister opcode
        0x05, // Register id = R5
        0x01, // Type = Boolean
        0x01, // Has default value
        0x7F, // Default expression: TrueLeaf
    });
    try deserialize(&tree, &reader, &arena);

    try std.testing.expectEqual(@as(u16, 2), tree.node_count);
    try std.testing.expectEqual(ExprTag.deserialize_register, tree.nodes[0].tag);
    try std.testing.expectEqual(TypePool.BOOLEAN, tree.nodes[0].result_type);
    try std.testing.expectEqual(ExprTag.true_leaf, tree.nodes[1].tag);
    // Data format: reg_id(8 high) | has_default(8 low)
    const data = tree.nodes[0].data;
    const reg_id: u8 = @truncate(data >> 8);
    const has_default: u8 = @truncate(data);
    try std.testing.expectEqual(@as(u8, 5), reg_id);
    try std.testing.expectEqual(@as(u8, 1), has_default);
}
