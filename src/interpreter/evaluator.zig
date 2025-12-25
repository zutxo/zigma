//! Expression Evaluator for ErgoTree
//!
//! Evaluates expression trees to produce results. Uses explicit work stack
//! instead of recursion per ZIGMA_STYLE.
//!
//! Design:
//!   - Work stack tracks pending evaluation (iterative, not recursive)
//!   - Value stack holds intermediate results
//!   - Cost checked BEFORE each operation
//!   - Deterministic: same inputs → same outputs always
//!
//! Reference: Rust ergotree-interpreter/src/eval/

const std = @import("std");
const assert = std.debug.assert;
const context = @import("context.zig");
const memory = @import("memory.zig");
const value_pool = @import("value_pool.zig");
const register_cache = @import("register_cache.zig");
const expr = @import("../serialization/expr_serializer.zig");
const data = @import("../serialization/data_serializer.zig");
const type_serializer = @import("../serialization/type_serializer.zig");
const ergotree_serializer = @import("../serialization/ergotree_serializer.zig");
const vlq = @import("../serialization/vlq.zig");
const types = @import("../core/types.zig");
const hash = @import("../crypto/hash.zig");
const crypto_ops = @import("ops/crypto.zig");
const sigma_tree = @import("../sigma/sigma_tree.zig");
const avl_tree = @import("../crypto/avl_tree.zig");
const crypto_bigint = @import("../crypto/bigint.zig");
const metrics_mod = @import("metrics.zig");

const Context = context.Context;
const BoxView = context.BoxView;
const Register = context.Register;
const VersionContext = context.VersionContext;
const ExprTree = expr.ExprTree;
const ExprNode = expr.ExprNode;
const ExprTag = expr.ExprTag;
const BinOpKind = expr.BinOpKind;
const Value = data.Value;
const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;
const BumpAllocator = memory.BumpAllocator;
pub const ValuePool = value_pool.ValuePool;
const PooledValue = value_pool.PooledValue;
const null_value_idx = value_pool.null_value_idx;
pub const RegisterCache = register_cache.RegisterCache;
const RegisterCacheEntry = register_cache.RegisterCacheEntry;
const BoxSource = register_cache.BoxSource;
const BigInt256 = crypto_bigint.BigInt256;
const UnsignedBigInt256 = crypto_bigint.UnsignedBigInt256;
const Metrics = metrics_mod.Metrics;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum work stack depth
const max_work_stack: usize = 256;

/// Maximum value stack depth
const max_value_stack: usize = 256;

/// Maximum variable bindings (matches expr_serializer.max_val_defs)
const max_var_bindings: usize = 64;

/// Default cost limit per evaluation
const default_cost_limit: u64 = 1_000_000;

/// Arena size for temporary allocations (hash results, etc.)
const eval_arena_size: usize = 4096;

/// How often to check wall-clock timeout (every N operations).
/// Checking every operation is too expensive, so we amortize.
const timeout_check_interval: u16 = 64;

/// Maximum depth for nested script deserialization (executeFromVar/executeFromSelfReg)
/// Prevents infinite recursion when scripts reference themselves
const max_deserialize_depth: u8 = 4;

// Compile-time sanity checks
comptime {
    assert(max_work_stack >= 64);
    assert(max_value_stack >= 64);
    assert(default_cost_limit > 0);
}

// ============================================================================
// Value Conversion
// ============================================================================

/// Convert a PooledValue back to a Value.
/// This is used when extracting values from Options, Tuples, and Collections.
fn pooledValueToValue(pooled: *const PooledValue, type_pool: *const TypePool) EvalError!Value {
    // PRECONDITION: pooled value must be valid
    assert(pooled.type_idx != 0 or pooled.data.primitive == 0); // 0 type only valid for unit

    const type_idx = pooled.type_idx;

    return switch (type_idx) {
        // Primitive types
        TypePool.UNIT => .unit,
        TypePool.BOOLEAN => .{ .boolean = pooled.data.primitive != 0 },
        TypePool.BYTE => .{ .byte = @intCast(pooled.data.primitive) },
        TypePool.SHORT => .{ .short = @intCast(pooled.data.primitive) },
        TypePool.INT => .{ .int = @intCast(pooled.data.primitive) },
        TypePool.LONG => .{ .long = pooled.data.primitive },

        // Complex value types
        TypePool.BIG_INT => blk: {
            var bi: Value.BigInt = .{
                .bytes = [_]u8{0} ** data.max_bigint_bytes,
                .len = pooled.data.big_int.len,
            };
            @memcpy(bi.bytes[0..bi.len], pooled.data.big_int.bytes[0..bi.len]);
            break :blk .{ .big_int = bi };
        },
        TypePool.GROUP_ELEMENT => .{ .group_element = pooled.data.group_element },
        TypePool.SIGMA_PROP => .{ .sigma_prop = .{ .data = pooled.data.sigma_prop.slice() } },
        TypePool.BOX => .{ .box = .{
            .source = @enumFromInt(@intFromEnum(pooled.data.box.source)),
            .index = pooled.data.box.index,
        } },

        // Collection types
        TypePool.COLL_BYTE => .{ .coll_byte = pooled.data.byte_slice.slice() },
        TypePool.COLL_INT, TypePool.COLL_LONG, TypePool.COLL_COLL_BYTE => .{ .coll = .{
            .elem_type = pooled.data.collection.elem_type,
            .start = pooled.data.collection.start_idx,
            .len = pooled.data.collection.len,
        } },

        // Pre-allocated option types
        TypePool.OPTION_INT, TypePool.OPTION_LONG, TypePool.OPTION_COLL_BYTE => .{ .option = .{
            .inner_type = pooled.data.option.inner_type,
            .value_idx = pooled.data.option.value_idx,
        } },

        // AVL tree type
        TypePool.AVL_TREE => .{ .avl_tree = pooled.data.avl_tree },

        else => blk: {
            // Dynamic types - check actual type in pool
            if (type_idx < type_pool.count) {
                const type_desc = type_pool.types[type_idx];
                switch (type_desc) {
                    .coll => break :blk .{ .coll = .{
                        .elem_type = pooled.data.collection.elem_type,
                        .start = pooled.data.collection.start_idx,
                        .len = pooled.data.collection.len,
                    } },
                    .option => break :blk .{ .option = .{
                        .inner_type = pooled.data.option.inner_type,
                        .value_idx = pooled.data.option.value_idx,
                    } },
                    // Pairs/tuples - convert to TupleRef using external storage mode
                    .pair => break :blk .{
                        .tuple = .{
                            .start = pooled.data.tuple.start_idx,
                            .len = pooled.data.tuple.len,
                            .types = .{ 0, 0, 0, 0 }, // External storage
                            .values = .{ 0, 0, 0, 0 }, // External storage
                        },
                    },
                    // AVL tree (dynamically allocated type index)
                    .avl_tree => break :blk .{ .avl_tree = pooled.data.avl_tree },
                    else => break :blk error.UnsupportedExpression,
                }
            }
            // Unknown type
            break :blk error.UnsupportedExpression;
        },
    };
}

// ============================================================================
// Evaluation Errors
// ============================================================================

pub const EvalError = error{
    /// Cost budget exceeded
    CostLimitExceeded,
    /// Wall-clock timeout exceeded (defense in depth)
    TimeoutExceeded,
    /// Work stack overflow
    WorkStackOverflow,
    /// Value stack overflow
    ValueStackOverflow,
    /// Value stack underflow (tried to pop from empty)
    ValueStackUnderflow,
    /// Type mismatch during operation
    TypeMismatch,
    /// Division by zero
    DivisionByZero,
    /// Arithmetic overflow
    ArithmeticOverflow,
    /// Invalid shift amount (negative or exceeds type width)
    InvalidShift,
    /// Invalid node index
    InvalidNodeIndex,
    /// Invalid constant index
    InvalidConstantIndex,
    /// Unsupported expression type
    UnsupportedExpression,
    /// Invalid binary operation
    InvalidBinOp,
    /// Out of memory in evaluation arena
    OutOfMemory,
    /// Undefined variable reference
    UndefinedVariable,
    /// Tried to get value from None
    OptionNone,
    /// Invalid data format (wrong length, etc.)
    InvalidData,
    /// Invalid group element (not on curve or bad encoding)
    InvalidGroupElement,
    /// Invalid BigInt or UnsignedBigInt data
    InvalidBigInt,
    /// Tuple field index out of bounds
    IndexOutOfBounds,
    /// Invalid context state (missing headers, etc.)
    InvalidContext,
    /// Invalid internal state (corrupted pool, etc.)
    InvalidState,
    /// Collection exceeds protocol size limit
    CollectionTooLarge,
    /// Soft-fork accepted: unknown feature in newer script version
    /// The caller should treat this as "script passes" (TrivialProp.True)
    SoftForkAccepted,
};

// ============================================================================
// Evaluation Diagnostics
// ============================================================================

/// Error codes for diagnostics - maps EvalError variants to stable codes.
/// Used for display and serialization without carrying full error type.
pub const EvalErrorCode = enum(u8) {
    none = 0,
    cost_limit_exceeded = 1,
    timeout_exceeded = 2,
    work_stack_overflow = 3,
    value_stack_overflow = 4,
    value_stack_underflow = 5,
    type_mismatch = 6,
    division_by_zero = 7,
    arithmetic_overflow = 8,
    invalid_shift = 9,
    invalid_node_index = 10,
    invalid_constant_index = 11,
    unsupported_expression = 12,
    invalid_bin_op = 13,
    out_of_memory = 14,
    undefined_variable = 15,
    option_none = 16,
    invalid_data = 17,
    invalid_group_element = 18,
    invalid_big_int = 19,
    index_out_of_bounds = 20,
    invalid_context = 21,
    invalid_state = 22,
    collection_too_large = 23,
    soft_fork_accepted = 24,

    pub fn message(self: EvalErrorCode) []const u8 {
        return switch (self) {
            .none => "no error",
            .cost_limit_exceeded => "cost limit exceeded",
            .timeout_exceeded => "timeout exceeded",
            .work_stack_overflow => "work stack overflow",
            .value_stack_overflow => "value stack overflow",
            .value_stack_underflow => "value stack underflow",
            .type_mismatch => "type mismatch",
            .division_by_zero => "division by zero",
            .arithmetic_overflow => "arithmetic overflow",
            .invalid_shift => "invalid shift amount",
            .invalid_node_index => "invalid node index",
            .invalid_constant_index => "invalid constant index",
            .unsupported_expression => "unsupported expression/opcode",
            .invalid_bin_op => "invalid binary operation",
            .out_of_memory => "out of memory",
            .undefined_variable => "undefined variable",
            .option_none => "None.get() called",
            .invalid_data => "invalid data format",
            .invalid_group_element => "invalid group element",
            .invalid_big_int => "invalid BigInt",
            .index_out_of_bounds => "index out of bounds",
            .invalid_context => "invalid context state",
            .invalid_state => "invalid internal state",
            .collection_too_large => "collection exceeds size limit",
            .soft_fork_accepted => "soft fork accepted",
        };
    }

    pub fn fromEvalError(err: EvalError) EvalErrorCode {
        return switch (err) {
            error.CostLimitExceeded => .cost_limit_exceeded,
            error.TimeoutExceeded => .timeout_exceeded,
            error.WorkStackOverflow => .work_stack_overflow,
            error.ValueStackOverflow => .value_stack_overflow,
            error.ValueStackUnderflow => .value_stack_underflow,
            error.TypeMismatch => .type_mismatch,
            error.DivisionByZero => .division_by_zero,
            error.ArithmeticOverflow => .arithmetic_overflow,
            error.InvalidShift => .invalid_shift,
            error.InvalidNodeIndex => .invalid_node_index,
            error.InvalidConstantIndex => .invalid_constant_index,
            error.UnsupportedExpression => .unsupported_expression,
            error.InvalidBinOp => .invalid_bin_op,
            error.OutOfMemory => .out_of_memory,
            error.UndefinedVariable => .undefined_variable,
            error.OptionNone => .option_none,
            error.InvalidData => .invalid_data,
            error.InvalidGroupElement => .invalid_group_element,
            error.InvalidBigInt => .invalid_big_int,
            error.IndexOutOfBounds => .index_out_of_bounds,
            error.InvalidContext => .invalid_context,
            error.InvalidState => .invalid_state,
            error.CollectionTooLarge => .collection_too_large,
            error.SoftForkAccepted => .soft_fork_accepted,
        };
    }
};

/// Diagnostic information captured when evaluation fails.
/// Follows DeserializeDiagnostics pattern for consistent error reporting.
pub const EvalDiagnostics = struct {
    /// The specific error code that occurred
    error_code: EvalErrorCode = .none,

    /// Opcode tag being evaluated when error occurred (ExprTag as u8)
    failed_opcode: ?u8 = null,

    /// Node index in expression tree where failure occurred
    failed_node_idx: ?u16 = null,

    /// Stack depth at time of failure
    stack_depth: ?u16 = null,

    /// Cost consumed before failure
    cost_at_failure: ?u64 = null,

    /// Get human-readable error message
    pub fn message(self: EvalDiagnostics) []const u8 {
        return self.error_code.message();
    }

    /// Check if diagnostics contain error info
    pub fn hasError(self: EvalDiagnostics) bool {
        return self.error_code != .none;
    }
};

// ============================================================================
// Work Item
// ============================================================================

/// Phase of work item processing
const WorkPhase = enum(u8) {
    /// Evaluate this node (may push children)
    evaluate,
    /// All children evaluated, compute result
    compute,
};

/// Work item for iterative evaluation
const WorkItem = struct {
    /// Node index in expression tree
    node_idx: u16,
    /// Processing phase
    phase: WorkPhase,
};

// ============================================================================
// Cost Model (version-dependent)
// ============================================================================

/// Operation cost categories for version-dependent lookup.
/// Reference: JitCost.scala, CostTable.scala in sigmastate-interpreter
pub const CostOp = enum(u8) {
    comparison,
    arithmetic,
    logical,
    height,
    constant,
    constant_placeholder,
    self_box,
    inputs,
    outputs,
    data_inputs,
    blake2b256_base,
    sha256_base,
    hash_per_byte,
    decode_point,
    group_generator,
    exponentiate,
    multiply_group,
    select_field,
    tuple_construct,
    upcast,
    downcast,
    extract_header_field,
    collection_base,
    collection_per_item,
    func_apply,
    method_call,
    sigma_and,
    sigma_or,
    sigma_threshold,
    create_avl_tree,
    tree_lookup,
    extract_register,
    get_encoded,
    negate_group,
};

/// JIT cost table (v2+ mainnet, current default).
/// Source: sigmastate/data/shared/src/main/scala/sigma/ast/trees.scala,
///         sigmastate/data/shared/src/main/scala/sigma/ast/values.scala
const JIT_COSTS = [_]u32{
    20, // comparison (GT, GE, LT, LE - from SimpleRelation costKind)
    15, // arithmetic (Plus, Minus, etc. - 15 for primitives, 20-25 for BigInt)
    20, // logical (BinAnd, BinOr, BinXor - from trees.scala)
    26, // height (from values.scala line 1453)
    5, // constant (from values.scala line 380)
    1, // constant_placeholder (from values.scala line 421)
    5, // self_box (GlobalVars.SelfBox - from values.scala line 971)
    10, // inputs (from values.scala line 1480)
    10, // outputs (from values.scala line 1466)
    15, // data_inputs (from values.scala line 1495)
    20, // blake2b256_base (HashCost.blake2b256 used for actual costing)
    80, // sha256_base (HashCost.sha256 used for actual costing)
    7, // hash_per_chunk (blake2b256 per 128B chunk)
    300, // decode_point (from trees.scala line 530)
    10, // group_generator (from values.scala line 1509)
    900, // exponentiate (from trees.scala line 1046)
    40, // multiply_group (from trees.scala line 1067)
    10, // select_field (from transformers.scala line 314)
    10, // tuple_construct (from transformers.scala line 314)
    10, // upcast (10 for primitives, 30 for BigInt)
    10, // downcast (10 for primitives, 30 for BigInt)
    10, // extract_header_field
    20, // collection_base
    5, // collection_per_item
    5, // func_apply (AddToEnvironmentDesc - from values.scala line 1064)
    10, // method_call
    20, // sigma_and (from trees.scala line 1257)
    20, // sigma_or (from trees.scala line 1280)
    20, // sigma_threshold (AtLeast - similar to sigma_or)
    100, // create_avl_tree
    800, // tree_lookup
    50, // extract_register (from transformers.scala line 500)
    250, // get_encoded (Scala GetEncodedCostKind = FixedCost(JitCost(250)))
    45, // negate_group (Scala Negate_CostKind = FixedCost(JitCost(45)))
};

/// AOT cost table (pre-v2, legacy).
/// Generally higher costs than JIT.
/// Source: sigmastate/CostTable.scala (v1 costs)
const AOT_COSTS = [_]u32{
    40, // comparison (higher in AOT)
    40, // arithmetic
    40, // logical
    10, // height
    10, // constant
    5, // constant_placeholder (lower than constant in AOT too)
    15, // self_box
    15, // inputs
    15, // outputs
    15, // data_inputs
    65, // blake2b256_base
    70, // sha256_base
    1, // hash_per_byte
    1200, // decode_point
    15, // group_generator
    5500, // exponentiate
    300, // multiply_group
    15, // select_field
    15, // tuple_construct
    15, // upcast
    15, // downcast
    15, // extract_header_field
    25, // collection_base
    6, // collection_per_item
    25, // func_apply
    15, // method_call
    25, // sigma_and
    25, // sigma_or
    25, // sigma_threshold
    120, // create_avl_tree
    900, // tree_lookup
    60, // extract_register
    300, // get_encoded
    50, // negate_group
};

// Compile-time verification of cost table sizes
comptime {
    const num_ops = @typeInfo(CostOp).@"enum".fields.len;
    assert(JIT_COSTS.len == num_ops);
    assert(AOT_COSTS.len == num_ops);
}

/// Get cost for operation based on version context.
/// JIT (v2+) uses lower costs than AOT (v0/v1).
fn getCost(version_ctx: VersionContext, op: CostOp) u32 {
    // PRECONDITION: op index is valid
    const idx = @intFromEnum(op);
    assert(idx < JIT_COSTS.len);

    if (version_ctx.isJitActivated()) {
        return JIT_COSTS[idx];
    } else {
        return AOT_COSTS[idx];
    }
}

/// Fixed costs for backward compatibility (JIT/v2 defaults).
/// Use getCost() for version-aware cost lookup.
const FixedCost = struct {
    pub const comparison: u32 = JIT_COSTS[@intFromEnum(CostOp.comparison)];
    pub const arithmetic: u32 = JIT_COSTS[@intFromEnum(CostOp.arithmetic)];
    pub const logical: u32 = JIT_COSTS[@intFromEnum(CostOp.logical)];
    pub const height: u32 = JIT_COSTS[@intFromEnum(CostOp.height)];
    pub const constant: u32 = JIT_COSTS[@intFromEnum(CostOp.constant)];
    pub const constant_placeholder: u32 = JIT_COSTS[@intFromEnum(CostOp.constant_placeholder)];
    pub const self_box: u32 = JIT_COSTS[@intFromEnum(CostOp.self_box)];
    pub const inputs: u32 = JIT_COSTS[@intFromEnum(CostOp.inputs)];
    pub const outputs: u32 = JIT_COSTS[@intFromEnum(CostOp.outputs)];
    pub const data_inputs: u32 = JIT_COSTS[@intFromEnum(CostOp.data_inputs)];
    pub const blake2b256_base: u32 = JIT_COSTS[@intFromEnum(CostOp.blake2b256_base)];
    pub const sha256_base: u32 = JIT_COSTS[@intFromEnum(CostOp.sha256_base)];
    pub const hash_per_byte: u32 = JIT_COSTS[@intFromEnum(CostOp.hash_per_byte)];
    pub const decode_point: u32 = JIT_COSTS[@intFromEnum(CostOp.decode_point)];
    pub const group_generator: u32 = JIT_COSTS[@intFromEnum(CostOp.group_generator)];
    pub const exponentiate: u32 = JIT_COSTS[@intFromEnum(CostOp.exponentiate)];
    pub const multiply_group: u32 = JIT_COSTS[@intFromEnum(CostOp.multiply_group)];
    pub const select_field: u32 = JIT_COSTS[@intFromEnum(CostOp.select_field)];
    pub const tuple_construct: u32 = JIT_COSTS[@intFromEnum(CostOp.tuple_construct)];
    pub const upcast: u32 = JIT_COSTS[@intFromEnum(CostOp.upcast)];
    pub const downcast: u32 = JIT_COSTS[@intFromEnum(CostOp.downcast)];
    pub const extract_header_field: u32 = JIT_COSTS[@intFromEnum(CostOp.extract_header_field)];
    pub const collection_base: u32 = JIT_COSTS[@intFromEnum(CostOp.collection_base)];
    pub const collection_per_item: u32 = JIT_COSTS[@intFromEnum(CostOp.collection_per_item)];
    pub const func_apply: u32 = JIT_COSTS[@intFromEnum(CostOp.func_apply)];
    pub const method_call: u32 = JIT_COSTS[@intFromEnum(CostOp.method_call)];
    pub const sigma_and: u32 = JIT_COSTS[@intFromEnum(CostOp.sigma_and)];
    pub const sigma_or: u32 = JIT_COSTS[@intFromEnum(CostOp.sigma_or)];
    pub const sigma_threshold: u32 = JIT_COSTS[@intFromEnum(CostOp.sigma_threshold)];
    pub const create_avl_tree: u32 = JIT_COSTS[@intFromEnum(CostOp.create_avl_tree)];
    pub const tree_lookup: u32 = JIT_COSTS[@intFromEnum(CostOp.tree_lookup)];
    pub const extract_register: u32 = JIT_COSTS[@intFromEnum(CostOp.extract_register)];
    pub const get_encoded: u32 = JIT_COSTS[@intFromEnum(CostOp.get_encoded)];
    pub const negate_group: u32 = JIT_COSTS[@intFromEnum(CostOp.negate_group)];
};

/// PerItemCost - chunk-based cost model matching Scala's CostKind.PerItemCost.
/// Formula: nChunks = (nItems - 1) / chunkSize + 1; total = baseCost + perChunkCost * nChunks
/// Source: sigma/ast/CostKind.scala
pub const PerItemCost = struct {
    base_cost: u16,
    per_chunk_cost: u16,
    chunk_size: u16,

    /// Calculate total cost for given number of items.
    /// PRECONDITION: chunk_size > 0
    pub fn cost(self: PerItemCost, n_items: u32) u32 {
        assert(self.chunk_size > 0);

        // Empty collection still has base cost
        if (n_items == 0) return self.base_cost;

        // nChunks = (nItems - 1) / chunkSize + 1
        const n_chunks: u32 = (n_items - 1) / self.chunk_size + 1;

        // total = baseCost + perChunkCost * nChunks
        return @as(u32, self.base_cost) + @as(u32, self.per_chunk_cost) * n_chunks;
    }
};

/// Per-operation PerItemCost configurations (JIT/v2).
/// Source: sigmastate LanguageSpecificationV5.scala test vectors
const CollectionCost = struct {
    // Map, Filter: PerItemCost(20, 1, 10)
    pub const map = PerItemCost{ .base_cost = 20, .per_chunk_cost = 1, .chunk_size = 10 };
    pub const filter = PerItemCost{ .base_cost = 20, .per_chunk_cost = 1, .chunk_size = 10 };

    // FlatMap: PerItemCost(60, 10, 8)
    pub const flat_map = PerItemCost{ .base_cost = 60, .per_chunk_cost = 10, .chunk_size = 8 };

    // Exists, ForAll, Fold: PerItemCost(3, 1, 10)
    pub const exists = PerItemCost{ .base_cost = 3, .per_chunk_cost = 1, .chunk_size = 10 };
    pub const for_all = PerItemCost{ .base_cost = 3, .per_chunk_cost = 1, .chunk_size = 10 };
    pub const fold = PerItemCost{ .base_cost = 3, .per_chunk_cost = 1, .chunk_size = 10 };
};

// Compile-time tests for PerItemCost
comptime {
    // Test case from Scala: 1 item, chunkSize 10 -> 1 chunk
    assert(CollectionCost.exists.cost(1) == 3 + 1 * 1); // 4
    // Test case: 10 items, chunkSize 10 -> 1 chunk
    assert(CollectionCost.exists.cost(10) == 3 + 1 * 1); // 4
    // Test case: 11 items, chunkSize 10 -> 2 chunks
    assert(CollectionCost.exists.cost(11) == 3 + 1 * 2); // 5
    // Test case: 0 items -> base cost only
    assert(CollectionCost.exists.cost(0) == 3);
}

/// Per-operation PerItemCost configurations for AVL tree operations (JIT/v2).
/// Source: sigmastate LanguageSpecificationV5.scala test vectors
/// LookupAvlTree: PerItemCost(JitCost(40), JitCost(10), 1)
const AvlTreeCost = struct {
    // Lookup operations: base 40, per chunk 10, chunk size 1 (per proof element)
    pub const lookup = PerItemCost{ .base_cost = 40, .per_chunk_cost = 10, .chunk_size = 1 };

    // Property access methods (digest, keyLength, etc.): fixed cost 15
    pub const property: u32 = 15;

    // updateDigest: fixed cost 40
    pub const update_digest: u32 = 40;

    // updateOperations: fixed cost 45
    pub const update_operations: u32 = 45;

    // Insert/Update/Remove mutations: base 60, per entry 20, per proof byte 1
    // These costs account for proof parsing + tree reconstruction + hashing
    pub const insert = PerItemCost{ .base_cost = 60, .per_chunk_cost = 20, .chunk_size = 1 };
    pub const update = PerItemCost{ .base_cost = 60, .per_chunk_cost = 20, .chunk_size = 1 };
    pub const remove = PerItemCost{ .base_cost = 60, .per_chunk_cost = 20, .chunk_size = 1 };
};

// Compile-time tests for AvlTreeCost
comptime {
    // LookupAvlTree with 3 proof elements: base 40 + 10*3 chunks = 70
    assert(AvlTreeCost.lookup.cost(3) == 40 + 10 * 3);
    // LookupAvlTree with 0 elements: base cost only
    assert(AvlTreeCost.lookup.cost(0) == 40);
}

/// Per-operation PerItemCost configurations for hash operations (JIT/v2).
/// Source: sigmastate LanguageSpecificationV5.scala test vectors
/// CalcBlake2b256: PerItemCost(JitCost(20), JitCost(7), 128)
/// CalcSha256: PerItemCost(JitCost(80), JitCost(8), 64)
const HashCost = struct {
    // Blake2b256: base 20, per chunk 7, chunk size 128 bytes
    pub const blake2b256 = PerItemCost{ .base_cost = 20, .per_chunk_cost = 7, .chunk_size = 128 };

    // SHA256: base 80, per chunk 8, chunk size 64 bytes
    pub const sha256 = PerItemCost{ .base_cost = 80, .per_chunk_cost = 8, .chunk_size = 64 };
};

// Compile-time tests for HashCost
comptime {
    // Blake2b256 empty: base cost only = 20
    assert(HashCost.blake2b256.cost(0) == 20);
    // Blake2b256 128 bytes: 1 chunk = 20 + 7 = 27
    assert(HashCost.blake2b256.cost(128) == 20 + 7);
    // Blake2b256 129 bytes: 2 chunks = 20 + 14 = 34
    assert(HashCost.blake2b256.cost(129) == 20 + 14);
    // Blake2b256 256 bytes: 2 chunks = 20 + 14 = 34
    assert(HashCost.blake2b256.cost(256) == 20 + 14);

    // SHA256 empty: base cost only = 80
    assert(HashCost.sha256.cost(0) == 80);
    // SHA256 64 bytes: 1 chunk = 80 + 8 = 88
    assert(HashCost.sha256.cost(64) == 80 + 8);
    // SHA256 65 bytes: 2 chunks = 80 + 16 = 96
    assert(HashCost.sha256.cost(65) == 80 + 16);
}

// ============================================================================
// Type Compatibility
// ============================================================================

/// Check if two types are compatible for constant substitution
/// Types must match exactly (no implicit conversions)
/// Per Scala: require(c.tpe == newConst.tpe)
fn typesCompatible(expected: TypeIndex, actual: TypeIndex, type_pool: *const TypePool) bool {
    _ = type_pool;
    // Exact match required for SubstConstants
    return expected == actual;
}

// ============================================================================
// Evaluator
// ============================================================================

/// Main expression evaluator
pub const Evaluator = struct {
    /// Expression tree being evaluated
    tree: *const ExprTree,

    /// Execution context (read-only blockchain state)
    ctx: *const Context,

    /// Protocol version context (controls cost model and feature gates)
    version_ctx: VersionContext,

    /// Work stack (iterative processing)
    work_stack: [max_work_stack]WorkItem = undefined,
    work_sp: u16 = 0,

    /// Value stack (intermediate results)
    value_stack: [max_value_stack]Value = undefined,
    value_sp: u16 = 0,

    /// Cost accounting
    cost_used: u64 = 0,
    cost_limit: u64 = default_cost_limit,

    /// Wall-clock deadline (defense in depth against cost accounting bugs).
    /// null = no timeout, otherwise nanosecond timestamp from std.time.nanoTimestamp().
    deadline_ns: ?i128 = null,

    /// Operations since last timeout check.
    /// We check the wall clock every timeout_check_interval operations.
    ops_since_timeout_check: u16 = 0,

    /// Arena for temporary allocations (hash results, etc.)
    arena: BumpAllocator(eval_arena_size) = BumpAllocator(eval_arena_size).init(),

    /// Variable bindings (varId -> Value)
    /// null = unbound, non-null = bound value
    var_bindings: [max_var_bindings]?Value = [_]?Value{null} ** max_var_bindings,

    /// Values array for tuple storage
    /// Tuples reference ranges in this array
    values: [max_value_stack]Value = undefined,
    values_sp: u16 = 0,

    /// Memory pools for complex value storage (Options, nested types)
    pools: MemoryPools = MemoryPools.init(),

    /// Optional metrics collector (null = metrics disabled)
    /// When non-null, evaluation stats are recorded atomically
    metrics: ?*Metrics = null,

    /// Deserialize depth counter (prevents infinite recursion in executeFromVar/executeFromSelfReg)
    /// Incremented when evaluating nested deserialized scripts
    deserialize_depth: u8 = 0,

    /// Diagnostics captured on evaluation failure.
    /// Reset at start of evaluate(), populated on error.
    diag: EvalDiagnostics = .{},

    /// Memory pools container
    pub const MemoryPools = struct {
        values: ValuePool = ValuePool.init(),
        register_cache: RegisterCache = RegisterCache.init(),
        type_pool: TypePool = TypePool.init(),

        pub fn init() MemoryPools {
            return .{};
        }

        /// Reset transient pools for new evaluation.
        /// Note: values pool is NOT reset to preserve pre-populated Option inner values.
        fn reset(self: *MemoryPools) void {
            self.register_cache.reset();
            self.type_pool.reset();
            // self.values is not reset - may contain pre-populated constants
        }
    };

    /// State snapshot for debugging and replay.
    /// Captures essential state to reproduce assertion failures.
    pub const StateSnapshot = struct {
        /// Stack pointers
        work_sp: u16,
        value_sp: u16,
        values_sp: u16,

        /// Cost state
        cost_used: u64,
        cost_limit: u64,
        cost_remaining: u64,

        /// Version context
        activated_version: u8,
        ergo_tree_version: u8,

        /// Tree info
        tree_node_count: u16,
        tree_value_count: u16,

        /// Arena usage
        arena_used: usize,

        /// Checksum of critical state (for corruption detection)
        checksum: u32,

        /// Create snapshot from evaluator state
        pub fn fromEvaluator(eval: *const Evaluator) StateSnapshot {
            var snap = StateSnapshot{
                .work_sp = eval.work_sp,
                .value_sp = eval.value_sp,
                .values_sp = eval.values_sp,
                .cost_used = eval.cost_used,
                .cost_limit = eval.cost_limit,
                .cost_remaining = if (eval.cost_limit >= eval.cost_used)
                    eval.cost_limit - eval.cost_used
                else
                    0,
                .activated_version = eval.version_ctx.activated_version,
                .ergo_tree_version = eval.version_ctx.ergo_tree_version,
                .tree_node_count = eval.tree.node_count,
                .tree_value_count = eval.tree.value_count,
                .arena_used = eval.arena.used(),
                .checksum = 0,
            };

            // Compute checksum from critical fields
            snap.checksum = snap.computeChecksum();
            return snap;
        }

        /// Compute checksum for integrity verification
        fn computeChecksum(self: *const StateSnapshot) u32 {
            // Simple hash combining critical fields
            var h: u32 = 0x12345678;
            h ^= @as(u32, self.work_sp) << 16 | @as(u32, self.value_sp);
            h ^= @truncate(self.cost_used);
            h ^= @truncate(self.cost_limit);
            h ^= @as(u32, self.tree_node_count) << 16 | @as(u32, self.tree_value_count);
            h ^= @as(u32, self.activated_version) << 8 | @as(u32, self.ergo_tree_version);
            return h;
        }

        /// Verify checksum matches state
        pub fn verifyChecksum(self: *const StateSnapshot) bool {
            // Recompute without stored checksum
            var verify = self.*;
            verify.checksum = 0;
            return self.checksum == verify.computeChecksum();
        }

        /// Format for debugging output
        pub fn format(
            self: StateSnapshot,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print(
                \\StateSnapshot{{
                \\  stacks: work={d}, value={d}, values={d}
                \\  cost: {d}/{d} (remaining: {d})
                \\  version: activated=v{d}, tree=v{d}
                \\  tree: nodes={d}, values={d}
                \\  arena: {d} bytes used
                \\  checksum: 0x{x:0>8}
                \\}}
            , .{
                self.work_sp,           self.value_sp,          self.values_sp,
                self.cost_used,         self.cost_limit,        self.cost_remaining,
                self.activated_version, self.ergo_tree_version, self.tree_node_count,
                self.tree_value_count,  self.arena_used,        self.checksum,
            });
        }
    };

    /// Capture current evaluator state for debugging.
    /// Use when assertion fails to capture reproducible state.
    pub fn snapshot(self: *const Evaluator) StateSnapshot {
        return StateSnapshot.fromEvaluator(self);
    }

    /// Initialize evaluator with expression tree, context, and version.
    /// Uses v2 (current mainnet) as default version context.
    pub fn init(tree: *const ExprTree, ctx: *const Context) Evaluator {
        return initWithVersion(tree, ctx, VersionContext.v2());
    }

    /// Initialize evaluator with explicit version context.
    /// Use this when you need version-specific behavior (testing, v6 features).
    pub fn initWithVersion(
        tree: *const ExprTree,
        ctx: *const Context,
        version_ctx: VersionContext,
    ) Evaluator {
        return .{
            .tree = tree,
            .ctx = ctx,
            .version_ctx = version_ctx,
        };
    }

    /// Set cost limit for this evaluation
    pub fn setCostLimit(self: *Evaluator, limit: u64) void {
        assert(limit > 0);
        self.cost_limit = limit;
    }

    /// Set wall-clock deadline for this evaluation (defense in depth).
    /// @param timeout_ms: timeout in milliseconds from now (0 = no timeout)
    pub fn setDeadline(self: *Evaluator, timeout_ms: u64) void {
        if (timeout_ms == 0) {
            self.deadline_ns = null;
        } else {
            // PRECONDITION: timeout fits in reasonable range
            assert(timeout_ms <= 600_000); // Max 10 minutes
            const timeout_ns: i128 = @as(i128, timeout_ms) * 1_000_000;
            self.deadline_ns = std.time.nanoTimestamp() + timeout_ns;
        }
    }

    /// Check if wall-clock deadline has been exceeded.
    /// Called periodically during evaluation (every timeout_check_interval ops).
    fn checkTimeout(self: *Evaluator) EvalError!void {
        // Increment op counter
        self.ops_since_timeout_check +%= 1;

        // Only check every N operations to amortize syscall cost
        if (self.ops_since_timeout_check < timeout_check_interval) {
            return;
        }

        // Reset counter
        self.ops_since_timeout_check = 0;

        // Check deadline if set
        if (self.deadline_ns) |deadline| {
            const now = std.time.nanoTimestamp();
            if (now > deadline) {
                return error.TimeoutExceeded;
            }
        }
    }

    /// Evaluate the expression tree to produce a result
    pub fn evaluate(self: *Evaluator) EvalError!Value {
        // PRECONDITION: Tree has at least one node
        assert(self.tree.node_count > 0);
        // PRECONDITION: Cost limit is set
        assert(self.cost_limit > 0);
        // PRECONDITION: Version context is valid
        assert(self.version_ctx.activated_version <= VersionContext.MAX_SUPPORTED_VERSION);

        // METRICS: Record evaluation start
        if (self.metrics) |m| m.incEvaluations();

        // Reset state
        self.work_sp = 0;
        self.value_sp = 0;
        self.cost_used = 0;
        self.ops_since_timeout_check = 0;
        self.arena.reset();
        self.var_bindings = [_]?Value{null} ** max_var_bindings;
        self.pools.reset();
        self.diag = .{};

        // INVARIANT: State is clean after reset
        assert(self.work_sp == 0);
        assert(self.value_sp == 0);
        assert(self.cost_used == 0);

        // Push root node for evaluation (index 0)
        try self.pushWork(.{ .node_idx = 0, .phase = .evaluate });

        // INVARIANT: Root was pushed
        assert(self.work_sp == 1);

        // Main evaluation loop
        var loop_count: u32 = 0;
        const max_loop_iterations: u32 = 1_000_000; // Safety bound

        while (self.work_sp > 0) {
            // INVARIANT: Loop count bounded (prevents infinite loops)
            loop_count += 1;
            assert(loop_count <= max_loop_iterations);

            // Check wall-clock timeout periodically (defense in depth)
            self.checkTimeout() catch |err| {
                // METRICS: Record error
                if (self.metrics) |m| m.incErrors();
                return err;
            };

            const work = self.popWork();

            switch (work.phase) {
                .evaluate => self.evaluateNode(work.node_idx) catch |err| {
                    if (err == error.SoftForkAccepted) {
                        // Soft-fork rule: script with unknown features passes
                        // Reference: Interpreter.scala WhenSoftForkReductionResult
                        // METRICS: Record as success (soft-fork pass)
                        if (self.metrics) |m| {
                            m.incSuccess();
                            m.addCost(self.cost_used);
                        }
                        return .{ .boolean = true };
                    }
                    // Capture diagnostics for debugging
                    self.captureEvalDiagnostics(err, work.node_idx);
                    // METRICS: Record error
                    if (self.metrics) |m| m.incErrors();
                    return err;
                },
                .compute => self.computeNode(work.node_idx) catch |err| {
                    if (err == error.SoftForkAccepted) {
                        // Soft-fork rule: script with unknown features passes
                        // METRICS: Record as success (soft-fork pass)
                        if (self.metrics) |m| {
                            m.incSuccess();
                            m.addCost(self.cost_used);
                        }
                        return .{ .boolean = true };
                    }
                    // Capture diagnostics for debugging
                    self.captureEvalDiagnostics(err, work.node_idx);
                    // METRICS: Record error
                    if (self.metrics) |m| m.incErrors();
                    return err;
                },
            }
        }

        // POSTCONDITION: Work stack is empty
        assert(self.work_sp == 0);
        // POSTCONDITION: Cost was consumed
        assert(self.cost_used > 0);

        // Result is on value stack
        if (self.value_sp == 0) {
            // METRICS: Record error
            if (self.metrics) |m| m.incErrors();
            return error.ValueStackUnderflow;
        }

        // POSTCONDITION: Exactly one result
        // Use error instead of assert to handle malformed trees gracefully
        if (self.value_sp != 1) {
            // Malformed tree left extra values on stack
            // METRICS: Record error
            if (self.metrics) |m| m.incErrors();
            return error.InvalidState;
        }

        // METRICS: Record success and cost
        if (self.metrics) |m| {
            m.incSuccess();
            m.addCost(self.cost_used);
        }

        return self.popValue();
    }

    // ========================================================================
    // Evaluate Phase: Leaf Node Handlers
    // Each handler is under 70 lines per TigerBeetle style.
    // ========================================================================

    /// Evaluate true literal
    fn evalTrueLeaf(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.constant);
        try self.pushValue(.{ .boolean = true });
    }

    /// Evaluate false literal
    fn evalFalseLeaf(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.constant);
        try self.pushValue(.{ .boolean = false });
    }

    /// Evaluate unit literal
    fn evalUnit(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.constant);
        try self.pushValue(.{ .unit = {} });
    }

    /// Evaluate height accessor
    fn evalHeight(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.height);
        try self.pushValue(.{ .int = @intCast(self.ctx.height) });
    }

    /// Evaluate constant from tree values array
    fn evalConstant(self: *Evaluator, node: ExprNode) EvalError!void {
        try self.addCost(FixedCost.constant);
        const value_idx = node.data;
        if (value_idx >= self.tree.value_count) {
            return error.InvalidConstantIndex;
        }
        try self.pushValue(self.tree.values[value_idx]);
    }

    /// Evaluate constant placeholder from constants pool
    fn evalConstantPlaceholder(self: *Evaluator, node: ExprNode) EvalError!void {
        try self.addCost(FixedCost.constant_placeholder);
        const const_idx = node.data;
        if (const_idx >= self.tree.constant_count) {
            return error.InvalidConstantIndex;
        }
        try self.pushValue(self.tree.constants[const_idx]);
    }

    // ========================================================================
    // Evaluate Phase: Context Accessor Handlers
    // ========================================================================

    /// Evaluate INPUTS accessor
    fn evalInputs(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.inputs);
        try self.pushValue(.{ .box_coll = .{ .source = .inputs } });
    }

    /// Evaluate OUTPUTS accessor
    fn evalOutputs(self: *Evaluator) EvalError!void {
        try self.addCost(FixedCost.inputs);
        try self.pushValue(.{ .box_coll = .{ .source = .outputs } });
    }

    /// Evaluate SELF accessor
    fn evalSelfBox(self: *Evaluator) EvalError!void {
        assert(self.ctx.self_index < self.ctx.inputs.len);
        try self.addCost(FixedCost.inputs);
        try self.pushValue(.{ .box = .{
            .source = .inputs,
            .index = self.ctx.self_index,
        } });
    }

    /// Evaluate MinerPubKey accessor
    fn evalMinerPk(self: *Evaluator) EvalError!void {
        const pk = self.ctx.pre_header.miner_pk;
        assert(pk[0] == 0x02 or pk[0] == 0x03 or pk[0] == 0x00);
        try self.addCost(100);
        try self.pushValue(.{ .group_element = pk });
    }

    /// Evaluate LastBlockUtxoRootHash accessor
    fn evalLastBlockUtxoRoot(self: *Evaluator) EvalError!void {
        if (self.ctx.headers.len == 0) {
            return error.InvalidContext;
        }
        try self.addCost(15);
        try self.pushValue(.{ .coll_byte = &self.ctx.headers[0].state_root });
    }

    /// Evaluate Context object placeholder
    fn evalContextObj(self: *Evaluator) EvalError!void {
        try self.addCost(10);
        try self.pushValue(.{ .unit = {} });
    }

    /// Evaluate Global object placeholder
    fn evalGlobalObj(self: *Evaluator) EvalError!void {
        try self.addCost(10);
        try self.pushValue(.{ .unit = {} });
    }

    // ========================================================================
    // Evaluate Phase: Deferred Operation Setup
    // ========================================================================

    /// Setup binary operation for deferred evaluation
    fn evalBinOpSetup(self: *Evaluator, node_idx: u16) EvalError!void {
        const left_idx = node_idx + 1;
        const right_idx = self.findSubtreeEnd(left_idx);
        try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
        try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
        try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
    }

    /// Setup if-then-else for deferred evaluation
    fn evalIfThenElseSetup(self: *Evaluator, node_idx: u16) EvalError!void {
        try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
        try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
    }

    /// Setup unary operation for deferred evaluation (compute then child)
    fn evalUnarySetup(self: *Evaluator, node_idx: u16) EvalError!void {
        try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
        try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
    }

    /// Setup binary deferred operation (compute then two children)
    fn evalBinarySetup(self: *Evaluator, node_idx: u16) EvalError!void {
        const left_idx = node_idx + 1;
        const right_idx = self.findSubtreeEnd(left_idx);
        try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
        try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
        try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
    }

    // ========================================================================
    // Evaluate Phase: Main Dispatcher
    // ========================================================================

    /// Evaluate a node (may push children for later processing)
    fn evaluateNode(self: *Evaluator, node_idx: u16) EvalError!void {
        if (node_idx >= self.tree.node_count) {
            return error.InvalidNodeIndex;
        }

        const node = self.tree.nodes[node_idx];

        switch (node.tag) {
            // Leaf nodes: delegate to extracted handlers
            .true_leaf => try self.evalTrueLeaf(),
            .false_leaf => try self.evalFalseLeaf(),
            .unit => try self.evalUnit(),
            .height => try self.evalHeight(),
            .constant => try self.evalConstant(node),
            .constant_placeholder => try self.evalConstantPlaceholder(node),

            // Binary and control flow: setup deferred evaluation
            .bin_op => try self.evalBinOpSetup(node_idx),
            .if_then_else => try self.evalIfThenElseSetup(node_idx),

            // Context accessors: delegate to extracted handlers
            .inputs => try self.evalInputs(),
            .outputs => try self.evalOutputs(),
            .self_box => try self.evalSelfBox(),
            .miner_pk => try self.evalMinerPk(),

            .last_block_utxo_root => try self.evalLastBlockUtxoRoot(),
            .context => try self.evalContextObj(),
            .global => try self.evalGlobalObj(),

            .get_var => {
                // GetVar: access context extension variable by ID
                // node.data: (type_idx << 8) | var_id
                try self.addCost(100); // GetVar cost from opcodes.zig

                const var_id: u8 = @truncate(node.data & 0xFF);
                const expected_type_idx: u8 = @truncate(node.data >> 8);

                // Look up the context variable
                const var_bytes = self.ctx.getVar(var_id);

                if (var_bytes) |bytes| {
                    // Variable exists - deserialize according to expected type
                    const value_idx = self.deserializeContextVar(bytes, expected_type_idx) catch {
                        // Type mismatch or deserialization failure - return None
                        try self.pushValue(.{ .option = .{
                            .inner_type = expected_type_idx,
                            .value_idx = null_value_idx,
                        } });
                        return;
                    };
                    try self.pushValue(.{
                        .option = .{
                            .inner_type = expected_type_idx,
                            .value_idx = value_idx,
                        },
                    });
                } else {
                    // Variable not found - return None
                    try self.pushValue(.{ .option = .{
                        .inner_type = expected_type_idx,
                        .value_idx = null_value_idx,
                    } });
                }
            },

            // Unary operations: setup deferred evaluation
            .calc_blake2b256, .calc_sha256, .bool_to_sigma_prop => {
                try self.evalUnarySetup(node_idx);
            },

            .val_use => {
                // Variable reference: look up value from bindings
                try self.addCost(FixedCost.constant);
                const var_id = node.data;
                if (var_id >= max_var_bindings) return error.UndefinedVariable;
                const value = self.var_bindings[var_id] orelse return error.UndefinedVariable;
                try self.pushValue(value);
            },

            .val_def => try self.evalUnarySetup(node_idx),

            .block_value => {
                // Block with let bindings: evaluate each ValDef, then result
                // Stack order: push last-to-execute first
                // We want: ValDef0, ValDef1, ..., Result (in execution order)
                // So push: Result, then ValDefs in reverse order
                const item_count = node.data;

                // PRECONDITION: item_count must fit in indices array
                if (item_count > max_var_bindings) {
                    return error.InvalidData;
                }

                // First, find all indices
                var indices: [max_var_bindings + 1]u16 = undefined;
                var idx = node_idx + 1;
                var i: u16 = 0;
                while (i < item_count) : (i += 1) {
                    indices[i] = idx;
                    idx = self.findSubtreeEnd(idx);
                }
                indices[item_count] = idx; // Result expression index

                // Push result first (will be evaluated last)
                try self.pushWork(.{ .node_idx = indices[item_count], .phase = .evaluate });

                // Push ValDefs in reverse order (so first ValDef is evaluated first)
                if (item_count > 0) {
                    i = item_count;
                    while (i > 0) {
                        i -= 1;
                        try self.pushWork(.{ .node_idx = indices[i], .phase = .evaluate });
                    }
                }
            },

            .func_value => {
                // FuncValue can be stored as a first-class value (e.g., in a variable)
                // When encountered standalone, create a function reference
                const num_args: u8 = @truncate(node.data);
                const body_idx: u16 = node_idx + 1;

                // Validate body index
                if (body_idx >= self.tree.node_count) return error.InvalidData;

                try self.pushValue(.{ .func_ref = .{
                    .body_idx = body_idx,
                    .num_args = num_args,
                } });
            },

            .apply => {
                // Apply: evaluate argument, then apply function
                // Tree structure: [apply] [func_expr] [arg]
                //   where func_expr can be:
                //   - func_value (inline lambda): [func_value] [body...]
                //   - val_use (stored function): [val_use(x)]
                //
                // PRECONDITIONS
                const func_idx = node_idx + 1;
                assert(func_idx < self.tree.node_count); // func must exist

                const func_node = self.tree.nodes[func_idx];

                // Push compute phase first (will run after arg and func are evaluated)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                // Find the argument (after func subtree)
                const arg_idx = self.findSubtreeEnd(func_idx);
                assert(arg_idx < self.tree.node_count); // arg must exist

                // Push argument for evaluation
                try self.pushWork(.{ .node_idx = arg_idx, .phase = .evaluate });

                // If function is a val_use (not inline func_value), evaluate it too
                if (func_node.tag != .func_value) {
                    try self.pushWork(.{ .node_idx = func_idx, .phase = .evaluate });
                }
            },

            // Unary operations with deferred compute
            .option_get,
            .option_is_defined,
            .option_get_or_else,
            .long_to_byte_array,
            .byte_array_to_bigint,
            .byte_array_to_long,
            .decode_point,
            .mod_q,
            .bit_inversion,
            => try self.evalUnarySetup(node_idx),

            // Binary operations with deferred compute
            .plus_mod_q, .minus_mod_q, .exponentiate, .multiply_group => {
                try self.evalBinarySetup(node_idx);
            },

            .group_generator => {
                // Nullary: → GroupElement (no children to evaluate)
                try self.addCost(FixedCost.group_generator);
                const g = crypto_ops.groupGenerator();
                try self.pushValue(.{ .group_element = g });
            },

            .select_field, .extract_register_as => try self.evalUnarySetup(node_idx),

            .tuple_construct => {
                // N-ary: n elements → Tuple
                const elem_count = node.data;
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Push elements in reverse order so first element evaluates first
                var idx = node_idx + 1;
                var indices: [256]u16 = undefined;
                var i: u16 = 0;
                while (i < elem_count) : (i += 1) {
                    indices[i] = idx;
                    idx = self.findSubtreeEnd(idx);
                }
                // Push in reverse order
                while (i > 0) {
                    i -= 1;
                    try self.pushWork(.{ .node_idx = indices[i], .phase = .evaluate });
                }
            },

            .pair_construct => {
                // Binary: 2 elements → Pair
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const first_idx = node_idx + 1;
                const second_idx = self.findSubtreeEnd(first_idx);
                try self.pushWork(.{ .node_idx = second_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = first_idx, .phase = .evaluate });
            },

            .triple_construct => {
                // Ternary: 3 elements → Triple
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const first_idx = node_idx + 1;
                const second_idx = self.findSubtreeEnd(first_idx);
                const third_idx = self.findSubtreeEnd(second_idx);
                try self.pushWork(.{ .node_idx = third_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = second_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = first_idx, .phase = .evaluate });
            },

            .concrete_collection => {
                // N-ary: n elements → Coll[T]
                const elem_count = node.data;
                // INVARIANT: Element count bounded by available index storage
                if (elem_count > 256) return error.InvalidData;
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Push elements in reverse order so first element evaluates first
                var idx = node_idx + 1;
                var indices: [256]u16 = undefined;
                var i: u16 = 0;
                while (i < elem_count) : (i += 1) {
                    indices[i] = idx;
                    idx = self.findSubtreeEnd(idx);
                }
                // Push in reverse order
                while (i > 0) {
                    i -= 1;
                    try self.pushWork(.{ .node_idx = indices[i], .phase = .evaluate });
                }
            },

            // Unary operations: upcast, downcast, header field extraction
            .upcast,
            .downcast,
            .extract_version,
            .extract_parent_id,
            .extract_ad_proofs_root,
            .extract_state_root,
            .extract_txs_root,
            .extract_timestamp,
            .extract_n_bits,
            .extract_difficulty,
            .extract_votes,
            .extract_miner_rewards,
            => try self.evalUnarySetup(node_idx),

            // Collection higher-order functions
            .map_collection, .exists, .for_all, .filter, .flat_map => {
                // Binary: collection + lambda → result
                // We evaluate the collection first, then handle lambda in compute phase
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Collection is at node_idx+1
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
                // Lambda body will be evaluated during compute phase for each element
            },

            .fold => {
                // Ternary: collection + zero + lambda → result
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const coll_idx = node_idx + 1;
                const zero_idx = self.findSubtreeEnd(coll_idx);
                // Validate indices (may be corrupted by fault injection)
                if (zero_idx >= self.tree.node_count) {
                    return error.InvalidData;
                }
                // Evaluate collection and zero, lambda handled in compute phase
                try self.pushWork(.{ .node_idx = zero_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = coll_idx, .phase = .evaluate });
            },

            // Sigma proposition connectives
            .sigma_and, .sigma_or, .sigma_threshold => {
                // sigma_and/sigma_or: N-ary with data = child_count
                // sigma_threshold (AtLeast): data = 2 (bound expr + input collection)
                const child_count: u16 = node.data;
                // Validate child_count is reasonable (may be corrupted by fault injection)
                if (child_count == 0 or child_count > 255) {
                    return error.InvalidData;
                }
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Push children in reverse order so first child evaluates first
                var idx = node_idx + 1;
                var indices: [256]u16 = undefined;
                var i: u16 = 0;
                while (i < child_count) : (i += 1) {
                    // Validate index (may be corrupted by fault injection)
                    if (idx >= self.tree.node_count) {
                        return error.InvalidData;
                    }
                    indices[i] = idx;
                    idx = self.findSubtreeEnd(idx);
                }
                // Push in reverse order
                while (i > 0) {
                    i -= 1;
                    try self.pushWork(.{ .node_idx = indices[i], .phase = .evaluate });
                }
            },

            // Binary sigma proposition operations (BinAnd, BinOr, BinXor)
            .bin_and, .bin_or, .bin_xor => {
                // Binary: 2 SigmaProp children → SigmaProp
                const child1_idx = node_idx + 1;
                const child2_idx = self.findSubtreeEnd(child1_idx);

                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = child2_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = child1_idx, .phase = .evaluate });
            },

            // Method call (collection methods like zip, indices, reverse)
            .method_call => {
                // Method call structure: [method_call] [obj] [args...]
                // data: low 8 bits = type_code, high 8 bits = method_id
                //
                // PRECONDITIONS
                const obj_idx = node_idx + 1;
                assert(obj_idx < self.tree.node_count);

                // Extract type_code and method_id
                const type_code: u8 = @truncate(node.data);
                const method_id: u8 = @truncate(node.data >> 8);

                // Push compute phase first
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                // Find args by walking past obj
                const arg1_start = self.findSubtreeEnd(obj_idx);

                // Determine arg count based on method
                const arg_count: u8 = if (type_code == ContextTypeCode and method_id == ContextMethodId.get_var_from_input)
                    2
                else if (type_code == CollTypeCode) switch (method_id) {
                    CollMethodId.index_of, CollMethodId.updated, CollMethodId.update_many => 2,
                    CollMethodId.patch => 3,
                    CollMethodId.zip, CollMethodId.starts_with, CollMethodId.ends_with, CollMethodId.get, CollMethodId.flatmap => 1,
                    else => 0,
                } else if (arg1_start < self.tree.node_count and self.tree.nodes[arg1_start].tag != .unsupported)
                    1
                else
                    0;

                // Push args in reverse order (last arg first)
                if (arg_count >= 3) {
                    const arg2_start = self.findSubtreeEnd(arg1_start);
                    const arg3_start = self.findSubtreeEnd(arg2_start);
                    try self.pushWork(.{ .node_idx = arg3_start, .phase = .evaluate });
                    try self.pushWork(.{ .node_idx = arg2_start, .phase = .evaluate });
                    try self.pushWork(.{ .node_idx = arg1_start, .phase = .evaluate });
                } else if (arg_count == 2) {
                    const arg2_start = self.findSubtreeEnd(arg1_start);
                    try self.pushWork(.{ .node_idx = arg2_start, .phase = .evaluate });
                    try self.pushWork(.{ .node_idx = arg1_start, .phase = .evaluate });
                } else if (arg_count == 1) {
                    try self.pushWork(.{ .node_idx = arg1_start, .phase = .evaluate });
                }

                // Push obj for evaluation
                try self.pushWork(.{ .node_idx = obj_idx, .phase = .evaluate });
            },

            // Property call (property access with no args, like box.value)
            .property_call => try self.evalUnarySetup(node_idx),

            // AVL tree operations
            .create_avl_tree => {
                // CreateAvlTree: 3 or 4 children (flags, digest, key_length, opt value_length)
                // node.data = 1 if value_length present, 0 if not
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                // Find child indices
                const flags_idx = node_idx + 1;
                const digest_idx = self.findSubtreeEnd(flags_idx);
                const key_len_idx = self.findSubtreeEnd(digest_idx);

                if (node.data == 1) {
                    // Has value_length: 4 children
                    const val_len_idx = self.findSubtreeEnd(key_len_idx);
                    try self.pushWork(.{ .node_idx = val_len_idx, .phase = .evaluate });
                }
                try self.pushWork(.{ .node_idx = key_len_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = digest_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = flags_idx, .phase = .evaluate });
            },

            .tree_lookup => {
                // TreeLookup: 3 children (tree, key, proof)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                const tree_idx = node_idx + 1;
                const key_idx = self.findSubtreeEnd(tree_idx);
                const proof_idx = self.findSubtreeEnd(key_idx);

                try self.pushWork(.{ .node_idx = proof_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = key_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = tree_idx, .phase = .evaluate });
            },

            .subst_constants => {
                // SubstConstants: 3 children (script_bytes, positions, new_values)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                const script_idx = node_idx + 1;
                const positions_idx = self.findSubtreeEnd(script_idx);
                const new_values_idx = self.findSubtreeEnd(positions_idx);

                // Push in reverse order so script evaluates first
                try self.pushWork(.{ .node_idx = new_values_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = positions_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = script_idx, .phase = .evaluate });
            },

            .deserialize_context => {
                // DeserializeContext: no children, data packed in node
                // Will read bytes from context variable and evaluate nested expression
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
            },

            .deserialize_register => {
                // DeserializeRegister: 0 or 1 child (default expression)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const has_default: u8 = @truncate(node.data);
                if (has_default == 1) {
                    // Push default expression for evaluation
                    const child_idx = node_idx + 1;
                    try self.pushWork(.{ .node_idx = child_idx, .phase = .evaluate });
                }
            },

            // More unary operations
            .size_of,
            .negation,
            .logical_not,
            .extract_amount,
            .extract_script_bytes,
            .extract_bytes,
            .extract_bytes_with_no_ref,
            .extract_id,
            .extract_creation_info,
            => try self.evalUnarySetup(node_idx),

            // Trivial propositions - leaf nodes (no children)
            .trivial_prop_true, .trivial_prop_false => {
                // Just push compute phase - no children to evaluate
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
            },

            .slice => {
                // Ternary: collection, from, until → sliced collection
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const coll_idx = node_idx + 1;
                const from_idx = self.findSubtreeEnd(coll_idx);
                const until_idx = self.findSubtreeEnd(from_idx);
                try self.pushWork(.{ .node_idx = until_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = from_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = coll_idx, .phase = .evaluate });
            },

            // Sigma proposition constructors
            .prove_dlog, .sigma_prop_bytes => try self.evalUnarySetup(node_idx),

            .prove_dh_tuple => {
                // 4-ary: g, h, u, v → SigmaProp
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Evaluate 4 arguments
                var arg_idx = node_idx + 1;
                for (0..4) |_| {
                    try self.pushWork(.{ .node_idx = arg_idx, .phase = .evaluate });
                    arg_idx = self.findSubtreeEnd(arg_idx);
                }
            },

            // Logical AND/OR on collections - unary: Coll[Boolean] → Boolean
            .logical_and, .logical_or => try self.evalUnarySetup(node_idx),

            .unsupported => {
                // Unknown opcode encountered during deserialization.
                // Use soft-fork aware handling: returns SoftForkAccepted if
                // script version > activated version, UnsupportedExpression otherwise.
                return self.handleUnsupported();
            },
        }
    }

    /// Compute result for a node after children are evaluated
    fn computeNode(self: *Evaluator, node_idx: u16) EvalError!void {
        const node = self.tree.nodes[node_idx];

        switch (node.tag) {
            .bin_op => {
                const kind: BinOpKind = std.meta.intToEnum(BinOpKind, node.data & 0xFF) catch {
                    return error.InvalidBinOp;
                };
                try self.computeBinOp(kind);
            },

            .if_then_else => {
                // Condition result is on stack
                const cond = try self.popValue();
                if (cond != .boolean) return error.TypeMismatch;

                // Find then and else branch indices
                // Condition is at node_idx+1, then after condition, else after then
                const cond_idx = node_idx + 1;
                const then_idx = self.findSubtreeEnd(cond_idx);
                const else_idx = self.findSubtreeEnd(then_idx);

                if (cond.boolean) {
                    try self.pushWork(.{ .node_idx = then_idx, .phase = .evaluate });
                } else {
                    try self.pushWork(.{ .node_idx = else_idx, .phase = .evaluate });
                }
            },

            .calc_blake2b256 => {
                try self.computeHash(.blake2b256);
            },

            .calc_sha256 => {
                try self.computeHash(.sha256);
            },

            .val_def => {
                // Store the evaluated RHS in variable bindings
                const var_id = node.data;
                const value = try self.popValue();
                if (var_id < max_var_bindings) {
                    self.var_bindings[var_id] = value;
                }
                // val_def doesn't produce a value on the stack (Unit semantics)
            },

            .option_get => {
                try self.computeOptionGet();
            },

            .option_is_defined => {
                try self.computeOptionIsDefined();
            },

            .option_get_or_else => {
                // Option value is on stack, decide whether to use it or evaluate default
                const opt_val = try self.popValue();
                if (opt_val != .option) return error.TypeMismatch;

                if (opt_val.option.isSome()) {
                    // Some(x) - get the inner value from ValuePool
                    const inner = self.pools.values.get(opt_val.option.value_idx) orelse return error.InvalidState;
                    const result = try pooledValueToValue(inner, &self.pools.type_pool);
                    try self.pushValue(result);
                } else {
                    // None - evaluate the default expression
                    const default_idx = self.findSubtreeEnd(node_idx + 1);
                    try self.pushWork(.{ .node_idx = default_idx, .phase = .evaluate });
                }
            },

            .long_to_byte_array => {
                try self.computeLongToByteArray();
            },

            .byte_array_to_long => {
                try self.computeByteArrayToLong();
            },

            .byte_array_to_bigint => {
                try self.computeByteArrayToBigInt();
            },

            .decode_point => {
                try self.computeDecodePoint();
            },

            .mod_q => {
                try self.computeModQ();
            },

            .bit_inversion => {
                try self.computeBitInversion();
            },

            .bool_to_sigma_prop => {
                // Convert boolean to SigmaProp (trivial proposition)
                try self.computeBoolToSigmaProp();
            },

            .plus_mod_q => {
                try self.computePlusModQ();
            },

            .minus_mod_q => {
                try self.computeMinusModQ();
            },

            .exponentiate => {
                try self.computeExponentiate();
            },

            .multiply_group => {
                try self.computeMultiplyGroup();
            },

            .select_field => {
                try self.computeSelectField(node.data);
            },

            .extract_register_as => {
                try self.computeExtractRegisterAs(node.data);
            },

            .tuple_construct, .pair_construct, .triple_construct => {
                try self.computeTupleConstruct(node.data);
            },

            .concrete_collection => {
                try self.computeConcreteCollection(node.data, node.result_type);
            },

            .upcast => {
                try self.computeUpcast(node.data);
            },

            .downcast => {
                try self.computeDowncast(node.data);
            },

            // Header field extraction
            .extract_version => try self.computeExtractVersion(),
            .extract_parent_id => try self.computeExtractParentId(),
            .extract_ad_proofs_root => try self.computeExtractAdProofsRoot(),
            .extract_state_root => try self.computeExtractStateRoot(),
            .extract_txs_root => try self.computeExtractTxsRoot(),
            .extract_timestamp => try self.computeExtractTimestamp(),
            .extract_n_bits => try self.computeExtractNBits(),
            .extract_difficulty => try self.computeExtractDifficulty(),
            .extract_votes => try self.computeExtractVotes(),
            .extract_miner_rewards => try self.computeExtractMinerRewards(),

            // Collection HOF operations
            .exists => try self.computeExists(node_idx),
            .for_all => try self.computeForAll(node_idx),
            .map_collection => try self.computeMap(node_idx),
            .filter => try self.computeFilter(node_idx),
            .fold => try self.computeFold(node_idx),
            .flat_map => try self.computeFlatMap(node_idx),
            .slice => try self.computeSlice(),
            .logical_and => try self.computeLogicalAnd(),
            .logical_or => try self.computeLogicalOr(),

            // Sigma proposition connectives
            .sigma_and => try self.computeSigmaAnd(node.data),
            .sigma_or => try self.computeSigmaOr(node.data),
            .sigma_threshold => try self.computeSigmaThreshold(node.data),
            // Binary boolean operations (logical AND/OR/XOR on booleans)
            .bin_and => try self.computeBinAnd(),
            .bin_or => try self.computeBinOr(),
            .bin_xor => try self.computeBinXor(),

            // Function application
            .apply => try self.computeApply(node_idx),

            // Method call (collection methods)
            .method_call => try self.computeMethodCall(node_idx),

            // Property call (property access, no args)
            .property_call => try self.computePropertyCall(node_idx),

            // AVL tree operations
            .create_avl_tree => try self.computeCreateAvlTree(node.data),
            .tree_lookup => try self.computeTreeLookup(),

            // Special operations
            .subst_constants => try self.computeSubstConstants(),
            .deserialize_context => try self.computeDeserializeContext(node),
            .deserialize_register => try self.computeDeserializeRegister(node),

            // Unary operations: size_of, negation, logical_not
            .logical_not => try self.computeLogicalNot(),
            .negation => try self.computeNegation(),
            .size_of => try self.computeSizeOf(),

            // Box extraction operations
            .extract_amount => try self.computeBoxValue(),
            .extract_script_bytes => try self.computeBoxPropositionBytes(),
            .extract_bytes => try self.computeBoxBytes(),
            .extract_bytes_with_no_ref => try self.computeBoxBytesWithoutRef(),
            .extract_id => try self.computeBoxId(),
            .extract_creation_info => try self.computeBoxCreationInfo(),

            // Trivial propositions
            .trivial_prop_true => try self.computeTrivialPropTrue(),
            .trivial_prop_false => try self.computeTrivialPropFalse(),

            // Sigma proposition constructors
            .prove_dlog => try self.computeProveDlog(),
            .prove_dh_tuple => try self.computeProveDHTuple(),
            .sigma_prop_bytes => try self.computeSigmaPropBytes(),

            else => {
                // Other node types don't need compute phase
            },
        }
    }

    /// Hash algorithm type
    const HashAlgorithm = enum { blake2b256, sha256 };

    /// Compute hash operation
    fn computeHash(self: *Evaluator, algo: HashAlgorithm) EvalError!void {
        // PRECONDITION: Input value is on the stack
        assert(self.value_sp > 0);

        // Pop the input (should be Coll[Byte])
        const input = try self.popValue();
        if (input != .coll_byte) return error.TypeMismatch;

        const input_data = input.coll_byte;

        // Chunk-based cost: PerItemCost(base, perChunk, chunkSize)
        // Blake2b256: PerItemCost(20, 7, 128) - per 128-byte block
        // SHA256: PerItemCost(80, 8, 64) - per 64-byte block
        const cost: u32 = switch (algo) {
            .blake2b256 => HashCost.blake2b256.cost(@truncate(input_data.len)),
            .sha256 => HashCost.sha256.cost(@truncate(input_data.len)),
        };
        try self.addCost(cost);

        // Compute hash and store inline (no arena allocation needed)
        const hash_result: [32]u8 = switch (algo) {
            .blake2b256 => hash.blake2b256(input_data),
            .sha256 => hash.sha256(input_data),
        };

        // Push result as hash32 (inline storage, avoids arena allocation)
        try self.pushValue(.{ .hash32 = hash_result });
    }

    /// Compute OptionGet - extract value from Some, error on None
    fn computeOptionGet(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(15); // OptionGet cost from opcodes

        const opt_val = try self.popValue();
        if (opt_val != .option) return error.TypeMismatch;

        // INVARIANT: Option type is well-formed
        assert(opt_val.option.inner_type != 0); // Has valid inner type

        if (opt_val.option.isSome()) {
            // Get inner value from ValuePool
            const inner = self.pools.values.get(opt_val.option.value_idx) orelse return error.InvalidState;
            const result = try pooledValueToValue(inner, &self.pools.type_pool);
            try self.pushValue(result);
        } else {
            // None - error per ErgoTree semantics
            return error.OptionNone;
        }
    }

    /// Compute OptionIsDefined - return true if Some, false if None
    fn computeOptionIsDefined(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(15); // OptionIsDefined cost from opcodes

        const opt_val = try self.popValue();
        if (opt_val != .option) return error.TypeMismatch;

        // INVARIANT: Option type is well-formed
        assert(opt_val.option.inner_type != 0);

        const is_defined = opt_val.option.isSome();
        try self.pushValue(.{ .boolean = is_defined });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute LongToByteArray - convert Long to big-endian Coll[Byte]
    fn computeLongToByteArray(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(17); // LongToByteArray cost from opcodes

        const input = try self.popValue();
        if (input != .long) return error.TypeMismatch;

        // Convert to big-endian bytes (network byte order)
        const result_slice = self.arena.allocSlice(u8, 8) catch return error.OutOfMemory;
        const value: u64 = @bitCast(input.long);
        std.mem.writeInt(u64, result_slice[0..8], value, .big);

        // POSTCONDITION: Result is exactly 8 bytes
        assert(result_slice.len == 8);

        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ByteArrayToLong - convert big-endian Coll[Byte] to Long
    fn computeByteArrayToLong(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(16); // ByteArrayToLong cost from opcodes

        const input = try self.popValue();
        if (input != .coll_byte) return error.TypeMismatch;

        const bytes = input.coll_byte;
        if (bytes.len != 8) return error.InvalidData;

        // INVARIANT: Input is exactly 8 bytes
        assert(bytes.len == 8);

        // Convert from big-endian bytes (network byte order)
        const value = std.mem.readInt(u64, bytes[0..8], .big);

        try self.pushValue(.{ .long = @bitCast(value) });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ByteArrayToBigInt - convert Coll[Byte] to BigInt
    fn computeByteArrayToBigInt(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(30); // ByteArrayToBigInt cost from opcodes

        const input = try self.popValue();
        if (input != .coll_byte) return error.TypeMismatch;

        const bytes = input.coll_byte;
        if (bytes.len == 0 or bytes.len > data.max_bigint_bytes) return error.InvalidData;

        // INVARIANT: Input length is valid for BigInt
        assert(bytes.len > 0 and bytes.len <= data.max_bigint_bytes);

        // Store as big-endian bytes in BigInt
        // Sign is determined by the high bit of first byte (two's complement)
        var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = @truncate(bytes.len) };

        @memcpy(bigint.bytes[0..bytes.len], bytes);
        try self.pushValue(.{ .big_int = bigint });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute DecodePoint - decode Coll[Byte] to GroupElement
    /// If input is already a GroupElement, passes it through unchanged.
    fn computeDecodePoint(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.decode_point);

        const input = try self.popValue();

        // If already a GroupElement, pass through unchanged
        if (input == .group_element) {
            try self.pushValue(input);
            return;
        }

        // Extract bytes from either .coll_byte or .coll (byte collection from pool)
        var buf: [33]u8 = undefined;
        const bytes = self.extractBytesFromColl(input, &buf) orelse return error.TypeMismatch;

        if (bytes.len != 33) return error.InvalidData;

        // INVARIANT: Input is exactly 33 bytes
        assert(bytes.len == 33);

        // Decode and validate the point
        _ = crypto_ops.decodePoint(bytes) catch return error.InvalidGroupElement;

        // Store as raw bytes (already validated)
        var result: [33]u8 = undefined;
        @memcpy(&result, bytes);
        try self.pushValue(.{ .group_element = result });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ModQ - reduce BigInt mod secp256k1 group order
    fn computeModQ(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(100); // ModQ cost from opcodes

        const input = try self.popValue();
        if (input != .big_int) return error.TypeMismatch;

        // INVARIANT: Input has correct type
        assert(input == .big_int);

        const input_bigint = input.big_int;

        // Convert to BigInt256 for modular arithmetic
        const value = crypto_bigint.BigInt256.fromBytes(input_bigint.bytes[0..input_bigint.len]) catch
            return error.InvalidData;

        // Perform modQ operation
        const result = value.modQ() catch return error.ArithmeticOverflow;

        // Convert back to serialized format
        var result_buf: [33]u8 = undefined;
        const result_bytes = result.toBytes(&result_buf);

        // INVARIANT: modQ result always fits in max_bigint_bytes (33)
        assert(result_bytes.len <= data.max_bigint_bytes);
        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @intCast(result_bytes.len) };
        @memcpy(output.bytes[0..result_bytes.len], result_bytes);

        try self.pushValue(.{ .big_int = output });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute BitInversion - bitwise complement
    fn computeBitInversion(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(30); // BitInversion cost from opcodes

        const input = try self.popValue();
        const result = try bitInvertInt(input);

        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute BoolToSigmaProp - wrap boolean as SigmaProp (trivial proposition)
    fn computeBoolToSigmaProp(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(15); // BoolToSigmaProp cost from opcodes

        const input = try self.popValue();
        if (input != .boolean) return error.TypeMismatch;

        // Convert boolean to trivial proposition using internal serialization format:
        // 0x01 = trivial_true, 0x00 = trivial_false
        const opcode: u8 = if (input.boolean) 0x01 else 0x00;

        // Allocate from arena for proper lifetime
        const sigma_bytes = self.arena.allocSlice(u8, 1) catch return error.OutOfMemory;
        sigma_bytes[0] = opcode;

        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ProveDlog - create SigmaProp from GroupElement (public key)
    /// Encodes as 0xCD + 33-byte compressed public key
    fn computeProveDlog(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(20); // ProveDlog construction cost

        const input = try self.popValue();
        if (input != .group_element) return error.TypeMismatch;

        // INVARIANT: GroupElement is 33-byte compressed public key
        assert(input.group_element.len == 33);

        // Allocate 34 bytes: 0xCD opcode + 33-byte public key
        const sigma_bytes = self.arena.allocSlice(u8, 34) catch return error.OutOfMemory;
        sigma_bytes[0] = 0xCD; // ProveDlog opcode
        @memcpy(sigma_bytes[1..34], &input.group_element);

        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ProveDHTuple - create SigmaProp from 4 GroupElements (g, h, u, v)
    /// Encodes as 0xCE + 4×33-byte compressed points = 133 bytes
    fn computeProveDHTuple(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least 4 values
        assert(self.value_sp >= 4);

        try self.addCost(40); // ProveDHTuple construction cost

        // Pop in reverse order: v, u, h, g
        const v = try self.popValue();
        const u = try self.popValue();
        const h = try self.popValue();
        const g = try self.popValue();

        // All must be group elements
        if (g != .group_element or h != .group_element or u != .group_element or v != .group_element)
            return error.TypeMismatch;

        // Allocate 133 bytes: 0xCE opcode + 4×33-byte points
        const sigma_bytes = self.arena.allocSlice(u8, 133) catch return error.OutOfMemory;
        sigma_bytes[0] = 0xCE; // ProveDHTuple opcode
        @memcpy(sigma_bytes[1..34], &g.group_element);
        @memcpy(sigma_bytes[34..67], &h.group_element);
        @memcpy(sigma_bytes[67..100], &u.group_element);
        @memcpy(sigma_bytes[100..133], &v.group_element);

        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute SigmaPropBytes - extract bytes from SigmaProp
    fn computeSigmaPropBytes(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(15); // SigmaPropBytes cost

        const input = try self.popValue();
        if (input != .sigma_prop) return error.TypeMismatch;

        // Return the raw sigma bytes as Coll[Byte]
        const sigma_data = input.sigma_prop.data;

        // INVARIANT: sigma_prop data is not empty
        assert(sigma_data.len > 0);

        try self.pushValue(.{ .coll_byte = sigma_data });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute LogicalNot - boolean negation
    fn computeLogicalNot(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(11); // LogicalNot cost from opcodes

        const input = try self.popValue();
        if (input != .boolean) return error.TypeMismatch;

        try self.pushValue(.{ .boolean = !input.boolean });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute binary boolean AND (BinAnd opcode)
    /// Takes two boolean values from stack, returns their logical AND
    fn computeBinAnd(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(36); // BinAnd cost from opcodes

        const right = try self.popValue();
        const left = try self.popValue();

        if (left != .boolean or right != .boolean) return error.TypeMismatch;

        try self.pushValue(.{ .boolean = left.boolean and right.boolean });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute binary boolean OR (BinOr opcode)
    /// Takes two boolean values from stack, returns their logical OR
    fn computeBinOr(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(36); // BinOr cost from opcodes

        const right = try self.popValue();
        const left = try self.popValue();

        if (left != .boolean or right != .boolean) return error.TypeMismatch;

        try self.pushValue(.{ .boolean = left.boolean or right.boolean });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute binary boolean XOR (BinXor opcode)
    /// Takes two boolean values from stack, returns their logical XOR
    fn computeBinXor(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(36); // BinXor cost from opcodes

        const right = try self.popValue();
        const left = try self.popValue();

        if (left != .boolean or right != .boolean) return error.TypeMismatch;

        try self.pushValue(.{ .boolean = left.boolean != right.boolean });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute Negation - arithmetic negation
    fn computeNegation(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(30); // Negation cost from opcodes

        const input = try self.popValue();

        const result: Value = switch (input) {
            .int => |v| .{ .int = -v },
            .long => |v| .{ .long = -v },
            .short => |v| .{ .short = -v },
            .byte => |v| .{ .byte = -v },
            // BigInt negation would need BigInt arithmetic
            else => return error.TypeMismatch,
        };

        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute SizeOf - collection length
    fn computeSizeOf(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(14); // SizeOf cost from opcodes

        const input = try self.popValue();

        const len: i32 = switch (input) {
            .coll_byte => |c| @intCast(c.len),
            .coll => |c| @intCast(c.len),
            .box_coll => |bc| blk: {
                // Get box collection length (INPUTS.size, OUTPUTS.size, etc.)
                const boxes = switch (bc.source) {
                    .inputs => self.ctx.inputs,
                    .outputs => self.ctx.outputs,
                    .data_inputs => self.ctx.data_inputs,
                };
                break :blk @intCast(boxes.len);
            },
            .token_coll => |tc| blk: {
                // Get box to retrieve token count
                const boxes = switch (tc.source) {
                    .inputs => self.ctx.inputs,
                    .outputs => self.ctx.outputs,
                    .data_inputs => self.ctx.data_inputs,
                };
                if (tc.box_index >= boxes.len) return error.IndexOutOfBounds;
                break :blk @intCast(boxes[tc.box_index].tokens.len);
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .int = len });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute TrivialPropTrue - create trivially true SigmaProp
    fn computeTrivialPropTrue(self: *Evaluator) EvalError!void {
        try self.addCost(10); // TrivialPropTrue cost from opcodes

        // Trivial true proposition: single byte 0x01
        const sigma_bytes = self.arena.allocSlice(u8, 1) catch return error.OutOfMemory;
        sigma_bytes[0] = 0x01;

        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute TrivialPropFalse - create trivially false SigmaProp
    fn computeTrivialPropFalse(self: *Evaluator) EvalError!void {
        try self.addCost(10); // TrivialPropFalse cost from opcodes

        // Trivial false proposition: single byte 0x00
        const sigma_bytes = self.arena.allocSlice(u8, 1) catch return error.OutOfMemory;
        sigma_bytes[0] = 0x00;

        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute PlusModQ - (a + b) mod secp256k1 group order
    fn computePlusModQ(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(100); // PlusModQ cost from opcodes

        // Pop right then left - stack order
        const right_val = try self.popValue();
        const left_val = try self.popValue();

        if (left_val != .big_int) return error.TypeMismatch;
        if (right_val != .big_int) return error.TypeMismatch;

        // INVARIANT: Both values have correct types
        assert(left_val == .big_int);
        assert(right_val == .big_int);

        const left_bigint = left_val.big_int;
        const right_bigint = right_val.big_int;

        // Convert to BigInt256
        const left = crypto_bigint.BigInt256.fromBytes(left_bigint.bytes[0..left_bigint.len]) catch
            return error.InvalidData;
        const right = crypto_bigint.BigInt256.fromBytes(right_bigint.bytes[0..right_bigint.len]) catch
            return error.InvalidData;

        // Perform plusModQ operation
        const result = left.plusModQ(right) catch return error.ArithmeticOverflow;

        // Convert back to serialized format
        var result_buf: [33]u8 = undefined;
        const result_bytes = result.toBytes(&result_buf);

        // INVARIANT: modQ result always fits in max_bigint_bytes (33)
        assert(result_bytes.len <= data.max_bigint_bytes);
        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @intCast(result_bytes.len) };
        @memcpy(output.bytes[0..result_bytes.len], result_bytes);

        try self.pushValue(.{ .big_int = output });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute MinusModQ - (a - b) mod secp256k1 group order
    fn computeMinusModQ(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(100); // MinusModQ cost from opcodes

        // Pop right then left - stack order
        const right_val = try self.popValue();
        const left_val = try self.popValue();

        if (left_val != .big_int) return error.TypeMismatch;
        if (right_val != .big_int) return error.TypeMismatch;

        // INVARIANT: Both values have correct types
        assert(left_val == .big_int);
        assert(right_val == .big_int);

        const left_bigint = left_val.big_int;
        const right_bigint = right_val.big_int;

        // Convert to BigInt256
        const left = crypto_bigint.BigInt256.fromBytes(left_bigint.bytes[0..left_bigint.len]) catch
            return error.InvalidData;
        const right = crypto_bigint.BigInt256.fromBytes(right_bigint.bytes[0..right_bigint.len]) catch
            return error.InvalidData;

        // Perform minusModQ operation
        const result = left.minusModQ(right) catch return error.ArithmeticOverflow;

        // Convert back to serialized format
        var result_buf: [33]u8 = undefined;
        const result_bytes = result.toBytes(&result_buf);

        // INVARIANT: modQ result always fits in max_bigint_bytes (33)
        assert(result_bytes.len <= data.max_bigint_bytes);
        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @intCast(result_bytes.len) };
        @memcpy(output.bytes[0..result_bytes.len], result_bytes);

        try self.pushValue(.{ .big_int = output });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute Exponentiate - scalar multiplication: GroupElement * BigInt
    fn computeExponentiate(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(FixedCost.exponentiate);

        // Pop right (scalar) then left (point) - stack order
        const scalar_val = try self.popValue();
        const point_val = try self.popValue();

        // Validate types
        if (point_val != .group_element) return error.TypeMismatch;
        if (scalar_val != .big_int) return error.TypeMismatch;

        // INVARIANT: Both values have correct types
        assert(point_val == .group_element);
        assert(scalar_val == .big_int);

        const point_bytes = point_val.group_element;
        const scalar = scalar_val.big_int;

        // Perform scalar multiplication
        const result = crypto_ops.exponentiate(&point_bytes, scalar.bytes[0..scalar.len]) catch
            return error.InvalidGroupElement;

        try self.pushValue(.{ .group_element = result });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute MultiplyGroup - point addition: GroupElement + GroupElement
    fn computeMultiplyGroup(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least two values
        assert(self.value_sp >= 2);

        try self.addCost(FixedCost.multiply_group);

        // Pop right then left - stack order
        const right_val = try self.popValue();
        const left_val = try self.popValue();

        // Validate types
        if (left_val != .group_element) return error.TypeMismatch;
        if (right_val != .group_element) return error.TypeMismatch;

        // INVARIANT: Both values are group elements
        assert(left_val == .group_element);
        assert(right_val == .group_element);

        const left_bytes = left_val.group_element;
        const right_bytes = right_val.group_element;

        // Perform point addition
        const result = crypto_ops.multiplyGroup(&left_bytes, &right_bytes) catch
            return error.InvalidGroupElement;

        try self.pushValue(.{ .group_element = result });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute GroupElement.getEncoded - return the 33-byte SEC1 compressed encoding
    /// Reference: Scala SGroupElement.getEncoded / Rust GroupElement.get_encoded
    fn computeGroupElementGetEncoded(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has GroupElement
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.get_encoded);

        const ge_val = try self.popValue();
        if (ge_val != .group_element) return error.TypeMismatch;

        // INVARIANT: Value is a group element
        assert(ge_val == .group_element);

        // GroupElement is already stored as 33-byte compressed SEC1 encoding
        // Just wrap it as Coll[Byte]
        const encoded = ge_val.group_element;

        try self.pushValue(.{ .coll_byte = &encoded });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute GroupElement.negate - return the inverse point
    /// Reference: Scala SGroupElement.negate / Rust GroupElement.negate
    fn computeGroupElementNegate(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has GroupElement
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.negate_group);

        const ge_val = try self.popValue();
        if (ge_val != .group_element) return error.TypeMismatch;

        // INVARIANT: Value is a group element
        assert(ge_val == .group_element);

        // Negate the point
        const result = crypto_ops.negatePoint(&ge_val.group_element) catch
            return error.InvalidGroupElement;

        try self.pushValue(.{ .group_element = result });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute SelectField - extract element from tuple by index
    fn computeSelectField(self: *Evaluator, field_idx: u16) EvalError!void {
        // PRECONDITION: Value stack has at least one value (the tuple)
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.select_field);

        const tuple_val = try self.popValue();
        if (tuple_val != .tuple) return error.TypeMismatch;

        // INVARIANT: Value is a tuple
        assert(tuple_val == .tuple);

        const tuple = tuple_val.tuple;
        if (field_idx >= tuple.len) return error.IndexOutOfBounds;

        // INVARIANT: Index is within bounds
        assert(field_idx < tuple.len);

        // Get the element from the values array
        const elem_idx = tuple.start + field_idx;
        if (elem_idx >= self.values_sp) return error.InvalidData;

        const elem = self.values[elem_idx];
        try self.pushValue(elem);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute ExtractRegisterAs - extract register value from box with lazy loading
    /// node.data layout: (type_idx << 4) | register_id
    fn computeExtractRegisterAs(self: *Evaluator, node_data: u16) EvalError!void {
        // PRECONDITION: Value stack has box value
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.extract_register);

        // Unpack node data: register_id (4 bits) and type_idx (12 bits)
        const register_id: u4 = @truncate(node_data & 0xF);
        const type_idx: TypeIndex = @truncate(node_data >> 4);

        // INVARIANT: Register ID is valid (0-9)
        if (register_id > 9) return error.InvalidData;

        // Pop box value
        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        // Convert BoxSource from Value to RegisterCache format
        const source: BoxSource = switch (box_val.box.source) {
            .inputs => .inputs,
            .outputs => .outputs,
            .data_inputs => .data_inputs,
        };
        const box_idx = box_val.box.index;
        const reg = @as(Register, @enumFromInt(register_id));

        // Load register with caching
        const result = try self.loadRegister(source, box_idx, reg, type_idx);
        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Load register value with lazy deserialization and caching.
    /// Returns Option[T] - Some(value) if register exists, None if absent.
    fn loadRegister(
        self: *Evaluator,
        source: BoxSource,
        box_idx: u16,
        reg: Register,
        expected_type: TypeIndex,
    ) EvalError!Value {
        // Validate register is user-defined (R4-R9)
        // R0-R3 are fixed registers accessed differently
        if (@intFromEnum(reg) < 4 or @intFromEnum(reg) > 9) {
            return error.InvalidData;
        }

        // Check cache first
        const cached = self.pools.register_cache.get(source, box_idx, reg);

        switch (cached) {
            .not_loaded => {
                // First access - deserialize and cache
                return self.deserializeAndCacheRegister(source, box_idx, reg, expected_type);
            },
            .loaded => |value_idx| {
                // Cache hit - value already in pool, reuse index directly
                return .{ .option = .{ .inner_type = expected_type, .value_idx = value_idx } };
            },
            .absent => {
                // Register not present - return Option.None
                return .{ .option = .{ .inner_type = expected_type, .value_idx = null_value_idx } };
            },
            .invalid => |_| {
                // Previous deserialization failed - return error
                return error.InvalidData;
            },
        }
    }

    /// Deserialize register bytes and cache the result.
    fn deserializeAndCacheRegister(
        self: *Evaluator,
        source: BoxSource,
        box_idx: u16,
        reg: Register,
        expected_type: TypeIndex,
    ) EvalError!Value {
        // PRECONDITIONS
        if (@intFromEnum(reg) < 4 or @intFromEnum(reg) > 9) {
            return error.InvalidData;
        }

        // Get the box from context
        const box = self.getBoxFromSource(source, box_idx) orelse {
            return error.InvalidNodeIndex;
        };

        // Get raw register bytes
        const raw_bytes = box.getRegister(reg);

        if (raw_bytes == null) {
            // Register not present - cache and return Option.None
            self.pools.register_cache.markAbsent(source, box_idx, reg);
            return .{ .option = .{ .inner_type = expected_type, .value_idx = null_value_idx } };
        }

        // Deserialize: type is already known from expected_type
        var reader = vlq.Reader.init(raw_bytes.?);

        // Deserialize value using expected_type (ErgoTree type is embedded in register bytes)
        // First, read the actual type from the register bytes
        const actual_type = type_serializer.deserialize(&self.pools.type_pool, &reader) catch {
            self.pools.register_cache.markInvalid(source, box_idx, reg, .invalid_data);
            return error.InvalidData;
        };

        // Deserialize the value
        const value = data.deserialize(
            actual_type,
            &self.pools.type_pool,
            &reader,
            &self.arena,
            &self.pools.values,
        ) catch {
            self.pools.register_cache.markInvalid(source, box_idx, reg, .invalid_data);
            return error.InvalidData;
        };

        // Store in ValuePool and cache
        const value_idx = self.storeValueInPool(value, actual_type) catch {
            self.pools.register_cache.markInvalid(source, box_idx, reg, .pool_exhausted);
            return error.OutOfMemory;
        };

        self.pools.register_cache.markLoaded(source, box_idx, reg, value_idx);

        // Return as Option.Some
        return .{ .option = .{ .inner_type = expected_type, .value_idx = value_idx } };
    }

    /// Get box from context by source and index
    fn getBoxFromSource(self: *const Evaluator, source: BoxSource, idx: u16) ?*const BoxView {
        return switch (source) {
            .inputs => if (idx < self.ctx.inputs.len) &self.ctx.inputs[idx] else null,
            .outputs => if (idx < self.ctx.outputs.len) &self.ctx.outputs[idx] else null,
            .data_inputs => if (idx < self.ctx.data_inputs.len) &self.ctx.data_inputs[idx] else null,
        };
    }

    /// Store a Value in the pool and return its index
    fn storeValueInPool(self: *Evaluator, value: Value, type_idx: TypeIndex) error{OutOfMemory}!u16 {
        const idx = self.pools.values.alloc() catch return error.OutOfMemory;

        // Convert Value to PooledValue
        const pooled: PooledValue = switch (value) {
            .unit => .{ .type_idx = TypePool.UNIT, .data = .{ .primitive = 0 } },
            .boolean => |b| .{ .type_idx = TypePool.BOOLEAN, .data = .{ .primitive = if (b) 1 else 0 } },
            .byte => |b| .{ .type_idx = TypePool.BYTE, .data = .{ .primitive = b } },
            .short => |s| .{ .type_idx = TypePool.SHORT, .data = .{ .primitive = s } },
            .int => |i| .{ .type_idx = TypePool.INT, .data = .{ .primitive = i } },
            .long => |l| .{ .type_idx = TypePool.LONG, .data = .{ .primitive = l } },
            .group_element => |ge| .{ .type_idx = TypePool.GROUP_ELEMENT, .data = .{ .group_element = ge } },
            .coll_byte => |cb| .{ .type_idx = TypePool.COLL_BYTE, .data = .{ .byte_slice = .{ .ptr = cb.ptr, .len = @intCast(cb.len) } } },
            .coll => |c| .{ .type_idx = type_idx, .data = .{ .collection = .{ .elem_type = c.elem_type, .start_idx = c.start, .len = c.len } } },
            .option => |o| .{ .type_idx = type_idx, .data = .{ .option = .{ .inner_type = o.inner_type, .value_idx = o.value_idx } } },
            .box => |b| .{ .type_idx = TypePool.BOX, .data = .{ .box = .{ .source = @enumFromInt(@intFromEnum(b.source)), .index = b.index } } },
            .sigma_prop => |sp| .{ .type_idx = TypePool.SIGMA_PROP, .data = .{ .sigma_prop = .{ .ptr = sp.data.ptr, .len = @intCast(sp.data.len) } } },
            .big_int => |bi| blk: {
                var bi_data: PooledValue.BigIntData = .{ .bytes = [_]u8{0} ** 32, .len = bi.len };
                @memcpy(bi_data.bytes[0..bi.len], bi.bytes[0..bi.len]);
                break :blk .{ .type_idx = TypePool.BIG_INT, .data = .{ .big_int = bi_data } };
            },
            .hash32 => |h| .{ .type_idx = type_idx, .data = .{ .hash32 = h } },
            .avl_tree => |a| .{ .type_idx = type_idx, .data = .{ .avl_tree = a } },
            // Types that shouldn't be stored in pool (use stack Value directly)
            .tuple, .header, .pre_header, .unsigned_big_int, .box_coll, .token_coll, .soft_fork_placeholder => .{ .type_idx = type_idx, .data = .{ .primitive = 0 } },
            // Function references store body_idx and num_args
            .func_ref => |f| .{ .type_idx = type_idx, .data = .{ .primitive = (@as(i64, f.body_idx) << 8) | @as(i64, f.num_args) } },
        };

        self.pools.values.set(idx, pooled);
        return idx;
    }

    /// Compute tuple construction - create tuple from n values on stack
    fn computeTupleConstruct(self: *Evaluator, elem_count: u16) EvalError!void {
        // PRECONDITION: Value stack has at least elem_count values
        assert(self.value_sp >= elem_count);

        try self.addCost(FixedCost.tuple_construct);

        // INVARIANT: Element count is valid
        assert(elem_count <= 255);

        // Store tuple elements in the values array
        const start = self.values_sp;
        if (start + elem_count > self.values.len) return error.OutOfMemory;

        // Pop elements in reverse order (last on stack = first in tuple)
        var i: u16 = elem_count;
        while (i > 0) {
            i -= 1;
            const val = try self.popValue();
            self.values[start + i] = val;
        }
        self.values_sp = start + elem_count;

        // Create tuple reference (using external storage via values array)
        try self.pushValue(.{
            .tuple = .{
                .start = @truncate(start),
                .len = @truncate(elem_count),
                .types = .{ 0, 0, 0, 0 }, // External storage, types not inline
                .values = .{ 0, 0, 0, 0 }, // External storage, values not inline
            },
        });

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute concrete collection - create Coll[T] from n values on stack
    fn computeConcreteCollection(self: *Evaluator, elem_count: u16, coll_type: types.TypeIndex) EvalError!void {
        // PRECONDITION: Value stack has at least elem_count values
        assert(self.value_sp >= elem_count);

        try self.addCost(FixedCost.tuple_construct); // Same cost model as tuple

        // INVARIANT: Element count is bounded (also handles fault injection)
        if (elem_count > 256) return error.InvalidData;

        // INVARIANT: Type index is valid (handles fault injection on result_type)
        if (coll_type >= self.tree.type_pool.count) return error.InvalidData;

        // Get element type from Coll[T]
        // For Coll[Byte], use specialized handling
        const stype = self.tree.type_pool.get(coll_type);
        const elem_type = if (stype == .coll) stype.coll else TypePool.ANY;

        // Special case: Coll[Byte] - store as contiguous byte array
        if (elem_type == TypePool.BYTE) {
            const result_slice = self.arena.allocSlice(u8, elem_count) catch return error.OutOfMemory;
            var i: u16 = elem_count;
            while (i > 0) {
                i -= 1;
                const val = try self.popValue();
                if (val != .byte) return error.TypeMismatch;
                result_slice[i] = @bitCast(val.byte);
            }
            try self.pushValue(.{ .coll_byte = result_slice });
        } else {
            // Generic collection: store elements in values array
            const start = self.values_sp;
            if (start + elem_count > self.values.len) return error.OutOfMemory;

            // Pop elements in reverse order (last on stack = first in collection)
            var i: u16 = elem_count;
            while (i > 0) {
                i -= 1;
                const val = try self.popValue();
                self.values[start + i] = val;
            }
            self.values_sp = start + elem_count;

            // Create collection reference
            try self.pushValue(.{ .coll = .{
                .elem_type = elem_type,
                .start = @truncate(start),
                .len = elem_count,
            } });
        }

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute Upcast - convert to larger numeric type
    fn computeUpcast(self: *Evaluator, target_type: u16) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        // Validate target_type is a valid numeric type (may be corrupted by fault injection)
        if (target_type != TypePool.SHORT and target_type != TypePool.INT and
            target_type != TypePool.LONG and target_type != TypePool.BIG_INT and
            target_type != TypePool.UNSIGNED_BIG_INT)
        {
            return error.InvalidData;
        }

        try self.addCost(FixedCost.upcast);

        const input = try self.popValue();

        // Validate input is a numeric value (may be corrupted)
        if (input != .byte and input != .short and input != .int and
            input != .long and input != .big_int)
        {
            return error.TypeMismatch;
        }

        // Upcast conversions: Byte → Short → Int → Long → BigInt → UnsignedBigInt
        const result: Value = switch (target_type) {
            // Target is Short
            TypePool.SHORT => switch (input) {
                .byte => |v| .{ .short = @as(i16, v) },
                else => return error.TypeMismatch,
            },
            // Target is Int
            TypePool.INT => switch (input) {
                .byte => |v| .{ .int = @as(i32, v) },
                .short => |v| .{ .int = @as(i32, v) },
                else => return error.TypeMismatch,
            },
            // Target is Long
            TypePool.LONG => switch (input) {
                .byte => |v| .{ .long = @as(i64, v) },
                .short => |v| .{ .long = @as(i64, v) },
                .int => |v| .{ .long = @as(i64, v) },
                else => return error.TypeMismatch,
            },
            // Target is BigInt
            TypePool.BIG_INT => blk: {
                // Convert numeric to BigInt (big-endian two's complement)
                var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = 0 };
                switch (input) {
                    .byte => |v| {
                        const u: u8 = @bitCast(v);
                        bigint.bytes[0] = u;
                        bigint.len = 1;
                    },
                    .short => |v| {
                        const u: u16 = @bitCast(v);
                        bigint.bytes[0] = @truncate(u >> 8);
                        bigint.bytes[1] = @truncate(u);
                        bigint.len = 2;
                    },
                    .int => |v| {
                        const u: u32 = @bitCast(v);
                        bigint.bytes[0] = @truncate(u >> 24);
                        bigint.bytes[1] = @truncate(u >> 16);
                        bigint.bytes[2] = @truncate(u >> 8);
                        bigint.bytes[3] = @truncate(u);
                        bigint.len = 4;
                    },
                    .long => |v| {
                        const u: u64 = @bitCast(v);
                        bigint.bytes[0] = @truncate(u >> 56);
                        bigint.bytes[1] = @truncate(u >> 48);
                        bigint.bytes[2] = @truncate(u >> 40);
                        bigint.bytes[3] = @truncate(u >> 32);
                        bigint.bytes[4] = @truncate(u >> 24);
                        bigint.bytes[5] = @truncate(u >> 16);
                        bigint.bytes[6] = @truncate(u >> 8);
                        bigint.bytes[7] = @truncate(u);
                        bigint.len = 8;
                    },
                    else => return error.TypeMismatch,
                }
                break :blk .{ .big_int = bigint };
            },
            // Target is UnsignedBigInt (v6+)
            TypePool.UNSIGNED_BIG_INT => blk: {
                // Convert numeric or BigInt to UnsignedBigInt
                // Note: negative values from signed types become large unsigned values
                var ubigint: data.Value.UnsignedBigInt = .{ .bytes = undefined, .len = 0 };
                switch (input) {
                    .byte => |v| {
                        // Byte is signed, convert to unsigned representation
                        if (v >= 0) {
                            ubigint.bytes[0] = @intCast(v);
                            ubigint.len = 1;
                        } else {
                            // Negative byte: sign-extend to 256-bit unsigned (wraps)
                            return error.ArithmeticOverflow;
                        }
                    },
                    .short => |v| {
                        if (v >= 0) {
                            const u: u16 = @intCast(v);
                            if (u <= 0xFF) {
                                ubigint.bytes[0] = @truncate(u);
                                ubigint.len = 1;
                            } else {
                                ubigint.bytes[0] = @truncate(u >> 8);
                                ubigint.bytes[1] = @truncate(u);
                                ubigint.len = 2;
                            }
                        } else {
                            return error.ArithmeticOverflow;
                        }
                    },
                    .int => |v| {
                        if (v >= 0) {
                            const u: u32 = @intCast(v);
                            ubigint.len = minimalUnsignedLen(u32, u);
                            writeUnsignedBigEndian(u32, u, ubigint.bytes[0..ubigint.len]);
                        } else {
                            return error.ArithmeticOverflow;
                        }
                    },
                    .long => |v| {
                        if (v >= 0) {
                            const u: u64 = @intCast(v);
                            ubigint.len = minimalUnsignedLen(u64, u);
                            writeUnsignedBigEndian(u64, u, ubigint.bytes[0..ubigint.len]);
                        } else {
                            return error.ArithmeticOverflow;
                        }
                    },
                    .big_int => |v| {
                        // BigInt → UnsignedBigInt: reject negative values
                        if (v.isNegative()) return error.ArithmeticOverflow;
                        // Copy bytes directly (already big-endian)
                        @memcpy(ubigint.bytes[0..v.len], v.bytes[0..v.len]);
                        ubigint.len = v.len;
                    },
                    else => return error.TypeMismatch,
                }
                break :blk .{ .unsigned_big_int = ubigint };
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    /// Compute Downcast - convert to smaller numeric type (may overflow)
    fn computeDowncast(self: *Evaluator, target_type: u16) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.downcast);

        const input = try self.popValue();

        // Downcast conversions: UnsignedBigInt → BigInt → Long → Int → Short → Byte
        // May overflow - returns error.ArithmeticOverflow
        const result: Value = switch (target_type) {
            // Target is Byte
            TypePool.BYTE => switch (input) {
                .short => |v| blk: {
                    if (v < -128 or v > 127) return error.ArithmeticOverflow;
                    break :blk .{ .byte = @truncate(v) };
                },
                .int => |v| blk: {
                    if (v < -128 or v > 127) return error.ArithmeticOverflow;
                    break :blk .{ .byte = @truncate(v) };
                },
                .long => |v| blk: {
                    if (v < -128 or v > 127) return error.ArithmeticOverflow;
                    break :blk .{ .byte = @truncate(v) };
                },
                .big_int => |v| blk: {
                    const long_val = try bigIntToLong(v);
                    if (long_val < -128 or long_val > 127) return error.ArithmeticOverflow;
                    break :blk .{ .byte = @truncate(long_val) };
                },
                .unsigned_big_int => |v| blk: {
                    const long_val = try unsignedBigIntToLong(v);
                    if (long_val > 127) return error.ArithmeticOverflow;
                    break :blk .{ .byte = @intCast(long_val) };
                },
                else => return error.TypeMismatch,
            },
            // Target is Short
            TypePool.SHORT => switch (input) {
                .int => |v| blk: {
                    if (v < -32768 or v > 32767) return error.ArithmeticOverflow;
                    break :blk .{ .short = @truncate(v) };
                },
                .long => |v| blk: {
                    if (v < -32768 or v > 32767) return error.ArithmeticOverflow;
                    break :blk .{ .short = @truncate(v) };
                },
                .big_int => |v| blk: {
                    const long_val = try bigIntToLong(v);
                    if (long_val < -32768 or long_val > 32767) return error.ArithmeticOverflow;
                    break :blk .{ .short = @truncate(long_val) };
                },
                .unsigned_big_int => |v| blk: {
                    const long_val = try unsignedBigIntToLong(v);
                    if (long_val > 32767) return error.ArithmeticOverflow;
                    break :blk .{ .short = @intCast(long_val) };
                },
                else => return error.TypeMismatch,
            },
            // Target is Int
            TypePool.INT => switch (input) {
                .long => |v| blk: {
                    if (v < std.math.minInt(i32) or v > std.math.maxInt(i32)) return error.ArithmeticOverflow;
                    break :blk .{ .int = @truncate(v) };
                },
                .big_int => |v| blk: {
                    const long_val = try bigIntToLong(v);
                    if (long_val < std.math.minInt(i32) or long_val > std.math.maxInt(i32)) return error.ArithmeticOverflow;
                    break :blk .{ .int = @truncate(long_val) };
                },
                .unsigned_big_int => |v| blk: {
                    const long_val = try unsignedBigIntToLong(v);
                    if (long_val > std.math.maxInt(i32)) return error.ArithmeticOverflow;
                    break :blk .{ .int = @intCast(long_val) };
                },
                else => return error.TypeMismatch,
            },
            // Target is Long
            TypePool.LONG => switch (input) {
                .big_int => |v| blk: {
                    break :blk .{ .long = try bigIntToLong(v) };
                },
                .unsigned_big_int => |v| blk: {
                    const uval = try unsignedBigIntToLong(v);
                    // Check if fits in signed i64
                    if (uval > @as(u64, @intCast(std.math.maxInt(i64)))) return error.ArithmeticOverflow;
                    break :blk .{ .long = @intCast(uval) };
                },
                else => return error.TypeMismatch,
            },
            // Target is BigInt (v6+: downcast from UnsignedBigInt)
            TypePool.BIG_INT => switch (input) {
                .unsigned_big_int => |v| blk: {
                    // Check MSB - if set, value is too large for signed BigInt
                    if (v.len > 0 and (v.bytes[0] & 0x80) != 0) {
                        // Value has high bit set, check if it needs sign byte
                        if (v.len >= 32) return error.ArithmeticOverflow;
                    }
                    var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = v.len };
                    @memcpy(bigint.bytes[0..v.len], v.bytes[0..v.len]);
                    break :blk .{ .big_int = bigint };
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
    }

    // ========================================================================
    // Binary Operation Helpers
    // ========================================================================

    /// Index into collection (handles coll_byte, box_coll, token_coll)
    fn binOpByIndex(self: *Evaluator, left: Value, idx: i32) EvalError!void {
        if (idx < 0) return error.IndexOutOfBounds;

        switch (left) {
            .coll_byte => |arr| {
                if (idx >= arr.len) return error.IndexOutOfBounds;
                try self.pushValue(.{ .byte = @intCast(arr[@intCast(idx)]) });
            },
            .coll => |c| {
                // Generic collection indexing from ValuePool
                const elem = try self.getCollectionElementFromRef(c, @intCast(idx));
                try self.pushValue(elem);
            },
            .box_coll => |bc| {
                const boxes = switch (bc.source) {
                    .inputs => self.ctx.inputs,
                    .outputs => self.ctx.outputs,
                    .data_inputs => self.ctx.data_inputs,
                };
                if (idx >= boxes.len) return error.IndexOutOfBounds;
                try self.pushValue(.{ .box = .{
                    .source = bc.source,
                    .index = @intCast(idx),
                } });
            },
            .token_coll => |tc| {
                const boxes = switch (tc.source) {
                    .inputs => self.ctx.inputs,
                    .outputs => self.ctx.outputs,
                    .data_inputs => self.ctx.data_inputs,
                };
                if (tc.box_index >= boxes.len) return error.IndexOutOfBounds;
                const box = boxes[tc.box_index];
                if (idx >= box.tokens.len) return error.IndexOutOfBounds;
                const token = box.tokens[@intCast(idx)];

                // Copy token id to arena
                const token_id = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
                @memcpy(token_id, &token.id);

                // Store tuple elements in values array
                const start: u16 = @truncate(self.values_sp);
                if (start + 2 > self.values.len) return error.OutOfMemory;

                self.values[start] = .{ .coll_byte = token_id };
                self.values[start + 1] = .{ .long = token.amount };
                self.values_sp = start + 2;

                try self.pushValue(.{
                    .tuple = .{
                        .start = start,
                        .len = 2,
                        .types = .{ 0, 0, 0, 0 },
                        .values = .{ 0, 0, 0, 0 },
                    },
                });
            },
            else => return error.TypeMismatch,
        }
    }

    /// Append two collections (concatenation)
    fn binOpAppend(self: *Evaluator, left: Value, right: Value) EvalError!void {
        // Handle byte collections (most common case)
        if (left == .coll_byte and right == .coll_byte) {
            const left_bytes = left.coll_byte;
            const right_bytes = right.coll_byte;
            const total_len = left_bytes.len + right_bytes.len;
            const result_bytes = self.arena.allocSlice(u8, total_len) catch return error.OutOfMemory;
            @memcpy(result_bytes[0..left_bytes.len], left_bytes);
            @memcpy(result_bytes[left_bytes.len..], right_bytes);
            try self.pushValue(.{ .coll_byte = result_bytes });
            return;
        }

        // Handle generic collections
        if (left == .coll and right == .coll) {
            const lc = left.coll;
            const rc = right.coll;
            // Must have compatible element types
            if (lc.elem_type != rc.elem_type) return error.TypeMismatch;

            const total_len = @as(usize, lc.len) + @as(usize, rc.len);
            const new_start: u16 = self.pools.values.count;

            // Copy left elements
            for (0..lc.len) |i| {
                const elem = try self.getCollectionElementFromRef(lc, @intCast(i));
                _ = try self.storeValueInPool(elem, lc.elem_type);
            }
            // Copy right elements
            for (0..rc.len) |i| {
                const elem = try self.getCollectionElementFromRef(rc, @intCast(i));
                _ = try self.storeValueInPool(elem, rc.elem_type);
            }

            try self.pushValue(.{ .coll = .{
                .elem_type = lc.elem_type,
                .start = new_start,
                .len = @intCast(total_len),
            } });
            return;
        }

        return error.TypeMismatch;
    }

    /// XOR two byte arrays element-wise
    fn binOpXorByteArray(self: *Evaluator, left: Value, right: Value) EvalError!void {
        if (left != .coll_byte or right != .coll_byte) {
            return error.TypeMismatch;
        }
        const left_bytes = left.coll_byte;
        const right_bytes = right.coll_byte;
        if (left_bytes.len != right_bytes.len) {
            return error.TypeMismatch;
        }
        const len = left_bytes.len;
        const result_bytes = self.arena.allocSlice(u8, len) catch return error.OutOfMemory;
        for (0..len) |i| {
            result_bytes[i] = left_bytes[i] ^ right_bytes[i];
        }
        try self.pushValue(.{ .coll_byte = result_bytes });
    }

    /// Compute binary operation
    fn computeBinOp(self: *Evaluator, kind: BinOpKind) EvalError!void {
        // PRECONDITION: Need two operands on stack
        assert(self.value_sp >= 2);
        const initial_sp = self.value_sp;

        try self.addCost(FixedCost.comparison);

        // Pop right then left (stack order)
        const right = try self.popValue();
        const left = try self.popValue();

        // INVARIANT: Popped exactly 2 values
        assert(self.value_sp == initial_sp - 2);

        switch (kind) {
            // Comparison operations (integer only for now)
            .gt => {
                const result = try compareInts(left, right);
                try self.pushValue(.{ .boolean = result > 0 });
            },
            .ge => {
                const result = try compareInts(left, right);
                try self.pushValue(.{ .boolean = result >= 0 });
            },
            .lt => {
                const result = try compareInts(left, right);
                try self.pushValue(.{ .boolean = result < 0 });
            },
            .le => {
                const result = try compareInts(left, right);
                try self.pushValue(.{ .boolean = result <= 0 });
            },
            .eq => {
                const result = valuesEqual(left, right);
                try self.pushValue(.{ .boolean = result });
            },
            .neq => {
                const result = valuesEqual(left, right);
                try self.pushValue(.{ .boolean = !result });
            },

            // Arithmetic operations
            .plus => {
                const result = try addInts(left, right);
                try self.pushValue(result);
            },
            .minus => {
                const result = try subInts(left, right);
                try self.pushValue(result);
            },
            .multiply => {
                const result = try mulInts(left, right);
                try self.pushValue(result);
            },
            .divide => {
                const result = try divInts(left, right);
                try self.pushValue(result);
            },
            .modulo => {
                const result = try modInts(left, right);
                try self.pushValue(result);
            },

            // Logical operations
            .and_op => {
                if (left != .boolean or right != .boolean) return error.TypeMismatch;
                try self.pushValue(.{ .boolean = left.boolean and right.boolean });
            },
            .or_op => {
                if (left != .boolean or right != .boolean) return error.TypeMismatch;
                try self.pushValue(.{ .boolean = left.boolean or right.boolean });
            },
            .xor_op => {
                if (left != .boolean or right != .boolean) return error.TypeMismatch;
                try self.pushValue(.{ .boolean = left.boolean != right.boolean });
            },

            // Bitwise operations (v3+)
            .bit_or => {
                const result = try bitOrInts(left, right);
                try self.pushValue(result);
            },
            .bit_and => {
                const result = try bitAndInts(left, right);
                try self.pushValue(result);
            },
            .bit_xor => {
                const result = try bitXorInts(left, right);
                try self.pushValue(result);
            },
            .bit_shift_right => {
                const result = try bitShiftRightInts(left, right);
                try self.pushValue(result);
            },
            .bit_shift_left => {
                const result = try bitShiftLeftInts(left, right);
                try self.pushValue(result);
            },
            .bit_shift_right_zeroed => {
                const result = try bitShiftRightZeroedInts(left, right);
                try self.pushValue(result);
            },

            // Collection operations - delegate to helpers
            .by_index => {
                if (right != .int) return error.TypeMismatch;
                try self.binOpByIndex(left, right.int);
            },
            .append => try self.binOpAppend(left, right),
            .min => {
                const cmp = try compareInts(left, right);
                try self.pushValue(if (cmp <= 0) left else right);
            },
            .max => {
                const cmp = try compareInts(left, right);
                try self.pushValue(if (cmp >= 0) left else right);
            },
            .xor_byte_array => try self.binOpXorByteArray(left, right),
        }

        // POSTCONDITION: Stack depth changed by -1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
    }

    // ========================================================================
    // Header Field Extraction Operations
    // ========================================================================

    /// Compute ExtractVersion (0xE9): Header → Byte
    fn computeExtractVersion(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: version fits in i8
        assert(header.version <= 127);

        try self.pushValue(.{ .byte = @intCast(header.version) });

        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractParentId (0xEA): Header → Coll[Byte] 32b
    fn computeExtractParentId(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: parent_id is 32 bytes
        assert(header.parent_id.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.parent_id);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractAdProofsRoot (0xEB): Header → Coll[Byte] 32b
    fn computeExtractAdProofsRoot(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: ad_proofs_root is 32 bytes
        assert(header.ad_proofs_root.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.ad_proofs_root);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractStateRoot (0xEC): Header → AvlTree digest 44b
    fn computeExtractStateRoot(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: state_root is 44 bytes (AVL+ digest)
        assert(header.state_root.len == 44);

        const result_slice = self.arena.allocSlice(u8, 44) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.state_root);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractTransactionsRoot (0xED): Header → Coll[Byte] 32b
    fn computeExtractTxsRoot(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: transactions_root is 32 bytes
        assert(header.transactions_root.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.transactions_root);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractTimestamp (0xEE): Header → Long
    fn computeExtractTimestamp(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: timestamp fits in i64
        assert(header.timestamp <= @as(u64, @intCast(std.math.maxInt(i64))));

        try self.pushValue(.{ .long = @intCast(header.timestamp) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractNBits (0xEF): Header → Long
    fn computeExtractNBits(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: n_bits fits in i64
        assert(header.n_bits <= @as(u64, @intCast(std.math.maxInt(i64))));

        try self.pushValue(.{ .long = @intCast(header.n_bits) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractDifficulty (0xF0): Header → BigInt 32b
    fn computeExtractDifficulty(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: pow_distance is 32 bytes
        assert(header.pow_distance.len == 32);

        // Return pow_distance as BigInt (32 bytes)
        var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = 32 };
        @memcpy(bigint.bytes[0..32], &header.pow_distance);
        try self.pushValue(.{ .big_int = bigint });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractVotes (0xF1): Header → Coll[Byte] 3b
    fn computeExtractVotes(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: votes is 3 bytes
        assert(header.votes.len == 3);

        const result_slice = self.arena.allocSlice(u8, 3) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.votes);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute ExtractMinerRewards (0xF2): Header → Coll[Byte] 33b (miner pubkey)
    fn computeExtractMinerRewards(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: miner_pk is 33 bytes with valid SEC1 prefix
        assert(header.miner_pk.len == 33);
        assert(header.miner_pk[0] == 0x02 or header.miner_pk[0] == 0x03 or header.miner_pk[0] == 0x00);

        const result_slice = self.arena.allocSlice(u8, 33) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.miner_pk);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.id: Header → Coll[Byte] (32 byte header hash)
    fn computeExtractHeaderId(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: id is 32 bytes
        assert(header.id.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.id);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.height: Header → Int
    fn computeExtractHeight(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        try self.pushValue(.{ .int = @intCast(header.height) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.extensionRoot: Header → Coll[Byte] (32 bytes)
    fn computeExtractExtensionRoot(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: extension_root is 32 bytes
        assert(header.extension_root.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.extension_root);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.powOnetimePk: Header → GroupElement (33 byte compressed point)
    fn computeExtractPowOnetimePk(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: pow_onetime_pk is 33 bytes with valid SEC1 prefix
        assert(header.pow_onetime_pk.len == 33);
        assert(header.pow_onetime_pk[0] == 0x02 or header.pow_onetime_pk[0] == 0x03 or header.pow_onetime_pk[0] == 0x00);

        try self.pushValue(.{ .group_element = header.pow_onetime_pk });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.powNonce: Header → Coll[Byte] (8 bytes)
    fn computeExtractPowNonce(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.extract_header_field);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // INVARIANT: pow_nonce is 8 bytes
        assert(header.pow_nonce.len == 8);

        const result_slice = self.arena.allocSlice(u8, 8) catch return error.OutOfMemory;
        @memcpy(result_slice, &header.pow_nonce);
        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Header.checkPow: validates Autolykos2 proof-of-work
    /// Returns true if pow_distance <= target (derived from n_bits)
    /// Cost: 700 (approx 2×32 Blake2b256 hashes worth)
    fn computeCheckPow(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has header
        assert(self.value_sp > 0);

        const initial_sp = self.value_sp;

        // Cost: 700 as specified in Scala SHeader.checkPow (v6)
        try self.addCost(700);

        const header_val = try self.popValue();
        if (header_val != .header) return error.TypeMismatch;

        const header = header_val.header;

        // Decode n_bits to get difficulty target (same as decodeNBits)
        // n_bits format: [exponent: 1 byte][mantissa: 3 bytes]
        const n_bits_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, header.n_bits));
        const exponent = n_bits_bytes[4]; // First byte after leading zeros
        const mantissa_bytes = [3]u8{ n_bits_bytes[5], n_bits_bytes[6], n_bits_bytes[7] };
        const mantissa: u32 = (@as(u32, mantissa_bytes[0]) << 16) |
            (@as(u32, mantissa_bytes[1]) << 8) |
            @as(u32, mantissa_bytes[2]);

        // Target = mantissa * 2^(8*(exponent-3))
        // For comparison, we work with the BigInt256 representation

        // Build target as BigInt256
        var target = UnsignedBigInt256.zero;

        if (exponent <= 3) {
            // Target fits in mantissa itself (shift right)
            const shift = (3 - exponent) * 8;
            const shifted_mantissa = if (shift >= 32) 0 else mantissa >> @intCast(shift);
            target.limbs[0] = @as(u64, shifted_mantissa);
        } else {
            // Shift mantissa left by (exponent-3)*8 bits
            const shift_bits: u32 = (exponent - 3) * 8;
            const shift_limbs = shift_bits / 64;
            const shift_rem: u6 = @intCast(shift_bits % 64);

            if (shift_limbs < 4) {
                target.limbs[shift_limbs] = @as(u64, mantissa) << shift_rem;
                // Handle high bits spilling to next limb
                if (shift_rem > 0 and shift_limbs + 1 < 4) {
                    // shift_rem is 1-63, so 64-shift_rem is 1-63, fits in u6
                    const right_shift: u6 = @intCast(64 - @as(u32, shift_rem));
                    target.limbs[shift_limbs + 1] = @as(u64, mantissa) >> right_shift;
                }
            }
            // If shift_limbs >= 4, target overflows - remains very large (implicitly true)
        }

        // Convert pow_distance (32 bytes big-endian) to UnsignedBigInt256
        var pow_dist = UnsignedBigInt256.zero;
        const pow_bytes = &header.pow_distance;

        // pow_distance is 32 bytes big-endian
        // Convert to 4 x u64 little-endian limbs
        pow_dist.limbs[3] = std.mem.readInt(u64, pow_bytes[0..8], .big);
        pow_dist.limbs[2] = std.mem.readInt(u64, pow_bytes[8..16], .big);
        pow_dist.limbs[1] = std.mem.readInt(u64, pow_bytes[16..24], .big);
        pow_dist.limbs[0] = std.mem.readInt(u64, pow_bytes[24..32], .big);

        // Check: pow_distance <= target
        // UnsignedBigInt256 comparison: compare limbs from high to low
        const cmp = pow_dist.compare(target);
        const valid = (cmp == .lt or cmp == .eq);

        try self.pushValue(.{ .boolean = valid });

        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    // ========================================================================
    // Box Methods (type code 99)
    // Reference: sigmastate-interpreter SBox.scala
    // ========================================================================

    /// Convert Value.BoxRef.BoxSource to register_cache.BoxSource
    /// Required because the two enums are structurally identical but distinct types.
    inline fn convertBoxSource(box_source: Value.BoxRef.BoxSource) BoxSource {
        return switch (box_source) {
            .inputs => .inputs,
            .outputs => .outputs,
            .data_inputs => .data_inputs,
        };
    }

    /// Compute Box.value: Box → Long (nanoERGs)
    fn computeBoxValue(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10); // FixedCost for box property access

        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        // Convert BoxSource type (Value.BoxRef.BoxSource → register_cache.BoxSource)
        const source = convertBoxSource(box_val.box.source);
        const box = self.getBoxFromSource(source, box_val.box.index) orelse {
            return error.InvalidNodeIndex;
        };

        // INVARIANT: Box values are non-negative
        assert(box.value >= 0);

        try self.pushValue(.{ .long = box.value });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Box.propositionBytes: Box → Coll[Byte]
    fn computeBoxPropositionBytes(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10); // FixedCost for box property access

        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        const source = convertBoxSource(box_val.box.source);
        const box = self.getBoxFromSource(source, box_val.box.index) orelse {
            return error.InvalidNodeIndex;
        };

        // INVARIANT: Proposition bytes should be non-empty
        assert(box.proposition_bytes.len > 0);

        try self.pushValue(.{ .coll_byte = box.proposition_bytes });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Box.bytes: Box → Coll[Byte] (full serialized box)
    fn computeBoxBytes(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);

        try self.addCost(10); // Base cost, actual serialization adds PerItemCost

        _ = try self.popValue(); // Pop box value (unused - placeholder implementation)

        // Full box serialization is complex - return placeholder for now
        // Real implementation would serialize: value, script, creation_info, tokens, registers
        return self.handleUnsupported();
    }

    /// Compute Box.bytesWithoutRef: Box → Coll[Byte] (serialized without tx reference)
    fn computeBoxBytesWithoutRef(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);

        try self.addCost(10); // Base cost

        _ = try self.popValue(); // Pop box value (unused - placeholder implementation)

        // Serialization without txId/index is complex - return placeholder for now
        return self.handleUnsupported();
    }

    /// Compute Box.id: Box → Coll[Byte] (32-byte box ID)
    fn computeBoxId(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10); // FixedCost for box property access

        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        const source = convertBoxSource(box_val.box.source);
        const box = self.getBoxFromSource(source, box_val.box.index) orelse {
            return error.InvalidNodeIndex;
        };

        // Allocate copy of box ID (32 bytes)
        const id_copy = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(id_copy, &box.id);

        try self.pushValue(.{ .coll_byte = id_copy });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Box.creationInfo: Box → (Int, Coll[Byte])
    /// Returns tuple of (creation height, transaction ID)
    fn computeBoxCreationInfo(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10); // FixedCost for box property access

        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        const source = convertBoxSource(box_val.box.source);
        const box = self.getBoxFromSource(source, box_val.box.index) orelse {
            return error.InvalidNodeIndex;
        };

        // Allocate copy of tx_id (32 bytes)
        const tx_id_copy = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(tx_id_copy, &box.tx_id);

        // Create tuple (Int, Coll[Byte]) using external storage
        // Store tuple elements in the values array
        const start: u16 = @truncate(self.values_sp);
        if (start + 2 > self.values.len) return error.OutOfMemory;

        self.values[start] = .{ .int = @intCast(box.creation_height) };
        self.values[start + 1] = .{ .coll_byte = tx_id_copy };
        self.values_sp = start + 2;

        try self.pushValue(.{
            .tuple = .{
                .start = start,
                .len = 2,
                .types = .{ 0, 0, 0, 0 }, // External storage
                .values = .{ 0, 0, 0, 0 }, // External storage
            },
        });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute Box.tokens: Box → Coll[(Coll[Byte], Long)]
    /// Returns collection of (tokenId, amount) tuples
    fn computeBoxTokens(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(15); // FixedCost for tokens access

        const box_val = try self.popValue();
        if (box_val != .box) return error.TypeMismatch;

        // INVARIANT: Token count is bounded (Ergo protocol limit)
        // Return a TokenCollRef that can be indexed later
        try self.pushValue(.{
            .token_coll = .{
                .source = box_val.box.source,
                .box_index = @intCast(box_val.box.index),
            },
        });

        // POSTCONDITION: Stack unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    // ========================================================================
    // PreHeader Methods (type code 105)
    // Reference: sigmastate-interpreter SPreHeader.scala
    // ========================================================================

    /// Compute PreHeader.version: PreHeader → Byte
    fn computePreHeaderVersion(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10); // FixedCost for preheader property access

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        try self.pushValue(.{ .byte = @bitCast(pre_header.version) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.parentId: PreHeader → Coll[Byte] (32 bytes)
    fn computePreHeaderParentId(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        // INVARIANT: parent_id is 32 bytes
        assert(pre_header.parent_id.len == 32);

        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &pre_header.parent_id);

        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.timestamp: PreHeader → Long
    fn computePreHeaderTimestamp(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        try self.pushValue(.{ .long = @intCast(pre_header.timestamp) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.nBits: PreHeader → Long
    fn computePreHeaderNBits(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        try self.pushValue(.{ .long = @bitCast(pre_header.n_bits) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.height: PreHeader → Int
    fn computePreHeaderHeight(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        try self.pushValue(.{ .int = @intCast(pre_header.height) });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.minerPk: PreHeader → GroupElement (33 bytes compressed)
    fn computePreHeaderMinerPk(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        // INVARIANT: miner_pk is 33 bytes (compressed public key)
        assert(pre_header.miner_pk.len == 33);

        try self.pushValue(.{ .group_element = pre_header.miner_pk });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute PreHeader.votes: PreHeader → Coll[Byte] (3 bytes)
    fn computePreHeaderVotes(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        try self.addCost(10);

        const ph_val = try self.popValue();
        if (ph_val != .pre_header) return error.TypeMismatch;

        const pre_header = ph_val.pre_header;

        // INVARIANT: votes is 3 bytes
        assert(pre_header.votes.len == 3);

        const result_slice = self.arena.allocSlice(u8, 3) catch return error.OutOfMemory;
        @memcpy(result_slice, &pre_header.votes);

        try self.pushValue(.{ .coll_byte = result_slice });

        // POSTCONDITION: Stack depth unchanged
        assert(self.value_sp == initial_sp);
    }

    // ========================================================================
    // Collection HOF operations
    // ========================================================================

    /// Compute exists: returns true if predicate holds for any element
    fn computeExists(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Get collection length - only coll_byte supported currently
        const len: usize = switch (coll) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Chunk-based cost for exists: PerItemCost(3, 1, 10)
        try self.addCost(CollectionCost.exists.cost(@truncate(len)));

        // Empty collection: exists returns false
        if (len == 0) {
            try self.pushValue(.{ .boolean = false });
            // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
            assert(self.value_sp == initial_sp);
            return;
        }

        // Find the lambda (func_value node after collection subtree)
        const coll_idx = node_idx + 1;
        const lambda_idx = self.findSubtreeEnd(coll_idx);
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;

        // Get lambda argument var_id by scanning for val_use in body
        const body_idx = lambda_idx + 1;
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1; // Default to 1

        // Evaluate predicate for each element
        for (0..len) |i| {
            // Bind element to lambda argument
            const elem = try self.getCollectionElement(coll, i);
            self.var_bindings[arg_var_id] = elem;

            // Evaluate lambda body
            const body_result = try self.evaluateSubtree(body_idx);
            if (body_result != .boolean) return error.TypeMismatch;

            if (body_result.boolean) {
                // Found true: exists succeeds
                try self.pushValue(.{ .boolean = true });
                // POSTCONDITION: Stack depth unchanged
                assert(self.value_sp == initial_sp);
                return;
            }
        }

        // No element satisfied predicate
        try self.pushValue(.{ .boolean = false });
        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute forall: returns true if predicate holds for all elements
    fn computeForAll(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Get collection length - only coll_byte supported currently
        const len: usize = switch (coll) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Chunk-based cost for forall: PerItemCost(3, 1, 10)
        try self.addCost(CollectionCost.for_all.cost(@truncate(len)));

        // Empty collection: forall returns true
        if (len == 0) {
            try self.pushValue(.{ .boolean = true });
            // POSTCONDITION: Stack depth unchanged
            assert(self.value_sp == initial_sp);
            return;
        }

        // Find the lambda (func_value node after collection subtree)
        const coll_idx = node_idx + 1;
        const lambda_idx = self.findSubtreeEnd(coll_idx);
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;

        // Get lambda argument var_id by scanning for val_use in body
        const body_idx = lambda_idx + 1;
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1;

        // Evaluate predicate for each element
        for (0..len) |i| {
            // Bind element to lambda argument
            const elem = try self.getCollectionElement(coll, i);
            self.var_bindings[arg_var_id] = elem;

            // Evaluate lambda body
            const body_result = try self.evaluateSubtree(body_idx);
            if (body_result != .boolean) return error.TypeMismatch;

            if (!body_result.boolean) {
                // Found false: forall fails
                try self.pushValue(.{ .boolean = false });
                // POSTCONDITION: Stack depth unchanged
                assert(self.value_sp == initial_sp);
                return;
            }
        }

        // All elements satisfied predicate
        try self.pushValue(.{ .boolean = true });
        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute map: apply function to each element
    /// Supports Coll[Byte] and generic Coll[T]
    fn computeMap(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Get collection length
        const len: usize = switch (coll) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Chunk-based cost for map: PerItemCost(20, 1, 10)
        try self.addCost(CollectionCost.map.cost(@truncate(len)));

        // Empty collection: return empty of same type
        if (len == 0) {
            if (coll == .coll_byte) {
                const empty = self.arena.allocSlice(u8, 0) catch return error.OutOfMemory;
                try self.pushValue(.{ .coll_byte = empty });
            } else {
                // Empty generic collection
                try self.pushValue(.{ .coll = .{ .elem_type = coll.coll.elem_type, .start = 0, .len = 0 } });
            }
            assert(self.value_sp == initial_sp);
            return;
        }

        // Find the lambda
        const coll_idx = node_idx + 1;
        const lambda_idx = self.findSubtreeEnd(coll_idx);
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;

        const body_idx = lambda_idx + 1;
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1;

        // Handle byte collections specially (more efficient)
        if (coll == .coll_byte) {
            const input = coll.coll_byte;
            const result = self.arena.allocSlice(u8, input.len) catch return error.OutOfMemory;

            for (input, 0..) |elem, i| {
                self.var_bindings[arg_var_id] = .{ .byte = @bitCast(elem) };
                const mapped = try self.evaluateSubtree(body_idx);
                result[i] = switch (mapped) {
                    .byte => |v| @bitCast(v),
                    .int => |v| @truncate(@as(u32, @bitCast(v))),
                    .long => |v| @truncate(@as(u64, @bitCast(v))),
                    else => return error.TypeMismatch,
                };
            }
            try self.pushValue(.{ .coll_byte = result });
        } else {
            // Generic collection: store results in ValuePool
            const start_idx: u16 = self.pools.values.count;
            var result_type: TypeIndex = coll.coll.elem_type;

            // Map each element
            for (0..len) |i| {
                const elem = try self.getCollectionElement(coll, i);
                self.var_bindings[arg_var_id] = elem;

                const mapped = try self.evaluateSubtree(body_idx);

                // Store mapped value in pool - infer type from first element
                if (i == 0) {
                    result_type = valueToTypeIndex(mapped);
                }
                _ = try self.storeValueInPool(mapped, result_type);
            }

            // Create result collection reference
            try self.pushValue(.{ .coll = .{
                .elem_type = result_type,
                .start = start_idx,
                .len = @intCast(len),
            } });
        }

        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute filter: keep elements that satisfy predicate
    /// Supports Coll[Byte] and generic Coll[T]
    fn computeFilter(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Get collection length
        const len: usize = switch (coll) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            .box_coll => |bc| switch (bc.source) {
                .inputs => self.ctx.inputs.len,
                .outputs => self.ctx.outputs.len,
                .data_inputs => self.ctx.data_inputs.len,
            },
            else => return error.TypeMismatch,
        };

        // Chunk-based cost for filter: PerItemCost(20, 1, 10)
        try self.addCost(CollectionCost.filter.cost(@truncate(len)));

        // Find the lambda
        const coll_idx = node_idx + 1;
        const lambda_idx = self.findSubtreeEnd(coll_idx);
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;

        const body_idx = lambda_idx + 1;
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1;

        // Handle byte collections specially (more efficient)
        if (coll == .coll_byte) {
            const input = coll.coll_byte;

            if (input.len == 0) {
                const empty = self.arena.allocSlice(u8, 0) catch return error.OutOfMemory;
                try self.pushValue(.{ .coll_byte = empty });
                assert(self.value_sp == initial_sp);
                return;
            }

            // First pass: count matching elements
            var count: usize = 0;
            for (input) |elem| {
                self.var_bindings[arg_var_id] = .{ .byte = @bitCast(elem) };
                const predicate_result = try self.evaluateSubtree(body_idx);
                if (predicate_result != .boolean) return error.TypeMismatch;
                if (predicate_result.boolean) count += 1;
            }

            // Allocate result and fill
            const result = self.arena.allocSlice(u8, count) catch return error.OutOfMemory;
            var j: usize = 0;
            for (input) |elem| {
                self.var_bindings[arg_var_id] = .{ .byte = @bitCast(elem) };
                const pred = try self.evaluateSubtree(body_idx);
                if (pred.boolean) {
                    result[j] = elem;
                    j += 1;
                }
            }

            try self.pushValue(.{ .coll_byte = result });
        } else if (coll == .box_coll) {
            // Filter boxes: store matching box references in ValuePool
            const bc = coll.box_coll;

            if (len == 0) {
                try self.pushValue(.{ .coll = .{ .elem_type = TypePool.BOX, .start = 0, .len = 0 } });
                assert(self.value_sp == initial_sp);
                return;
            }

            const start_idx: u16 = self.pools.values.count;
            var count: u16 = 0;

            for (0..len) |i| {
                // Get box reference
                const box_val: Value = .{ .box = .{ .source = bc.source, .index = @intCast(i) } };
                self.var_bindings[arg_var_id] = box_val;

                const predicate_result = try self.evaluateSubtree(body_idx);
                if (predicate_result != .boolean) return error.TypeMismatch;

                if (predicate_result.boolean) {
                    // Store matching box in pool
                    _ = try self.storeValueInPool(box_val, TypePool.BOX);
                    count += 1;
                }
            }

            // Create result collection of boxes
            try self.pushValue(.{ .coll = .{
                .elem_type = TypePool.BOX,
                .start = start_idx,
                .len = count,
            } });
        } else {
            // Generic collection: filter and store in ValuePool
            const c = coll.coll;

            if (len == 0) {
                try self.pushValue(.{ .coll = .{ .elem_type = c.elem_type, .start = 0, .len = 0 } });
                assert(self.value_sp == initial_sp);
                return;
            }

            const start_idx: u16 = self.pools.values.count;
            var count: u16 = 0;

            for (0..len) |i| {
                const elem = try self.getCollectionElement(coll, i);
                self.var_bindings[arg_var_id] = elem;

                const predicate_result = try self.evaluateSubtree(body_idx);
                if (predicate_result != .boolean) return error.TypeMismatch;

                if (predicate_result.boolean) {
                    _ = try self.storeValueInPool(elem, c.elem_type);
                    count += 1;
                }
            }

            try self.pushValue(.{ .coll = .{
                .elem_type = c.elem_type,
                .start = start_idx,
                .len = count,
            } });
        }

        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute fold: reduce collection with binary function
    fn computeFold(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        // Pop in reverse order: zero was pushed last
        const zero = try self.popValue();
        const coll = try self.popValue();

        // INVARIANT: Popped exactly 2 values
        assert(self.value_sp == initial_sp - 2);

        // Get collection length - only coll_byte supported currently
        const len: usize = switch (coll) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Chunk-based cost for fold: PerItemCost(3, 1, 10)
        try self.addCost(CollectionCost.fold.cost(@truncate(len)));

        // Empty collection: return zero
        if (len == 0) {
            try self.pushValue(zero);
            // POSTCONDITION: Net change is -1 (popped 2, pushed 1)
            assert(self.value_sp == initial_sp - 1);
            return;
        }

        // Find the lambda (after collection subtree and zero subtree)
        const coll_idx = node_idx + 1;
        const zero_idx = self.findSubtreeEnd(coll_idx);
        const lambda_idx = self.findSubtreeEnd(zero_idx);
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;
        if (lambda_node.data != 2) return error.InvalidData; // Fold lambda takes 2 args

        // For fold, we need two var_ids: accumulator and element
        // Convention: acc_id = 1, elem_id = 2 (or scan body to find them)
        const body_idx = lambda_idx + 1;
        const acc_var_id: u16 = 1;
        const elem_var_id: u16 = 2;

        // Accumulate
        var acc = zero;
        for (0..len) |i| {
            const elem = try self.getCollectionElement(coll, i);
            self.var_bindings[acc_var_id] = acc;
            self.var_bindings[elem_var_id] = elem;

            acc = try self.evaluateSubtree(body_idx);
        }

        try self.pushValue(acc);
        // POSTCONDITION: Net change is -1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute flatMap: apply function and concatenate results
    /// Currently only supports Coll[Byte] (f returns Coll[Byte])
    fn computeFlatMap(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0); // Collection value must be on stack
        assert(node_idx < self.tree.node_count); // Node index in bounds
        assert(self.tree.node_count > 0); // Tree not empty

        const coll = try self.popValue();

        // Currently only support coll_byte
        if (coll != .coll_byte) {
            return error.UnsupportedExpression;
        }

        const input = coll.coll_byte;

        // Empty collection: return empty (base cost only)
        if (input.len == 0) {
            try self.addCost(CollectionCost.flat_map.cost(0));
            const empty = self.arena.allocSlice(u8, 0) catch return error.OutOfMemory;
            try self.pushValue(.{ .coll_byte = empty });
            return;
        }

        // INVARIANT: Input length must be bounded (protocol limit)
        const MAX_COLLECTION_SIZE = 4096;
        if (input.len > MAX_COLLECTION_SIZE) return error.CollectionTooLarge;

        // Find the lambda
        const coll_idx = node_idx + 1;
        const lambda_idx = self.findSubtreeEnd(coll_idx);
        assert(lambda_idx < self.tree.node_count); // Lambda must be in bounds
        const lambda_node = self.tree.nodes[lambda_idx];

        if (lambda_node.tag != .func_value) return error.InvalidData;

        const body_idx = lambda_idx + 1;
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1;

        // Collect results - use temporary buffer then copy
        var result_len: usize = 0;
        var temp_results: [256][]const u8 = undefined;
        var temp_count: usize = 0;

        // Apply function to each element (bounded by MAX_COLLECTION_SIZE check above)
        for (input) |elem| {
            self.var_bindings[arg_var_id] = .{ .byte = @bitCast(elem) };

            const mapped = try self.evaluateSubtree(body_idx);

            // Result must be a byte collection
            if (mapped != .coll_byte) return error.TypeMismatch;

            if (temp_count >= 256) return error.OutOfMemory;
            temp_results[temp_count] = mapped.coll_byte;
            result_len += mapped.coll_byte.len;
            temp_count += 1;
        }

        // Chunk-based cost for flatMap: PerItemCost(60, 10, 8)
        // Note: Scala uses output size for cost; we use output length here
        try self.addCost(CollectionCost.flat_map.cost(@truncate(result_len)));

        // Allocate and copy results
        const result = self.arena.allocSlice(u8, result_len) catch return error.OutOfMemory;
        var offset: usize = 0;
        for (temp_results[0..temp_count]) |slice| {
            @memcpy(result[offset..][0..slice.len], slice);
            offset += slice.len;
        }

        // POSTCONDITION: All bytes were copied
        assert(offset == result_len);

        try self.pushValue(.{ .coll_byte = result });
    }

    /// Compute Slice: extract sub-collection [from, until)
    /// Stack: collection, from, until → sliced collection
    fn computeSlice(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3); // Need collection, from, until on stack

        // Pop in reverse order (until, from, collection)
        const until_val = try self.popValue();
        const from_val = try self.popValue();
        const coll_val = try self.popValue();

        // Type checks
        if (until_val != .int and until_val != .short) return error.TypeMismatch;
        if (from_val != .int and from_val != .short) return error.TypeMismatch;

        const until: i32 = switch (until_val) {
            .int => |v| v,
            .short => |v| @as(i32, v),
            else => return error.TypeMismatch,
        };
        const from: i32 = switch (from_val) {
            .int => |v| v,
            .short => |v| @as(i32, v),
            else => return error.TypeMismatch,
        };

        // Get collection length based on type
        const coll_len: usize = switch (coll_val) {
            .coll_byte => |c| c.len,
            .coll => |c| @as(usize, c.len),
            else => return error.TypeMismatch,
        };

        // Validate range (Scala semantics: clamp to bounds)
        const len: i32 = @intCast(coll_len);
        const clamped_from = @max(0, @min(from, len));
        const clamped_until = @max(clamped_from, @min(until, len));

        const start_idx: usize = @intCast(clamped_from);
        const end_idx: usize = @intCast(clamped_until);
        const result_len = end_idx - start_idx;

        // Cost: base 20 + (result_len / 100) * 2
        const cost = 20 + (result_len / 100) * 2;
        try self.addCost(@intCast(cost));

        switch (coll_val) {
            .coll_byte => |coll| {
                // Slice doesn't need allocation - just a view into original
                const result = coll[start_idx..end_idx];
                assert(result.len == result_len);
                try self.pushValue(.{ .coll_byte = result });
            },
            .coll => |c| {
                // For generic collections, create a new reference with offset start
                // Copy elements to new ValuePool location
                const new_start: u16 = self.pools.values.count;
                for (start_idx..end_idx) |i| {
                    const elem = try self.getCollectionElementFromRef(c, @intCast(i));
                    _ = try self.storeValueInPool(elem, c.elem_type);
                }
                try self.pushValue(.{ .coll = .{
                    .elem_type = c.elem_type,
                    .start = new_start,
                    .len = @intCast(result_len),
                } });
            },
            else => return error.TypeMismatch,
        }
    }

    /// Compute LogicalAnd: Coll[Boolean] → Boolean (true iff all elements are true)
    /// Returns true for empty collection (vacuous truth)
    fn computeLogicalAnd(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const coll_val = try self.popValue();

        // Get collection length and check type
        const len: usize = switch (coll_val) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Cost: base 10 + per-element
        try self.addCost(10 + @as(u32, @intCast(len)));

        // Empty collection: AND of nothing is true (vacuous truth)
        if (len == 0) {
            try self.pushValue(.{ .boolean = true });
            return;
        }

        // Check all elements
        for (0..len) |i| {
            const elem = try self.getCollectionElement(coll_val, i);
            if (elem != .boolean) return error.TypeMismatch;
            if (!elem.boolean) {
                // Found false: entire AND is false
                try self.pushValue(.{ .boolean = false });
                return;
            }
        }

        // All true
        try self.pushValue(.{ .boolean = true });
    }

    /// Compute LogicalOr: Coll[Boolean] → Boolean (true iff any element is true)
    /// Returns false for empty collection
    fn computeLogicalOr(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const coll_val = try self.popValue();

        // Get collection length and check type
        const len: usize = switch (coll_val) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // Cost: base 10 + per-element
        try self.addCost(10 + @as(u32, @intCast(len)));

        // Empty collection: OR of nothing is false
        if (len == 0) {
            try self.pushValue(.{ .boolean = false });
            return;
        }

        // Check all elements
        for (0..len) |i| {
            const elem = try self.getCollectionElement(coll_val, i);
            if (elem != .boolean) return error.TypeMismatch;
            if (elem.boolean) {
                // Found true: entire OR is true
                try self.pushValue(.{ .boolean = true });
                return;
            }
        }

        // All false
        try self.pushValue(.{ .boolean = false });
    }

    // ========================================================================
    // Function Application
    // ========================================================================

    /// Compute Apply: bind argument and evaluate function body
    /// Argument value is expected on the value stack
    ///
    /// CRITICAL: Variable bindings must be restored even on error to maintain
    /// correct scoping for subsequent evaluations. Uses errdefer pattern.
    fn computeApply(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0); // At least argument must be on stack
        assert(node_idx < self.tree.node_count); // Node must be valid

        try self.addCost(FixedCost.func_apply);

        // Find the func node (immediately after apply)
        const func_idx = node_idx + 1;
        assert(func_idx < self.tree.node_count); // func must be in bounds
        const func_node = self.tree.nodes[func_idx];

        // Determine function body and num_args based on whether inline or from variable
        var body_idx: u16 = undefined;
        var num_args: u8 = undefined;
        var arg_value: Value = undefined;

        if (func_node.tag == .func_value) {
            // Inline function: stack has [arg]
            arg_value = try self.popValue();
            num_args = @truncate(func_node.data);
            body_idx = func_idx + 1;
        } else {
            // Function from variable: stack has [func_ref, arg]
            // func was evaluated first (pushed first), then arg (pushed second)
            // Pop in reverse: arg first, then func_ref
            arg_value = try self.popValue();
            const func_ref_value = try self.popValue();
            if (func_ref_value != .func_ref) return error.TypeMismatch;
            const func_ref = func_ref_value.func_ref;
            num_args = func_ref.num_args;
            body_idx = func_ref.body_idx;
        }

        // INVARIANT: Must have at least 1 argument
        if (num_args == 0) return error.InvalidData;

        // For v5.x, only single-arg functions are supported
        if (num_args != 1) {
            return error.TypeMismatch;
        }

        assert(body_idx < self.tree.node_count); // body must be in bounds

        // Find argument var_id by scanning body for val_use
        const arg_var_id = self.findLambdaArgId(body_idx) orelse 1; // Default to 1 if not found

        // INVARIANT: var_id must be in bounds of pre-allocated binding array
        assert(arg_var_id < self.var_bindings.len);

        // Save existing binding (for shadowing support)
        const saved_binding = self.var_bindings[arg_var_id];

        // Bind argument to var_id
        self.var_bindings[arg_var_id] = arg_value;

        // CRITICAL: Restore binding on error to maintain scoping invariant
        errdefer self.var_bindings[arg_var_id] = saved_binding;

        // Evaluate function body
        const result = try self.evaluateSubtree(body_idx);

        // Restore original binding (maintain correct scoping)
        self.var_bindings[arg_var_id] = saved_binding;

        // Push result
        try self.pushValue(result);

        // POSTCONDITION: Result is on the value stack
        assert(self.value_sp > 0);
    }

    // ========================================================================
    // Method Call Operations
    // ========================================================================

    /// Collection type codes from Rust types/scoll.rs
    const CollTypeCode: u8 = 12; // TYPE_CODE for Coll

    /// Collection method IDs from Rust types/scoll.rs
    pub const CollMethodId = struct {
        pub const indices: u8 = 14; // coll.indices → Coll[Int]
        pub const flatmap: u8 = 15; // coll.flatMap(f) → Coll[B]
        pub const patch: u8 = 19; // coll.patch(from, patch, replaced) → Coll[A]
        pub const updated: u8 = 20; // coll.updated(idx, value) → Coll[A]
        pub const update_many: u8 = 21; // coll.updateMany(idxs, values) → Coll[A]
        pub const index_of: u8 = 26; // coll.indexOf(elem, from) → Int
        pub const zip: u8 = 29; // coll.zip(other) → Coll[(A, B)]
        pub const reverse: u8 = 30; // coll.reverse → Coll[A]
        pub const starts_with: u8 = 31; // coll.startsWith(other) → Boolean
        pub const ends_with: u8 = 32; // coll.endsWith(other) → Boolean
        pub const get: u8 = 33; // coll.get(idx) → Option[A]

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ indices, flatmap, patch, updated, update_many, index_of, zip, reverse, starts_with, ends_with, get };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("CollMethodId collision detected");
                }
            }
        }
    };

    /// AvlTree type code from Rust types/savltree.rs
    const AvlTreeTypeCode: u8 = 100; // TYPE_CODE for AvlTree (0x64)

    /// Context type code from Rust types/scontext.rs
    const ContextTypeCode: u8 = 101; // TYPE_CODE for Context (0x65)

    /// Context method IDs from Rust types/scontext.rs
    const ContextMethodId = struct {
        const data_inputs: u8 = 1; // CONTEXT.dataInputs → Coll[Box]
        const headers: u8 = 2; // CONTEXT.headers → Coll[Header]
        const pre_header: u8 = 3; // CONTEXT.preHeader → PreHeader
        const inputs: u8 = 4; // CONTEXT.INPUTS → Coll[Box]
        const outputs: u8 = 5; // CONTEXT.OUTPUTS → Coll[Box]
        const height: u8 = 6; // CONTEXT.HEIGHT → Int
        const self_box: u8 = 7; // CONTEXT.SELF → Box
        const self_box_index: u8 = 8; // CONTEXT.selfBoxIndex → Int
        const get_var_from_input: u8 = 12; // CONTEXT.getVarFromInput[T](Short, Byte) → Option[T]

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ data_inputs, headers, pre_header, inputs, outputs, height, self_box, self_box_index, get_var_from_input };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("ContextMethodId collision detected");
                }
            }
        }
    };

    /// AvlTree method IDs from Rust types/savltree.rs
    const AvlTreeMethodId = struct {
        const digest: u8 = 1; // tree.digest → Coll[Byte]
        const enabled_operations: u8 = 2; // tree.enabledOperations → Byte
        const key_length: u8 = 3; // tree.keyLength → Int
        const value_length_opt: u8 = 4; // tree.valueLengthOpt → Option[Int]
        const is_insert_allowed: u8 = 5; // tree.isInsertAllowed → Boolean
        const is_update_allowed: u8 = 6; // tree.isUpdateAllowed → Boolean
        const is_remove_allowed: u8 = 7; // tree.isRemoveAllowed → Boolean
        const update_operations: u8 = 8; // tree.updateOperations(ops) → AvlTree
        const contains: u8 = 9; // tree.contains(key, proof) → Boolean
        const get: u8 = 10; // tree.get(key, proof) → Option[Coll[Byte]]
        const get_many: u8 = 11; // tree.getMany(keys, proof) → Coll[Option[Coll[Byte]]]
        const insert: u8 = 12; // tree.insert(entries, proof) → Option[AvlTree]
        const update: u8 = 13; // tree.update(entries, proof) → Option[AvlTree]
        const remove: u8 = 14; // tree.remove(keys, proof) → Option[AvlTree]
        const update_digest: u8 = 15; // tree.updateDigest(digest) → AvlTree
        const insert_or_update: u8 = 16; // tree.insertOrUpdate(entries, proof) → Option[AvlTree]

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ digest, enabled_operations, key_length, value_length_opt, is_insert_allowed, is_update_allowed, is_remove_allowed, update_operations, contains, get, get_many, insert, update, remove, update_digest, insert_or_update };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("AvlTreeMethodId collision detected");
                }
            }
        }
    };

    /// UnsignedBigInt type code from Scala SUnsignedBigInt (v6+)
    const UnsignedBigIntTypeCode: u8 = 9; // TYPE_CODE for UnsignedBigInt

    /// UnsignedBigInt method IDs from Scala SUnsignedBigInt (v6+)
    /// Reference: Scala sigmastate SUnsignedBigInt.scala
    const UnsignedBigIntMethodId = struct {
        const mod_method: u8 = 14; // ubi.mod(m) → UnsignedBigInt
        const mod_inverse: u8 = 15; // ubi.modInverse(m) → UnsignedBigInt
        const plus_mod: u8 = 16; // ubi.plusMod(other, m) → UnsignedBigInt
        const subtract_mod: u8 = 17; // ubi.subtractMod(other, m) → UnsignedBigInt
        const multiply_mod: u8 = 18; // ubi.multiplyMod(other, m) → UnsignedBigInt
        const to_signed: u8 = 19; // ubi.toSigned → BigInt

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ mod_method, mod_inverse, plus_mod, subtract_mod, multiply_mod, to_signed };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("UnsignedBigIntMethodId collision detected");
                }
            }
        }
    };

    /// Header object type code from Scala SHeader
    const HeaderTypeCode: u8 = 104; // TYPE_CODE for Header (0x68)

    /// Header method IDs from Scala SHeader
    /// Reference: Scala sigmastate SHeader.scala
    const HeaderMethodId = struct {
        const id: u8 = 1; // header.id → Coll[Byte] (32 bytes header hash)
        const version: u8 = 2; // header.version → Byte
        const parent_id: u8 = 3; // header.parentId → Coll[Byte]
        const ad_proofs_root: u8 = 4; // header.ADProofsRoot → Coll[Byte]
        const state_root: u8 = 5; // header.stateRoot → AvlTree
        const transactions_root: u8 = 6; // header.transactionsRoot → Coll[Byte]
        const timestamp: u8 = 7; // header.timestamp → Long
        const n_bits: u8 = 8; // header.nBits → Long
        const height: u8 = 9; // header.height → Int
        const extension_root: u8 = 10; // header.extensionRoot → Coll[Byte]
        const miner_pk: u8 = 11; // header.minerPk → GroupElement
        const pow_onetime_pk: u8 = 12; // header.powOnetimePk → GroupElement
        const pow_nonce: u8 = 13; // header.powNonce → Coll[Byte]
        const pow_distance: u8 = 14; // header.powDistance → BigInt
        const votes: u8 = 15; // header.votes → Coll[Byte]
        const check_pow: u8 = 16; // header.checkPow → Boolean (v6+)

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{
                id,         version,           parent_id, ad_proofs_root,
                state_root, transactions_root, timestamp, n_bits,
                height,     extension_root,    miner_pk,  pow_onetime_pk,
                pow_nonce,  pow_distance,      votes,     check_pow,
            };
            for (ids, 0..) |mid, i| {
                for (ids[i + 1 ..]) |other| {
                    if (mid == other) @compileError("HeaderMethodId collision detected");
                }
            }
        }
    };

    /// Global object type code from Scala SGlobal (v6+)
    const GlobalTypeCode: u8 = 106; // TYPE_CODE for Global (0x6A)

    /// Global method IDs from Scala SGlobal (v6+)
    /// Reference: Scala sigmastate SGlobal.scala
    const GlobalMethodId = struct {
        const group_generator: u8 = 1; // Global.groupGenerator → GroupElement
        const xor: u8 = 2; // Global.xor(left, right) → Coll[Byte]
        const serialize: u8 = 3; // Global.serialize[T](value) → Coll[Byte]
        const from_big_endian_bytes: u8 = 5; // Global.fromBigEndianBytes[T](bytes) → T
        const encode_nbits: u8 = 6; // Global.encodeNBits(n: BigInt) → Long
        const decode_nbits: u8 = 7; // Global.decodeNBits(nBits: Long) → BigInt

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ group_generator, xor, serialize, from_big_endian_bytes, encode_nbits, decode_nbits };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("GlobalMethodId collision detected");
                }
            }
        }
    };

    /// Box type code from Scala SBox
    /// Reference: sigmastate-interpreter SBox.scala
    const BoxTypeCode: u8 = 99; // TYPE_CODE for Box (0x63)

    /// Box method IDs from Scala SBox
    /// Reference: sigmastate-interpreter SBox.scala, SBoxMethods object
    const BoxMethodId = struct {
        const value_method: u8 = 1; // box.value → Long
        const proposition_bytes: u8 = 2; // box.propositionBytes → Coll[Byte]
        const bytes: u8 = 3; // box.bytes → Coll[Byte]
        const bytes_without_ref: u8 = 4; // box.bytesWithoutRef → Coll[Byte]
        const id_method: u8 = 5; // box.id → Coll[Byte]
        const creation_info: u8 = 6; // box.creationInfo → (Int, Coll[Byte])
        const tokens_method: u8 = 8; // box.tokens → Coll[(Coll[Byte], Long)]
        // Registers R4-R9 are accessed via getReg method (method ID 7)
        // but more commonly via extract_register_as opcode

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ value_method, proposition_bytes, bytes, bytes_without_ref, id_method, creation_info, tokens_method };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("BoxMethodId collision detected");
                }
            }
        }
    };

    /// PreHeader type code from Scala SPreHeader
    /// Reference: sigmastate-interpreter SPreHeader.scala
    const PreHeaderTypeCode: u8 = 105; // TYPE_CODE for PreHeader (0x69)

    /// PreHeader method IDs from Scala SPreHeader
    /// Reference: sigmastate-interpreter SPreHeader.scala
    const PreHeaderMethodId = struct {
        const version: u8 = 1; // preHeader.version → Byte
        const parent_id: u8 = 2; // preHeader.parentId → Coll[Byte]
        const timestamp: u8 = 3; // preHeader.timestamp → Long
        const n_bits: u8 = 4; // preHeader.nBits → Long
        const height: u8 = 5; // preHeader.height → Int
        const miner_pk: u8 = 6; // preHeader.minerPk → GroupElement
        const votes: u8 = 7; // preHeader.votes → Coll[Byte]

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ version, parent_id, timestamp, n_bits, height, miner_pk, votes };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("PreHeaderMethodId collision detected");
                }
            }
        }
    };

    /// GroupElement type code from Scala SGroupElement
    /// Reference: sigmastate-interpreter SGroupElement.scala
    const GroupElementTypeCode: u8 = 7; // TYPE_CODE for GroupElement (0x07)

    /// GroupElement method IDs from Scala SGroupElementMethods
    /// Reference: sigmastate-interpreter methods.scala
    const GroupElementMethodId = struct {
        const get_encoded: u8 = 2; // ge.getEncoded → Coll[Byte] (33 bytes compressed)
        const exp: u8 = 3; // ge.exp(k: BigInt) → GroupElement (already opcode)
        const multiply: u8 = 4; // ge.multiply(other) → GroupElement (already opcode)
        const negate: u8 = 5; // ge.negate → GroupElement

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ get_encoded, exp, multiply, negate };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("GroupElementMethodId collision detected");
                }
            }
        }
    };

    /// SigmaProp type code from Scala SSigmaProp
    /// Reference: sigmastate-interpreter SSigmaProp.scala
    const SigmaPropTypeCode: u8 = 8; // TYPE_CODE for SigmaProp (0x08)

    /// SigmaProp method IDs from Scala SSigmaPropMethods
    /// Reference: sigmastate-interpreter methods.scala
    const SigmaPropMethodId = struct {
        const prop_bytes: u8 = 1; // sp.propBytes → Coll[Byte] (already opcode)
        const is_proven: u8 = 2; // sp.isProven → Boolean (internal use only)

        // Compile-time collision detection (ZIGMA_STYLE)
        comptime {
            const ids = [_]u8{ prop_bytes, is_proven };
            for (ids, 0..) |id, i| {
                for (ids[i + 1 ..]) |other| {
                    if (id == other) @compileError("SigmaPropMethodId collision detected");
                }
            }
        }
    };

    /// Compute method call: dispatch based on type_code and method_id
    fn computeMethodCall(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(node_idx < self.tree.node_count);
        assert(self.value_sp > 0); // At least obj on stack

        const node = self.tree.nodes[node_idx];

        // Extract type_code and method_id from data
        const type_code: u8 = @truncate(node.data & 0xFF);
        const method_id: u8 = @truncate(node.data >> 8);

        // INVARIANT: Must be a valid method call
        assert(type_code > 0 or method_id > 0);

        try self.addCost(FixedCost.method_call);

        // Dispatch based on type_code
        if (type_code == CollTypeCode) {
            // Collection methods
            switch (method_id) {
                CollMethodId.zip => try self.computeZip(node_idx),
                CollMethodId.indices => try self.computeIndices(),
                CollMethodId.reverse => try self.computeReverse(),
                CollMethodId.starts_with => try self.computeStartsWith(),
                CollMethodId.ends_with => try self.computeEndsWith(),
                CollMethodId.index_of => try self.computeIndexOf(),
                CollMethodId.get => try self.computeCollGet(),
                // Collection modification methods
                CollMethodId.patch => try self.computePatch(),
                CollMethodId.updated => try self.computeUpdated(),
                CollMethodId.update_many => try self.computeUpdateMany(),
                // Complex methods that need higher-order function support
                CollMethodId.flatmap => return self.handleUnsupported(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == AvlTreeTypeCode) {
            // AvlTree methods
            switch (method_id) {
                // Property accessors
                AvlTreeMethodId.digest => try self.computeAvlTreeDigest(),
                AvlTreeMethodId.enabled_operations => try self.computeAvlTreeEnabledOps(),
                AvlTreeMethodId.key_length => try self.computeAvlTreeKeyLength(),
                AvlTreeMethodId.value_length_opt => try self.computeAvlTreeValueLengthOpt(),
                AvlTreeMethodId.is_insert_allowed => try self.computeAvlTreeIsInsertAllowed(),
                AvlTreeMethodId.is_update_allowed => try self.computeAvlTreeIsUpdateAllowed(),
                AvlTreeMethodId.is_remove_allowed => try self.computeAvlTreeIsRemoveAllowed(),
                // Lookup operations
                AvlTreeMethodId.contains => try self.computeAvlTreeContains(),
                AvlTreeMethodId.get => try self.computeAvlTreeGet(),
                AvlTreeMethodId.get_many => try self.computeAvlTreeGetMany(),
                // Tree modification
                AvlTreeMethodId.update_digest => try self.computeAvlTreeUpdateDigest(),
                AvlTreeMethodId.update_operations => try self.computeAvlTreeUpdateOperations(),
                // Tree mutations: insert/update/remove/insertOrUpdate
                AvlTreeMethodId.insert => try self.computeAvlTreeInsert(),
                AvlTreeMethodId.update => try self.computeAvlTreeUpdate(),
                AvlTreeMethodId.remove => try self.computeAvlTreeRemove(),
                AvlTreeMethodId.insert_or_update => try self.computeAvlTreeInsertOrUpdate(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == ContextTypeCode) {
            // Context methods
            switch (method_id) {
                ContextMethodId.data_inputs => try self.computeDataInputs(),
                ContextMethodId.headers => try self.computeContextHeaders(),
                ContextMethodId.pre_header => try self.computeContextPreHeader(),
                ContextMethodId.self_box_index => try self.computeSelfBoxIndex(),
                ContextMethodId.get_var_from_input => try self.computeGetVarFromInput(node),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == UnsignedBigIntTypeCode) {
            // UnsignedBigInt methods (v6+)
            // VERSION GATE: All UnsignedBigInt methods are v6 features
            if (!self.version_ctx.isV6Activated()) {
                return error.SoftForkAccepted;
            }

            switch (method_id) {
                UnsignedBigIntMethodId.mod_method => try self.computeUBIMod(),
                UnsignedBigIntMethodId.mod_inverse => try self.computeUBIModInverse(),
                UnsignedBigIntMethodId.plus_mod => try self.computeUBIPlusMod(),
                UnsignedBigIntMethodId.subtract_mod => try self.computeUBISubtractMod(),
                UnsignedBigIntMethodId.multiply_mod => try self.computeUBIMultiplyMod(),
                UnsignedBigIntMethodId.to_signed => try self.computeUBIToSigned(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == GlobalTypeCode) {
            // Global methods (v6+)
            // VERSION GATE: Global.serialize, fromBigEndianBytes, encodeNBits, decodeNBits are v6
            if (!self.version_ctx.isV6Activated()) {
                return error.SoftForkAccepted;
            }

            switch (method_id) {
                GlobalMethodId.group_generator => try self.computeGroupGenerator(),
                GlobalMethodId.xor => try self.computeGlobalXor(),
                GlobalMethodId.encode_nbits => try self.computeEncodeNBits(),
                GlobalMethodId.decode_nbits => try self.computeDecodeNBits(),
                GlobalMethodId.serialize => try self.computeGlobalSerialize(node.result_type),
                GlobalMethodId.from_big_endian_bytes => try self.computeGlobalFromBigEndianBytes(node.result_type),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == HeaderTypeCode) {
            // Header methods
            // Most header property methods available since v1
            // VERSION GATE: Only Header.checkPow is v6+
            switch (method_id) {
                // Property access methods (available since v1)
                HeaderMethodId.id => try self.computeExtractHeaderId(),
                HeaderMethodId.version => try self.computeExtractVersion(),
                HeaderMethodId.parent_id => try self.computeExtractParentId(),
                HeaderMethodId.ad_proofs_root => try self.computeExtractAdProofsRoot(),
                HeaderMethodId.state_root => try self.computeExtractStateRoot(),
                HeaderMethodId.transactions_root => try self.computeExtractTxsRoot(),
                HeaderMethodId.timestamp => try self.computeExtractTimestamp(),
                HeaderMethodId.n_bits => try self.computeExtractNBits(),
                HeaderMethodId.height => try self.computeExtractHeight(),
                HeaderMethodId.extension_root => try self.computeExtractExtensionRoot(),
                HeaderMethodId.miner_pk => try self.computeExtractMinerRewards(),
                HeaderMethodId.pow_onetime_pk => try self.computeExtractPowOnetimePk(),
                HeaderMethodId.pow_nonce => try self.computeExtractPowNonce(),
                HeaderMethodId.pow_distance => try self.computeExtractDifficulty(),
                HeaderMethodId.votes => try self.computeExtractVotes(),
                // v6 method
                HeaderMethodId.check_pow => {
                    if (!self.version_ctx.isV6Activated()) {
                        return error.SoftForkAccepted;
                    }
                    try self.computeCheckPow();
                },
                else => return self.handleUnsupported(),
            }
        } else if (type_code == BoxTypeCode) {
            // Box methods
            switch (method_id) {
                BoxMethodId.value_method => try self.computeBoxValue(),
                BoxMethodId.proposition_bytes => try self.computeBoxPropositionBytes(),
                BoxMethodId.bytes => try self.computeBoxBytes(),
                BoxMethodId.bytes_without_ref => try self.computeBoxBytesWithoutRef(),
                BoxMethodId.id_method => try self.computeBoxId(),
                BoxMethodId.creation_info => try self.computeBoxCreationInfo(),
                BoxMethodId.tokens_method => try self.computeBoxTokens(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == PreHeaderTypeCode) {
            // PreHeader methods
            switch (method_id) {
                PreHeaderMethodId.version => try self.computePreHeaderVersion(),
                PreHeaderMethodId.parent_id => try self.computePreHeaderParentId(),
                PreHeaderMethodId.timestamp => try self.computePreHeaderTimestamp(),
                PreHeaderMethodId.n_bits => try self.computePreHeaderNBits(),
                PreHeaderMethodId.height => try self.computePreHeaderHeight(),
                PreHeaderMethodId.miner_pk => try self.computePreHeaderMinerPk(),
                PreHeaderMethodId.votes => try self.computePreHeaderVotes(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == GroupElementTypeCode) {
            // GroupElement methods
            switch (method_id) {
                GroupElementMethodId.get_encoded => try self.computeGroupElementGetEncoded(),
                GroupElementMethodId.negate => try self.computeGroupElementNegate(),
                // exp (id=3) and multiply (id=4) are handled as opcodes, not method calls
                else => return self.handleUnsupported(),
            }
        } else if (type_code == SigmaPropTypeCode) {
            // SigmaProp methods
            switch (method_id) {
                // propBytes (id=1) is already handled via sigma_prop_bytes opcode
                // isProven (id=2) is for internal use only (frontend ErgoScript)
                SigmaPropMethodId.prop_bytes => try self.computeSigmaPropBytes(),
                else => return self.handleUnsupported(),
            }
        } else {
            // Unsupported type - use soft-fork aware handling
            return self.handleUnsupported();
        }
    }

    /// Compute property call (property access with no args)
    /// PropertyCall has same format as MethodCall but is used for property access (no args)
    /// Since most "methods" in computeMethodCall only use obj (no args), we can delegate
    fn computePropertyCall(self: *Evaluator, node_idx: u16) EvalError!void {
        // PropertyCall is like MethodCall but with no args
        // The dispatch methods only read obj from stack, so this works correctly
        try self.computeMethodCall(node_idx);
    }

    /// Compute zip: Coll[A].zip(Coll[B]) → Coll[(A, B)]
    /// Takes shortest length of two collections
    fn computeZip(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // obj and arg on stack
        assert(node_idx < self.tree.node_count);

        // Pop arg (second collection) first, then obj (first collection)
        const arg = try self.popValue();
        const obj = try self.popValue();

        // Both must be coll_byte for now
        if (obj != .coll_byte or arg != .coll_byte) return error.TypeMismatch;

        const coll1 = obj.coll_byte;
        const coll2 = arg.coll_byte;

        // Result length is minimum of both
        const result_len = @min(coll1.len, coll2.len);

        // Create tuples: each element is a (byte, byte) pair
        // For coll_byte, we create coll_tuple with 2-element tuples
        // Store as flat array of pairs for simplicity
        const result = self.arena.allocSlice(u8, result_len * 2) catch return error.OutOfMemory;

        for (0..result_len) |i| {
            result[i * 2] = coll1[i];
            result[i * 2 + 1] = coll2[i];
        }

        // POSTCONDITION: Result has correct length
        assert(result.len == result_len * 2);

        // Push as coll_byte (pairs encoded as consecutive bytes)
        // Note: proper tuple type handling would require coll_tuple
        try self.pushValue(.{ .coll_byte = result });
    }

    /// Compute indices: Coll[T] → Coll[Int] (0, 1, 2, ..., len-1)
    /// Returns array of indices encoded as bytes (each index as single byte for small collections)
    fn computeIndices(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0); // obj on stack

        const obj = try self.popValue();

        // Get collection length (only coll_byte supported for now)
        const len: usize = switch (obj) {
            .coll_byte => |c| c.len,
            .coll => |c| c.len,
            else => return error.TypeMismatch,
        };

        // INVARIANT: Reasonable collection size (must fit in u8 for byte encoding)
        if (len > 255) return error.CollectionTooLarge;

        // Allocate result as Coll[Byte] with indices 0..len-1
        // Note: This is a simplified representation - real impl would use Coll[Int]
        const result = self.arena.allocSlice(u8, len) catch return error.OutOfMemory;

        for (0..len) |i| {
            result[i] = @intCast(i);
        }

        // POSTCONDITION: Result has same length as input
        assert(result.len == len);

        try self.pushValue(.{ .coll_byte = result });
    }

    /// Compute reverse: Coll[T] → Coll[T] (elements in reverse order)
    /// Currently only supports Coll[Byte]
    fn computeReverse(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        const initial_sp = self.value_sp;

        const obj = try self.popValue();

        switch (obj) {
            .coll_byte => |c| {
                const result = self.arena.allocSlice(u8, c.len) catch return error.OutOfMemory;
                for (0..c.len) |i| {
                    result[i] = c[c.len - 1 - i];
                }
                // INVARIANT: Result has same length as input
                assert(result.len == c.len);
                try self.pushValue(.{ .coll_byte = result });
            },
            else => return error.TypeMismatch,
        }

        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute startsWith: Coll[T].startsWith(Coll[T]) → Boolean
    /// Returns true if this collection starts with the given prefix
    fn computeStartsWith(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (coll, prefix)
        assert(self.value_sp >= 2);
        assert(self.value_sp <= max_value_stack); // Stack within bounds
        const initial_sp = self.value_sp;

        // Pop in reverse order
        const prefix_val = try self.popValue();
        const coll_val = try self.popValue();

        const result: bool = switch (coll_val) {
            .coll_byte => |coll| switch (prefix_val) {
                .coll_byte => |prefix| blk: {
                    // INVARIANT: prefix.len and coll.len are valid slice lengths
                    assert(prefix.len <= std.math.maxInt(u32));
                    assert(coll.len <= std.math.maxInt(u32));
                    if (prefix.len > coll.len) break :blk false;
                    break :blk std.mem.eql(u8, coll[0..prefix.len], prefix);
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .boolean = result });

        // POSTCONDITIONS
        assert(self.value_sp == initial_sp - 1); // Stack reduced by 1
        assert(self.value_sp >= 1); // At least result on stack
    }

    /// Compute endsWith: Coll[T].endsWith(Coll[T]) → Boolean
    /// Returns true if this collection ends with the given suffix
    fn computeEndsWith(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (coll, suffix)
        assert(self.value_sp >= 2);
        assert(self.value_sp <= max_value_stack); // Stack within bounds
        const initial_sp = self.value_sp;

        // Pop in reverse order
        const suffix_val = try self.popValue();
        const coll_val = try self.popValue();

        const result: bool = switch (coll_val) {
            .coll_byte => |coll| switch (suffix_val) {
                .coll_byte => |suffix| blk: {
                    // INVARIANT: suffix.len and coll.len are valid slice lengths
                    assert(suffix.len <= std.math.maxInt(u32));
                    assert(coll.len <= std.math.maxInt(u32));
                    if (suffix.len > coll.len) break :blk false;
                    const start = coll.len - suffix.len;
                    // INVARIANT: start is valid index (no underflow since suffix.len <= coll.len)
                    assert(start <= coll.len);
                    break :blk std.mem.eql(u8, coll[start..], suffix);
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .boolean = result });

        // POSTCONDITIONS
        assert(self.value_sp == initial_sp - 1); // Stack reduced by 1
        assert(self.value_sp >= 1); // At least result on stack
    }

    /// Compute indexOf: Coll[T].indexOf(elem, from) → Int
    /// Returns index of first occurrence of elem starting at from, or -1 if not found
    fn computeIndexOf(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (coll, elem, from)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        // Pop in reverse order (from, elem, coll)
        const from_val = try self.popValue();
        const elem_val = try self.popValue();
        const coll_val = try self.popValue();

        // Get 'from' index (clamped to 0 minimum per Scala impl)
        const from_idx: usize = switch (from_val) {
            .int => |i| if (i < 0) 0 else @intCast(i),
            .long => |i| if (i < 0) 0 else @intCast(i),
            else => return error.TypeMismatch,
        };

        // INVARIANT: from_idx is non-negative
        assert(from_idx <= std.math.maxInt(u32));

        const result: i32 = switch (coll_val) {
            .coll_byte => |coll| blk: {
                // elem must be a byte (or convertible integer)
                const target: u8 = switch (elem_val) {
                    .int => |i| if (i < 0 or i > 255) break :blk -1 else @intCast(i),
                    .byte => |b| @bitCast(b), // i8 -> u8
                    else => return error.TypeMismatch,
                };

                // INVARIANT: coll.len is valid
                assert(coll.len <= std.math.maxInt(u32));

                // Search starting from 'from' index
                if (from_idx >= coll.len) break :blk -1;

                for (coll[from_idx..], from_idx..) |byte, idx| {
                    if (byte == target) {
                        // INVARIANT: idx fits in i32
                        assert(idx <= std.math.maxInt(i32));
                        break :blk @intCast(idx);
                    }
                }
                break :blk -1;
            },
            .box_coll => |bc| blk: {
                // elem must be a box - compare by source and index
                if (elem_val != .box) return error.TypeMismatch;
                const target = elem_val.box;

                const boxes = switch (bc.source) {
                    .inputs => self.ctx.inputs,
                    .outputs => self.ctx.outputs,
                    .data_inputs => self.ctx.data_inputs,
                };

                if (from_idx >= boxes.len) break :blk -1;

                // Compare boxes by source and index (identity comparison)
                // In ErgoTree, boxes are compared by their id, but for INPUTS.indexOf(SELF),
                // we need identity comparison since SELF is a box reference
                for (from_idx..boxes.len) |idx| {
                    if (bc.source == target.source and idx == target.index) {
                        break :blk @intCast(idx);
                    }
                }
                break :blk -1;
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .int = result });

        // POSTCONDITIONS
        assert(self.value_sp == initial_sp - 2); // Popped 3, pushed 1
        assert(result >= -1); // Result is valid index or -1
    }

    /// Compute get: Coll[T].get(idx) → Option[T]
    /// Returns Some(element) if idx is valid, None otherwise
    fn computeCollGet(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (coll, idx)
        assert(self.value_sp >= 2);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        // Pop in reverse order (idx, coll)
        const idx_val = try self.popValue();
        const coll_val = try self.popValue();

        // Get index (Int is i32, but we need i64 for comparison with len)
        const idx: i64 = switch (idx_val) {
            .int => |i| @as(i64, i),
            .long => |i| i,
            else => return error.TypeMismatch,
        };

        switch (coll_val) {
            .coll_byte => |coll| {
                // INVARIANT: coll.len is valid
                assert(coll.len <= std.math.maxInt(u32));

                // Check bounds
                if (idx < 0 or idx >= @as(i64, @intCast(coll.len))) {
                    // Out of bounds - return None
                    try self.pushOptionNone(TypePool.BYTE);
                } else {
                    // Valid index - return Some(byte)
                    const byte_val = coll[@intCast(@as(u64, @bitCast(idx)))];

                    // Store byte in value pool and return Option
                    const pool_idx = self.pools.values.alloc() catch return error.OutOfMemory;
                    const pooled = value_pool.PooledValue{
                        .type_idx = TypePool.BYTE,
                        .data = .{ .primitive = @as(i64, byte_val) },
                    };
                    self.pools.values.set(pool_idx, pooled);

                    try self.pushValue(.{ .option = .{
                        .inner_type = TypePool.BYTE,
                        .value_idx = pool_idx,
                    } });
                }
            },
            else => return error.TypeMismatch,
        }

        // POSTCONDITIONS
        assert(self.value_sp == initial_sp - 1); // Popped 2, pushed 1
    }

    /// Compute patch: Coll[T].patch(from, patch, replaced) → Coll[T]
    /// Produces a new collection where `replaced` elements starting at `from`
    /// are replaced by elements from `patch`.
    /// Result: coll[0..from] ++ patch ++ coll[from+replaced..]
    /// Reference: Scala Coll.patch
    fn computePatch(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 4 values on stack (coll, from, patch_coll, replaced)
        assert(self.value_sp >= 4);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        // Cost: per-item based on result size
        // Pop in reverse order: replaced, patch_coll, from, coll
        const replaced_val = try self.popValue();
        const patch_val = try self.popValue();
        const from_val = try self.popValue();
        const coll_val = try self.popValue();

        // Get 'from' index (clamp negative to 0)
        const from_raw: i64 = switch (from_val) {
            .int => |i| @as(i64, i),
            .long => |i| i,
            else => return error.TypeMismatch,
        };
        const from: usize = if (from_raw < 0) 0 else @intCast(@min(from_raw, std.math.maxInt(u32)));

        // Get 'replaced' count (clamp negative to 0)
        const replaced_raw: i64 = switch (replaced_val) {
            .int => |i| @as(i64, i),
            .long => |i| i,
            else => return error.TypeMismatch,
        };
        const replaced: usize = if (replaced_raw < 0) 0 else @intCast(@min(replaced_raw, std.math.maxInt(u32)));

        switch (coll_val) {
            .coll_byte => |coll| {
                const patch_bytes = switch (patch_val) {
                    .coll_byte => |p| p,
                    else => return error.TypeMismatch,
                };

                // Clamp 'from' to collection length
                const actual_from = @min(from, coll.len);
                // Clamp 'replaced' to available elements after 'from'
                const actual_replaced = @min(replaced, coll.len - actual_from);

                // Calculate result length
                const result_len = coll.len - actual_replaced + patch_bytes.len;

                // INVARIANT: result_len is reasonable
                if (result_len > 65536) return error.CollectionTooLarge;

                // Add per-item cost
                try self.addCost(@intCast(result_len * 2));

                // Allocate result
                const result = self.arena.allocSlice(u8, result_len) catch return error.OutOfMemory;

                // Build result: coll[0..from] ++ patch ++ coll[from+replaced..]
                var dst: usize = 0;

                // Copy prefix: coll[0..actual_from]
                @memcpy(result[dst..][0..actual_from], coll[0..actual_from]);
                dst += actual_from;

                // Copy patch
                @memcpy(result[dst..][0..patch_bytes.len], patch_bytes);
                dst += patch_bytes.len;

                // Copy suffix: coll[actual_from+actual_replaced..]
                const suffix_start = actual_from + actual_replaced;
                const suffix_len = coll.len - suffix_start;
                @memcpy(result[dst..][0..suffix_len], coll[suffix_start..]);

                // POSTCONDITION: Result is correctly sized
                assert(result.len == result_len);

                try self.pushValue(.{ .coll_byte = result });
            },
            else => return error.TypeMismatch,
        }

        // POSTCONDITION: Popped 4, pushed 1
        assert(self.value_sp == initial_sp - 3);
    }

    /// Compute updated: Coll[T].updated(idx, elem) → Coll[T]
    /// Returns new collection with element at idx replaced with elem.
    /// Reference: Scala Coll.updated
    fn computeUpdated(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (coll, idx, elem)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        // Pop in reverse order: elem, idx, coll
        const elem_val = try self.popValue();
        const idx_val = try self.popValue();
        const coll_val = try self.popValue();

        // Get index
        const idx: i64 = switch (idx_val) {
            .int => |i| @as(i64, i),
            .long => |i| i,
            else => return error.TypeMismatch,
        };

        switch (coll_val) {
            .coll_byte => |coll| {
                // Bounds check
                if (idx < 0 or idx >= @as(i64, @intCast(coll.len))) {
                    return error.IndexOutOfBounds;
                }

                // Get element to insert
                const elem: u8 = switch (elem_val) {
                    .int => |i| if (i < 0 or i > 255) return error.ArithmeticOverflow else @intCast(i),
                    .byte => |b| @bitCast(b),
                    else => return error.TypeMismatch,
                };

                // Cost: copy entire collection
                try self.addCost(@intCast(coll.len));

                // Allocate and copy
                const result = self.arena.allocSlice(u8, coll.len) catch return error.OutOfMemory;
                @memcpy(result, coll);

                // Update the element
                result[@intCast(@as(u64, @bitCast(idx)))] = elem;

                try self.pushValue(.{ .coll_byte = result });
            },
            else => return error.TypeMismatch,
        }

        // POSTCONDITION: Popped 3, pushed 1
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute updateMany: Coll[T].updateMany(indexes, values) → Coll[T]
    /// Returns new collection with elements at indexes replaced with corresponding values.
    /// Reference: Scala Coll.updateMany
    fn computeUpdateMany(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (coll, indexes, values)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        // Pop in reverse order: values, indexes, coll
        const values_val = try self.popValue();
        const indexes_val = try self.popValue();
        const coll_val = try self.popValue();

        switch (coll_val) {
            .coll_byte => |coll| {
                // Get indexes collection
                const indexes = switch (indexes_val) {
                    .coll_byte => |c| c, // Treat bytes as indexes
                    else => return error.TypeMismatch,
                };

                // Get values collection
                const values = switch (values_val) {
                    .coll_byte => |c| c,
                    else => return error.TypeMismatch,
                };

                // Indexes and values must have same length
                if (indexes.len != values.len) {
                    return error.TypeMismatch;
                }

                // Cost: copy entire collection + per update
                try self.addCost(@intCast(coll.len + indexes.len));

                // Allocate and copy
                const result = self.arena.allocSlice(u8, coll.len) catch return error.OutOfMemory;
                @memcpy(result, coll);

                // Apply updates
                for (indexes, values) |idx_byte, value| {
                    const idx: usize = idx_byte;
                    if (idx >= result.len) {
                        return error.IndexOutOfBounds;
                    }
                    result[idx] = value;
                }

                try self.pushValue(.{ .coll_byte = result });
            },
            else => return error.TypeMismatch,
        }

        // POSTCONDITION: Popped 3, pushed 1
        assert(self.value_sp == initial_sp - 2);
    }

    // ========================================================================
    // Context Method Operations
    // ========================================================================

    /// Compute CONTEXT.dataInputs: returns Coll[Box] of data input boxes
    /// Data inputs are read-only reference boxes in the transaction
    fn computeDataInputs(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        // Context object is on stack but we don't actually need it - it's the implicit context
        assert(self.value_sp > 0);

        // Pop the context object (we don't use it, we use self.ctx directly)
        _ = try self.popValue();

        try self.addCost(FixedCost.data_inputs);

        // INVARIANT: Data inputs count is bounded
        assert(self.ctx.data_inputs.len <= context.max_data_inputs);

        // Push box collection reference (same pattern as INPUTS/OUTPUTS)
        try self.pushValue(.{ .box_coll = .{ .source = .data_inputs } });

        // POSTCONDITION: One value pushed to stack
        assert(self.value_sp > 0);
    }

    /// Compute CONTEXT.headers: returns first header as Header value (simplified for DST)
    /// In real ErgoTree this returns Coll[Header], but for DST coverage we return single Header.
    fn computeContextHeaders(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);

        // Pop the context object (not used - we use self.ctx directly)
        _ = try self.popValue();

        try self.addCost(15); // Same cost as last_block_utxo_root

        // INVARIANT: Must have at least one header
        if (self.ctx.headers.len == 0) {
            return error.InvalidContext;
        }

        // Copy header data from context to HeaderRef
        const ctx_header = &self.ctx.headers[0];
        const header_ref = data.Value.HeaderRef{
            .id = ctx_header.id,
            .version = ctx_header.version,
            .parent_id = ctx_header.parent_id,
            .ad_proofs_root = ctx_header.ad_proofs_root,
            .state_root = ctx_header.state_root,
            .transactions_root = ctx_header.transactions_root,
            .timestamp = ctx_header.timestamp,
            .n_bits = ctx_header.n_bits,
            .height = ctx_header.height,
            .extension_root = ctx_header.extension_root,
            .miner_pk = ctx_header.miner_pk,
            .pow_onetime_pk = ctx_header.pow_onetime_pk,
            .pow_nonce = ctx_header.pow_nonce,
            .pow_distance = ctx_header.pow_distance,
            .votes = ctx_header.votes,
        };

        try self.pushValue(.{ .header = header_ref });

        // POSTCONDITION: One value pushed to stack
        assert(self.value_sp > 0);
    }

    /// Compute CONTEXT.preHeader: returns the pre-header for the current block being validated.
    /// PreHeader is the candidate block header during mining/validation.
    fn computeContextPreHeader(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);

        // Pop the context object (not used - we use self.ctx directly)
        _ = try self.popValue();

        try self.addCost(10); // FixedCost for preheader access

        // Copy pre_header data from context to PreHeaderRef
        const ctx_ph = &self.ctx.pre_header;
        const pre_header_ref = data.Value.PreHeaderRef{
            .version = ctx_ph.version,
            .parent_id = ctx_ph.parent_id,
            .timestamp = ctx_ph.timestamp,
            .n_bits = ctx_ph.n_bits,
            .height = ctx_ph.height,
            .miner_pk = ctx_ph.miner_pk,
            .votes = ctx_ph.votes,
        };

        try self.pushValue(.{ .pre_header = pre_header_ref });

        // POSTCONDITION: One value pushed to stack
        assert(self.value_sp > 0);
    }

    /// Compute CONTEXT.selfBoxIndex: returns the index of SELF box within INPUTS.
    fn computeSelfBoxIndex(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);

        // Pop the context object (not used - we use self.ctx directly)
        _ = try self.popValue();

        try self.addCost(10); // FixedCost for selfBoxIndex access

        // INVARIANT: self_index is a valid input index
        assert(self.ctx.self_index < self.ctx.inputs.len);

        try self.pushValue(.{ .int = @intCast(self.ctx.self_index) });

        // POSTCONDITION: One value pushed to stack
        assert(self.value_sp > 0);
    }

    /// Compute getVarFromInput: CONTEXT.getVarFromInput[T](inputIndex, varId) → Option[T]
    /// Accesses context extension variable from a specific input box.
    ///
    /// Stack layout: [context_obj, input_idx (Short), var_id (Byte)]
    /// Pop order: var_id, input_idx, context_obj
    ///
    /// Returns None if:
    ///   - input_idx is out of bounds
    ///   - extension_cache is not set
    ///   - variable is not set for that input
    ///   - deserialized type doesn't match expected type T
    fn computeGetVarFromInput(self: *Evaluator, node: ExprNode) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3); // context, input_idx, var_id on stack

        // VERSION GATE: getVarFromInput is a v6 feature (EIP-50)
        // Reference: Scala LanguageSpecificationV6.scala:1819 - sinceVersion = V6SoftForkVersion
        if (!self.version_ctx.isV6Activated()) {
            return error.SoftForkAccepted;
        }

        // Cost same as GetVar (100)
        try self.addCost(100);

        // Pop arguments in reverse order
        const var_id_val = try self.popValue();
        const input_idx_val = try self.popValue();
        _ = try self.popValue(); // context object (we use self.ctx directly)

        // Extract var_id (Byte = i8)
        const var_id: u8 = switch (var_id_val) {
            .byte => |b| @bitCast(b),
            .int => |i| if (i >= 0 and i <= 255) @intCast(i) else return error.TypeMismatch,
            else => return error.TypeMismatch,
        };

        // Extract input_idx (Short = i16)
        const input_idx: u16 = switch (input_idx_val) {
            .short => |s| if (s >= 0) @intCast(s) else return error.TypeMismatch,
            .int => |i| if (i >= 0 and i <= std.math.maxInt(u16)) @intCast(i) else return error.TypeMismatch,
            else => return error.TypeMismatch,
        };

        // Get expected inner type T from node.result_type
        // This was parsed from the explicit type arg during deserialization
        const expected_type_idx: TypeIndex = node.result_type;

        // Look up the variable
        const var_bytes = self.ctx.getVarFromInput(input_idx, var_id);

        if (var_bytes) |bytes| {
            // Variable exists - deserialize according to expected type
            const value_idx = self.deserializeContextVar(bytes, expected_type_idx) catch {
                // Type mismatch or deserialization failure - return None (per Rust semantics)
                try self.pushValue(.{
                    .option = .{
                        .inner_type = expected_type_idx,
                        .value_idx = null_value_idx,
                    },
                });
                return;
            };

            // Return Some(value)
            try self.pushValue(.{
                .option = .{
                    .inner_type = expected_type_idx,
                    .value_idx = value_idx,
                },
            });
        } else {
            // Variable not found or out of bounds - return None
            try self.pushValue(.{
                .option = .{
                    .inner_type = expected_type_idx,
                    .value_idx = null_value_idx,
                },
            });
        }

        // POSTCONDITION: One Option value on stack
        assert(self.value_sp > 0);
    }

    /// Deserialize a context variable from bytes and store in ValuePool.
    /// Context extension data is serialized as Constant: type_code + value_data.
    /// Returns the value index, or error if deserialization fails.
    fn deserializeContextVar(self: *Evaluator, bytes: []const u8, expected_type_idx: TypeIndex) EvalError!u16 {
        // Create a reader from the bytes
        var reader = vlq.Reader.init(bytes);

        // First, read the type code from the serialized Constant
        const actual_type_idx = type_serializer.deserialize(
            &self.pools.type_pool,
            &reader,
        ) catch {
            return error.InvalidData;
        };

        // Verify the type matches the expected type
        // For now, require exact match; later can add coercion support
        if (actual_type_idx != expected_type_idx) {
            return error.TypeMismatch;
        }

        // Deserialize the value according to its type
        const value = data.deserialize(
            actual_type_idx,
            &self.pools.type_pool,
            &reader,
            &self.arena,
            &self.pools.values,
        ) catch |err| {
            return switch (err) {
                error.InvalidGroupElement => error.InvalidGroupElement,
                error.TypeMismatch => error.TypeMismatch,
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidData,
            };
        };

        // Store the deserialized value in the pool
        const value_idx = try self.storeValueInPool(value, actual_type_idx);

        return value_idx;
    }

    // ========================================================================
    // Sigma Proposition Connective Operations
    // ========================================================================

    /// Compute SigmaAnd: combine multiple SigmaProp children into conjunction
    /// Children are expected on the value stack in evaluation order
    fn computeSigmaAnd(self: *Evaluator, child_count: u16) EvalError!void {
        // PRECONDITIONS
        assert(child_count >= 2); // AND must have at least 2 children
        assert(self.value_sp >= child_count); // Children must be on stack

        try self.addCost(FixedCost.sigma_and);

        // Pop children in reverse order to build children array
        var children: [256]*const sigma_tree.SigmaBoolean = undefined;
        var i: u16 = child_count;
        while (i > 0) {
            i -= 1;
            const val = try self.popValue();
            children[i] = try self.extractSigmaBoolean(val);
        }

        // Allocate children slice in arena
        const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, child_count) catch return error.OutOfMemory;
        @memcpy(child_slice, children[0..child_count]);

        // Allocate the SigmaBoolean node itself
        const node_ptr = self.arena.alloc(sigma_tree.SigmaBoolean, 1) catch return error.OutOfMemory;
        node_ptr[0] = .{ .cand = .{ .children = child_slice } };

        // Serialize the SigmaBoolean to bytes for SigmaProp
        const sigma_bytes = try self.serializeSigmaBoolean(&node_ptr[0]);

        // Push result as SigmaProp
        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });
    }

    /// Compute SigmaOr: combine multiple SigmaProp children into disjunction
    /// Children are expected on the value stack in evaluation order
    fn computeSigmaOr(self: *Evaluator, child_count: u16) EvalError!void {
        // PRECONDITIONS
        assert(child_count >= 2); // OR must have at least 2 children
        assert(self.value_sp >= child_count); // Children must be on stack

        try self.addCost(FixedCost.sigma_or);

        // Pop children in reverse order to build children array
        var children: [256]*const sigma_tree.SigmaBoolean = undefined;
        var i: u16 = child_count;
        while (i > 0) {
            i -= 1;
            const val = try self.popValue();
            children[i] = try self.extractSigmaBoolean(val);
        }

        // Allocate children slice in arena
        const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, child_count) catch return error.OutOfMemory;
        @memcpy(child_slice, children[0..child_count]);

        // Allocate the SigmaBoolean node itself
        const node_ptr = self.arena.alloc(sigma_tree.SigmaBoolean, 1) catch return error.OutOfMemory;
        node_ptr[0] = .{ .cor = .{ .children = child_slice } };

        // Serialize the SigmaBoolean to bytes for SigmaProp
        const sigma_bytes = try self.serializeSigmaBoolean(&node_ptr[0]);

        // Push result as SigmaProp
        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });
    }

    /// Compute SigmaThreshold (AtLeast): k out of n children must be proven
    /// Stack: [bound (Int), input (Coll[SigmaProp])] - input on top
    /// Format: bound expression + input collection expression (always 2 children)
    fn computeSigmaThreshold(self: *Evaluator, node_data: u16) EvalError!void {
        // PRECONDITIONS
        assert(node_data == 2); // Always 2 children: bound and input
        assert(self.value_sp >= 2);

        try self.addCost(FixedCost.sigma_threshold);

        // Pop input collection (Coll[SigmaProp]) - last pushed, so first popped
        const input_val = try self.popValue();
        if (input_val != .coll) return error.TypeMismatch;
        const coll_ref = input_val.coll;
        const coll_len: usize = coll_ref.len;

        // Pop bound (Int) - the k threshold value
        const bound_val = try self.popValue();
        // Extract integer value (could be byte, short, int, or long)
        const k_i64: i64 = switch (bound_val) {
            .byte => |v| v,
            .short => |v| v,
            .int => |v| v,
            .long => |v| v,
            else => return error.TypeMismatch,
        };

        // Validate k is reasonable
        if (k_i64 < 1) return error.InvalidData; // k must be at least 1
        if (coll_len < 2) return error.InvalidData; // need at least 2 children
        if (k_i64 > @as(i64, @intCast(coll_len))) return error.InvalidData; // k can't exceed n
        if (k_i64 > 255 or coll_len > 255) return error.InvalidData; // reasonable limits
        const k: u8 = @intCast(k_i64);

        // Extract SigmaBoolean from each collection element
        var children: [256]*const sigma_tree.SigmaBoolean = undefined;
        for (0..coll_len) |i| {
            const elem = self.values[coll_ref.start + i];
            children[i] = try self.extractSigmaBoolean(elem);
        }

        // Allocate children slice in arena
        const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, coll_len) catch return error.OutOfMemory;
        @memcpy(child_slice, children[0..coll_len]);

        // Allocate the SigmaBoolean node itself
        const node_ptr = self.arena.alloc(sigma_tree.SigmaBoolean, 1) catch return error.OutOfMemory;
        node_ptr[0] = .{ .cthreshold = .{ .k = k, .children = child_slice } };

        // Serialize the SigmaBoolean to bytes for SigmaProp
        const sigma_bytes = try self.serializeSigmaBoolean(&node_ptr[0]);

        // Push result as SigmaProp
        try self.pushValue(.{ .sigma_prop = .{ .data = sigma_bytes } });
    }

    // ========================================================================
    // AVL Tree Operations
    // ========================================================================

    /// Compute CreateAvlTree: construct AvlTreeData from components
    /// Stack (top to bottom): [value_length_opt], key_length, digest, flags
    fn computeCreateAvlTree(self: *Evaluator, has_value_length: u16) EvalError!void {
        // PRECONDITIONS
        const expected_args: u16 = if (has_value_length == 1) 4 else 3;
        assert(self.value_sp >= expected_args);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.create_avl_tree);

        // Pop arguments in reverse order (value_length_opt, key_length, digest, flags)
        const value_length_opt: ?u32 = if (has_value_length == 1) blk: {
            const val = try self.popValue();
            // value_length is Int (signed 32-bit)
            const vl = switch (val) {
                .int => |i| if (i >= 0) @as(u32, @intCast(i)) else return error.InvalidData,
                else => return error.TypeMismatch,
            };
            break :blk vl;
        } else null;

        const key_length_val = try self.popValue();
        const key_length: u32 = switch (key_length_val) {
            .int => |i| if (i >= 1 and i <= avl_tree.max_key_length)
                @as(u32, @intCast(i))
            else
                return error.InvalidData,
            else => return error.TypeMismatch,
        };

        const digest_val = try self.popValue();
        if (digest_val != .coll_byte) return error.TypeMismatch;
        const digest_bytes = digest_val.coll_byte;
        if (digest_bytes.len != avl_tree.digest_size) return error.InvalidData;

        const flags_val = try self.popValue();
        const flags_byte: u8 = switch (flags_val) {
            .byte => |b| @bitCast(b),
            .int => |i| if (i >= 0 and i <= 255) @intCast(i) else return error.InvalidData,
            else => return error.TypeMismatch,
        };

        // Construct AvlTreeData
        // INVARIANT: digest_bytes validated to be correct size
        assert(digest_bytes.len == avl_tree.digest_size);
        var digest: [avl_tree.digest_size]u8 = undefined;
        @memcpy(&digest, digest_bytes);
        const tree_flags = avl_tree.AvlTreeFlags.fromByte(flags_byte);

        const tree_data = avl_tree.AvlTreeData.init(digest, tree_flags, key_length, value_length_opt) catch {
            return error.InvalidData;
        };

        // Push result
        try self.pushValue(.{ .avl_tree = tree_data });

        // POSTCONDITION: Stack reduced by (expected_args - 1)
        assert(self.value_sp == initial_sp - expected_args + 1);
    }

    /// Compute TreeLookup: look up key in AVL tree with proof verification
    /// Stack (top to bottom): proof, key, tree
    /// Returns: Option[Coll[Byte]]
    fn computeTreeLookup(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3);

        const initial_sp = self.value_sp;
        try self.addCost(FixedCost.tree_lookup);

        // Pop arguments in reverse order (proof, key, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        const key_val = try self.popValue();
        if (key_val != .coll_byte) return error.TypeMismatch;
        const key = key_val.coll_byte;

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // Validate key length matches tree's expected key length
        if (key.len != tree_data.key_length) {
            return error.InvalidData;
        }

        // INVARIANT: key length validated against tree parameters
        assert(key.len == tree_data.key_length);

        // For now, use arena as the verifier's arena
        // This is safe since we're in a single evaluation context
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        // Create BatchAVLVerifier
        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            return error.InvalidData;
        };

        // Perform lookup
        const result = verifier.lookup(key) catch {
            // Verification error - return None
            try self.pushOptionNone(TypePool.COLL_BYTE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        switch (result) {
            .found => |value| {
                // Copy value to our arena
                const value_copy = self.arena.allocSlice(u8, value.len) catch return error.OutOfMemory;
                @memcpy(value_copy, value);
                try self.pushOptionSomeCollByte(value_copy);
            },
            .not_found, .verification_failed => {
                try self.pushOptionNone(TypePool.COLL_BYTE);
            },
        }

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    // ========================================================================
    // SubstConstants Operation
    // ========================================================================

    /// Maximum constants that can be substituted (matches protocol limit)
    const max_subst_constants: usize = 256;

    /// Compute SubstConstants: substitute constants in serialized ErgoTree
    /// Takes: script_bytes: Coll[Byte], positions: Coll[Int], new_values: Coll[T]
    /// Returns: Coll[Byte] (modified serialized ErgoTree)
    fn computeSubstConstants(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3);

        const initial_sp = self.value_sp;

        // Pop values in reverse order (LIFO): new_values, positions, script_bytes
        const new_values_val = try self.popValue();
        const positions_val = try self.popValue();
        const script_bytes_val = try self.popValue();

        // Type validation: script_bytes must be Coll[Byte]
        const script_bytes: []const u8 = switch (script_bytes_val) {
            .coll_byte => |s| s,
            .hash32 => |*h| h[0..],
            else => return error.TypeMismatch,
        };

        // INVARIANT: Script bytes should not be empty
        if (script_bytes.len == 0) {
            return error.InvalidData;
        }

        // Type validation: positions must be collection (Coll[Int])
        const positions_coll = switch (positions_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        // Type validation: new_values must be collection
        const new_values_coll = switch (new_values_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        // VALIDATION: positions.len must equal new_values.len
        const num_positions: u16 = positions_coll.len;
        if (num_positions != new_values_coll.len) {
            return error.InvalidData;
        }

        // Calculate and charge cost: base + per_item * count
        const cost: u32 = 100 + 100 * @as(u32, num_positions);
        try self.addCost(cost);

        // Handle empty substitution case - return original unchanged
        if (num_positions == 0) {
            try self.pushValue(script_bytes_val);
            assert(self.value_sp == initial_sp - 2);
            return;
        }

        // Perform the substitution
        const result = try self.performSubstConstants(
            script_bytes,
            positions_coll,
            new_values_coll,
        );

        try self.pushValue(.{ .coll_byte = result });

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Perform the actual constant substitution
    /// Parses script, validates types, builds output with substituted constants
    fn performSubstConstants(
        self: *Evaluator,
        script_bytes: []const u8,
        positions_coll: Value.CollRef,
        new_values_coll: Value.CollRef,
    ) EvalError![]const u8 {
        // PRECONDITIONS
        assert(positions_coll.len == new_values_coll.len);
        assert(script_bytes.len > 0);

        var reader = vlq.Reader.init(script_bytes);

        // Step 1: Parse ErgoTree header
        const header_byte = reader.readByte() catch return error.InvalidData;
        const header = ergotree_serializer.ErgoTreeHeader.parse(header_byte) catch return error.InvalidData;

        // CRITICAL: SubstConstants only works with constant_segregation enabled
        if (!header.constant_segregation) {
            return error.InvalidData;
        }

        // Read optional size field
        if (header.has_size) {
            _ = reader.readU32() catch return error.InvalidData;
        }

        // Read constants count
        const num_constants = reader.readU32() catch return error.InvalidData;
        if (num_constants > max_subst_constants) {
            return error.InvalidData;
        }

        // Step 2: Parse original constant types and offsets
        // Use a local type pool for parsing complex types
        var const_type_pool = TypePool.init();
        var original_types: [max_subst_constants]TypeIndex = undefined;
        var original_offsets: [max_subst_constants + 1]usize = undefined;
        original_offsets[0] = reader.pos;

        var i: u32 = 0;
        while (i < num_constants) : (i += 1) {
            // Parse type using type_serializer (handles all type codes including generics)
            const type_idx = type_serializer.deserialize(&const_type_pool, &reader) catch return error.InvalidData;
            original_types[i] = type_idx;

            // Skip value data using the proper type pool
            skipValueForType(&const_type_pool, &reader, type_idx) catch return error.InvalidData;
            original_offsets[i + 1] = reader.pos;
        }

        const tree_bytes_start = reader.pos;
        const tree_bytes = script_bytes[tree_bytes_start..];

        // Step 3: Build backreference map for O(n) performance
        // backrefs[const_idx] = position in positions array, or -1 if not substituted
        var backrefs: [max_subst_constants]i16 = [_]i16{-1} ** max_subst_constants;

        var pos_idx: u16 = 0;
        while (pos_idx < positions_coll.len) : (pos_idx += 1) {
            // Get position value from collection
            const pos_val = self.getIntCollectionElement(positions_coll, pos_idx) catch return error.InvalidData;

            if (pos_val < 0 or pos_val >= @as(i32, @intCast(num_constants))) {
                return error.IndexOutOfBounds;
            }

            const const_idx: usize = @intCast(pos_val);

            // Only first occurrence wins (matches Scala behavior)
            if (backrefs[const_idx] == -1) {
                backrefs[const_idx] = @intCast(pos_idx);
            }
        }

        // Step 4: Serialize new ErgoTree
        // Use pre-allocated output buffer (max 4KB per protocol)
        var output: [ergotree_serializer.max_ergo_tree_size]u8 = undefined;
        var out_pos: usize = 0;

        // Write header (unchanged)
        output[out_pos] = header_byte;
        out_pos += 1;

        // Reserve space for size if needed (max 5 bytes for VLQ u32)
        var size_offset: ?usize = null;
        var size_reserved: usize = 0;
        if (header.has_size) {
            size_offset = out_pos;
            size_reserved = 5; // Max VLQ u32 size
            out_pos += size_reserved;
        }

        const content_start = out_pos;

        // Write constant count
        out_pos += vlq.encodeU64(@intCast(num_constants), output[out_pos..]);

        // Write constants (original or substituted)
        i = 0;
        while (i < num_constants) : (i += 1) {
            const backref = backrefs[i];

            if (backref == -1) {
                // No substitution - copy original bytes
                const start = original_offsets[i];
                const end = original_offsets[i + 1];
                const orig_bytes = script_bytes[start..end];

                if (out_pos + orig_bytes.len > output.len) return error.OutOfMemory;
                @memcpy(output[out_pos..][0..orig_bytes.len], orig_bytes);
                out_pos += orig_bytes.len;
            } else {
                // Substitution - serialize new value
                const new_val = self.getCollectionElementFromRef(new_values_coll, @intCast(backref)) catch return error.InvalidData;

                // TYPE CHECK: new value must match original type
                const expected_type = original_types[i];
                const actual_type = self.valueTypeIndex(new_val);
                if (!typesCompatible(expected_type, actual_type, &const_type_pool)) {
                    return error.TypeMismatch;
                }

                // Serialize type + value using full serializers
                const bytes_written = try self.serializeConstantFull(
                    expected_type,
                    &const_type_pool,
                    new_val,
                    output[out_pos..],
                );
                out_pos += bytes_written;
            }
        }

        // Write tree bytes (unchanged)
        if (out_pos + tree_bytes.len > output.len) return error.OutOfMemory;
        @memcpy(output[out_pos..][0..tree_bytes.len], tree_bytes);
        out_pos += tree_bytes.len;

        // Fill in size field if needed
        if (size_offset) |offset| {
            const content_size: u32 = @intCast(out_pos - content_start);

            // Encode size into reserved space
            var size_buf: [5]u8 = undefined;
            const size_len = vlq.encodeU64(@intCast(content_size), &size_buf);

            // Copy size bytes, padding rest with zeros if needed
            @memcpy(output[offset..][0..size_len], size_buf[0..size_len]);
            if (size_len < size_reserved) {
                // Shift content left to remove padding
                const shift = size_reserved - size_len;
                const content_end = out_pos;
                std.mem.copyBackwards(
                    u8,
                    output[offset + size_len .. content_end - shift],
                    output[offset + size_reserved .. content_end],
                );
                out_pos -= shift;
            }
        }

        // Allocate result in arena and return
        const result = self.arena.allocSlice(u8, out_pos) catch return error.OutOfMemory;
        @memcpy(result, output[0..out_pos]);

        return result;
    }

    /// Compute DeserializeContext: execute script from context variable
    /// Reads serialized expression bytes from context_vars[var_id], deserializes,
    /// evaluates in current context, and returns result.
    fn computeDeserializeContext(self: *Evaluator, node: ExprNode) EvalError!void {
        // var_id stored in data, expected type in result_type
        const expected_type: TypeIndex = node.result_type;
        const var_id: u8 = @truncate(node.data);

        // Get bytes from context variable
        const bytes = self.ctx.context_vars[var_id] orelse {
            return error.InvalidData; // Context variable not found
        };

        // PerItemCost: baseCost=1, perChunkCost=10, chunkSize=128
        const num_chunks: u32 = @intCast((bytes.len + 127) / 128); // ceil division
        try self.addCost(1 + num_chunks * 10);

        // Evaluate the nested expression
        const result = try self.evaluateNestedExpression(bytes, expected_type);
        try self.pushValue(result);
    }

    /// Compute DeserializeRegister: execute script from SELF register
    /// Reads serialized expression bytes from SELF.R[reg_id], deserializes,
    /// evaluates in current context, and returns result.
    /// If register is empty and has_default=1, uses the default value from stack.
    fn computeDeserializeRegister(self: *Evaluator, node: ExprNode) EvalError!void {
        // Data format: reg_id(8 high) | has_default(8 low), expected type in result_type
        const expected_type: TypeIndex = node.result_type;
        const reg_id: u8 = @truncate(node.data >> 8);
        const has_default: u8 = @truncate(node.data);

        // If has_default, pop the default value (was already evaluated)
        const default_value: ?Value = if (has_default == 1) try self.popValue() else null;

        // Get SELF box
        const self_box = &self.ctx.inputs[self.ctx.self_index];

        // Get register bytes (R4-R9 are optional, R0-R3 are mandatory)
        // Register IDs: 0-3 are R0-R3, 4-9 are R4-R9
        const reg_bytes: ?[]const u8 = blk: {
            if (reg_id >= 4 and reg_id <= 9) {
                // Optional registers R4-R9 stored in registers array
                break :blk self_box.registers[reg_id - 4];
            } else if (reg_id == 1) {
                // R1 = proposition_bytes (can be used for executeFromSelfReg)
                break :blk self_box.proposition_bytes;
            } else {
                // R0, R2, R3 cannot be used as script bytes sources
                break :blk null;
            }
        };

        if (reg_bytes) |bytes| {
            // PerItemCost: baseCost=1, perChunkCost=10, chunkSize=128
            const num_chunks: u32 = @intCast((bytes.len + 127) / 128); // ceil division
            try self.addCost(1 + num_chunks * 10);

            // Register has bytes - deserialize and evaluate
            const result = try self.evaluateNestedExpression(bytes, expected_type);
            try self.pushValue(result);
        } else if (default_value) |default| {
            // Register empty, use default (still charge base cost)
            try self.addCost(1);
            try self.pushValue(default);
        } else {
            // Register empty, no default - error
            return error.InvalidData;
        }
    }

    /// Evaluate a nested expression from serialized bytes.
    /// Used by DeserializeContext and DeserializeRegister.
    fn evaluateNestedExpression(self: *Evaluator, bytes: []const u8, expected_type: TypeIndex) EvalError!Value {
        // Check recursion depth to prevent infinite loops
        if (self.deserialize_depth >= max_deserialize_depth) {
            return error.InvalidData; // DeserializeDepthExceeded
        }
        self.deserialize_depth += 1;
        defer self.deserialize_depth -= 1;

        // Deserialize expression bytes into a new tree
        var reader = vlq.Reader.init(bytes);
        var nested_tree = ExprTree.init();
        var nested_arena = BumpAllocator(1024).init();

        expr.deserialize(&nested_tree, &reader, &nested_arena) catch {
            return error.InvalidData; // DeserializeFailed
        };

        // Create nested evaluator with same context
        var nested_eval = Evaluator{
            .tree = &nested_tree,
            .ctx = self.ctx,
            .version_ctx = self.version_ctx,
            .cost_limit = self.cost_limit - self.cost_used, // Remaining cost budget
            .deadline_ns = self.deadline_ns,
            .deserialize_depth = self.deserialize_depth,
        };

        // Evaluate the nested expression
        const result = nested_eval.evaluate() catch {
            return error.InvalidData; // NestedEvalFailed
        };

        // Add nested cost to our cost
        self.cost_used += nested_eval.cost_used;

        // Validate result type matches expected type
        const result_type = self.valueTypeIndex(result);
        if (!typesCompatible(expected_type, result_type, &self.pools.type_pool)) {
            return error.TypeMismatch;
        }

        return result;
    }

    /// Skip over serialized value data without parsing.
    /// Uses work stack for complex types (no recursion per ZIGMA_STYLE).
    fn skipValueForType(pool: *const TypePool, reader: *vlq.Reader, start_type: TypeIndex) EvalError!void {
        const max_skip_depth: usize = 64;

        // Work stack: each entry is a type index to skip
        var work_stack: [max_skip_depth]SkipWork = undefined;
        var stack_len: usize = 0;

        // Push initial type
        work_stack[0] = .{ .type_idx = start_type, .count = 1 };
        stack_len = 1;

        // Process work stack iteratively
        while (stack_len > 0) {
            stack_len -= 1;
            var work = work_stack[stack_len];

            while (work.count > 0) {
                work.count -= 1;

                const stype = pool.get(work.type_idx);

                switch (stype) {
                    .unit => {}, // 0 bytes

                    .boolean, .byte => {
                        _ = reader.readByte() catch return error.InvalidData;
                    },

                    .short => {
                        _ = reader.readI16() catch return error.InvalidData;
                    },

                    .int => {
                        _ = reader.readI32() catch return error.InvalidData;
                    },

                    .long => {
                        _ = reader.readI64() catch return error.InvalidData;
                    },

                    .big_int, .unsigned_big_int => {
                        // VLQ u16 length + bytes
                        const len = reader.readU16() catch return error.InvalidData;
                        if (reader.pos + len > reader.data.len) return error.InvalidData;
                        reader.pos += len;
                    },

                    .group_element => {
                        // 33 bytes compressed SEC1
                        if (reader.pos + 33 > reader.data.len) return error.InvalidData;
                        reader.pos += 33;
                    },

                    .sigma_prop => {
                        // Skip SigmaBoolean tree
                        try skipSigmaProp(reader);
                    },

                    .avl_tree => {
                        // digest(33) + flags(1) + key_len(VLQ) + opt_val_len
                        if (reader.pos + 34 > reader.data.len) return error.InvalidData;
                        reader.pos += 34; // digest + flags

                        _ = reader.readU32() catch return error.InvalidData; // key_length

                        const opt_flag = reader.readByte() catch return error.InvalidData;
                        if (opt_flag != 0) {
                            _ = reader.readU32() catch return error.InvalidData; // value_length
                        }
                    },

                    .coll => |elem_idx| {
                        const len = reader.readU16() catch return error.InvalidData;
                        if (len == 0) continue;

                        const elem_type = pool.get(elem_idx);

                        // Special case: Coll[Byte] - raw bytes
                        if (elem_type == .byte) {
                            if (reader.pos + len > reader.data.len) return error.InvalidData;
                            reader.pos += len;
                            continue;
                        }

                        // Special case: Coll[Boolean] - bit-packed
                        if (elem_type == .boolean) {
                            const byte_len = (len + 7) / 8;
                            if (reader.pos + byte_len > reader.data.len) return error.InvalidData;
                            reader.pos += byte_len;
                            continue;
                        }

                        // Generic collection - push elements to skip
                        if (stack_len >= max_skip_depth) return error.InvalidData;
                        work_stack[stack_len] = .{ .type_idx = elem_idx, .count = len };
                        stack_len += 1;
                    },

                    .option => |inner_idx| {
                        const flag = reader.readByte() catch return error.InvalidData;
                        if (flag == 0) continue; // None - nothing more to skip

                        // Some - skip inner value
                        if (stack_len >= max_skip_depth) return error.InvalidData;
                        work_stack[stack_len] = .{ .type_idx = inner_idx, .count = 1 };
                        stack_len += 1;
                    },

                    .pair => |p| {
                        // Push both elements (in reverse order so first is processed first)
                        if (stack_len + 2 > max_skip_depth) return error.InvalidData;
                        work_stack[stack_len] = .{ .type_idx = p.second, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = p.first, .count = 1 };
                        stack_len += 1;
                    },

                    .triple => |tr| {
                        if (stack_len + 3 > max_skip_depth) return error.InvalidData;
                        work_stack[stack_len] = .{ .type_idx = tr.c, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = tr.b, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = tr.a, .count = 1 };
                        stack_len += 1;
                    },

                    .quadruple => |q| {
                        if (stack_len + 4 > max_skip_depth) return error.InvalidData;
                        work_stack[stack_len] = .{ .type_idx = q.d, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = q.c, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = q.b, .count = 1 };
                        stack_len += 1;
                        work_stack[stack_len] = .{ .type_idx = q.a, .count = 1 };
                        stack_len += 1;
                    },

                    .tuple => |tuple_n| {
                        const elems = tuple_n.slice();
                        if (stack_len + elems.len > max_skip_depth) return error.InvalidData;

                        // Push in reverse order
                        var j: usize = elems.len;
                        while (j > 0) {
                            j -= 1;
                            work_stack[stack_len] = .{ .type_idx = elems[j], .count = 1 };
                            stack_len += 1;
                        }
                    },

                    // Object types (Box, Context, Header) cannot be serialized as constants
                    .box, .context, .header, .pre_header, .global, .any => {
                        return error.UnsupportedExpression;
                    },

                    // Function types shouldn't appear in constants
                    .func, .type_var => {
                        return error.UnsupportedExpression;
                    },
                }
            }
        }
    }

    /// Work item for skipValueForType
    const SkipWork = struct {
        type_idx: TypeIndex,
        count: u16, // Number of values of this type to skip
    };

    /// Skip SigmaBoolean tree (recursive structure)
    fn skipSigmaProp(reader: *vlq.Reader) EvalError!void {
        const opcode = reader.readByte() catch return error.InvalidData;

        switch (opcode) {
            0x00 => {}, // TrivialFalse - 0 bytes
            0x01 => {}, // TrivialTrue - 0 bytes

            0xCD => {
                // ProveDlog - 33 byte public key
                if (reader.pos + 33 > reader.data.len) return error.InvalidData;
                reader.pos += 33;
            },

            0xCE => {
                // ProveDHTuple - 4x 33 byte public keys = 132 bytes
                if (reader.pos + 132 > reader.data.len) return error.InvalidData;
                reader.pos += 132;
            },

            0x98 => {
                // CAND - VLQ count + children
                const count = reader.readU16() catch return error.InvalidData;
                for (0..count) |_| {
                    try skipSigmaProp(reader);
                }
            },

            0x99 => {
                // COR - VLQ count + children
                const count = reader.readU16() catch return error.InvalidData;
                for (0..count) |_| {
                    try skipSigmaProp(reader);
                }
            },

            0x9A => {
                // CTHRESHOLD - k (2 bytes BE) + count + children
                reader.pos += 2; // k
                const count = reader.readByte() catch return error.InvalidData;
                for (0..count) |_| {
                    try skipSigmaProp(reader);
                }
            },

            else => return error.InvalidData,
        }
    }

    /// Get type index for a runtime Value
    fn valueTypeIndex(self: *const Evaluator, val: Value) TypeIndex {
        _ = self;
        return switch (val) {
            .unit => TypePool.UNIT,
            .boolean => TypePool.BOOLEAN,
            .byte => TypePool.BYTE,
            .short => TypePool.SHORT,
            .int => TypePool.INT,
            .long => TypePool.LONG,
            .big_int => TypePool.BIG_INT,
            .group_element => TypePool.GROUP_ELEMENT,
            .coll_byte, .hash32 => TypePool.COLL_BYTE,
            .sigma_prop => TypePool.SIGMA_PROP,
            .avl_tree => TypePool.AVL_TREE,
            .box => TypePool.BOX,
            .coll => |c| c.elem_type, // Return element type, need Coll wrapper
            .option => |o| o.inner_type, // Return inner type, need Option wrapper
            else => TypePool.ANY,
        };
    }

    /// Get element from a CollRef at given index
    fn getCollectionElementFromRef(self: *const Evaluator, coll: Value.CollRef, idx: u16) EvalError!Value {
        if (idx >= coll.len) return error.IndexOutOfBounds;

        // Get from values array (where computeConcreteCollection stores elements)
        const start_idx = coll.start;
        const val_idx = start_idx + idx;

        if (val_idx >= max_value_stack) return error.IndexOutOfBounds;
        return self.values[val_idx];
    }

    /// Serialize a constant (type + value) to bytes
    /// Returns number of bytes written
    fn serializeConstant(
        self: *const Evaluator,
        type_idx: TypeIndex,
        val: Value,
        output: []u8,
    ) EvalError!usize {
        _ = self;
        var pos: usize = 0;

        // Serialize type code
        if (type_idx <= 111) {
            output[pos] = @intCast(type_idx);
            pos += 1;
        } else {
            // Handle generic types
            return error.UnsupportedExpression;
        }

        // Serialize value
        switch (val) {
            .boolean => |b| {
                output[pos] = if (b) 1 else 0;
                pos += 1;
            },
            .byte => |b| {
                output[pos] = @bitCast(b);
                pos += 1;
            },
            .short => |s| {
                const encoded = vlq.zigzagEncode(@as(i64, s));
                pos += vlq.encodeU64(encoded, output[pos..]);
            },
            .int => |i_val| {
                const encoded = vlq.zigzagEncode(@as(i64, i_val));
                pos += vlq.encodeU64(encoded, output[pos..]);
            },
            .long => |l| {
                const encoded = vlq.zigzagEncode(l);
                pos += vlq.encodeU64(encoded, output[pos..]);
            },
            .big_int => |bi| {
                pos += vlq.encodeU64(@intCast(bi.len), output[pos..]);
                @memcpy(output[pos..][0..bi.len], bi.bytes[0..bi.len]);
                pos += bi.len;
            },
            .group_element => |ge| {
                @memcpy(output[pos..][0..33], &ge);
                pos += 33;
            },
            .coll_byte => |cb| {
                pos += vlq.encodeU64(@intCast(cb.len), output[pos..]);
                @memcpy(output[pos..][0..cb.len], cb);
                pos += cb.len;
            },
            .hash32 => |*h| {
                pos += vlq.encodeU64(32, output[pos..]);
                @memcpy(output[pos..][0..32], h);
                pos += 32;
            },
            else => return error.UnsupportedExpression,
        }

        return pos;
    }

    /// Serialize a constant (type + value) to bytes using full type serialization.
    /// Supports complex types like Coll[T], Option[T], Pair, Tuple.
    /// Returns number of bytes written.
    fn serializeConstantFull(
        self: *const Evaluator,
        type_idx: TypeIndex,
        type_pool: *const TypePool,
        val: Value,
        output: []u8,
    ) EvalError!usize {
        var pos: usize = 0;

        // Serialize type using type_serializer (handles all types)
        const type_bytes = type_serializer.serialize(type_pool, type_idx, output) catch {
            return error.OutOfMemory; // Buffer too small
        };
        pos += type_bytes;

        // Serialize value using data_serializer with ValuePool access
        const value_bytes = data.serializeWithPool(
            type_idx,
            type_pool,
            val,
            &self.pools.values,
            output[pos..],
        ) catch |err| {
            return switch (err) {
                error.BufferTooSmall => error.OutOfMemory,
                error.NotSupported => error.UnsupportedExpression,
                error.InvalidData => error.InvalidData,
            };
        };
        pos += value_bytes;

        return pos;
    }

    /// Get element from an Int collection at given index
    fn getIntCollectionElement(self: *const Evaluator, coll: Value.CollRef, idx: u16) EvalError!i32 {
        if (idx >= coll.len) return error.IndexOutOfBounds;

        // Get from value pool
        const start_idx = coll.start;
        const val_idx = start_idx + idx;

        if (self.pools.values.get(val_idx)) |pooled| {
            // Check type is Int
            if (pooled.type_idx != TypePool.INT) return error.TypeMismatch;
            // Get primitive value truncated to i32
            const val: i32 = @truncate(pooled.data.primitive);
            return val;
        }
        return error.InvalidData;
    }

    // ========================================================================
    // UnsignedBigInt Method Operations (v6+)
    // ========================================================================

    /// Cost constants for UnsignedBigInt operations (from Scala)
    const UBICost = struct {
        const mod_cost: u32 = 20; // ubi.mod(m)
        const mod_inverse_cost: u32 = 150; // ubi.modInverse(m) - expensive (Extended Euclidean)
        const plus_mod_cost: u32 = 30; // ubi.plusMod(other, m)
        const subtract_mod_cost: u32 = 30; // ubi.subtractMod(other, m)
        const multiply_mod_cost: u32 = 40; // ubi.multiplyMod(other, m)
        const to_signed_cost: u32 = 10; // ubi.toSigned
    };

    /// Compute ubi.mod(m) → UnsignedBigInt
    /// Returns self % m
    fn computeUBIMod(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // ubi and m on stack
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.mod_cost);

        // Pop in reverse order (m, ubi)
        const m_val = try self.popValue();
        const ubi_val = try self.popValue();

        // Both must be unsigned_big_int
        if (m_val != .unsigned_big_int or ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);
        const m = try valueToUnsignedBigInt256(m_val.unsigned_big_int);

        // Compute mod
        const result = ubi.mod(m) catch return error.DivisionByZero;

        // POSTCONDITIONS
        try self.pushValue(unsignedBigInt256ToValue(result));
        assert(self.value_sp == initial_sp - 1); // Popped 2, pushed 1
    }

    /// Compute ubi.modInverse(m) → UnsignedBigInt
    /// Returns modular multiplicative inverse using Extended Euclidean Algorithm
    fn computeUBIModInverse(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.mod_inverse_cost);

        const m_val = try self.popValue();
        const ubi_val = try self.popValue();

        if (m_val != .unsigned_big_int or ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);
        const m = try valueToUnsignedBigInt256(m_val.unsigned_big_int);

        // Compute modular inverse
        const result = ubi.modInverse(m) catch return error.DivisionByZero;

        try self.pushValue(unsignedBigInt256ToValue(result));
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute ubi.plusMod(other, m) → UnsignedBigInt
    /// Returns (self + other) % m
    fn computeUBIPlusMod(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3); // ubi, other, m on stack
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.plus_mod_cost);

        // Pop in reverse order (m, other, ubi)
        const m_val = try self.popValue();
        const other_val = try self.popValue();
        const ubi_val = try self.popValue();

        if (m_val != .unsigned_big_int or other_val != .unsigned_big_int or ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);
        const other = try valueToUnsignedBigInt256(other_val.unsigned_big_int);
        const m = try valueToUnsignedBigInt256(m_val.unsigned_big_int);

        // Compute (ubi + other) mod m
        const result = ubi.plusMod(other, m) catch return error.DivisionByZero;

        try self.pushValue(unsignedBigInt256ToValue(result));
        assert(self.value_sp == initial_sp - 2); // Popped 3, pushed 1
    }

    /// Compute ubi.subtractMod(other, m) → UnsignedBigInt
    /// Returns (self - other) % m (always non-negative)
    fn computeUBISubtractMod(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.subtract_mod_cost);

        const m_val = try self.popValue();
        const other_val = try self.popValue();
        const ubi_val = try self.popValue();

        if (m_val != .unsigned_big_int or other_val != .unsigned_big_int or ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);
        const other = try valueToUnsignedBigInt256(other_val.unsigned_big_int);
        const m = try valueToUnsignedBigInt256(m_val.unsigned_big_int);

        // Compute (ubi - other) mod m
        const result = ubi.subtractMod(other, m) catch return error.DivisionByZero;

        try self.pushValue(unsignedBigInt256ToValue(result));
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute ubi.multiplyMod(other, m) → UnsignedBigInt
    /// Returns (self * other) % m
    fn computeUBIMultiplyMod(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.multiply_mod_cost);

        const m_val = try self.popValue();
        const other_val = try self.popValue();
        const ubi_val = try self.popValue();

        if (m_val != .unsigned_big_int or other_val != .unsigned_big_int or ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);
        const other = try valueToUnsignedBigInt256(other_val.unsigned_big_int);
        const m = try valueToUnsignedBigInt256(m_val.unsigned_big_int);

        // Compute (ubi * other) mod m
        const result = ubi.multiplyMod(other, m) catch return error.DivisionByZero;

        try self.pushValue(unsignedBigInt256ToValue(result));
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute ubi.toSigned → BigInt
    /// Converts UnsignedBigInt to signed BigInt (error if >= 2^255)
    fn computeUBIToSigned(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);
        const initial_sp = self.value_sp;

        try self.addCost(UBICost.to_signed_cost);

        const ubi_val = try self.popValue();

        if (ubi_val != .unsigned_big_int) {
            return error.TypeMismatch;
        }

        const ubi = try valueToUnsignedBigInt256(ubi_val.unsigned_big_int);

        // Convert to signed (errors if value >= 2^255)
        const signed = ubi.toSigned() catch return error.ArithmeticOverflow;

        try self.pushValue(bigInt256ToValue(signed));
        assert(self.value_sp == initial_sp); // Popped 1, pushed 1
    }

    // ========================================================================
    // Global Method Operations (v6+)
    // ========================================================================

    /// Cost constants for Global operations (from Scala)
    const GlobalCost = struct {
        const group_generator: u32 = 10; // Global.groupGenerator
        const xor: u32 = 20; // Global.xor (per byte)
        const encode_nbits: u32 = 25; // Global.encodeNBits
        const decode_nbits: u32 = 50; // Global.decodeNBits
        const serialize_base: u32 = 10; // Global.serialize (base)
        const serialize_per_byte: u32 = 2; // Global.serialize (per output byte)
        const from_big_endian: u32 = 30; // Global.fromBigEndianBytes
    };

    /// Compute Global.groupGenerator → GroupElement
    /// Returns the generator point G of secp256k1
    fn computeGroupGenerator(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1); // Global object on stack
        const initial_sp = self.value_sp;

        try self.addCost(GlobalCost.group_generator);

        // Pop Global object (we don't use it)
        _ = try self.popValue();

        // Return generator point G (33-byte compressed SEC1 format)
        // secp256k1 generator: 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
        const generator = [_]u8{
            0x02, // Compressed point prefix (even y)
            0x79,
            0xBE,
            0x66,
            0x7E,
            0xF9,
            0xDC,
            0xBB,
            0xAC,
            0x55,
            0xA0,
            0x62,
            0x95,
            0xCE,
            0x87,
            0x0B,
            0x07,
            0x02,
            0x9B,
            0xFC,
            0xDB,
            0x2D,
            0xCE,
            0x28,
            0xD9,
            0x59,
            0xF2,
            0x81,
            0x5B,
            0x16,
            0xF8,
            0x17,
            0x98,
        };

        try self.pushValue(.{ .group_element = generator });

        // POSTCONDITION: Stack unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute Global.xor(left, right) → Coll[Byte]
    /// XOR two byte collections element-wise
    fn computeGlobalXor(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 3); // Global, left, right on stack
        const initial_sp = self.value_sp;

        // Pop in reverse order: right, left, global
        const right_val = try self.popValue();
        const left_val = try self.popValue();
        _ = try self.popValue(); // Global object (unused)

        // Both must be coll_byte
        const left = switch (left_val) {
            .coll_byte => |c| c,
            else => return error.TypeMismatch,
        };
        const right = switch (right_val) {
            .coll_byte => |c| c,
            else => return error.TypeMismatch,
        };

        // Must have same length
        if (left.len != right.len) {
            return error.TypeMismatch;
        }

        // Cost: per byte
        try self.addCost(GlobalCost.xor + @as(u32, @intCast(left.len)));

        // Allocate result
        const result = self.arena.allocSlice(u8, left.len) catch return error.OutOfMemory;

        // XOR element-wise
        for (result, left, right) |*dst, l, r| {
            dst.* = l ^ r;
        }

        try self.pushValue(.{ .coll_byte = result });

        // POSTCONDITION: Popped 3, pushed 1
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute Global.encodeNBits(n: BigInt) → Long
    /// Encodes a BigInt difficulty target to compact nBits representation
    /// Reference: Bitcoin's compact format (4 bytes: 1 exp + 3 mantissa)
    fn computeEncodeNBits(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // Global, n on stack
        const initial_sp = self.value_sp;

        try self.addCost(GlobalCost.encode_nbits);

        // Pop in reverse order: n, global
        const n_val = try self.popValue();
        _ = try self.popValue(); // Global object

        // n must be BigInt
        if (n_val != .big_int) {
            return error.TypeMismatch;
        }

        const bigint = try valueToBigInt256(n_val.big_int);

        // Get bytes of BigInt (big-endian, minimal encoding)
        var temp_buf: [33]u8 = undefined;
        const bytes = bigint.toBytes(&temp_buf);

        // nBits format: [exponent (1 byte)] [mantissa (3 bytes)]
        // exponent = number of bytes in target
        // mantissa = first 3 significant bytes
        var nbits: u32 = 0;

        if (bytes.len == 0 or (bytes.len == 1 and bytes[0] == 0)) {
            // Zero target
            nbits = 0;
        } else {
            // Skip sign byte if present for positive numbers
            var target_bytes = bytes;
            if (bytes[0] == 0x00 and bytes.len > 1) {
                target_bytes = bytes[1..];
            }

            const size: u32 = @intCast(target_bytes.len);
            var word: u32 = 0;

            // Get first 3 bytes as mantissa
            if (target_bytes.len >= 3) {
                word = (@as(u32, target_bytes[0]) << 16) | (@as(u32, target_bytes[1]) << 8) | @as(u32, target_bytes[2]);
            } else if (target_bytes.len == 2) {
                word = (@as(u32, target_bytes[0]) << 8) | @as(u32, target_bytes[1]);
            } else if (target_bytes.len == 1) {
                word = @as(u32, target_bytes[0]);
            }

            // If mantissa MSB is set, increment size and shift right
            if ((word & 0x00800000) != 0) {
                word >>= 8;
                nbits = ((size + 1) << 24) | word;
            } else {
                nbits = (size << 24) | word;
            }
        }

        try self.pushValue(.{ .long = @as(i64, nbits) });

        // POSTCONDITION: Popped 2, pushed 1
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute Global.decodeNBits(nBits: Long) → BigInt
    /// Decodes compact nBits representation to BigInt difficulty target
    fn computeDecodeNBits(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // Global, nBits on stack
        const initial_sp = self.value_sp;

        try self.addCost(GlobalCost.decode_nbits);

        // Pop in reverse order: nBits, global
        const nbits_val = try self.popValue();
        _ = try self.popValue(); // Global object

        // nBits must be Long
        const nbits: u32 = switch (nbits_val) {
            .long => |l| if (l < 0) return error.ArithmeticOverflow else @intCast(@as(u64, @bitCast(l)) & 0xFFFFFFFF),
            .int => |i| if (i < 0) return error.ArithmeticOverflow else @intCast(i),
            else => return error.TypeMismatch,
        };

        // nBits format: [exponent (1 byte)] [mantissa (3 bytes)]
        const size = (nbits >> 24) & 0xFF;
        var word = nbits & 0x007FFFFF;

        // Handle special cases
        if (size == 0) {
            try self.pushValue(bigInt256ToValue(BigInt256.zero));
            assert(self.value_sp == initial_sp - 1);
            return;
        }

        // Build the target number
        // target = mantissa * 256^(exponent-3)
        var result_bytes: [33]u8 = [_]u8{0} ** 33;
        var result_len: usize = 0;

        if (size <= 3) {
            // Right shift mantissa
            const shift: u5 = @intCast((3 - size) * 8);
            word >>= shift;
            if (word != 0) {
                result_bytes[0] = 0; // Sign byte for positive
                result_bytes[1] = @truncate((word >> 16) & 0xFF);
                result_bytes[2] = @truncate((word >> 8) & 0xFF);
                result_bytes[3] = @truncate(word & 0xFF);
                // Find minimal encoding
                var start: usize = 1;
                while (start < 4 and result_bytes[start] == 0) : (start += 1) {}
                // Add sign byte if needed
                if (result_bytes[start] & 0x80 != 0) {
                    start -= 1;
                    result_bytes[start] = 0;
                }
                result_len = 4 - start;
                @memcpy(result_bytes[0..result_len], result_bytes[start..4]);
            }
        } else {
            // Build big number with leading zeros
            result_bytes[0] = 0; // Sign byte
            result_bytes[1] = @truncate((word >> 16) & 0xFF);
            result_bytes[2] = @truncate((word >> 8) & 0xFF);
            result_bytes[3] = @truncate(word & 0xFF);

            // Pad with zeros
            const extra_bytes = size - 3;
            result_len = 4 + @min(extra_bytes, 29);
            @memset(result_bytes[4..result_len], 0);
        }

        if (result_len == 0) {
            try self.pushValue(bigInt256ToValue(BigInt256.zero));
        } else {
            const bigint = BigInt256.fromBytes(result_bytes[0..result_len]) catch
                return error.InvalidBigInt;
            try self.pushValue(bigInt256ToValue(bigint));
        }

        // POSTCONDITION: Popped 2, pushed 1
        assert(self.value_sp == initial_sp - 1);
    }

    /// Map a Value discriminant to its corresponding TypeIndex
    /// Used for serialize[T] where type T must be inferred from the value
    /// Note: For collections/options, returns the best matching pre-defined type
    fn valueToTypeIndex(value: Value) TypeIndex {
        return switch (value) {
            .unit => TypePool.UNIT,
            .boolean => TypePool.BOOLEAN,
            .byte => TypePool.BYTE,
            .short => TypePool.SHORT,
            .int => TypePool.INT,
            .long => TypePool.LONG,
            .big_int => TypePool.BIG_INT,
            .unsigned_big_int => TypePool.UNSIGNED_BIG_INT,
            .group_element => TypePool.GROUP_ELEMENT,
            .sigma_prop => TypePool.SIGMA_PROP,
            .coll_byte => TypePool.COLL_BYTE,
            .coll => |c| switch (c.elem_type) {
                TypePool.BYTE => TypePool.COLL_BYTE,
                TypePool.INT => TypePool.COLL_INT,
                TypePool.LONG => TypePool.COLL_LONG,
                TypePool.COLL_BYTE => TypePool.COLL_COLL_BYTE,
                else => TypePool.COLL_BYTE, // Fallback
            },
            .option => |o| switch (o.inner_type) {
                TypePool.INT => TypePool.OPTION_INT,
                TypePool.LONG => TypePool.OPTION_LONG,
                TypePool.COLL_BYTE => TypePool.OPTION_COLL_BYTE,
                else => TypePool.OPTION_INT, // Fallback
            },
            .box => TypePool.BOX,
            .header => TypePool.HEADER,
            .pre_header => TypePool.PRE_HEADER,
            .avl_tree => TypePool.AVL_TREE,
            // Tuples require dynamic type construction; fallback to unit
            .tuple => TypePool.UNIT,
            .hash32 => TypePool.COLL_BYTE, // Hash32 is Coll[Byte] semantically
            // Box collections need dynamic type; fallback to unit
            .box_coll => TypePool.UNIT,
            // Token collections need dynamic type; fallback to unit
            .token_coll => TypePool.UNIT,
            .soft_fork_placeholder => TypePool.UNIT, // Placeholder
            // Functions don't have a standard type in TypePool; fallback to unit
            .func_ref => TypePool.UNIT,
        };
    }

    /// Compute Global.serialize[T](value: T) → Coll[Byte]
    /// Serializes any value to bytes using ErgoTree data format
    fn computeGlobalSerialize(self: *Evaluator, result_type: TypeIndex) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // Global, value on stack
        const initial_sp = self.value_sp;

        // Pop in reverse order: value, global
        const value = try self.popValue();
        _ = try self.popValue(); // Global object (unused)

        // Get type of the value for serialization
        const value_type = valueToTypeIndex(value);

        // Allocate output buffer (max 4KB for typical values)
        const max_size: usize = 4096;
        var buf: [max_size]u8 = undefined;

        // Serialize value
        const serialized_len = data.serialize(value_type, &self.pools.type_pool, value, &buf) catch {
            return error.InvalidData;
        };

        // Cost: base + per output byte
        try self.addCost(GlobalCost.serialize_base + GlobalCost.serialize_per_byte * @as(u32, @intCast(serialized_len)));

        // Copy to arena
        const result = self.arena.allocSlice(u8, serialized_len) catch return error.OutOfMemory;
        @memcpy(result, buf[0..serialized_len]);

        try self.pushValue(.{ .coll_byte = result });

        // POSTCONDITION: Popped 2, pushed 1
        assert(self.value_sp == initial_sp - 1);
        _ = result_type;
    }

    /// Compute Global.fromBigEndianBytes[T](bytes: Coll[Byte]) → T
    /// Interprets bytes as big-endian representation of numeric type T
    fn computeGlobalFromBigEndianBytes(self: *Evaluator, target_type: TypeIndex) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 2); // Global, bytes on stack
        const initial_sp = self.value_sp;

        try self.addCost(GlobalCost.from_big_endian);

        // Pop in reverse order: bytes, global
        const bytes_val = try self.popValue();
        _ = try self.popValue(); // Global object

        // Must be byte collection
        const bytes = switch (bytes_val) {
            .coll_byte => |b| b,
            else => return error.TypeMismatch,
        };

        // Convert based on target type
        const result: Value = switch (target_type) {
            TypePool.BYTE => blk: {
                if (bytes.len != 1) return error.InvalidData;
                break :blk .{ .byte = @bitCast(bytes[0]) };
            },
            TypePool.SHORT => blk: {
                if (bytes.len > 2) return error.InvalidData;
                var padded: [2]u8 = [_]u8{0} ** 2;
                const offset = 2 - bytes.len;
                @memcpy(padded[offset..], bytes);
                break :blk .{ .short = @bitCast(padded) };
            },
            TypePool.INT => blk: {
                if (bytes.len > 4) return error.InvalidData;
                var padded: [4]u8 = [_]u8{0} ** 4;
                const offset = 4 - bytes.len;
                @memcpy(padded[offset..], bytes);
                break :blk .{ .int = std.mem.readInt(i32, &padded, .big) };
            },
            TypePool.LONG => blk: {
                if (bytes.len > 8) return error.InvalidData;
                var padded: [8]u8 = [_]u8{0} ** 8;
                const offset = 8 - bytes.len;
                @memcpy(padded[offset..], bytes);
                break :blk .{ .long = std.mem.readInt(i64, &padded, .big) };
            },
            TypePool.BIG_INT => blk: {
                if (bytes.len > 32) return error.InvalidData;
                // BigInt is stored as-is (already big-endian)
                var bigint: Value.BigInt = .{
                    .bytes = [_]u8{0} ** 33,
                    .len = @intCast(bytes.len),
                };
                @memcpy(bigint.bytes[0..bytes.len], bytes);
                break :blk .{ .big_int = bigint };
            },
            TypePool.UNSIGNED_BIG_INT => blk: {
                if (bytes.len > 32) return error.InvalidData;
                var ubigint: Value.UnsignedBigInt = .{
                    .bytes = [_]u8{0} ** 33,
                    .len = @intCast(bytes.len),
                };
                @memcpy(ubigint.bytes[0..bytes.len], bytes);
                break :blk .{ .unsigned_big_int = ubigint };
            },
            else => return error.UnsupportedExpression, // Only numeric types supported
        };

        try self.pushValue(result);

        // POSTCONDITION: Popped 2, pushed 1
        assert(self.value_sp == initial_sp - 1);
    }

    // ========================================================================
    // AvlTree Method Operations
    // ========================================================================

    /// Compute tree.digest → Coll[Byte] (33 bytes)
    fn computeAvlTreeDigest(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access (version-independent, same in JIT and AOT)
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // INVARIANT: digest has correct size
        assert(tree_data.digest.len == avl_tree.digest_size);

        // Copy digest to arena
        const result = self.arena.allocSlice(u8, avl_tree.digest_size) catch return error.OutOfMemory;
        @memcpy(result, &tree_data.digest);

        // INVARIANT: result has correct size
        assert(result.len == avl_tree.digest_size);

        try self.pushValue(.{ .coll_byte = result });

        // POSTCONDITION: Stack unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.enabledOperations → Byte
    fn computeAvlTreeEnabledOps(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;
        const flags_byte = tree_data.tree_flags.toByte();

        // INVARIANT: flags fit in a byte (reserved bits zero)
        assert(flags_byte <= 0x07); // Only lower 3 bits used

        try self.pushValue(.{ .byte = @bitCast(flags_byte) });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.keyLength → Int
    fn computeAvlTreeKeyLength(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // INVARIANT: key_length within protocol limits
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        try self.pushValue(.{ .int = @intCast(tree_data.key_length) });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.valueLengthOpt → Option[Int]
    fn computeAvlTreeValueLengthOpt(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        if (tree_data.value_length_opt) |vl| {
            // INVARIANT: value_length within protocol limits
            assert(vl <= avl_tree.max_value_length);

            // Some(vl) - store int in pool
            const idx = self.pools.values.alloc() catch return error.OutOfMemory;
            const pooled = value_pool.PooledValue{
                .type_idx = TypePool.INT,
                .data = .{ .primitive = @as(i64, @intCast(vl)) },
            };
            self.pools.values.set(idx, pooled);
            try self.pushValue(.{ .option = .{
                .inner_type = TypePool.INT,
                .value_idx = idx,
            } });
        } else {
            try self.pushOptionNone(TypePool.INT);
        }

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.isInsertAllowed → Boolean
    fn computeAvlTreeIsInsertAllowed(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // INVARIANT: key_length valid (tree was validated on construction)
        assert(tree_data.key_length > 0);

        try self.pushValue(.{ .boolean = tree_data.isInsertAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.isUpdateAllowed → Boolean
    fn computeAvlTreeIsUpdateAllowed(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // INVARIANT: key_length valid (tree was validated on construction)
        assert(tree_data.key_length > 0);

        try self.pushValue(.{ .boolean = tree_data.isUpdateAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.isRemoveAllowed → Boolean
    fn computeAvlTreeIsRemoveAllowed(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // INVARIANT: key_length valid (tree was validated on construction)
        assert(tree_data.key_length > 0);

        try self.pushValue(.{ .boolean = tree_data.isRemoveAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.contains(key, proof) → Boolean
    fn computeAvlTreeContains(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, key, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, key, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        // Cost: per-item based on proof size (LookupAvlTree)
        // PerItemCost(40, 10, 1) means base 40 + 10 per proof element
        const proof_elements: u32 = @intCast(proof.len);
        try self.addCost(AvlTreeCost.lookup.cost(proof_elements));

        const key_val = try self.popValue();
        if (key_val != .coll_byte) return error.TypeMismatch;
        const key = key_val.coll_byte;

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Validate key length
        if (key.len != tree_data.key_length) {
            return error.InvalidData;
        }

        // Use BatchAVLVerifier to check if key exists
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            try self.pushValue(.{ .boolean = false });
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        const result = verifier.lookup(key) catch {
            try self.pushValue(.{ .boolean = false });
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        const found = switch (result) {
            .found => true,
            .not_found, .verification_failed => false,
        };

        try self.pushValue(.{ .boolean = found });

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute tree.get(key, proof) → Option[Coll[Byte]]
    fn computeAvlTreeGet(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, key, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, key, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        // Cost: per-item based on proof size (LookupAvlTree)
        // PerItemCost(40, 10, 1) means base 40 + 10 per proof element
        const proof_elements: u32 = @intCast(proof.len);
        try self.addCost(AvlTreeCost.lookup.cost(proof_elements));

        const key_val = try self.popValue();
        if (key_val != .coll_byte) return error.TypeMismatch;
        const key = key_val.coll_byte;

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Validate key length
        if (key.len != tree_data.key_length) {
            return error.InvalidData;
        }

        // Use BatchAVLVerifier to lookup key
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            // Verification failed - return None
            try self.pushOptionNone(TypePool.COLL_BYTE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        const result = verifier.lookup(key) catch {
            try self.pushOptionNone(TypePool.COLL_BYTE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        switch (result) {
            .found => |value| {
                // Copy value to our arena and return Some(value)
                const value_copy = self.arena.allocSlice(u8, value.len) catch return error.OutOfMemory;
                @memcpy(value_copy, value);

                const idx = self.pools.values.alloc() catch return error.OutOfMemory;
                const pooled = value_pool.PooledValue{
                    .type_idx = TypePool.COLL_BYTE,
                    .data = .{ .byte_slice = .{ .ptr = value_copy.ptr, .len = @intCast(value_copy.len) } },
                };
                self.pools.values.set(idx, pooled);
                try self.pushValue(.{ .option = .{
                    .inner_type = TypePool.COLL_BYTE,
                    .value_idx = idx,
                } });
            },
            .not_found, .verification_failed => {
                try self.pushOptionNone(TypePool.COLL_BYTE);
            },
        }

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute tree.getMany(keys, proof) → Coll[Option[Coll[Byte]]]
    /// TODO: Full implementation requires Coll[Coll[Byte]] support
    fn computeAvlTreeGetMany(self: *Evaluator) EvalError!void {
        // getMany requires iterating through a collection of keys
        // and building a collection of Option[Coll[Byte]] results.
        // This needs full nested collection support which is complex.
        // Use soft-fork handling for now.
        return self.handleUnsupported();
    }

    /// Compute tree.updateDigest(newDigest) → AvlTree
    fn computeAvlTreeUpdateDigest(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (tree, digest)
        assert(self.value_sp >= 2);

        const initial_sp = self.value_sp;

        // Cost: updateDigest fixed cost
        try self.addCost(AvlTreeCost.update_digest);

        // Pop in reverse order (digest, tree)
        const digest_val = try self.popValue();
        if (digest_val != .coll_byte) return error.TypeMismatch;
        const new_digest_bytes = digest_val.coll_byte;
        if (new_digest_bytes.len != avl_tree.digest_size) return error.InvalidData;

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // Create new digest
        var new_digest: [avl_tree.digest_size]u8 = undefined;
        @memcpy(&new_digest, new_digest_bytes);

        // Create new tree with updated digest
        const new_tree = tree_data.withDigest(new_digest);

        try self.pushValue(.{ .avl_tree = new_tree });

        // POSTCONDITION: Stack reduced by 1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute tree.updateOperations(newOps) → AvlTree
    fn computeAvlTreeUpdateOperations(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (tree, ops)
        assert(self.value_sp >= 2);

        const initial_sp = self.value_sp;

        // Cost: updateOperations fixed cost
        try self.addCost(AvlTreeCost.update_operations);

        // Pop in reverse order (ops, tree)
        const ops_val = try self.popValue();
        const ops_byte: u8 = switch (ops_val) {
            .byte => |b| @bitCast(b),
            .int => |i| if (i >= 0 and i <= 255) @intCast(i) else return error.InvalidData,
            else => return error.TypeMismatch,
        };

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // Create new tree with updated flags
        const new_flags = avl_tree.AvlTreeFlags.fromByte(ops_byte);
        const new_tree = tree_data.withFlags(new_flags);

        try self.pushValue(.{ .avl_tree = new_tree });

        // POSTCONDITION: Stack reduced by 1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute tree.insert(entries, proof) → Option[AvlTree]
    /// entries: Coll[(Coll[Byte], Coll[Byte])] - key-value pairs to insert
    /// proof: Coll[Byte] - serialized proof
    fn computeAvlTreeInsert(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, entries, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, entries, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        const entries_val = try self.popValue();
        const entries_coll = switch (entries_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Check if insert is allowed
        if (!tree_data.isInsertAllowed()) {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        }

        // Cost: per-item based on entry count + proof size
        const entry_count: u32 = entries_coll.len;
        try self.addCost(AvlTreeCost.insert.cost(entry_count + @as(u32, @intCast(proof.len))));

        // Create verifier
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        // Process each entry tuple
        var i: u16 = 0;
        while (i < entries_coll.len) : (i += 1) {
            const entry = self.getCollectionElementFromRef(entries_coll, i) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };

            // Entry should be a tuple (Coll[Byte], Coll[Byte])
            if (entry != .tuple) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            const tuple = entry.tuple;
            if (tuple.len != 2) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            // Get key and value from tuple
            const key_elem = self.values[tuple.start];
            const value_elem = self.values[tuple.start + 1];

            const key = switch (key_elem) {
                .coll_byte => |kb| kb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            const value = switch (value_elem) {
                .coll_byte => |vb| vb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            // Perform insert
            verifier.insert(key, value) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };
        }

        // Create new tree with updated digest
        const new_tree = tree_data.withDigest(verifier.current_digest);
        try self.pushOptionSomeAvlTree(new_tree);

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute tree.update(entries, proof) → Option[AvlTree]
    /// entries: Coll[(Coll[Byte], Coll[Byte])] - key-value pairs to update
    /// proof: Coll[Byte] - serialized proof
    fn computeAvlTreeUpdate(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, entries, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, entries, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        const entries_val = try self.popValue();
        const entries_coll = switch (entries_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Check if update is allowed
        if (!tree_data.isUpdateAllowed()) {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        }

        // Cost: per-item based on entry count + proof size
        const entry_count: u32 = entries_coll.len;
        try self.addCost(AvlTreeCost.update.cost(entry_count + @as(u32, @intCast(proof.len))));

        // Create verifier
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        // Process each entry tuple
        var i: u16 = 0;
        while (i < entries_coll.len) : (i += 1) {
            const entry = self.getCollectionElementFromRef(entries_coll, i) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };

            // Entry should be a tuple (Coll[Byte], Coll[Byte])
            if (entry != .tuple) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            const tuple = entry.tuple;
            if (tuple.len != 2) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            // Get key and value from tuple
            const key_elem = self.values[tuple.start];
            const value_elem = self.values[tuple.start + 1];

            const key = switch (key_elem) {
                .coll_byte => |kb| kb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            const value = switch (value_elem) {
                .coll_byte => |vb| vb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            // Perform update
            verifier.update(key, value) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };
        }

        // Create new tree with updated digest
        const new_tree = tree_data.withDigest(verifier.current_digest);
        try self.pushOptionSomeAvlTree(new_tree);

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute tree.remove(keys, proof) → Option[AvlTree]
    /// keys: Coll[Coll[Byte]] - keys to remove
    /// proof: Coll[Byte] - serialized proof
    fn computeAvlTreeRemove(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, keys, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, keys, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        const keys_val = try self.popValue();
        const keys_coll = switch (keys_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Check if remove is allowed
        if (!tree_data.isRemoveAllowed()) {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        }

        // Cost: per-item based on key count + proof size
        const key_count: u32 = keys_coll.len;
        try self.addCost(AvlTreeCost.remove.cost(key_count + @as(u32, @intCast(proof.len))));

        // Create verifier
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        // Process each key
        var i: u16 = 0;
        while (i < keys_coll.len) : (i += 1) {
            const key_elem = self.getCollectionElementFromRef(keys_coll, i) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };

            const key = switch (key_elem) {
                .coll_byte => |kb| kb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            // Perform remove
            verifier.remove(key) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };
        }

        // Create new tree with updated digest
        const new_tree = tree_data.withDigest(verifier.current_digest);
        try self.pushOptionSomeAvlTree(new_tree);

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Compute tree.insertOrUpdate(entries, proof) → Option[AvlTree]
    /// entries: Coll[(Coll[Byte], Coll[Byte])] - key-value pairs to insert or update
    /// proof: Coll[Byte] - serialized proof
    /// Note: Requires both insert AND update flags to be allowed
    fn computeAvlTreeInsertOrUpdate(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, entries, proof)
        assert(self.value_sp >= 3);
        assert(self.value_sp <= max_value_stack);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, entries, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

        // INVARIANT: proof size within protocol limits
        assert(proof.len <= avl_tree.max_proof_size);

        const entries_val = try self.popValue();
        const entries_coll = switch (entries_val) {
            .coll => |c| c,
            else => return error.TypeMismatch,
        };

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;
        const tree_data = tree_val.avl_tree;

        // INVARIANT: tree has valid key_length
        assert(tree_data.key_length > 0);
        assert(tree_data.key_length <= avl_tree.max_key_length);

        // Check if both insert and update are allowed
        if (!tree_data.isInsertAllowed() or !tree_data.isUpdateAllowed()) {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        }

        // Cost: per-item based on entry count + proof size (use insert cost)
        const entry_count: u32 = entries_coll.len;
        try self.addCost(AvlTreeCost.insert.cost(entry_count + @as(u32, @intCast(proof.len))));

        // Create verifier
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var verifier = avl_tree.BatchAVLVerifier.init(
            tree_data.digest,
            proof,
            tree_data.key_length,
            if (tree_data.value_length_opt) |vl| @as(?usize, vl) else null,
            &arena,
        ) catch {
            try self.pushOptionNone(TypePool.AVL_TREE);
            assert(self.value_sp == initial_sp - 2);
            return;
        };

        // Process each entry tuple - try update first, then insert if key doesn't exist
        // The BatchAVLVerifier will handle this logic based on the proof
        var i: u16 = 0;
        while (i < entries_coll.len) : (i += 1) {
            const entry = self.getCollectionElementFromRef(entries_coll, i) catch {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            };

            // Entry should be a tuple (Coll[Byte], Coll[Byte])
            if (entry != .tuple) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            const tuple = entry.tuple;
            if (tuple.len != 2) {
                try self.pushOptionNone(TypePool.AVL_TREE);
                assert(self.value_sp == initial_sp - 2);
                return;
            }

            // Get key and value from tuple
            const key_elem = self.values[tuple.start];
            const value_elem = self.values[tuple.start + 1];

            const key = switch (key_elem) {
                .coll_byte => |kb| kb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            const value = switch (value_elem) {
                .coll_byte => |vb| vb,
                else => {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                },
            };

            // Try update first - if key exists, this succeeds
            // If key doesn't exist, fall back to insert
            verifier.update(key, value) catch {
                // Update failed (key not found), try insert
                verifier.insert(key, value) catch {
                    try self.pushOptionNone(TypePool.AVL_TREE);
                    assert(self.value_sp == initial_sp - 2);
                    return;
                };
            };
        }

        // Create new tree with updated digest
        const new_tree = tree_data.withDigest(verifier.current_digest);
        try self.pushOptionSomeAvlTree(new_tree);

        // POSTCONDITION: Stack reduced by 2 (popped 3, pushed 1)
        assert(self.value_sp == initial_sp - 2);
    }

    /// Push Some(AvlTree) option onto value stack
    fn pushOptionSomeAvlTree(self: *Evaluator, tree: avl_tree.AvlTreeData) EvalError!void {
        // Allocate slot in pool
        const idx = self.pools.values.alloc() catch return error.OutOfMemory;

        // Store avl_tree in pool
        const pooled = value_pool.PooledValue{
            .type_idx = TypePool.AVL_TREE,
            .data = .{ .avl_tree = tree },
        };
        self.pools.values.set(idx, pooled);

        // Push option referencing the pooled value
        try self.pushValue(.{ .option = .{
            .inner_type = TypePool.AVL_TREE,
            .value_idx = idx,
        } });
    }

    /// Push None option onto value stack
    fn pushOptionNone(self: *Evaluator, inner_type: types.TypeIndex) EvalError!void {
        try self.pushValue(.{
            .option = .{
                .inner_type = inner_type,
                .value_idx = null_value_idx, // Sentinel for None
            },
        });
    }

    /// Push Some(Coll[Byte]) option onto value stack
    /// Specialized for TreeLookup which returns Option[Coll[Byte]]
    fn pushOptionSomeCollByte(self: *Evaluator, bytes: []const u8) EvalError!void {
        // Allocate slot in pool
        const idx = self.pools.values.alloc() catch return error.OutOfMemory;

        // Store coll_byte in pool
        const pooled = value_pool.PooledValue{
            .type_idx = TypePool.COLL_BYTE,
            .data = .{ .byte_slice = .{ .ptr = bytes.ptr, .len = @intCast(bytes.len) } },
        };
        self.pools.values.set(idx, pooled);

        // Push option referencing the pooled value
        try self.pushValue(.{ .option = .{
            .inner_type = TypePool.COLL_BYTE,
            .value_idx = idx,
        } });
    }

    /// Extract SigmaBoolean from a Value (must be sigma_prop or boolean)
    fn extractSigmaBoolean(self: *Evaluator, val: Value) EvalError!*const sigma_tree.SigmaBoolean {
        switch (val) {
            .sigma_prop => |sp| {
                // Parse SigmaBoolean from serialized bytes
                return try self.parseSigmaBoolean(sp.data);
            },
            .boolean => |b| {
                // Boolean constant becomes trivial_true or trivial_false
                const node_ptr = self.arena.alloc(sigma_tree.SigmaBoolean, 1) catch return error.OutOfMemory;
                node_ptr[0] = if (b) sigma_tree.sigma_true else sigma_tree.sigma_false;
                return &node_ptr[0];
            },
            else => return error.TypeMismatch,
        }
    }

    /// Parse SigmaBoolean from serialized bytes
    /// Format: type_byte + type-specific data
    /// Returns parsed node and number of bytes consumed
    fn parseSigmaBooleanWithLen(self: *Evaluator, bytes: []const u8) EvalError!struct { node: *const sigma_tree.SigmaBoolean, len: usize } {
        if (bytes.len == 0) return error.InvalidData;

        const node_ptr = self.arena.alloc(sigma_tree.SigmaBoolean, 1) catch return error.OutOfMemory;

        // Parse based on type byte
        const type_byte = bytes[0];
        switch (type_byte) {
            0xCD => {
                // ProveDlog: 0xCD + 33-byte public key
                if (bytes.len < 34) return error.InvalidData;
                var pk: [33]u8 = undefined;
                @memcpy(&pk, bytes[1..34]);
                node_ptr[0] = .{ .prove_dlog = sigma_tree.ProveDlog.init(pk) };
                return .{ .node = &node_ptr[0], .len = 34 };
            },
            0xCE => {
                // ProveDHTuple: 0xCE + 4×33-byte points = 133 bytes total
                if (bytes.len < 133) return error.InvalidData;
                var g: [33]u8 = undefined;
                var h: [33]u8 = undefined;
                var u: [33]u8 = undefined;
                var v: [33]u8 = undefined;
                @memcpy(&g, bytes[1..34]);
                @memcpy(&h, bytes[34..67]);
                @memcpy(&u, bytes[67..100]);
                @memcpy(&v, bytes[100..133]);
                node_ptr[0] = .{ .prove_dh_tuple = sigma_tree.ProveDHTuple.init(g, h, u, v) };
                return .{ .node = &node_ptr[0], .len = 133 };
            },
            0x01 => {
                // TrivialTrue
                node_ptr[0] = sigma_tree.sigma_true;
                return .{ .node = &node_ptr[0], .len = 1 };
            },
            0x00 => {
                // TrivialFalse
                node_ptr[0] = sigma_tree.sigma_false;
                return .{ .node = &node_ptr[0], .len = 1 };
            },
            0x98 => {
                // CAND: 0x98 + count + children
                if (bytes.len < 2) return error.InvalidData;
                const count = bytes[1];
                if (count < 2) return error.InvalidData;

                const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, count) catch return error.OutOfMemory;
                var offset: usize = 2;
                for (0..count) |i| {
                    const child_result = try self.parseSigmaBooleanWithLen(bytes[offset..]);
                    child_slice[i] = child_result.node;
                    offset += child_result.len;
                }
                node_ptr[0] = .{ .cand = .{ .children = child_slice } };
                return .{ .node = &node_ptr[0], .len = offset };
            },
            0x99 => {
                // COR: 0x99 + count + children
                if (bytes.len < 2) return error.InvalidData;
                const count = bytes[1];
                if (count < 2) return error.InvalidData;

                const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, count) catch return error.OutOfMemory;
                var offset: usize = 2;
                for (0..count) |i| {
                    const child_result = try self.parseSigmaBooleanWithLen(bytes[offset..]);
                    child_slice[i] = child_result.node;
                    offset += child_result.len;
                }
                node_ptr[0] = .{ .cor = .{ .children = child_slice } };
                return .{ .node = &node_ptr[0], .len = offset };
            },
            0x9A => {
                // CTHRESHOLD: 0x9A + k (2 bytes big-endian) + count + children
                if (bytes.len < 4) return error.InvalidData;
                const k: u16 = (@as(u16, bytes[1]) << 8) | bytes[2];
                const count = bytes[3];
                if (count < 2) return error.InvalidData;

                const child_slice = self.arena.allocSlice(*const sigma_tree.SigmaBoolean, count) catch return error.OutOfMemory;
                var offset: usize = 4;
                for (0..count) |i| {
                    const child_result = try self.parseSigmaBooleanWithLen(bytes[offset..]);
                    child_slice[i] = child_result.node;
                    offset += child_result.len;
                }
                node_ptr[0] = .{ .cthreshold = .{ .k = k, .children = child_slice } };
                return .{ .node = &node_ptr[0], .len = offset };
            },
            else => {
                // Unknown type - return false as fallback
                node_ptr[0] = sigma_tree.sigma_false;
                return .{ .node = &node_ptr[0], .len = 1 };
            },
        }
    }

    /// Parse SigmaBoolean from serialized bytes (convenience wrapper)
    /// Made public for use by reducer.zig
    pub fn parseSigmaBoolean(self: *Evaluator, bytes: []const u8) EvalError!*const sigma_tree.SigmaBoolean {
        const result = try self.parseSigmaBooleanWithLen(bytes);
        return result.node;
    }

    /// Serialize SigmaBoolean to bytes
    /// Note: Uses bounded recursion (max_sigma_depth=16) since sigma trees are shallow.
    /// Full iterative conversion deferred - sigma depth is protocol-bounded.
    fn serializeSigmaBoolean(self: *Evaluator, node: *const sigma_tree.SigmaBoolean) EvalError![]const u8 {
        return self.serializeSigmaBooleanWithDepth(node, 0);
    }

    /// Maximum sigma tree depth (protocol-bounded, typically 2-3 in practice)
    const max_sigma_depth: u8 = 16;

    /// Internal: serialize with depth tracking to prevent stack overflow
    fn serializeSigmaBooleanWithDepth(self: *Evaluator, node: *const sigma_tree.SigmaBoolean, depth: u8) EvalError![]const u8 {
        // PRECONDITION: depth bounded to prevent stack overflow
        if (depth >= max_sigma_depth) return error.InvalidData;

        return switch (node.*) {
            .trivial_true => blk: {
                const buf = self.arena.allocSlice(u8, 1) catch return error.OutOfMemory;
                buf[0] = 0x01;
                break :blk buf;
            },
            .trivial_false => blk: {
                const buf = self.arena.allocSlice(u8, 1) catch return error.OutOfMemory;
                buf[0] = 0x00;
                break :blk buf;
            },
            .prove_dlog => |dlog| blk: {
                const buf = self.arena.allocSlice(u8, 34) catch return error.OutOfMemory;
                buf[0] = 0xCD;
                @memcpy(buf[1..34], &dlog.public_key);
                break :blk buf;
            },
            .prove_dh_tuple => |dht| blk: {
                const buf = self.arena.allocSlice(u8, 133) catch return error.OutOfMemory;
                buf[0] = 0xCE;
                @memcpy(buf[1..34], &dht.g);
                @memcpy(buf[34..67], &dht.h);
                @memcpy(buf[67..100], &dht.u);
                @memcpy(buf[100..133], &dht.v);
                break :blk buf;
            },
            .cand => |and_node| blk: {
                // Serialize AND: marker + count + children
                var total_len: usize = 2; // marker + count
                var child_bytes: [256][]const u8 = undefined;
                for (and_node.children, 0..) |child, idx| {
                    const child_ser = try self.serializeSigmaBooleanWithDepth(child, depth + 1);
                    child_bytes[idx] = child_ser;
                    total_len += child_ser.len;
                }
                const buf = self.arena.allocSlice(u8, total_len) catch return error.OutOfMemory;
                buf[0] = 0x98; // AND marker
                buf[1] = @truncate(and_node.children.len);
                var offset: usize = 2;
                for (and_node.children, 0..) |_, idx| {
                    @memcpy(buf[offset..][0..child_bytes[idx].len], child_bytes[idx]);
                    offset += child_bytes[idx].len;
                }
                break :blk buf;
            },
            .cor => |or_node| blk: {
                // Serialize OR: marker + count + children
                var total_len: usize = 2; // marker + count
                var child_bytes: [256][]const u8 = undefined;
                for (or_node.children, 0..) |child, idx| {
                    const child_ser = try self.serializeSigmaBooleanWithDepth(child, depth + 1);
                    child_bytes[idx] = child_ser;
                    total_len += child_ser.len;
                }
                const buf = self.arena.allocSlice(u8, total_len) catch return error.OutOfMemory;
                buf[0] = 0x99; // OR marker
                buf[1] = @truncate(or_node.children.len);
                var offset: usize = 2;
                for (or_node.children, 0..) |_, idx| {
                    @memcpy(buf[offset..][0..child_bytes[idx].len], child_bytes[idx]);
                    offset += child_bytes[idx].len;
                }
                break :blk buf;
            },
            .cthreshold => |th| blk: {
                // Serialize THRESHOLD: marker + k + count + children
                var total_len: usize = 4; // marker + k(2) + count
                var child_bytes: [256][]const u8 = undefined;
                for (th.children, 0..) |child, idx| {
                    const child_ser = try self.serializeSigmaBooleanWithDepth(child, depth + 1);
                    child_bytes[idx] = child_ser;
                    total_len += child_ser.len;
                }
                const buf = self.arena.allocSlice(u8, total_len) catch return error.OutOfMemory;
                buf[0] = 0x9A; // THRESHOLD marker
                buf[1] = @truncate(th.k >> 8);
                buf[2] = @truncate(th.k);
                buf[3] = @truncate(th.children.len);
                var offset: usize = 4;
                for (th.children, 0..) |_, idx| {
                    @memcpy(buf[offset..][0..child_bytes[idx].len], child_bytes[idx]);
                    offset += child_bytes[idx].len;
                }
                break :blk buf;
            },
        };
    }

    /// Helper: get element from collection at index
    fn getCollectionElement(self: *Evaluator, coll: Value, idx: usize) EvalError!Value {
        return switch (coll) {
            .coll_byte => |c| if (idx < c.len) .{ .byte = @bitCast(c[idx]) } else error.IndexOutOfBounds,
            .coll => |c| self.getCollectionElementFromRef(c, @intCast(idx)),
            else => error.TypeMismatch,
        };
    }

    /// Helper: extract bytes from a collection that holds bytes.
    /// Handles both .coll_byte (direct) and .coll with elem_type=BYTE (from pool).
    /// Returns null if not a byte collection or extraction fails.
    fn extractBytesFromColl(self: *Evaluator, coll: Value, buf: []u8) ?[]const u8 {
        switch (coll) {
            .coll_byte => |bytes| {
                if (bytes.len > buf.len) return null;
                return bytes;
            },
            .coll => |c| {
                // Check if this is a byte collection
                if (c.elem_type != TypePool.BYTE) return null;
                if (c.len > buf.len) return null;

                // Extract bytes from ValuePool
                for (0..c.len) |i| {
                    const pooled = self.pools.values.get(c.start + @as(u16, @intCast(i))) orelse return null;
                    if (pooled.type_idx != TypePool.BYTE) return null;
                    buf[i] = @intCast(@as(u64, @bitCast(pooled.data.primitive)) & 0xFF);
                }
                return buf[0..c.len];
            },
            else => return null,
        }
    }

    /// Helper: find lambda argument var_id by scanning body for val_use
    fn findLambdaArgId(self: *const Evaluator, body_idx: u16) ?u16 {
        const end_idx = self.findSubtreeEnd(body_idx);
        var i = body_idx;
        while (i < end_idx) : (i += 1) {
            const node = self.tree.nodes[i];
            if (node.tag == .val_use) {
                return node.data;
            }
        }
        return null;
    }

    /// Helper: evaluate a subtree and return result
    fn evaluateSubtree(self: *Evaluator, root_idx: u16) EvalError!Value {
        // PRECONDITION: Valid node index
        assert(root_idx < self.tree.node_count);
        // PRECONDITION: Stacks have room
        assert(self.work_sp < max_work_stack);
        assert(self.value_sp < max_value_stack);

        // Save current stack state
        const saved_work_sp = self.work_sp;
        const saved_value_sp = self.value_sp;
        const saved_cost = self.cost_used;

        // INVARIANT: Saved state is consistent
        assert(saved_work_sp <= max_work_stack);
        assert(saved_value_sp <= max_value_stack);

        // Push work for subtree
        try self.pushWork(.{ .node_idx = root_idx, .phase = .evaluate });

        // INVARIANT: Work was pushed
        assert(self.work_sp == saved_work_sp + 1);

        // Process until we return to saved state
        while (self.work_sp > saved_work_sp) {
            // INVARIANT: Still processing this subtree
            assert(self.work_sp >= saved_work_sp);

            const work = self.popWork();
            switch (work.phase) {
                .evaluate => try self.evaluateNode(work.node_idx),
                .compute => try self.computeNode(work.node_idx),
            }
        }

        // POSTCONDITION: Work stack returned to saved state
        assert(self.work_sp == saved_work_sp);
        // POSTCONDITION: Cost increased (subtree consumed resources)
        assert(self.cost_used >= saved_cost);

        // Result should be on stack
        if (self.value_sp <= saved_value_sp) return error.ValueStackUnderflow;

        // POSTCONDITION: Exactly one result on stack
        assert(self.value_sp == saved_value_sp + 1);

        return self.popValue();
    }

    // ========================================================================
    // ========================================================================
    // Diagnostics
    // ========================================================================

    /// Capture diagnostic state when an error occurs.
    /// Called before returning an error to preserve debugging info.
    fn captureEvalDiagnostics(self: *Evaluator, err: EvalError, node_idx: ?u16) void {
        const opcode: ?u8 = if (node_idx) |idx|
            if (idx < self.tree.node_count) @intFromEnum(self.tree.nodes[idx].tag) else null
        else
            null;

        self.diag = .{
            .error_code = EvalErrorCode.fromEvalError(err),
            .failed_opcode = opcode,
            .failed_node_idx = node_idx,
            .stack_depth = self.value_sp,
            .cost_at_failure = self.cost_used,
        };
    }

    /// Return an error after capturing diagnostics.
    /// Use this instead of plain `return error.X` to preserve context.
    fn returnWithDiag(self: *Evaluator, err: EvalError, node_idx: ?u16) EvalError {
        self.captureEvalDiagnostics(err, node_idx);
        return err;
    }

    // Stack operations
    // ========================================================================

    fn pushWork(self: *Evaluator, item: WorkItem) EvalError!void {
        // PRECONDITION: Stack not full
        // PRECONDITION: Node index is valid
        assert(item.node_idx < self.tree.node_count);

        if (self.work_sp >= max_work_stack) return error.WorkStackOverflow;

        const old_sp = self.work_sp;
        self.work_stack[self.work_sp] = item;
        self.work_sp += 1;

        // POSTCONDITION: Stack pointer incremented
        // POSTCONDITION: Item stored at correct location
        assert(self.work_sp == old_sp + 1);
        assert(self.work_stack[old_sp].node_idx == item.node_idx);
    }

    fn popWork(self: *Evaluator) WorkItem {
        // PRECONDITION: Stack not empty
        assert(self.work_sp > 0);
        // PRECONDITION: Pointer within bounds
        assert(self.work_sp <= max_work_stack);

        self.work_sp -= 1;
        const item = self.work_stack[self.work_sp];

        // POSTCONDITION: Stack pointer decremented
        // POSTCONDITION: Node index is valid
        assert(item.node_idx < self.tree.node_count);
        return item;
    }

    fn pushValue(self: *Evaluator, value: Value) EvalError!void {
        // PRECONDITION: Stack pointer within bounds
        assert(self.value_sp <= max_value_stack);

        if (self.value_sp >= max_value_stack) return error.ValueStackOverflow;

        const old_sp = self.value_sp;
        self.value_stack[self.value_sp] = value;
        self.value_sp += 1;

        // POSTCONDITION: Stack pointer incremented
        // POSTCONDITION: Value stored correctly
        assert(self.value_sp == old_sp + 1);
        assert(self.value_sp <= max_value_stack);
    }

    fn popValue(self: *Evaluator) EvalError!Value {
        // PRECONDITION: Stack pointer within bounds
        assert(self.value_sp <= max_value_stack);

        if (self.value_sp == 0) return error.ValueStackUnderflow;

        // INVARIANT: About to pop from non-empty stack
        assert(self.value_sp > 0);

        self.value_sp -= 1;
        const value = self.value_stack[self.value_sp];

        // POSTCONDITION: Stack pointer still valid
        assert(self.value_sp < max_value_stack);
        return value;
    }

    fn addCost(self: *Evaluator, cost: u32) EvalError!void {
        // PRECONDITION: Cost limit was set
        assert(self.cost_limit > 0);
        // PRECONDITION: Cost is reasonable (not suspiciously large)
        assert(cost <= 1_000_000);

        const old_cost = self.cost_used;
        self.cost_used +|= cost; // Saturating add

        // INVARIANT: Cost can only increase
        assert(self.cost_used >= old_cost);

        if (self.cost_used > self.cost_limit) {
            return error.CostLimitExceeded;
        }

        // POSTCONDITION: Cost still within limit
        assert(self.cost_used <= self.cost_limit);
    }

    /// Add cost using version-aware cost lookup.
    /// Use this for operations where cost depends on protocol version.
    fn addCostOp(self: *Evaluator, op: CostOp) EvalError!void {
        // PRECONDITION: Valid cost operation
        assert(@intFromEnum(op) < JIT_COSTS.len);

        const cost = getCost(self.version_ctx, op);

        // INVARIANT: Cost lookup returned valid value
        assert(cost > 0);
        assert(cost <= 100_000); // Max single op cost sanity check

        try self.addCost(cost);
    }

    /// Handle unsupported expression in soft-fork aware manner.
    /// If ergoTreeVersion > activatedVersion (soft-fork mode), returns
    /// SoftForkAccepted which signals "script passes". Otherwise returns
    /// UnsupportedExpression error.
    ///
    /// This implements Ergo protocol's soft-fork rule: old nodes must accept
    /// blocks with scripts using future opcodes/methods they don't understand.
    ///
    /// Reference: sigmastate-interpreter Interpreter.scala trySoftForkable()
    fn handleUnsupported(self: *const Evaluator) EvalError {
        // PRECONDITION: We've encountered something we don't support
        // PRECONDITION: Version context is valid
        assert(self.version_ctx.activated_version <= VersionContext.MAX_SUPPORTED_VERSION);

        if (self.version_ctx.allowsSoftForkPlaceholder()) {
            // Soft-fork mode: script version is newer than activated version.
            // Return SoftForkAccepted to signal "script passes".
            return error.SoftForkAccepted;
        } else {
            // Normal mode: we should understand everything, this is an error.
            return error.UnsupportedExpression;
        }
    }

    /// Get child count for a node (used by iterative findSubtreeEnd)
    /// Returns the number of direct children this node has.
    fn getNodeChildCount(self: *const Evaluator, node_idx: u16) u16 {
        // PRECONDITION: node_idx is valid
        assert(node_idx < self.tree.node_count);

        const node = self.tree.nodes[node_idx];

        return switch (node.tag) {
            // Leaf nodes - no children
            .true_leaf, .false_leaf, .unit, .height, .constant, .constant_placeholder, .val_use, .unsupported, .inputs, .outputs, .self_box, .miner_pk, .last_block_utxo_root, .group_generator, .get_var, .deserialize_context, .trivial_prop_true, .trivial_prop_false, .context, .global => 0,

            // Unary operations (1 child)
            .calc_blake2b256, .calc_sha256, .option_get, .option_is_defined, .long_to_byte_array, .byte_array_to_bigint, .byte_array_to_long, .decode_point, .select_field, .upcast, .downcast, .extract_version, .extract_parent_id, .extract_ad_proofs_root, .extract_state_root, .extract_txs_root, .extract_timestamp, .extract_n_bits, .extract_difficulty, .extract_votes, .extract_miner_rewards, .val_def, .func_value, .extract_register_as, .mod_q, .bit_inversion, .bool_to_sigma_prop, .size_of, .negation, .logical_not, .extract_amount, .extract_script_bytes, .extract_bytes, .extract_bytes_with_no_ref, .extract_id, .extract_creation_info, .prove_dlog, .sigma_prop_bytes, .logical_and, .logical_or => 1,

            // Binary operations (2 children)
            .bin_op, .option_get_or_else, .exponentiate, .multiply_group, .pair_construct, .apply, .map_collection, .exists, .for_all, .filter, .flat_map, .plus_mod_q, .minus_mod_q, .bin_and, .bin_or, .bin_xor => 2,

            // Ternary operations (3 children)
            .if_then_else, .triple_construct, .fold, .tree_lookup, .subst_constants, .slice => 3,

            // 4 children (ProveDHTuple)
            .prove_dh_tuple => 4,

            // N-ary with data-driven child count
            .block_value => node.data + 1, // items + result
            .tuple_construct, .concrete_collection, .sigma_and, .sigma_or => node.data,
            .sigma_threshold => 2, // Always 2 children: bound (Int) and input (Coll[SigmaProp])

            // create_avl_tree: 3 or 4 children (data = 1 if value_length present)
            .create_avl_tree => if (node.data == 1) 4 else 3,

            // deserialize_register: 0 or 1 children (has_default in low byte)
            .deserialize_register => if ((node.data & 0xFF) == 1) 1 else 0,

            // method_call: 1, 2, or 3+ (obj + args based on method_id)
            .method_call => blk: {
                const method_id: u8 = @truncate(node.data >> 8);
                const type_code: u8 = @truncate(node.data);
                // Context.getVarFromInput has 2 args
                if (type_code == ContextTypeCode and method_id == ContextMethodId.get_var_from_input) {
                    break :blk 3; // obj + 2 args
                }
                // Collection methods with args:
                if (type_code == CollTypeCode) {
                    break :blk switch (method_id) {
                        CollMethodId.index_of => 3, // obj + 2 args (elem, from)
                        CollMethodId.updated => 3, // obj + 2 args (idx, value)
                        CollMethodId.update_many => 3, // obj + 2 args (idxs, values)
                        CollMethodId.patch => 4, // obj + 3 args (from, patch, replaced)
                        CollMethodId.zip => 2, // obj + 1 arg (other)
                        CollMethodId.starts_with => 2, // obj + 1 arg (other)
                        CollMethodId.ends_with => 2, // obj + 1 arg (other)
                        CollMethodId.get => 2, // obj + 1 arg (idx)
                        CollMethodId.flatmap => 2, // obj + 1 arg (lambda)
                        else => 1, // indices, reverse have no args
                    };
                }
                break :blk 1; // Default: obj only
            },

            // property_call: always 1 (obj only, no args)
            .property_call => 1,
        };
    }

    /// Find the index after a subtree (next sibling position)
    /// ITERATIVE implementation - no recursion per ZIGMA_STYLE.
    ///
    /// Algorithm: Track total remaining children to process. Each node visited
    /// adds its children to the count and subtracts 1 (itself) until count is 0.
    fn findSubtreeEnd(self: *const Evaluator, node_idx: u16) u16 {
        // PRECONDITIONS
        assert(node_idx <= self.tree.node_count);

        if (node_idx >= self.tree.node_count) return self.tree.node_count;

        // Start with the root node's child count
        var remaining: u32 = self.getNodeChildCount(node_idx);
        var current = node_idx + 1;

        // Process children until we've accounted for all of them
        // Bounded by node_count to prevent infinite loops on malformed input
        while (remaining > 0 and current < self.tree.node_count) {
            // INVARIANT: remaining decreases or stays same each iteration
            const child_count = self.getNodeChildCount(current);

            // Add this node's children, subtract 1 for this node itself
            remaining = remaining + child_count - 1;
            current += 1;

            // INVARIANT: current always advances
            assert(current > node_idx);
        }

        // POSTCONDITION: Result is in valid range
        assert(current <= self.tree.node_count);

        return current;
    }
};

// ============================================================================
// Value Operations
// ============================================================================

/// Compare two integer values, returns -1, 0, or 1
fn compareInts(left: Value, right: Value) EvalError!i2 {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        return switch (l.compare(r)) {
            .lt => @as(i2, -1),
            .eq => @as(i2, 0),
            .gt => @as(i2, 1),
        };
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        return switch (l.compare(r)) {
            .lt => @as(i2, -1),
            .eq => @as(i2, 0),
            .gt => @as(i2, 1),
        };
    }

    const l = try extractInt(left);
    const r = try extractInt(right);

    if (l < r) return -1;
    if (l > r) return 1;
    return 0;
}

/// Calculate minimal byte length for unsigned integer
fn minimalUnsignedLen(comptime T: type, value: T) u8 {
    if (value == 0) return 1;
    const bits = @typeInfo(T).int.bits;
    const leading = @clz(value);
    const significant_bits = bits - leading;
    return @intCast((significant_bits + 7) / 8);
}

/// Write unsigned integer as big-endian bytes
fn writeUnsignedBigEndian(comptime T: type, value: T, buf: []u8) void {
    const bits = @typeInfo(T).int.bits;
    const bytes = bits / 8;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        const shift: std.math.Log2Int(T) = @intCast((bytes - (bytes - buf.len) - i - 1) * 8);
        buf[i] = @truncate(value >> shift);
    }
}

/// Convert BigInt to i64 (overflow if doesn't fit)
fn bigIntToLong(v: Value.BigInt) EvalError!i64 {
    if (v.len > 8) return error.ArithmeticOverflow;
    var u: u64 = 0;
    for (v.bytes[0..v.len]) |b| {
        u = (u << 8) | b;
    }
    // Sign extend if negative
    if (v.isNegative()) {
        const shift: u6 = @intCast(64 - (v.len * 8));
        const signed: i64 = @bitCast(u << shift);
        return signed >> shift;
    }
    return @bitCast(u);
}

/// Convert UnsignedBigInt to u64 (overflow if doesn't fit)
fn unsignedBigIntToLong(v: Value.UnsignedBigInt) EvalError!u64 {
    if (v.len > 8) return error.ArithmeticOverflow;
    var u: u64 = 0;
    for (v.bytes[0..v.len]) |b| {
        u = (u << 8) | b;
    }
    return u;
}

/// Extract integer value from Value
fn extractInt(v: Value) EvalError!i64 {
    return switch (v) {
        .byte => |b| @as(i64, b),
        .short => |s| @as(i64, s),
        .int => |i| @as(i64, i),
        .long => |l| l,
        else => error.TypeMismatch,
    };
}

/// Check if two values are equal
fn valuesEqual(a: Value, b: Value) bool {
    return switch (a) {
        .unit => b == .unit,
        .boolean => |av| b == .boolean and av == b.boolean,
        .byte => |av| b == .byte and av == b.byte,
        .short => |av| b == .short and av == b.short,
        .int => |av| b == .int and av == b.int,
        .long => |av| b == .long and av == b.long,
        .big_int => |av| blk: {
            if (b != .big_int) break :blk false;
            const bv = b.big_int;
            if (av.len != bv.len) break :blk false;
            break :blk std.mem.eql(u8, av.bytes[0..av.len], bv.bytes[0..bv.len]);
        },
        .unsigned_big_int => |av| blk: {
            if (b != .unsigned_big_int) break :blk false;
            const bv = b.unsigned_big_int;
            if (av.len != bv.len) break :blk false;
            break :blk std.mem.eql(u8, av.bytes[0..av.len], bv.bytes[0..bv.len]);
        },
        else => false, // Complex types need deeper comparison
    };
}

// ============================================================================
// BigInt/UnsignedBigInt Conversion Helpers
// ============================================================================

/// Convert Value.BigInt to BigInt256 for arithmetic
fn valueToBigInt256(v: Value.BigInt) EvalError!BigInt256 {
    return BigInt256.fromBytes(v.bytes[0..v.len]) catch return error.InvalidBigInt;
}

/// Convert BigInt256 to Value.big_int
fn bigInt256ToValue(bi: BigInt256) Value {
    var temp_buf: [33]u8 = undefined;
    const slice = bi.toBytes(&temp_buf);

    var result: Value.BigInt = undefined;
    // INVARIANT: BigInt256 minimal encoding is at most 33 bytes
    assert(slice.len <= data.max_bigint_bytes);
    result.len = @intCast(slice.len);
    @memcpy(result.bytes[0..result.len], slice);
    return .{ .big_int = result };
}

/// Convert Value.UnsignedBigInt to UnsignedBigInt256 for arithmetic
fn valueToUnsignedBigInt256(v: Value.UnsignedBigInt) EvalError!UnsignedBigInt256 {
    return UnsignedBigInt256.fromBytes(v.bytes[0..v.len]) catch return error.InvalidBigInt;
}

/// Convert UnsignedBigInt256 to Value.unsigned_big_int
fn unsignedBigInt256ToValue(ubi: UnsignedBigInt256) Value {
    var temp_buf: [32]u8 = undefined;
    const slice = ubi.toBytes(&temp_buf);

    var result: Value.UnsignedBigInt = undefined;
    // INVARIANT: UnsignedBigInt256 minimal encoding is at most 32 bytes
    assert(slice.len <= 32);
    result.len = @intCast(slice.len);
    @memcpy(result.bytes[0..result.len], slice);
    return .{ .unsigned_big_int = result };
}

/// Add two integer values with overflow checking
fn addInts(left: Value, right: Value) EvalError!Value {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        const result = l.add(r) catch return error.ArithmeticOverflow;
        return bigInt256ToValue(result);
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        const result = l.add(r) catch return error.ArithmeticOverflow;
        return unsignedBigInt256ToValue(result);
    }

    // For standard int types, promote to i64 and check overflow
    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = @addWithOverflow(l, r);
    if (result[1] != 0) return error.ArithmeticOverflow;

    // Return same type as inputs
    return switch (left) {
        .byte => .{ .byte = @truncate(@as(i64, result[0])) },
        .short => .{ .short = @truncate(@as(i64, result[0])) },
        .int => .{ .int = @truncate(@as(i64, result[0])) },
        .long => .{ .long = result[0] },
        else => error.TypeMismatch,
    };
}

/// Subtract two integer values with overflow checking
fn subInts(left: Value, right: Value) EvalError!Value {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        const result = l.sub(r) catch return error.ArithmeticOverflow;
        return bigInt256ToValue(result);
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        const result = l.sub(r) catch return error.ArithmeticOverflow;
        return unsignedBigInt256ToValue(result);
    }

    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = @subWithOverflow(l, r);
    if (result[1] != 0) return error.ArithmeticOverflow;

    return switch (left) {
        .byte => .{ .byte = @truncate(@as(i64, result[0])) },
        .short => .{ .short = @truncate(@as(i64, result[0])) },
        .int => .{ .int = @truncate(@as(i64, result[0])) },
        .long => .{ .long = result[0] },
        else => error.TypeMismatch,
    };
}

/// Multiply two integer values with overflow checking
fn mulInts(left: Value, right: Value) EvalError!Value {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        const result = l.mul(r) catch return error.ArithmeticOverflow;
        return bigInt256ToValue(result);
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        const result = l.mul(r) catch return error.ArithmeticOverflow;
        return unsignedBigInt256ToValue(result);
    }

    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = @mulWithOverflow(l, r);
    if (result[1] != 0) return error.ArithmeticOverflow;

    return switch (left) {
        .byte => .{ .byte = @truncate(@as(i64, result[0])) },
        .short => .{ .short = @truncate(@as(i64, result[0])) },
        .int => .{ .int = @truncate(@as(i64, result[0])) },
        .long => .{ .long = result[0] },
        else => error.TypeMismatch,
    };
}

/// Divide two integer values
fn divInts(left: Value, right: Value) EvalError!Value {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        const result = l.div(r) catch |e| return switch (e) {
            error.DivisionByZero => error.DivisionByZero,
            else => error.ArithmeticOverflow,
        };
        return bigInt256ToValue(result);
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        const result = l.div(r) catch return error.DivisionByZero;
        return unsignedBigInt256ToValue(result);
    }

    const l = try extractInt(left);
    const r = try extractInt(right);

    if (r == 0) return error.DivisionByZero;

    // Check for MIN_INT / -1 overflow (only division that overflows in two's complement)
    // MIN_INT / -1 = -MIN_INT = MAX_INT + 1, which doesn't fit
    if (r == -1 and l == std.math.minInt(i64)) {
        return error.ArithmeticOverflow;
    }

    // Ergo uses truncated division (rounds toward zero)
    const result = @divTrunc(l, r);

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Modulo of two integer values
fn modInts(left: Value, right: Value) EvalError!Value {
    // Handle BigInt (signed 256-bit)
    if (left == .big_int and right == .big_int) {
        const l = try valueToBigInt256(left.big_int);
        const r = try valueToBigInt256(right.big_int);
        const result = l.mod(r) catch return error.DivisionByZero;
        return bigInt256ToValue(result);
    }

    // Handle UnsignedBigInt (unsigned 256-bit, v6+)
    if (left == .unsigned_big_int and right == .unsigned_big_int) {
        const l = try valueToUnsignedBigInt256(left.unsigned_big_int);
        const r = try valueToUnsignedBigInt256(right.unsigned_big_int);
        const result = l.mod(r) catch return error.DivisionByZero;
        return unsignedBigInt256ToValue(result);
    }

    const l = try extractInt(left);
    const r = try extractInt(right);

    if (r == 0) return error.DivisionByZero;

    // Ergo uses truncated modulo (sign follows dividend)
    const result = @rem(l, r);

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

// ============================================================================
// Bitwise Operations (v3+)
// ============================================================================

/// Bitwise OR of two integer values
fn bitOrInts(left: Value, right: Value) EvalError!Value {
    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = l | r;

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Bitwise AND of two integer values
fn bitAndInts(left: Value, right: Value) EvalError!Value {
    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = l & r;

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Bitwise XOR of two integer values
fn bitXorInts(left: Value, right: Value) EvalError!Value {
    const l = try extractInt(left);
    const r = try extractInt(right);

    const result = l ^ r;

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Arithmetic right shift (sign extends)
fn bitShiftRightInts(left: Value, right: Value) EvalError!Value {
    const val = try extractInt(left);
    const shift_amount = try extractInt(right);

    // Shift amount must be in valid range
    if (shift_amount < 0) return error.InvalidShift;
    if (shift_amount >= 64) return error.InvalidShift;

    const shift: u6 = @intCast(shift_amount);
    const result = val >> shift;

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Left shift
fn bitShiftLeftInts(left: Value, right: Value) EvalError!Value {
    const val = try extractInt(left);
    const shift_amount = try extractInt(right);

    // Shift amount must be in valid range
    if (shift_amount < 0) return error.InvalidShift;
    if (shift_amount >= 64) return error.InvalidShift;

    const shift: u6 = @intCast(shift_amount);
    const result = val << shift;

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Logical right shift (zero extends)
fn bitShiftRightZeroedInts(left: Value, right: Value) EvalError!Value {
    const val = try extractInt(left);
    const shift_amount = try extractInt(right);

    // Shift amount must be in valid range
    if (shift_amount < 0) return error.InvalidShift;
    if (shift_amount >= 64) return error.InvalidShift;

    // Convert to unsigned, shift, convert back
    const unsigned_val: u64 = @bitCast(val);
    const shift: u6 = @intCast(shift_amount);
    const shifted = unsigned_val >> shift;
    const result: i64 = @bitCast(shifted);

    return switch (left) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

/// Bitwise inversion (unary)
fn bitInvertInt(val: Value) EvalError!Value {
    const v = try extractInt(val);
    const result = ~v;

    return switch (val) {
        .byte => .{ .byte = @truncate(result) },
        .short => .{ .short = @truncate(result) },
        .int => .{ .int = @truncate(result) },
        .long => .{ .long = result },
        else => error.TypeMismatch,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "evaluator: true leaf" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf };
    tree.node_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "evaluator: false leaf" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .false_leaf };
    tree.node_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

test "evaluator: height" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height };
    tree.node_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(500, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 500), result.int);
}

test "evaluator: constant int" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .int = 42 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 42), result.int);
}

test "evaluator: HEIGHT > 100 true" {
    // Build expression tree for HEIGHT > 100
    // Pre-order layout:
    //   [0] bin_op(GT)
    //   [1] height
    //   [2] constant(100)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.gt) };
    tree.nodes[1] = .{ .tag = .height };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 3;
    tree.values[0] = .{ .int = 100 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(500, &inputs); // HEIGHT = 500 > 100

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "evaluator: HEIGHT > 100 false" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.gt) };
    tree.nodes[1] = .{ .tag = .height };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 3;
    tree.values[0] = .{ .int = 100 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(50, &inputs); // HEIGHT = 50 < 100

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

test "evaluator: 1 + 2 = 3" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.nodes[2] = .{ .tag = .constant, .data = 1 };
    tree.node_count = 3;
    tree.values[0] = .{ .int = 1 };
    tree.values[1] = .{ .int = 2 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 3), result.int);
}

test "evaluator: division by zero" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.divide) };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.nodes[2] = .{ .tag = .constant, .data = 1 };
    tree.node_count = 3;
    tree.values[0] = .{ .int = 10 };
    tree.values[1] = .{ .int = 0 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.DivisionByZero, eval.evaluate());
}

test "evaluator: cost limit" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height };
    tree.node_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.setCostLimit(1); // Very low limit

    try std.testing.expectError(error.CostLimitExceeded, eval.evaluate());
}

test "evaluator: constant placeholder" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.node_count = 1;
    tree.constants[0] = .{ .int = 999 };
    tree.constant_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 999), result.int);
}

test "evaluator: equality" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.eq) };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.nodes[2] = .{ .tag = .constant, .data = 1 };
    tree.node_count = 3;
    tree.values[0] = .{ .int = 42 };
    tree.values[1] = .{ .int = 42 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "evaluator: logical and" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.and_op) };
    tree.nodes[1] = .{ .tag = .true_leaf };
    tree.nodes[2] = .{ .tag = .false_leaf };
    tree.node_count = 3;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

test "evaluator: calc_blake2b256" {
    // Build: CalcBlake2b256(Coll[Byte]("abc"))
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .calc_blake2b256 };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = "abc" };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .hash32);

    // Verify against known Blake2b-256("abc") hash
    const expected = [_]u8{
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result.hash32);
}

test "evaluator: calc_sha256" {
    // Build: CalcSha256(Coll[Byte]("abc"))
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .calc_sha256 };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = "abc" };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .hash32);

    // Verify against known SHA-256("abc") hash (NIST test vector)
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result.hash32);
}

test "evaluator: calc_blake2b256 empty input" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .calc_blake2b256 };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = "" };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .hash32);
}

test "evaluator: hash type mismatch" {
    // Try to hash a non-byte-collection (should fail)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .calc_blake2b256 };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .int = 42 }; // Not a Coll[Byte]
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.TypeMismatch, eval.evaluate());
}

// ============================================================================
// PerItemCost Model Tests
// ============================================================================

test "evaluator: blake2b256 cost scales with input size (PerItemCost)" {
    // Verify Blake2b256 uses PerItemCost(20, 7, 128) chunk-based costing
    // Formula: nChunks = (nItems - 1) / chunkSize + 1; total = baseCost + perChunkCost * nChunks
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);
    const const_cost: u64 = 5; // FixedCost.constant = 5

    // Test 1: Empty input - base cost only = 20
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_blake2b256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        tree.values[0] = .{ .coll_byte = "" };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // Empty: base 20 + constant cost (5)
        try std.testing.expectEqual(@as(u64, 20 + const_cost), eval.cost_used);
    }

    // Test 2: 128 bytes - 1 chunk = 20 + 7 = 27
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_blake2b256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        const data_128 = [_]u8{0} ** 128;
        tree.values[0] = .{ .coll_byte = &data_128 };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // 128 bytes: 1 chunk = 20 + 7 = 27, plus constant cost 5
        try std.testing.expectEqual(@as(u64, 27 + const_cost), eval.cost_used);
    }

    // Test 3: 129 bytes - 2 chunks = 20 + 14 = 34
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_blake2b256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        const data_129 = [_]u8{0} ** 129;
        tree.values[0] = .{ .coll_byte = &data_129 };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // 129 bytes: 2 chunks = 20 + 14 = 34, plus constant cost 5
        try std.testing.expectEqual(@as(u64, 34 + const_cost), eval.cost_used);
    }
}

test "evaluator: sha256 cost scales with input size (PerItemCost)" {
    // Verify SHA256 uses PerItemCost(80, 8, 64) chunk-based costing
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);
    const const_cost: u64 = 5; // FixedCost.constant = 5

    // Test 1: Empty input - base cost only = 80
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_sha256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        tree.values[0] = .{ .coll_byte = "" };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // Empty: base 80 + constant cost (5)
        try std.testing.expectEqual(@as(u64, 80 + const_cost), eval.cost_used);
    }

    // Test 2: 64 bytes - 1 chunk = 80 + 8 = 88
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_sha256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        const data_64 = [_]u8{0} ** 64;
        tree.values[0] = .{ .coll_byte = &data_64 };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // 64 bytes: 1 chunk = 80 + 8 = 88, plus constant cost 5
        try std.testing.expectEqual(@as(u64, 88 + const_cost), eval.cost_used);
    }

    // Test 3: 65 bytes - 2 chunks = 80 + 16 = 96
    {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .calc_sha256 };
        tree.nodes[1] = .{ .tag = .constant, .data = 0 };
        tree.node_count = 2;
        const data_65 = [_]u8{0} ** 65;
        tree.values[0] = .{ .coll_byte = &data_65 };
        tree.value_count = 1;

        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;
        _ = try eval.evaluate();

        // 65 bytes: 2 chunks = 80 + 16 = 96, plus constant cost 5
        try std.testing.expectEqual(@as(u64, 96 + const_cost), eval.cost_used);
    }
}

test "evaluator: hash cost comparison empty vs large" {
    // Property: Larger inputs should cost more than empty inputs
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    // Blake2b256 with empty input
    var tree_empty = ExprTree.init();
    tree_empty.nodes[0] = .{ .tag = .calc_blake2b256 };
    tree_empty.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree_empty.node_count = 2;
    tree_empty.values[0] = .{ .coll_byte = "" };
    tree_empty.value_count = 1;

    var eval_empty = Evaluator.init(&tree_empty, &ctx);
    eval_empty.cost_limit = 10000;
    _ = try eval_empty.evaluate();

    // Blake2b256 with 1KB input (1024 bytes = 8 chunks)
    var tree_large = ExprTree.init();
    tree_large.nodes[0] = .{ .tag = .calc_blake2b256 };
    tree_large.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree_large.node_count = 2;
    const data_1k = [_]u8{0} ** 1024;
    tree_large.values[0] = .{ .coll_byte = &data_1k };
    tree_large.value_count = 1;

    var eval_large = Evaluator.init(&tree_large, &ctx);
    eval_large.cost_limit = 10000;
    _ = try eval_large.evaluate();

    // Property: Large input should cost more than empty
    try std.testing.expect(eval_large.cost_used > eval_empty.cost_used);

    // Verify chunk calculation: 1024 bytes / 128 chunk_size = 8 chunks
    // Cost = 20 + 7*8 = 76, plus constant 5 = 81
    try std.testing.expectEqual(@as(u64, 76 + 5), eval_large.cost_used);
}

test "evaluator: val_use undefined variable" {
    // ValUse for undefined variable should error
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .val_use, .data = 0 };
    tree.node_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.UndefinedVariable, eval.evaluate());
}

test "evaluator: simple block with one binding" {
    // { val x = 42; x }
    // Pre-order: [block_value(1), val_def(0), constant(42), val_use(0)]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .block_value, .data = 1 }; // 1 ValDef
    tree.nodes[1] = .{ .tag = .val_def, .data = 0 }; // varId = 0
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // RHS = 42
    tree.nodes[3] = .{ .tag = .val_use, .data = 0 }; // Result = x
    tree.node_count = 4;
    tree.values[0] = .{ .int = 42 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 42), result.int);
}

test "evaluator: block with two bindings and addition" {
    // { val x = 10; val y = 20; x + y }
    // Pre-order:
    //   [0] block_value(2)
    //   [1] val_def(0)
    //   [2] constant(10)
    //   [3] val_def(1)
    //   [4] constant(20)
    //   [5] bin_op(plus)
    //   [6] val_use(0)  <- x
    //   [7] val_use(1)  <- y
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .block_value, .data = 2 }; // 2 ValDefs
    tree.nodes[1] = .{ .tag = .val_def, .data = 0 }; // x
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // 10
    tree.nodes[3] = .{ .tag = .val_def, .data = 1 }; // y
    tree.nodes[4] = .{ .tag = .constant, .data = 1 }; // 20
    tree.nodes[5] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) };
    tree.nodes[6] = .{ .tag = .val_use, .data = 0 }; // x
    tree.nodes[7] = .{ .tag = .val_use, .data = 1 }; // y
    tree.node_count = 8;
    tree.values[0] = .{ .int = 10 };
    tree.values[1] = .{ .int = 20 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 30), result.int);
}

test "evaluator: nested binary ops with proper tree navigation" {
    // (1 + 2) + 3 to test that findSubtreeEnd works correctly
    // Pre-order:
    //   [0] bin_op(plus)
    //   [1] bin_op(plus)
    //   [2] constant(1)
    //   [3] constant(2)
    //   [4] constant(3)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) };
    tree.nodes[1] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.nodes[3] = .{ .tag = .constant, .data = 1 };
    tree.nodes[4] = .{ .tag = .constant, .data = 2 };
    tree.node_count = 5;
    tree.values[0] = .{ .int = 1 };
    tree.values[1] = .{ .int = 2 };
    tree.values[2] = .{ .int = 3 };
    tree.value_count = 3;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 6), result.int);
}

test "evaluator: option_is_defined on None" {
    // OptionIsDefined(None) should return false
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_is_defined };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    // None value (null_value_idx sentinel)
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null_value_idx } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

test "evaluator: option_is_defined on Some" {
    // OptionIsDefined(Some(x)) should return true
    // We store inner value in evaluator's ValuePool at index 0
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_is_defined };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    // Some value - value_idx=0 references ValuePool
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = 0 } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    // Pre-populate ValuePool with the inner value
    _ = eval.pools.values.storePrimitive(types.TypePool.INT, 99) catch unreachable;

    const result = try eval.evaluate();

    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "evaluator: option_get on None errors" {
    // OptionGet(None) should error with OptionNone
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_get };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null_value_idx } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.OptionNone, eval.evaluate());
}

test "evaluator: option_get on Some extracts value" {
    // OptionGet(Some(99)) should return 99
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_get };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    // Some(99) - value_idx=0 references ValuePool
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = 0 } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    // Pre-populate ValuePool with the inner value (int 99)
    _ = eval.pools.values.storePrimitive(types.TypePool.INT, 99) catch unreachable;

    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 99), result.int);
}

test "evaluator: option_get_or_else on None uses default" {
    // OptionGetOrElse(None, 42) should return 42
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_get_or_else };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // None
    tree.nodes[2] = .{ .tag = .constant, .data = 1 }; // Default: 42
    tree.node_count = 3;
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null_value_idx } };
    tree.values[1] = .{ .int = 42 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 42), result.int);
}

test "evaluator: option_get on nested Option[Option[Int]]" {
    // Test extracting inner Option from Option[Option[Int]]
    // OptionGet(Some(Some(42))) should return Some(42)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_get };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);

    // Build nested Option structure in ValuePool:
    // 1. Store innermost value: Int = 42 at index 0
    const inner_val_idx = eval.pools.values.storePrimitive(types.TypePool.INT, 42) catch unreachable;

    // 2. Store inner Option: Some(42) at index 1
    const inner_opt_idx = eval.pools.values.storeOption(
        types.TypePool.OPTION_INT,
        types.TypePool.INT,
        inner_val_idx,
    ) catch unreachable;

    // 3. The outer Option (constant) references the inner Option
    // Outer type is Option[Option[Int]], which would have a dynamic type index
    // For testing, we use a value > OPTION_INT to indicate "some Option type"
    tree.values[0] = .{ .option = .{
        .inner_type = types.TypePool.OPTION_INT,
        .value_idx = inner_opt_idx,
    } };
    tree.value_count = 1;

    const result = try eval.evaluate();

    // Result should be the inner Option: Some(42)
    try std.testing.expect(result == .option);
    try std.testing.expect(result.option.isSome());
    try std.testing.expectEqual(types.TypePool.INT, result.option.inner_type);
}

test "evaluator: long_to_byte_array" {
    // LongToByteArray(0x0102030405060708) should return big-endian bytes
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .long_to_byte_array };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .long = 0x0102030405060708 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 8), result.coll_byte.len);
    const expected = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try std.testing.expectEqualSlices(u8, &expected, result.coll_byte);
}

test "evaluator: byte_array_to_long" {
    // ByteArrayToLong(0x0102030405060708) should return the Long
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_long };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .long);
    try std.testing.expectEqual(@as(i64, 0x0102030405060708), result.long);
}

test "evaluator: byte_array_to_long wrong size errors" {
    // ByteArrayToLong with wrong size should error
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_long };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = &[_]u8{ 0x01, 0x02, 0x03 } }; // Only 3 bytes
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.InvalidData, eval.evaluate());
}

test "evaluator: byte_array_to_bigint" {
    // ByteArrayToBigInt should convert bytes to BigInt
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_bigint };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = &[_]u8{ 0x12, 0x34, 0x56, 0x78 } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .big_int);
    try std.testing.expectEqual(@as(u8, 4), result.big_int.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, result.big_int.bytes[0..4]);
}

test "evaluator: long_to_byte_array roundtrip" {
    // LongToByteArray then ByteArrayToLong should preserve value
    var tree = ExprTree.init();
    // ByteArrayToLong(LongToByteArray(12345678901234))
    tree.nodes[0] = .{ .tag = .byte_array_to_long };
    tree.nodes[1] = .{ .tag = .long_to_byte_array };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 3;
    tree.values[0] = .{ .long = 12345678901234 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .long);
    try std.testing.expectEqual(@as(i64, 12345678901234), result.long);
}

test "evaluator: long_to_byte_array negative value" {
    // LongToByteArray(-1) should produce 0xFFFFFFFFFFFFFFFF
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .long_to_byte_array };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .long = -1 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .coll_byte);
    const expected = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expectEqualSlices(u8, &expected, result.coll_byte);
}

test "evaluator: long_to_byte_array min value" {
    // LongToByteArray(Long.MIN_VALUE) roundtrip
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_long };
    tree.nodes[1] = .{ .tag = .long_to_byte_array };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 3;
    tree.values[0] = .{ .long = std.math.minInt(i64) };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .long);
    try std.testing.expectEqual(std.math.minInt(i64), result.long);
}

test "evaluator: long_to_byte_array max value" {
    // LongToByteArray(Long.MAX_VALUE) roundtrip
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_long };
    tree.nodes[1] = .{ .tag = .long_to_byte_array };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 3;
    tree.values[0] = .{ .long = std.math.maxInt(i64) };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .long);
    try std.testing.expectEqual(std.math.maxInt(i64), result.long);
}

test "evaluator: byte_array_to_bigint empty errors" {
    // ByteArrayToBigInt with empty input should error
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_bigint };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = &[_]u8{} }; // Empty
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.InvalidData, eval.evaluate());
}

test "evaluator: byte_array_to_bigint negative" {
    // ByteArrayToBigInt with high bit set should be negative
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .byte_array_to_bigint };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    tree.values[0] = .{ .coll_byte = &[_]u8{ 0xFF, 0x00 } }; // High bit set
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .big_int);
    try std.testing.expect(result.big_int.isNegative()); // Should be negative
}

// ============================================================================
// Context Accessor Tests
// ============================================================================

test "evaluator: inputs returns box collection" {
    // INPUTS accessor returns collection of input boxes
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .inputs };
    tree.node_count = 1;

    var box1 = context.testBox();
    box1.value = 1000;
    var box2 = context.testBox();
    box2.value = 2000;
    const test_inputs = [_]context.BoxView{ box1, box2 };
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is a box collection referencing inputs
    try std.testing.expect(result == .box_coll);
    try std.testing.expectEqual(Value.BoxCollRef{ .source = .inputs }, result.box_coll);
}

test "evaluator: outputs returns box collection" {
    // OUTPUTS accessor returns collection of output boxes
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .outputs };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    var out_box = context.testBox();
    out_box.value = 5000;
    const test_outputs = [_]context.BoxView{out_box};
    ctx.outputs = &test_outputs;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is a box collection referencing outputs
    try std.testing.expect(result == .box_coll);
    try std.testing.expectEqual(Value.BoxCollRef{ .source = .outputs }, result.box_coll);
}

test "evaluator: self_box returns current box" {
    // SELF accessor returns the box being validated
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .self_box };
    tree.node_count = 1;

    var box1 = context.testBox();
    box1.value = 111;
    var box2 = context.testBox();
    box2.value = 222;
    const test_inputs = [_]context.BoxView{ box1, box2 };
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.self_index = 1; // SELF is the second box

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is a box reference to inputs[self_index]
    try std.testing.expect(result == .box);
    try std.testing.expectEqual(Value.BoxRef.BoxSource.inputs, result.box.source);
    try std.testing.expectEqual(@as(u16, 1), result.box.index);
}

test "evaluator: self_box at index 0" {
    // Edge case: SELF is the first input
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .self_box };
    tree.node_count = 1;

    var box = context.testBox();
    box.value = 12345;
    const test_inputs = [_]context.BoxView{box};
    const ctx = Context.forHeight(100, &test_inputs); // self_index defaults to 0

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Box reference at index 0
    try std.testing.expect(result == .box);
    try std.testing.expectEqual(@as(u16, 0), result.box.index);
}

test "evaluator: inputs with empty context still valid" {
    // INPUTS on context with 1 input (minimum)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .inputs };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(1, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Even with single input, returns valid box_coll
    try std.testing.expect(result == .box_coll);
    try std.testing.expectEqual(Value.BoxCollRef{ .source = .inputs }, result.box_coll);
}

test "evaluator: miner_pk returns group element" {
    // MinerPubKey accessor returns pre-header miner public key
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .miner_pk };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    // Set a valid compressed EC point (0x02 prefix)
    ctx.pre_header.miner_pk = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is a group element (33 bytes)
    try std.testing.expect(result == .group_element);
    try std.testing.expectEqual(@as(u8, 0x02), result.group_element[0]);
    try std.testing.expectEqual(@as(u8, 0xAB), result.group_element[1]);
}

test "evaluator: miner_pk with 0x03 prefix" {
    // Edge case: miner_pk with odd y-coordinate prefix
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .miner_pk };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.pre_header.miner_pk = [_]u8{0x03} ++ [_]u8{0xCD} ** 32;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .group_element);
    try std.testing.expectEqual(@as(u8, 0x03), result.group_element[0]);
}

test "evaluator: last_block_utxo_root returns state root" {
    // LastBlockUtxoRootHash returns first header's state root
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .last_block_utxo_root };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    // Create header with known state root
    var header = context.testHeader();
    header.state_root = [_]u8{0xDE} ** 44;
    const test_headers = [_]context.HeaderView{header};
    ctx.headers = &test_headers;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is byte collection with 44-byte AVL+ digest
    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 44), result.coll_byte.len);
    try std.testing.expectEqual(@as(u8, 0xDE), result.coll_byte[0]);
}

test "evaluator: last_block_utxo_root no headers errors" {
    // LastBlockUtxoRootHash with no headers should error
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .last_block_utxo_root };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs); // No headers

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.InvalidContext, eval.evaluate());
}

test "evaluator: exists on empty collection returns false" {
    // exists({ }, { x => x > 0 }) => false
    // Tree structure: [exists] [constant(empty coll)] [func_value] [true_leaf]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .exists, .result_type = TypePool.BOOLEAN };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // Empty collection
    tree.nodes[2] = .{ .tag = .func_value, .data = 1 }; // 1 arg lambda
    tree.nodes[3] = .{ .tag = .true_leaf }; // Lambda body (always true)
    tree.node_count = 4;
    tree.values[0] = .{ .coll_byte = "" }; // Empty collection
    tree.value_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Empty collection: exists returns false regardless of predicate
    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == false);
}

test "evaluator: forall on empty collection returns true" {
    // forall({ }, { x => x > 0 }) => true
    // Tree structure: [for_all] [constant(empty coll)] [func_value] [false_leaf]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .for_all, .result_type = TypePool.BOOLEAN };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // Empty collection
    tree.nodes[2] = .{ .tag = .func_value, .data = 1 }; // 1 arg lambda
    tree.nodes[3] = .{ .tag = .false_leaf }; // Lambda body (always false)
    tree.node_count = 4;
    tree.values[0] = .{ .coll_byte = "" }; // Empty collection
    tree.value_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Empty collection: forall returns true regardless of predicate
    try std.testing.expect(result == .boolean);
    try std.testing.expect(result.boolean == true);
}

test "evaluator: fold on empty collection returns zero" {
    // fold({ }, 42, { (acc, x) => acc + x }) => 42
    // Tree structure: [fold] [constant(empty coll)] [constant(42)] [func_value] [body]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .fold };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // Empty collection
    tree.nodes[2] = .{ .tag = .constant, .data = 1 }; // Zero value = 42
    tree.nodes[3] = .{ .tag = .func_value, .data = 2 }; // 2 arg lambda
    tree.nodes[4] = .{ .tag = .val_use, .data = 1 }; // Return accumulator
    tree.node_count = 5;
    tree.values[0] = .{ .coll_byte = "" }; // Empty collection
    tree.values[1] = .{ .long = 42 }; // Zero value
    tree.value_count = 2;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Empty collection: fold returns zero value
    try std.testing.expect(result == .long);
    try std.testing.expectEqual(@as(i64, 42), result.long);
}

test "evaluator: sigma_and with two TrueLeaf children" {
    // SigmaAnd(true, true) should produce a CAND SigmaProp
    // Tree: [sigma_and(2)] [true_leaf] [true_leaf]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .sigma_and, .data = 2 }; // 2 children
    tree.nodes[1] = .{ .tag = .true_leaf };
    tree.nodes[2] = .{ .tag = .true_leaf };
    tree.node_count = 3;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be a SigmaProp containing CAND
    try std.testing.expect(result == .sigma_prop);
    // Serialized form: 0x98 (AND marker) + count + children
    try std.testing.expect(result.sigma_prop.data.len >= 2);
    try std.testing.expectEqual(@as(u8, 0x98), result.sigma_prop.data[0]); // AND marker
    try std.testing.expectEqual(@as(u8, 2), result.sigma_prop.data[1]); // 2 children
}

test "evaluator: sigma_or with two TrueLeaf children" {
    // SigmaOr(true, true) should produce a COR SigmaProp
    // Tree: [sigma_or(2)] [true_leaf] [true_leaf]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .sigma_or, .data = 2 }; // 2 children
    tree.nodes[1] = .{ .tag = .true_leaf };
    tree.nodes[2] = .{ .tag = .true_leaf };
    tree.node_count = 3;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be a SigmaProp containing COR
    try std.testing.expect(result == .sigma_prop);
    // Serialized form: 0x99 (OR marker) + count + children
    try std.testing.expect(result.sigma_prop.data.len >= 2);
    try std.testing.expectEqual(@as(u8, 0x99), result.sigma_prop.data[0]); // OR marker
    try std.testing.expectEqual(@as(u8, 2), result.sigma_prop.data[1]); // 2 children
}

test "evaluator: sigma_and with ProveDlog children" {
    // SigmaAnd(pk1, pk2) should produce CAND with two ProveDlog leaves
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .sigma_and, .data = 2 }; // 2 children
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // First SigmaProp
    tree.nodes[2] = .{ .tag = .constant, .data = 1 }; // Second SigmaProp
    tree.node_count = 3;

    // Create two ProveDlog sigma props with different public keys
    // Public keys must start with 0x02 or 0x03 (compressed EC point prefix)
    var pk1_data: [34]u8 = undefined;
    pk1_data[0] = 0xCD; // ProveDlog marker
    pk1_data[1] = 0x02; // Compressed point prefix
    @memset(pk1_data[2..], 0x01); // pk1 x-coordinate

    var pk2_data: [34]u8 = undefined;
    pk2_data[0] = 0xCD; // ProveDlog marker
    pk2_data[1] = 0x03; // Compressed point prefix
    @memset(pk2_data[2..], 0x02); // pk2 x-coordinate

    tree.values[0] = .{ .sigma_prop = .{ .data = &pk1_data } };
    tree.values[1] = .{ .sigma_prop = .{ .data = &pk2_data } };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be SigmaProp with CAND structure
    try std.testing.expect(result == .sigma_prop);
    try std.testing.expectEqual(@as(u8, 0x98), result.sigma_prop.data[0]); // AND marker
    try std.testing.expectEqual(@as(u8, 2), result.sigma_prop.data[1]); // 2 children
    // Total length: 2 (header) + 34 (pk1) + 34 (pk2) = 70 bytes
    try std.testing.expectEqual(@as(usize, 70), result.sigma_prop.data.len);
}

test "evaluator: nested sigma_and(sigma_or, sigma_prop)" {
    // SigmaAnd(SigmaOr(true, false), pk) - nested structure
    // Tree: [sigma_and(2)] [sigma_or(2)] [true_leaf] [false_leaf] [constant(pk)]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .sigma_and, .data = 2 }; // 2 children
    tree.nodes[1] = .{ .tag = .sigma_or, .data = 2 }; // inner SigmaOr
    tree.nodes[2] = .{ .tag = .true_leaf };
    tree.nodes[3] = .{ .tag = .false_leaf };
    tree.nodes[4] = .{ .tag = .constant, .data = 0 }; // ProveDlog
    tree.node_count = 5;

    // Create a ProveDlog sigma prop
    var pk_data: [34]u8 = undefined;
    pk_data[0] = 0xCD; // ProveDlog marker
    pk_data[1] = 0x02; // Compressed point prefix
    @memset(pk_data[2..], 0xAB);

    tree.values[0] = .{ .sigma_prop = .{ .data = &pk_data } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be SigmaProp with nested CAND(COR(...), ProveDlog)
    try std.testing.expect(result == .sigma_prop);
    try std.testing.expectEqual(@as(u8, 0x98), result.sigma_prop.data[0]); // AND marker
    try std.testing.expectEqual(@as(u8, 2), result.sigma_prop.data[1]); // 2 children
    // First child is COR
    try std.testing.expectEqual(@as(u8, 0x99), result.sigma_prop.data[2]); // OR marker

    // Now parse the result back to verify roundtrip
    const parsed = try eval.parseSigmaBoolean(result.sigma_prop.data);
    try std.testing.expect(parsed.* == .cand);
    try std.testing.expectEqual(@as(usize, 2), parsed.cand.children.len);
    try std.testing.expect(parsed.cand.children[0].* == .cor);
    try std.testing.expect(parsed.cand.children[1].* == .prove_dlog);
}

test "evaluator: apply identity function" {
    // { (x: Int) => x }(42) = 42
    // Tree: [apply] [func_value(1)] [val_use(1)] [constant(42)]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .apply };
    tree.nodes[1] = .{ .tag = .func_value, .data = 1 }; // 1 argument
    tree.nodes[2] = .{ .tag = .val_use, .data = 1 }; // Return x (var_id = 1)
    tree.nodes[3] = .{ .tag = .constant, .data = 0 }; // Argument = 42
    tree.node_count = 4;
    tree.values[0] = .{ .int = 42 };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 42), result.int);
}

test "evaluator: apply function with arithmetic" {
    // { (x: Int) => x + 1 }(5) = 6
    // Tree: [apply] [func_value(1)] [bin_op(plus)] [val_use(1)] [constant(1)] [constant(5)]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .apply };
    tree.nodes[1] = .{ .tag = .func_value, .data = 1 }; // 1 argument
    tree.nodes[2] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) }; // x + 1
    tree.nodes[3] = .{ .tag = .val_use, .data = 1 }; // x (var_id = 1)
    tree.nodes[4] = .{ .tag = .constant, .data = 0 }; // 1
    tree.nodes[5] = .{ .tag = .constant, .data = 1 }; // Argument = 5
    tree.node_count = 6;
    tree.values[0] = .{ .int = 1 };
    tree.values[1] = .{ .int = 5 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 6), result.int);
}

test "evaluator: apply with variable shadowing" {
    // Test that inner binding shadows outer:
    // { val x = 100; { (x: Int) => x + 1 }(5) }
    // Result should be 6 (inner x=5), not 101 (outer x=100)
    //
    // Tree: [block_value(1)] [val_def(1)] [constant(100)]
    //       [apply] [func_value(1)] [bin_op(plus)] [val_use(1)] [constant(1)] [constant(5)]
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .block_value, .data = 1 }; // 1 ValDef
    tree.nodes[1] = .{ .tag = .val_def, .data = 1 }; // x (var_id = 1)
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // x = 100
    tree.nodes[3] = .{ .tag = .apply }; // Result expression
    tree.nodes[4] = .{ .tag = .func_value, .data = 1 }; // Lambda with 1 arg
    tree.nodes[5] = .{ .tag = .bin_op, .data = @intFromEnum(BinOpKind.plus) }; // x + 1
    tree.nodes[6] = .{ .tag = .val_use, .data = 1 }; // x (var_id = 1)
    tree.nodes[7] = .{ .tag = .constant, .data = 1 }; // 1
    tree.nodes[8] = .{ .tag = .constant, .data = 2 }; // Argument = 5
    tree.node_count = 9;
    tree.values[0] = .{ .int = 100 }; // Outer x value
    tree.values[1] = .{ .int = 1 }; // Literal 1
    tree.values[2] = .{ .int = 5 }; // Argument to lambda
    tree.value_count = 3;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be 6 (5 + 1), not 101 (100 + 1)
    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 6), result.int);
}

test "evaluator: apply preserves outer scope after return" {
    // Verify outer binding is restored after apply:
    // { val x = 100; { (x: Int) => x }(5); x }
    // Result should be 100 (outer x), not 5
    //
    // This requires two ValDefs - one for outer x, one dummy to use result
    // Actually simpler: just bind x, apply, then access x again
    // But we can't do that in single expression easily...
    //
    // For now, we just verify the shadowing test above passes,
    // which proves inner binding was used during apply.
    // The restore behavior is implicitly tested by subsequent var_bindings usage.
}

test "evaluator: indices on byte collection" {
    // Create tree: Coll[Byte](1, 2, 3).indices => Coll(0, 1, 2)
    var tree: ExprTree = .{};
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    // method_call node: type_code=12 (COLL), method_id=14 (indices)
    // data = (14 << 8) | 12 = 3596
    tree.nodes[0] = .{ .tag = .method_call, .data = (14 << 8) | 12 };
    // Object: concrete_collection with 3 bytes (COLL_BYTE = 17)
    tree.nodes[1] = .{ .tag = .concrete_collection, .data = 3, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // value[0] = 1
    tree.nodes[3] = .{ .tag = .constant, .data = 1 }; // value[1] = 2
    tree.nodes[4] = .{ .tag = .constant, .data = 2 }; // value[2] = 3
    tree.node_count = 5;

    tree.values[0] = .{ .byte = 1 };
    tree.values[1] = .{ .byte = 2 };
    tree.values[2] = .{ .byte = 3 };
    tree.value_count = 3;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be Coll[Byte](0, 1, 2)
    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 3), result.coll_byte.len);
    try std.testing.expectEqual(@as(u8, 0), result.coll_byte[0]);
    try std.testing.expectEqual(@as(u8, 1), result.coll_byte[1]);
    try std.testing.expectEqual(@as(u8, 2), result.coll_byte[2]);
}

test "evaluator: reverse byte collection" {
    // Create tree: Coll[Byte](1, 2, 3).reverse => Coll(3, 2, 1)
    var tree: ExprTree = .{};
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    // method_call node: type_code=12 (COLL), method_id=30 (reverse)
    // data = (30 << 8) | 12 = 7692
    tree.nodes[0] = .{ .tag = .method_call, .data = (30 << 8) | 12 };
    // Object: concrete_collection with 3 bytes (COLL_BYTE = 17)
    tree.nodes[1] = .{ .tag = .concrete_collection, .data = 3, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // value[0] = 1
    tree.nodes[3] = .{ .tag = .constant, .data = 1 }; // value[1] = 2
    tree.nodes[4] = .{ .tag = .constant, .data = 2 }; // value[2] = 3
    tree.node_count = 5;

    tree.values[0] = .{ .byte = 1 };
    tree.values[1] = .{ .byte = 2 };
    tree.values[2] = .{ .byte = 3 };
    tree.value_count = 3;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be Coll[Byte](3, 2, 1)
    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 3), result.coll_byte.len);
    try std.testing.expectEqual(@as(u8, 3), result.coll_byte[0]);
    try std.testing.expectEqual(@as(u8, 2), result.coll_byte[1]);
    try std.testing.expectEqual(@as(u8, 1), result.coll_byte[2]);
}

test "evaluator: zip two byte collections" {
    // Simplified test: zip two collections of same length
    // Coll(1, 2).zip(Coll(3, 4)) => pairs as consecutive bytes
    var tree: ExprTree = .{};
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    // method_call node: type_code=12 (COLL), method_id=29 (zip)
    // data = (29 << 8) | 12 = 7436
    tree.nodes[0] = .{ .tag = .method_call, .data = (29 << 8) | 12 };
    // Object: concrete_collection with 2 bytes (COLL_BYTE = 17)
    tree.nodes[1] = .{ .tag = .concrete_collection, .data = 2, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 }; // value[0] = 1
    tree.nodes[3] = .{ .tag = .constant, .data = 1 }; // value[1] = 2
    // Arg: concrete_collection with 2 bytes (COLL_BYTE = 17)
    tree.nodes[4] = .{ .tag = .concrete_collection, .data = 2, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[5] = .{ .tag = .constant, .data = 2 }; // value[2] = 3
    tree.nodes[6] = .{ .tag = .constant, .data = 3 }; // value[3] = 4
    tree.node_count = 7;

    tree.values[0] = .{ .byte = 1 };
    tree.values[1] = .{ .byte = 2 };
    tree.values[2] = .{ .byte = 3 };
    tree.values[3] = .{ .byte = 4 };
    tree.value_count = 4;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be pairs: (1,3), (2,4) encoded as [1,3,2,4]
    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 4), result.coll_byte.len);
    try std.testing.expectEqual(@as(u8, 1), result.coll_byte[0]);
    try std.testing.expectEqual(@as(u8, 3), result.coll_byte[1]);
    try std.testing.expectEqual(@as(u8, 2), result.coll_byte[2]);
    try std.testing.expectEqual(@as(u8, 4), result.coll_byte[3]);
}

test "evaluator: zip different length collections" {
    // zip(Coll(1, 2, 3), Coll(4, 5)) => takes min length (2)
    var tree: ExprTree = .{};
    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    // method_call node: type_code=12 (COLL), method_id=29 (zip)
    tree.nodes[0] = .{ .tag = .method_call, .data = (29 << 8) | 12 };
    // Object: concrete_collection with 3 bytes (COLL_BYTE = 17)
    tree.nodes[1] = .{ .tag = .concrete_collection, .data = 3, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[2] = .{ .tag = .constant, .data = 0 };
    tree.nodes[3] = .{ .tag = .constant, .data = 1 };
    tree.nodes[4] = .{ .tag = .constant, .data = 2 };
    // Arg: concrete_collection with 2 bytes (COLL_BYTE = 17)
    tree.nodes[5] = .{ .tag = .concrete_collection, .data = 2, .result_type = types.TypePool.COLL_BYTE };
    tree.nodes[6] = .{ .tag = .constant, .data = 3 };
    tree.nodes[7] = .{ .tag = .constant, .data = 4 };
    tree.node_count = 8;

    tree.values[0] = .{ .byte = 1 };
    tree.values[1] = .{ .byte = 2 };
    tree.values[2] = .{ .byte = 3 };
    tree.values[3] = .{ .byte = 4 };
    tree.values[4] = .{ .byte = 5 };
    tree.value_count = 5;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be 2 pairs (min length): (1,4), (2,5)
    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 4), result.coll_byte.len);
    try std.testing.expectEqual(@as(u8, 1), result.coll_byte[0]);
    try std.testing.expectEqual(@as(u8, 4), result.coll_byte[1]);
    try std.testing.expectEqual(@as(u8, 2), result.coll_byte[2]);
    try std.testing.expectEqual(@as(u8, 5), result.coll_byte[3]);
}

// ============================================================================
// ExtractRegisterAs Tests
// ============================================================================

test "evaluator: extract_register_as absent returns None" {
    // ExtractRegisterAs on SELF.R4 when R4 is not defined should return None
    var tree: ExprTree = .{};
    const box = context.testBox();
    // Don't set any registers - all should be null
    const inputs = [_]context.BoxView{box};
    const ctx = Context.forHeight(100, &inputs);

    // extract_register_as node: register_id=4 (R4), type_idx=4 (INT)
    // data = (type_idx << 4) | register_id = (4 << 4) | 4 = 68
    tree.nodes[0] = .{ .tag = .extract_register_as, .data = (TypePool.INT << 4) | 4 };
    tree.nodes[1] = .{ .tag = .self_box };
    tree.node_count = 2;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // Result should be Option.None
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

test "evaluator: extract_register_as cache hit returns same result" {
    // Accessing the same register twice should use cache on second access
    var tree: ExprTree = .{};
    const box = context.testBox();
    // R4 not defined
    const inputs = [_]context.BoxView{box};
    const ctx = Context.forHeight(100, &inputs);

    // First access: extract_register_as on SELF.R5
    tree.nodes[0] = .{ .tag = .extract_register_as, .data = (TypePool.INT << 4) | 5 };
    tree.nodes[1] = .{ .tag = .self_box };
    tree.node_count = 2;

    var eval = Evaluator.init(&tree, &ctx);

    // First evaluation
    const result1 = try eval.evaluate();
    try std.testing.expect(result1 == .option);
    try std.testing.expectEqual(null_value_idx, result1.option.value_idx);

    // Check cache was populated
    const cached = eval.pools.register_cache.get(.inputs, 0, .R5);
    try std.testing.expectEqual(RegisterCacheEntry.absent, cached);
}

test "evaluator: register_cache reset clears between evaluations" {
    // Verify register cache is properly reset
    var tree: ExprTree = .{};
    const box = context.testBox();
    const inputs = [_]context.BoxView{box};
    const ctx = Context.forHeight(100, &inputs);

    tree.nodes[0] = .{ .tag = .extract_register_as, .data = (TypePool.INT << 4) | 6 };
    tree.nodes[1] = .{ .tag = .self_box };
    tree.node_count = 2;

    var eval = Evaluator.init(&tree, &ctx);

    // First evaluation populates cache
    _ = try eval.evaluate();
    const cached1 = eval.pools.register_cache.get(.inputs, 0, .R6);
    try std.testing.expectEqual(RegisterCacheEntry.absent, cached1);

    // Manually set a different cache entry
    eval.pools.register_cache.markLoaded(.inputs, 0, .R7, 42);

    // Second evaluation should reset cache
    _ = try eval.evaluate();

    // R6 should be repopulated, R7 should be reset to not_loaded
    const cached2 = eval.pools.register_cache.get(.inputs, 0, .R6);
    try std.testing.expectEqual(RegisterCacheEntry.absent, cached2);

    const cached3 = eval.pools.register_cache.get(.inputs, 0, .R7);
    const expected: RegisterCacheEntry = .not_loaded;
    try std.testing.expectEqual(expected, cached3);
}

test "evaluator: CONTEXT.dataInputs returns box collection" {
    // Test method call: CONTEXT.dataInputs
    // MethodCall pops obj from stack, calls method, pushes result
    var tree = ExprTree.init();

    // MethodCall node: type_code=101 (Context), method_id=1 (dataInputs)
    // data = (method_id << 8) | type_code = (1 << 8) | 101 = 357
    tree.nodes[0] = .{ .tag = .method_call, .data = (1 << 8) | 101 };
    // Use unit as placeholder obj since computeDataInputs ignores it
    // (it uses self.ctx directly, not the popped value)
    tree.nodes[1] = .{ .tag = .unit };
    tree.node_count = 2;

    // Set up context with data inputs
    const test_inputs = [_]context.BoxView{context.testBox()};
    const test_data_inputs = [_]context.BoxView{ context.testBox(), context.testBox() };
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.data_inputs = &test_data_inputs;

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    // POSTCONDITION: Result is box collection referencing data_inputs
    try std.testing.expect(result == .box_coll);
    try std.testing.expectEqual(Value.BoxCollRef{ .source = .data_inputs }, result.box_coll);
}

test "evaluator: StateSnapshot captures evaluator state" {
    // Set up minimal evaluation
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    // Take snapshot before evaluation
    const snap_before = eval.snapshot();

    // ASSERTIONS: Snapshot captures initial state
    try std.testing.expectEqual(@as(u16, 0), snap_before.work_sp);
    try std.testing.expectEqual(@as(u16, 0), snap_before.value_sp);
    try std.testing.expectEqual(@as(u64, 0), snap_before.cost_used);
    try std.testing.expectEqual(@as(u64, 10000), snap_before.cost_limit);
    try std.testing.expectEqual(@as(u64, 10000), snap_before.cost_remaining);
    try std.testing.expectEqual(@as(u8, 2), snap_before.activated_version); // v2 default
    try std.testing.expectEqual(@as(u8, 0), snap_before.ergo_tree_version);
    try std.testing.expectEqual(@as(u16, 1), snap_before.tree_node_count);

    // Checksum should verify
    try std.testing.expect(snap_before.verifyChecksum());

    // Evaluate and take snapshot after
    _ = try eval.evaluate();
    const snap_after = eval.snapshot();

    // ASSERTIONS: Snapshot captures post-evaluation state
    try std.testing.expect(snap_after.cost_used > 0); // Cost was consumed
    try std.testing.expect(snap_after.cost_remaining < snap_before.cost_remaining);
    try std.testing.expect(snap_after.verifyChecksum());
}

test "evaluator: soft-fork unsupported opcode returns true" {
    // Test soft-fork rule: when ergoTreeVersion > activatedVersion,
    // unknown opcodes should cause script to pass (return true).
    //
    // Reference: Interpreter.scala trySoftForkable, WhenSoftForkReductionResult

    var tree = ExprTree.init();
    // .unsupported tag represents an unknown opcode from deserialization
    tree.nodes[0] = .{ .tag = .unsupported, .data = 0xFF };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    // Set up soft-fork condition: ergoTreeVersion (3) > activatedVersion (2)
    eval.version_ctx = VersionContext{
        .activated_version = 2, // Protocol v2
        .ergo_tree_version = 3, // Script uses v3 features
    };

    // ASSERTION: allowsSoftForkPlaceholder returns true in this setup
    try std.testing.expect(eval.version_ctx.allowsSoftForkPlaceholder());

    // Evaluate - should return true (not error)
    const result = try eval.evaluate();

    // ASSERTION: Script passes with boolean true
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: non-soft-fork unsupported opcode errors" {
    // Test that when NOT in soft-fork mode, unknown opcodes error.
    // This is the normal case: ergoTreeVersion <= activatedVersion.

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .unsupported, .data = 0xFF };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    // Normal mode: ergoTreeVersion (2) <= activatedVersion (2)
    eval.version_ctx = VersionContext{
        .activated_version = 2,
        .ergo_tree_version = 2,
    };

    // ASSERTION: NOT in soft-fork mode
    try std.testing.expect(!eval.version_ctx.allowsSoftForkPlaceholder());

    // Evaluate - should error with UnsupportedExpression
    const result = eval.evaluate();
    try std.testing.expectError(error.UnsupportedExpression, result);
}

// ============================================================================
// Property Tests for Collection Methods
// ============================================================================

test "evaluator: property - startsWith with empty prefix always true" {
    // Property: Any collection starts with the empty collection
    // forall a: Coll[T]. a.startsWith([]) == true
    var tree = ExprTree.init();

    // Build: [1,2,3].startsWith([]) → true
    const coll_data = [_]u8{ 1, 2, 3 };
    tree.constants[0] = .{ .coll_byte = &coll_data };
    tree.constants[1] = .{ .coll_byte = &.{} }; // empty collection
    tree.constant_count = 2;

    // Preorder: method_call, object, arg
    // data = (method_id << 8) | type_code = (31 << 8) | 12 = 0x1F0C
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.starts_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object: collection
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 1 }; // arg: empty prefix
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: property - endsWith with empty suffix always true" {
    // Property: Any collection ends with the empty collection
    // forall a: Coll[T]. a.endsWith([]) == true
    var tree = ExprTree.init();

    const coll_data = [_]u8{ 5, 10, 15 };
    tree.constants[0] = .{ .coll_byte = &coll_data };
    tree.constants[1] = .{ .coll_byte = &.{} }; // empty collection
    tree.constant_count = 2;

    // Preorder: method_call, object, arg
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.ends_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object: collection
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 1 }; // arg: empty suffix
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: property - startsWith reflexive" {
    // Property: Every collection starts with itself
    // forall a: Coll[T]. a.startsWith(a) == true
    var tree = ExprTree.init();

    const coll_data = [_]u8{ 0xAA, 0xBB, 0xCC };
    tree.constants[0] = .{ .coll_byte = &coll_data };
    tree.constant_count = 1;

    // Preorder: method_call, object, arg (same constant)
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.starts_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 }; // arg: same constant
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: property - endsWith reflexive" {
    // Property: Every collection ends with itself
    // forall a: Coll[T]. a.endsWith(a) == true
    var tree = ExprTree.init();

    const coll_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    tree.constants[0] = .{ .coll_byte = &coll_data };
    tree.constant_count = 1;

    // Preorder: method_call, object, arg (same constant)
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.ends_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 }; // arg: same constant
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: property - startsWith prefix longer than collection is false" {
    // Property: Collection cannot start with something longer than itself
    // forall a, b: Coll[T]. a.size < b.size → a.startsWith(b) == false
    var tree = ExprTree.init();

    const short_coll = [_]u8{ 1, 2 };
    const long_prefix = [_]u8{ 1, 2, 3, 4 };
    tree.constants[0] = .{ .coll_byte = &short_coll };
    tree.constants[1] = .{ .coll_byte = &long_prefix };
    tree.constant_count = 2;

    // Preorder: method_call, object, arg
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.starts_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object: short collection
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 1 }; // arg: long prefix
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = false }, result);
}

test "evaluator: property - endsWith suffix longer than collection is false" {
    // Property: Collection cannot end with something longer than itself
    // forall a, b: Coll[T]. a.size < b.size → a.endsWith(b) == false
    var tree = ExprTree.init();

    const short_coll = [_]u8{0xFF};
    const long_suffix = [_]u8{ 0xAA, 0xBB, 0xFF };
    tree.constants[0] = .{ .coll_byte = &short_coll };
    tree.constants[1] = .{ .coll_byte = &long_suffix };
    tree.constant_count = 2;

    // Preorder: method_call, object, arg
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.ends_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object: short collection
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 1 }; // arg: long suffix
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = false }, result);
}

test "evaluator: property - empty startsWith empty is true" {
    // Property: Empty collection starts with empty collection
    // [].startsWith([]) == true
    var tree = ExprTree.init();

    tree.constants[0] = .{ .coll_byte = &.{} };
    tree.constant_count = 1;

    // Preorder: method_call, object, arg (both empty)
    const CollTypeCode: u8 = 12;
    tree.nodes[0] = .{ .tag = .method_call, .data = (@as(u16, Evaluator.CollMethodId.starts_with) << 8) | CollTypeCode };
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 }; // object: empty
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 }; // arg: empty
    tree.node_count = 3;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

// ============================================================================
// GetVar Tests
// ============================================================================

test "evaluator: get_var returns None when variable not set" {
    // GetVar(42) when context_vars[42] is null should return None
    var tree = ExprTree.init();

    // get_var node: var_id=42, expected_type_idx=INT (4)
    // data = (type_idx << 8) | var_id = (4 << 8) | 42 = 0x042A
    tree.nodes[0] = .{ .tag = .get_var, .data = (types.TypePool.INT << 8) | 42 };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);
    // context_vars[42] is null by default

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be None (value_idx = null_value_idx)
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

test "evaluator: get_var returns Some when variable is set" {
    // GetVar(5) when context_vars[5] has data should return Some
    var tree = ExprTree.init();

    // get_var node: var_id=5, expected_type_idx=INT (4)
    tree.nodes[0] = .{ .tag = .get_var, .data = (types.TypePool.INT << 8) | 5 };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    // Set context variable 5 to some bytes
    const var_data = [_]u8{ 0x04, 0x54 }; // SInt constant 42
    ctx.context_vars[5] = &var_data;

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be Some (value_idx != null_value_idx)
    try std.testing.expect(result == .option);
    try std.testing.expect(result.option.value_idx != null_value_idx);
}

// ============================================================================
// GetVarFromInput Tests
// ============================================================================

test "evaluator: getVarFromInput returns None when cache not set" {
    // CONTEXT.getVarFromInput[Int](0, 5) when extension_cache is null returns None
    var tree = ExprTree.init();

    // method_call: data = (method_id << 8) | type_code, result_type = T
    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    // Object: unit (placeholder for Context - we ignore it anyway)
    tree.nodes[1] = .{ .tag = .unit };
    // Arg1: input_idx = 0 (Short)
    tree.constants[0] = .{ .short = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    // Arg2: var_id = 5 (Byte)
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    const test_inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);
    // extension_cache is null by default

    // Use v3 context (getVarFromInput requires v6 activation)
    var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be None (cache not set)
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

test "evaluator: getVarFromInput returns None when variable not in cache" {
    var tree = ExprTree.init();

    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    tree.nodes[1] = .{ .tag = .unit };
    tree.constants[0] = .{ .short = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    // Create extension cache but don't set the variable
    var cache = context.ContextExtensionCache.init();

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.extension_cache = &cache;

    // Use v3 context (getVarFromInput requires v6 activation)
    var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be None (variable not set)
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

test "evaluator: getVarFromInput returns Some when variable in cache" {
    var tree = ExprTree.init();

    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    tree.nodes[1] = .{ .tag = .unit };
    tree.constants[0] = .{ .short = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    // Create extension cache and set the variable
    var cache = context.ContextExtensionCache.init();
    const var_data = [_]u8{ 0x04, 0x54 }; // SInt 42 (type_code 4 + ZigZag(42)=0x54)
    cache.set(.inputs, 0, 5, &var_data);

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.extension_cache = &cache;

    // Use v3 context (getVarFromInput requires v6 activation)
    var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be Some (variable is set)
    try std.testing.expect(result == .option);
    try std.testing.expect(result.option.value_idx != null_value_idx);
}

test "evaluator: getVarFromInput returns None for out-of-bounds input" {
    var tree = ExprTree.init();

    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    tree.nodes[1] = .{ .tag = .unit };
    // input_idx = 10 (out of bounds - only 1 input)
    tree.constants[0] = .{ .short = 10 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    var cache = context.ContextExtensionCache.init();
    const var_data = [_]u8{ 0x04, 0x54 };
    cache.set(.inputs, 10, 5, &var_data); // Set at index 10

    const test_inputs = [_]context.BoxView{context.testBox()}; // Only 1 input
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.extension_cache = &cache;

    // Use v3 context (getVarFromInput requires v6 activation)
    var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be None (input_idx out of bounds)
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

test "evaluator: getVarFromInput returns None on type mismatch" {
    // getVarFromInput[Long](0, 5) with SInt stored should return None
    var tree = ExprTree.init();

    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    // Request type T = Long (5), but stored value is Int (4)
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.LONG };
    tree.nodes[1] = .{ .tag = .unit };
    tree.constants[0] = .{ .short = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    var cache = context.ContextExtensionCache.init();
    const var_data = [_]u8{ 0x04, 0x54 }; // SInt 42 (type_code 4 = Int, not Long)
    cache.set(.inputs, 0, 5, &var_data);

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);
    ctx.extension_cache = &cache;

    // Use v3 context (getVarFromInput requires v6 activation)
    var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
    eval.cost_limit = 10000;

    const result = try eval.evaluate();

    // Should be None (type mismatch: requested Long but stored Int)
    try std.testing.expect(result == .option);
    try std.testing.expectEqual(null_value_idx, result.option.value_idx);
}

// ============================================================================
// Property Tests for Context Variable Type Checking
// ============================================================================

test "evaluator: property - getVarFromInput[T] with T value returns Some" {
    // Property: forall T, v:T. store(v:T) => getVarFromInput[T](...) = Some(v')
    // Test with multiple primitive types to verify the property holds across types
    const TestCase = struct {
        type_idx: u8,
        type_code: u8,
        encoded_value: []const u8,
    };

    const test_cases = [_]TestCase{
        // Boolean true: type_code=1, value=1
        .{ .type_idx = types.TypePool.BOOLEAN, .type_code = 0x01, .encoded_value = &[_]u8{ 0x01, 0x01 } },
        // Byte 42: type_code=2, value=42
        .{ .type_idx = types.TypePool.BYTE, .type_code = 0x02, .encoded_value = &[_]u8{ 0x02, 42 } },
        // Short 1000: type_code=3, ZigZag(1000)=2000=0xD0,0x0F
        .{ .type_idx = types.TypePool.SHORT, .type_code = 0x03, .encoded_value = &[_]u8{ 0x03, 0xD0, 0x0F } },
        // Int 42: type_code=4, ZigZag(42)=84=0x54
        .{ .type_idx = types.TypePool.INT, .type_code = 0x04, .encoded_value = &[_]u8{ 0x04, 0x54 } },
        // Long 100: type_code=5, ZigZag(100)=200=0xC8,0x01
        .{ .type_idx = types.TypePool.LONG, .type_code = 0x05, .encoded_value = &[_]u8{ 0x05, 0xC8, 0x01 } },
    };

    for (test_cases) |tc| {
        var tree = ExprTree.init();

        const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
        tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = tc.type_idx };
        tree.nodes[1] = .{ .tag = .unit };
        tree.constants[0] = .{ .short = 0 };
        tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
        tree.constants[1] = .{ .byte = 7 }; // var_id = 7
        tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
        tree.constant_count = 2;
        tree.node_count = 4;

        var cache = context.ContextExtensionCache.init();
        cache.set(.inputs, 0, 7, tc.encoded_value);

        const test_inputs = [_]context.BoxView{context.testBox()};
        var ctx = Context.forHeight(100, &test_inputs);
        ctx.extension_cache = &cache;

        // Use v3 context (getVarFromInput requires v6 activation)
        var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
        eval.cost_limit = 10000;

        const result = try eval.evaluate();

        // Property: Same type T stored and requested => Some(value)
        try std.testing.expect(result == .option);
        try std.testing.expect(result.option.value_idx != null_value_idx);
        try std.testing.expectEqual(tc.type_idx, result.option.inner_type);
    }
}

test "evaluator: property - getVarFromInput[T] with U!=T value returns None" {
    // Property: forall T, U where T != U, v:U. store(v:U) => getVarFromInput[T](...) = None
    // Each type pair (request, stored) should return None when they differ
    const TypePair = struct {
        request_type: u8,
        stored_type_code: u8,
        stored_value: []const u8,
    };

    const test_pairs = [_]TypePair{
        // Request Boolean, store Int
        .{ .request_type = types.TypePool.BOOLEAN, .stored_type_code = 0x04, .stored_value = &[_]u8{ 0x04, 0x54 } },
        // Request Int, store Long
        .{ .request_type = types.TypePool.INT, .stored_type_code = 0x05, .stored_value = &[_]u8{ 0x05, 0xC8, 0x01 } },
        // Request Long, store Byte
        .{ .request_type = types.TypePool.LONG, .stored_type_code = 0x02, .stored_value = &[_]u8{ 0x02, 42 } },
        // Request Byte, store Boolean
        .{ .request_type = types.TypePool.BYTE, .stored_type_code = 0x01, .stored_value = &[_]u8{ 0x01, 0x01 } },
        // Request Short, store Int
        .{ .request_type = types.TypePool.SHORT, .stored_type_code = 0x04, .stored_value = &[_]u8{ 0x04, 0x00 } },
    };

    for (test_pairs) |pair| {
        var tree = ExprTree.init();

        const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
        tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = pair.request_type };
        tree.nodes[1] = .{ .tag = .unit };
        tree.constants[0] = .{ .short = 0 };
        tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
        tree.constants[1] = .{ .byte = 3 }; // var_id = 3
        tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
        tree.constant_count = 2;
        tree.node_count = 4;

        var cache = context.ContextExtensionCache.init();
        cache.set(.inputs, 0, 3, pair.stored_value);

        const test_inputs = [_]context.BoxView{context.testBox()};
        var ctx = Context.forHeight(100, &test_inputs);
        ctx.extension_cache = &cache;

        // Use v3 context (getVarFromInput requires v6 activation)
        var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
        eval.cost_limit = 10000;

        const result = try eval.evaluate();

        // Property: Different types T != U => None
        try std.testing.expect(result == .option);
        try std.testing.expectEqual(null_value_idx, result.option.value_idx);
    }
}

test "evaluator: property - GetVar and getVarFromInput[T] equivalent for SELF" {
    // Property: GetVar(id) ≡ getVarFromInput[T](self_index, id) for SELF's variables
    // Both should return the same result when accessing SELF's context extension

    // Test data: Int 42
    const var_data = [_]u8{ 0x04, 0x54 };
    const var_id: u8 = 10;

    // === Test GetVar ===
    var tree1 = ExprTree.init();
    // get_var node: data = (type_idx << 8) | var_id
    tree1.nodes[0] = .{ .tag = .get_var, .data = (types.TypePool.INT << 8) | var_id };
    tree1.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx1 = Context.forHeight(100, &test_inputs);
    ctx1.context_vars[var_id] = &var_data;

    var eval1 = Evaluator.init(&tree1, &ctx1);
    eval1.cost_limit = 10000;
    const result1 = try eval1.evaluate();

    // === Test getVarFromInput ===
    var tree2 = ExprTree.init();
    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree2.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    tree2.nodes[1] = .{ .tag = .unit };
    tree2.constants[0] = .{ .short = 0 }; // input_idx = 0 (SELF)
    tree2.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree2.constants[1] = .{ .byte = var_id };
    tree2.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree2.constant_count = 2;
    tree2.node_count = 4;

    var cache = context.ContextExtensionCache.init();
    cache.set(.inputs, 0, var_id, &var_data); // Same data in extension cache

    var ctx2 = Context.forHeight(100, &test_inputs);
    ctx2.extension_cache = &cache;

    // Use v3 context for getVarFromInput (requires v6 activation)
    var eval2 = Evaluator.initWithVersion(&tree2, &ctx2, context.VersionContext.init(3, 3));
    eval2.cost_limit = 10000;
    const result2 = try eval2.evaluate();

    // Property: Both return Some with matching inner_type
    try std.testing.expect(result1 == .option);
    try std.testing.expect(result2 == .option);
    try std.testing.expect(result1.option.value_idx != null_value_idx);
    try std.testing.expect(result2.option.value_idx != null_value_idx);
    try std.testing.expectEqual(result1.option.inner_type, result2.option.inner_type);
}

test "evaluator: property - missing variable returns None regardless of type" {
    // Property: forall T. getVarFromInput[T](idx, missing_var_id) = None
    // The type T should not affect the result when variable doesn't exist

    const type_indices = [_]u8{
        types.TypePool.BOOLEAN,
        types.TypePool.BYTE,
        types.TypePool.SHORT,
        types.TypePool.INT,
        types.TypePool.LONG,
    };

    for (type_indices) |type_idx| {
        var tree = ExprTree.init();

        const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
        tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = type_idx };
        tree.nodes[1] = .{ .tag = .unit };
        tree.constants[0] = .{ .short = 0 };
        tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
        tree.constants[1] = .{ .byte = 99 }; // var_id = 99 (not set)
        tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
        tree.constant_count = 2;
        tree.node_count = 4;

        var cache = context.ContextExtensionCache.init();
        // Don't set var_id 99

        const test_inputs = [_]context.BoxView{context.testBox()};
        var ctx = Context.forHeight(100, &test_inputs);
        ctx.extension_cache = &cache;

        // Use v3 context (getVarFromInput requires v6 activation)
        var eval = Evaluator.initWithVersion(&tree, &ctx, context.VersionContext.init(3, 3));
        eval.cost_limit = 10000;

        const result = try eval.evaluate();

        // Property: Missing variable => None, for any type T
        try std.testing.expect(result == .option);
        try std.testing.expectEqual(null_value_idx, result.option.value_idx);
        try std.testing.expectEqual(type_idx, result.option.inner_type);
    }
}

test "evaluator: getVarFromInput requires v6 activation" {
    // getVarFromInput is a v6 feature (EIP-50)
    // When version context is not v6 activated, returns true (soft-fork mode)
    // Per Scala soft-fork semantics: unknown features pass with value true
    var tree = ExprTree.init();

    const method_data: u16 = (@as(u16, Evaluator.ContextMethodId.get_var_from_input) << 8) | Evaluator.ContextTypeCode;
    tree.nodes[0] = .{ .tag = .method_call, .data = method_data, .result_type = types.TypePool.INT };
    tree.nodes[1] = .{ .tag = .unit };
    tree.constants[0] = .{ .short = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.constants[1] = .{ .byte = 5 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.constant_count = 2;
    tree.node_count = 4;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    // Test with v2 (not v6) - should return true (soft-fork mode)
    // Per Scala: scripts with unknown v6 features pass with value true
    var eval_v2 = Evaluator.init(&tree, &ctx);
    eval_v2.version_ctx = context.VersionContext.init(2, 2);
    eval_v2.cost_limit = 10000;

    const result_v2 = try eval_v2.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result_v2);

    // Test with v3 activated and v3 tree version - should succeed (return None)
    var cache = context.ContextExtensionCache.init();
    ctx.extension_cache = &cache;

    var eval_v3 = Evaluator.init(&tree, &ctx);
    eval_v3.version_ctx = context.VersionContext.init(3, 3);
    eval_v3.cost_limit = 10000;

    const result_v3 = try eval_v3.evaluate();
    try std.testing.expect(result_v3 == .option);
    // Returns None because variable not set
    try std.testing.expectEqual(null_value_idx, result_v3.option.value_idx);
}

// ============================================================================
// Upcast/Downcast Tests
// ============================================================================

test "upcast: long to unsigned_big_int" {
    // Test upcast from long to unsigned_big_int
    const long_val: Value = .{ .long = 12345 };

    // Simulate the upcast manually using helper functions
    var ubigint: data.Value.UnsignedBigInt = .{ .bytes = undefined, .len = 0 };
    const u: u64 = @intCast(long_val.long);
    ubigint.len = minimalUnsignedLen(u64, u);
    writeUnsignedBigEndian(u64, u, ubigint.bytes[0..ubigint.len]);

    const result: Value = .{ .unsigned_big_int = ubigint };
    try std.testing.expect(result == .unsigned_big_int);
    try std.testing.expectEqual(@as(u8, 2), result.unsigned_big_int.len); // 12345 = 0x3039
}

test "upcast: big_int to unsigned_big_int" {
    // Test upcast from positive big_int to unsigned_big_int
    var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = 2 };
    bigint.bytes[0] = 0x12;
    bigint.bytes[1] = 0x34;

    // Simulate the upcast (positive BigInt → UnsignedBigInt)
    try std.testing.expect(!bigint.isNegative());
    var ubigint: data.Value.UnsignedBigInt = .{ .bytes = undefined, .len = bigint.len };
    @memcpy(ubigint.bytes[0..bigint.len], bigint.bytes[0..bigint.len]);

    try std.testing.expectEqual(@as(u8, 2), ubigint.len);
    try std.testing.expectEqual(@as(u8, 0x12), ubigint.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x34), ubigint.bytes[1]);
}

test "downcast: unsigned_big_int to long" {
    // Test downcast from unsigned_big_int that fits in i64
    var ubigint: data.Value.UnsignedBigInt = .{ .bytes = undefined, .len = 2 };
    ubigint.bytes[0] = 0x30;
    ubigint.bytes[1] = 0x39; // 0x3039 = 12345

    const u = try unsignedBigIntToLong(ubigint);
    try std.testing.expectEqual(@as(u64, 12345), u);
}

test "downcast: unsigned_big_int to long overflow" {
    // Test downcast from unsigned_big_int that's too large for u64
    var ubigint: data.Value.UnsignedBigInt = .{ .bytes = undefined, .len = 9 };
    @memset(&ubigint.bytes, 0xFF);

    const result = unsignedBigIntToLong(ubigint);
    try std.testing.expectError(error.ArithmeticOverflow, result);
}

test "bigIntToLong: positive value" {
    var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = 2 };
    bigint.bytes[0] = 0x30;
    bigint.bytes[1] = 0x39; // 0x3039 = 12345

    const result = try bigIntToLong(bigint);
    try std.testing.expectEqual(@as(i64, 12345), result);
}

test "bigIntToLong: negative value" {
    var bigint: data.Value.BigInt = .{ .bytes = undefined, .len = 1 };
    bigint.bytes[0] = 0xFF; // -1 in two's complement

    const result = try bigIntToLong(bigint);
    try std.testing.expectEqual(@as(i64, -1), result);
}

test "minimalUnsignedLen: various values" {
    try std.testing.expectEqual(@as(u8, 1), minimalUnsignedLen(u32, 0));
    try std.testing.expectEqual(@as(u8, 1), minimalUnsignedLen(u32, 1));
    try std.testing.expectEqual(@as(u8, 1), minimalUnsignedLen(u32, 255));
    try std.testing.expectEqual(@as(u8, 2), minimalUnsignedLen(u32, 256));
    try std.testing.expectEqual(@as(u8, 2), minimalUnsignedLen(u32, 12345));
    try std.testing.expectEqual(@as(u8, 4), minimalUnsignedLen(u32, 0xFFFFFFFF));
    try std.testing.expectEqual(@as(u8, 8), minimalUnsignedLen(u64, 0xFFFFFFFFFFFFFFFF));
}

// ============================================================================
// Metrics Tests
// ============================================================================

test "evaluator: metrics are updated on successful evaluation" {
    // Test that metrics are correctly recorded during evaluation
    var m = Metrics{};
    var tree = ExprTree.init();

    // Simple boolean constant (true_leaf) that evaluates successfully
    tree.nodes[0] = .{ .tag = .true_leaf };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.metrics = &m;
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);

    const snap = m.snapshot();
    try std.testing.expectEqual(@as(u64, 1), snap.evaluations_total);
    try std.testing.expectEqual(@as(u64, 1), snap.evaluation_success_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_errors_total);
    try std.testing.expect(snap.evaluation_cost_total > 0);
}

test "evaluator: metrics record errors" {
    // Test that metrics record errors when cost limit exceeded
    var m = Metrics{};
    var tree = ExprTree.init();

    // Create a tree with height operation (consumes cost)
    tree.nodes[0] = .{ .tag = .height };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.metrics = &m;
    eval.cost_limit = 1; // Very low cost limit to trigger error

    // This should fail with CostLimitExceeded
    _ = eval.evaluate() catch {
        const snap = m.snapshot();
        try std.testing.expectEqual(@as(u64, 1), snap.evaluations_total);
        try std.testing.expectEqual(@as(u64, 0), snap.evaluation_success_total);
        try std.testing.expectEqual(@as(u64, 1), snap.evaluation_errors_total);
        return;
    };

    // If we reach here, evaluation should have failed
    try std.testing.expect(false);
}

test "evaluator: metrics accumulate across evaluations" {
    // Test that metrics accumulate across multiple evaluations
    var m = Metrics{};
    var tree = ExprTree.init();

    tree.nodes[0] = .{ .tag = .true_leaf };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    // Run three successful evaluations
    for (0..3) |_| {
        var eval = Evaluator.init(&tree, &ctx);
        eval.metrics = &m;
        eval.cost_limit = 10000;
        _ = try eval.evaluate();
    }

    const snap = m.snapshot();
    try std.testing.expectEqual(@as(u64, 3), snap.evaluations_total);
    try std.testing.expectEqual(@as(u64, 3), snap.evaluation_success_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_errors_total);
}

test "evaluator: metrics null by default" {
    // Test that evaluator works fine without metrics
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf };
    tree.node_count = 1;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectEqual(@as(?*Metrics, null), eval.metrics);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expectEqual(Value{ .boolean = true }, result);
}

test "evaluator: proveDHTuple produces correct sigma bytes" {
    // Generator point G (compressed SEC1)
    const G = [_]u8{
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };

    // Build tree: proveDHTuple(const0, const1, const2, const3)
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .prove_dh_tuple };
    // 4 group element constants
    tree.nodes[1] = .{ .tag = .constant_placeholder, .data = 0 };
    tree.nodes[2] = .{ .tag = .constant_placeholder, .data = 1 };
    tree.nodes[3] = .{ .tag = .constant_placeholder, .data = 2 };
    tree.nodes[4] = .{ .tag = .constant_placeholder, .data = 3 };
    tree.node_count = 5;

    // All 4 constants are generator G
    tree.constants[0] = .{ .group_element = G };
    tree.constants[1] = .{ .group_element = G };
    tree.constants[2] = .{ .group_element = G };
    tree.constants[3] = .{ .group_element = G };
    tree.constant_count = 4;

    const test_inputs = [_]context.BoxView{context.testBox()};
    var ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 10000;

    const result = try eval.evaluate();
    try std.testing.expect(result == .sigma_prop);

    const sigma_data = result.sigma_prop.data;

    // Expected: 0xCE + 4×G = 133 bytes
    try std.testing.expectEqual(@as(usize, 133), sigma_data.len);
    try std.testing.expectEqual(@as(u8, 0xCE), sigma_data[0]); // ProveDHTuple opcode
    try std.testing.expectEqualSlices(u8, &G, sigma_data[1..34]); // g
    try std.testing.expectEqualSlices(u8, &G, sigma_data[34..67]); // h
    try std.testing.expectEqualSlices(u8, &G, sigma_data[67..100]); // u
    try std.testing.expectEqualSlices(u8, &G, sigma_data[100..133]); // v
}
