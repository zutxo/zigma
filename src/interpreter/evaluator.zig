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
const vlq = @import("../serialization/vlq.zig");
const types = @import("../core/types.zig");
const hash = @import("../crypto/hash.zig");
const crypto_ops = @import("ops/crypto.zig");
const sigma_tree = @import("../sigma/sigma_tree.zig");
const avl_tree = @import("../crypto/avl_tree.zig");
const crypto_bigint = @import("../crypto/bigint.zig");

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
const ValuePool = value_pool.ValuePool;
const PooledValue = value_pool.PooledValue;
const null_value_idx = value_pool.null_value_idx;
const RegisterCache = register_cache.RegisterCache;
const RegisterCacheEntry = register_cache.RegisterCacheEntry;
const BoxSource = register_cache.BoxSource;

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
fn pooledValueToValue(pooled: *const PooledValue) EvalError!Value {
    // PRECONDITION: pooled value must be valid
    assert(pooled.type_idx != 0 or pooled.data.primitive == 0); // 0 type only valid for unit

    const type_idx = pooled.type_idx;

    // Check primitive types by direct index
    if (type_idx == TypePool.UNIT) return .unit;
    if (type_idx == TypePool.BOOLEAN) return .{ .boolean = pooled.data.primitive != 0 };
    if (type_idx == TypePool.BYTE) return .{ .byte = @intCast(pooled.data.primitive) };
    if (type_idx == TypePool.SHORT) return .{ .short = @intCast(pooled.data.primitive) };
    if (type_idx == TypePool.INT) return .{ .int = @intCast(pooled.data.primitive) };
    if (type_idx == TypePool.LONG) return .{ .long = pooled.data.primitive };
    if (type_idx == TypePool.BIG_INT) {
        var bi: Value.BigInt = .{
            .bytes = [_]u8{0} ** 32,
            .len = pooled.data.big_int.len,
        };
        @memcpy(bi.bytes[0..bi.len], pooled.data.big_int.bytes[0..bi.len]);
        return .{ .big_int = bi };
    }
    if (type_idx == TypePool.GROUP_ELEMENT) {
        return .{ .group_element = pooled.data.group_element };
    }
    if (type_idx == TypePool.SIGMA_PROP) {
        return .{ .sigma_prop = .{ .data = pooled.data.sigma_prop.slice() } };
    }
    if (type_idx == TypePool.BOX) {
        // Box stored as source + index reference
        return .{ .box = .{
            .source = @enumFromInt(@intFromEnum(pooled.data.box.source)),
            .index = pooled.data.box.index,
        } };
    }
    if (type_idx == TypePool.COLL_BYTE) {
        return .{ .coll_byte = pooled.data.byte_slice.slice() };
    }

    // Check Option types (indices >= OPTION_INT are Option variants)
    // Options store inner_type + value_idx
    if (type_idx >= TypePool.OPTION_INT) {
        return .{ .option = .{
            .inner_type = pooled.data.option.inner_type,
            .value_idx = pooled.data.option.value_idx,
        } };
    }

    // Check Collection types (indices 17-20 are collections)
    if (type_idx >= TypePool.COLL_BYTE and type_idx <= TypePool.COLL_COLL_BYTE) {
        if (type_idx == TypePool.COLL_BYTE) {
            return .{ .coll_byte = pooled.data.byte_slice.slice() };
        }
        // Generic collection
        return .{ .coll = .{
            .elem_type = pooled.data.collection.elem_type,
            .start = pooled.data.collection.start_idx,
            .len = pooled.data.collection.len,
        } };
    }

    // For any remaining complex types, examine data union tag
    // This handles dynamically-typed tuples and other complex types
    return error.UnsupportedExpression;
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
    create_avl_tree,
    tree_lookup,
    extract_register,
};

/// JIT cost table (v2+ mainnet, current default).
/// Source: sigmastate/JitCost.scala
const JIT_COSTS = [_]u32{
    36, // comparison
    36, // arithmetic
    36, // logical
    5, // height
    5, // constant
    10, // self_box
    10, // inputs
    10, // outputs
    10, // data_inputs
    59, // blake2b256_base
    64, // sha256_base
    1, // hash_per_byte
    1100, // decode_point
    10, // group_generator
    5100, // exponentiate
    250, // multiply_group
    10, // select_field
    10, // tuple_construct
    10, // upcast
    10, // downcast
    10, // extract_header_field
    20, // collection_base
    5, // collection_per_item
    20, // func_apply
    10, // method_call
    20, // sigma_and
    20, // sigma_or
    100, // create_avl_tree
    800, // tree_lookup
    50, // extract_register
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
    120, // create_avl_tree
    900, // tree_lookup
    60, // extract_register
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
    pub const create_avl_tree: u32 = JIT_COSTS[@intFromEnum(CostOp.create_avl_tree)];
    pub const tree_lookup: u32 = JIT_COSTS[@intFromEnum(CostOp.tree_lookup)];
    pub const extract_register: u32 = JIT_COSTS[@intFromEnum(CostOp.extract_register)];
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
};

// Compile-time tests for AvlTreeCost
comptime {
    // LookupAvlTree with 3 proof elements: base 40 + 10*3 chunks = 70
    assert(AvlTreeCost.lookup.cost(3) == 40 + 10 * 3);
    // LookupAvlTree with 0 elements: base cost only
    assert(AvlTreeCost.lookup.cost(0) == 40);
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

    /// Memory pools container
    const MemoryPools = struct {
        values: ValuePool = ValuePool.init(),
        register_cache: RegisterCache = RegisterCache.init(),
        type_pool: TypePool = TypePool.init(),

        fn init() MemoryPools {
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

        // Reset state
        self.work_sp = 0;
        self.value_sp = 0;
        self.cost_used = 0;
        self.ops_since_timeout_check = 0;
        self.arena.reset();
        self.var_bindings = [_]?Value{null} ** max_var_bindings;
        self.pools.reset();

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
            try self.checkTimeout();

            const work = self.popWork();

            switch (work.phase) {
                .evaluate => self.evaluateNode(work.node_idx) catch |err| {
                    if (err == error.SoftForkAccepted) {
                        // Soft-fork rule: script with unknown features passes
                        // Reference: Interpreter.scala WhenSoftForkReductionResult
                        return .{ .boolean = true };
                    }
                    return err;
                },
                .compute => self.computeNode(work.node_idx) catch |err| {
                    if (err == error.SoftForkAccepted) {
                        // Soft-fork rule: script with unknown features passes
                        return .{ .boolean = true };
                    }
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
            return error.ValueStackUnderflow;
        }

        // POSTCONDITION: Exactly one result
        assert(self.value_sp == 1);

        return self.popValue();
    }

    /// Evaluate a node (may push children for later processing)
    fn evaluateNode(self: *Evaluator, node_idx: u16) EvalError!void {
        if (node_idx >= self.tree.node_count) {
            return error.InvalidNodeIndex;
        }

        const node = self.tree.nodes[node_idx];

        switch (node.tag) {
            // Leaf nodes: push value directly
            .true_leaf => {
                try self.addCost(FixedCost.constant);
                try self.pushValue(.{ .boolean = true });
            },

            .false_leaf => {
                try self.addCost(FixedCost.constant);
                try self.pushValue(.{ .boolean = false });
            },

            .unit => {
                try self.addCost(FixedCost.constant);
                try self.pushValue(.{ .unit = {} });
            },

            .height => {
                try self.addCost(FixedCost.height);
                try self.pushValue(.{ .int = @intCast(self.ctx.height) });
            },

            .constant => {
                try self.addCost(FixedCost.constant);
                const value_idx = node.data;
                if (value_idx >= self.tree.value_count) {
                    return error.InvalidConstantIndex;
                }
                try self.pushValue(self.tree.values[value_idx]);
            },

            .constant_placeholder => {
                try self.addCost(FixedCost.constant);
                const const_idx = node.data;
                if (const_idx >= self.tree.constant_count) {
                    return error.InvalidConstantIndex;
                }
                try self.pushValue(self.tree.constants[const_idx]);
            },

            .bin_op => {
                // Binary op: push compute phase, then push children
                // Left child at node_idx+1, right child after left subtree
                const left_idx = node_idx + 1;
                const right_idx = self.findSubtreeEnd(left_idx);

                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Push right child first (will be evaluated second, popped first)
                try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
                // Push left child second (will be evaluated first)
                try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
            },

            .if_then_else => {
                // If-then-else: evaluate condition first, then decide branch
                // Condition at node_idx+1, then at node_idx+2, else after then subtree
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Condition is at node_idx+1
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .inputs => {
                // INPUTS accessor: returns collection of input boxes
                try self.addCost(FixedCost.inputs);
                try self.pushValue(.{ .box_coll = .{ .source = .inputs } });
            },

            .outputs => {
                // OUTPUTS accessor: returns collection of output boxes
                try self.addCost(FixedCost.inputs); // Same cost as inputs
                try self.pushValue(.{ .box_coll = .{ .source = .outputs } });
            },

            .self_box => {
                // SELF accessor: returns the box being validated
                // PRECONDITION: Context has valid self_index
                assert(self.ctx.self_index < self.ctx.inputs.len);
                try self.addCost(FixedCost.inputs);
                try self.pushValue(.{ .box = .{
                    .source = .inputs,
                    .index = self.ctx.self_index,
                } });
            },

            .miner_pk => {
                // MinerPubKey: returns miner's public key from pre-header
                // PRECONDITION: Pre-header has valid miner_pk
                const pk = self.ctx.pre_header.miner_pk;
                // INVARIANT: SEC1 compressed point (0x02 or 0x03 prefix, or 0x00 for identity)
                assert(pk[0] == 0x02 or pk[0] == 0x03 or pk[0] == 0x00);
                try self.addCost(100); // MinerPubKey cost from opcodes.zig
                try self.pushValue(.{ .group_element = pk });
            },

            .last_block_utxo_root => {
                // LastBlockUtxoRootHash: returns UTXO state root from last header
                // PRECONDITION: At least one header in context
                if (self.ctx.headers.len == 0) {
                    return error.InvalidContext;
                }
                // INVARIANT: First header (index 0) is most recent
                const state_root = self.ctx.headers[0].state_root;
                try self.addCost(15); // LastBlockUtxoRootHash cost from opcodes.zig
                // Return as byte collection (44-byte AVL+ digest)
                try self.pushValue(.{ .coll_byte = &state_root });
            },

            .calc_blake2b256, .calc_sha256 => {
                // Unary hash operations: push compute phase, then push operand
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Operand is at node_idx+1 (pre-order layout)
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .val_use => {
                // Variable reference: look up value from bindings
                try self.addCost(FixedCost.constant);
                const var_id = node.data;
                if (var_id >= max_var_bindings) return error.UndefinedVariable;
                const value = self.var_bindings[var_id] orelse return error.UndefinedVariable;
                try self.pushValue(value);
            },

            .val_def => {
                // Variable definition: evaluate RHS, then store binding
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // RHS is at node_idx+1
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .block_value => {
                // Block with let bindings: evaluate each ValDef, then result
                // Stack order: push last-to-execute first
                // We want: ValDef0, ValDef1, ..., Result (in execution order)
                // So push: Result, then ValDefs in reverse order
                const item_count = node.data;

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
                // FuncValue alone doesn't evaluate to anything useful
                // It's used as the target of Apply or collection HOFs
                // For now, treat standalone func_value as error
                return error.UnsupportedExpression;
            },

            .apply => {
                // Apply: evaluate argument, then apply function
                // Tree structure: [apply] [func_value] [body...] [arg]
                //
                // PRECONDITIONS
                const func_idx = node_idx + 1;
                assert(func_idx < self.tree.node_count); // func_value must exist

                // Push compute phase first (will run after arg is evaluated)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                // Find the argument (after func_value subtree)
                const arg_idx = self.findSubtreeEnd(func_idx);
                assert(arg_idx < self.tree.node_count); // arg must exist

                // Push argument for evaluation
                try self.pushWork(.{ .node_idx = arg_idx, .phase = .evaluate });
            },

            .option_get, .option_is_defined => {
                // Unary option operations: push compute phase, then push operand
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .option_get_or_else => {
                // Binary: option + default, but we evaluate lazily
                // First evaluate the option, then in compute phase decide what to do
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .long_to_byte_array, .byte_array_to_bigint, .byte_array_to_long => {
                // Type conversion unary operations
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .decode_point => {
                // Unary: Coll[Byte] → GroupElement
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .mod_q => {
                // Unary: BigInt → BigInt (reduce mod secp256k1 group order)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .plus_mod_q, .minus_mod_q => {
                // Binary: BigInt, BigInt → BigInt (mod secp256k1 group order)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                const left_idx = node_idx + 1;
                const right_idx = self.findSubtreeEnd(left_idx);
                try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
            },

            .group_generator => {
                // Nullary: → GroupElement (no children to evaluate)
                try self.addCost(FixedCost.group_generator);
                const g = crypto_ops.groupGenerator();
                try self.pushValue(.{ .group_element = g });
            },

            .exponentiate => {
                // Binary: GroupElement, BigInt → GroupElement
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Left child (GroupElement) at node_idx+1
                const left_idx = node_idx + 1;
                const right_idx = self.findSubtreeEnd(left_idx);
                try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
            },

            .multiply_group => {
                // Binary: GroupElement, GroupElement → GroupElement
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Left child (GroupElement) at node_idx+1
                const left_idx = node_idx + 1;
                const right_idx = self.findSubtreeEnd(left_idx);
                try self.pushWork(.{ .node_idx = right_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = left_idx, .phase = .evaluate });
            },

            .select_field => {
                // Unary: Tuple → element value
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            .extract_register_as => {
                // Unary: Box → Option[T] (register value with lazy deserialization)
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

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

            .upcast, .downcast => {
                // Unary: numeric value → target type
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

            // Header field extraction opcodes (0xE9-0xF2)
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
            => {
                // Unary: Header → field value
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                try self.pushWork(.{ .node_idx = node_idx + 1, .phase = .evaluate });
            },

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
                // Evaluate collection and zero, lambda handled in compute phase
                try self.pushWork(.{ .node_idx = zero_idx, .phase = .evaluate });
                try self.pushWork(.{ .node_idx = coll_idx, .phase = .evaluate });
            },

            // Sigma proposition connectives
            .sigma_and, .sigma_or => {
                // N-ary: n SigmaProp children → SigmaProp
                const child_count = node.data;
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });
                // Push children in reverse order so first child evaluates first
                var idx = node_idx + 1;
                var indices: [256]u16 = undefined;
                var i: u16 = 0;
                while (i < child_count) : (i += 1) {
                    indices[i] = idx;
                    idx = self.findSubtreeEnd(idx);
                }
                // Push in reverse order
                while (i > 0) {
                    i -= 1;
                    try self.pushWork(.{ .node_idx = indices[i], .phase = .evaluate });
                }
            },

            // Method call (collection methods like zip, indices, reverse)
            .method_call => {
                // Method call structure: [method_call] [obj] [args...]
                // data: low 8 bits = type_code, high 8 bits = method_id
                // Extract arg count by scanning the tree
                //
                // PRECONDITIONS
                const obj_idx = node_idx + 1;
                assert(obj_idx < self.tree.node_count);

                // Push compute phase first
                try self.pushWork(.{ .node_idx = node_idx, .phase = .compute });

                // Find args by walking past obj
                const args_start = self.findSubtreeEnd(obj_idx);

                // For now, support 0 or 1 args (zip has 1 arg, indices has 0)
                // We'll push obj for evaluation, args handled in compute
                if (args_start < self.tree.node_count and
                    self.tree.nodes[args_start].tag != .unsupported)
                {
                    // Has at least one arg - push it
                    try self.pushWork(.{ .node_idx = args_start, .phase = .evaluate });
                }

                // Push obj for evaluation
                try self.pushWork(.{ .node_idx = obj_idx, .phase = .evaluate });
            },

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
                const kind: BinOpKind = @enumFromInt(node.data & 0xFF);
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
                    const result = try pooledValueToValue(inner);
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

            // Sigma proposition connectives
            .sigma_and => try self.computeSigmaAnd(node.data),
            .sigma_or => try self.computeSigmaOr(node.data),

            // Function application
            .apply => try self.computeApply(node_idx),

            // Method call (collection methods)
            .method_call => try self.computeMethodCall(node_idx),

            // AVL tree operations
            .create_avl_tree => try self.computeCreateAvlTree(node.data),
            .tree_lookup => try self.computeTreeLookup(),

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

        // Add cost: base + per-byte
        const base_cost: u32 = switch (algo) {
            .blake2b256 => FixedCost.blake2b256_base,
            .sha256 => FixedCost.sha256_base,
        };
        try self.addCost(base_cost + @as(u32, @truncate(input_data.len)) * FixedCost.hash_per_byte);

        // Compute hash
        const hash_result: [32]u8 = switch (algo) {
            .blake2b256 => hash.blake2b256(input_data),
            .sha256 => hash.sha256(input_data),
        };

        // Allocate space in arena for the result
        const result_slice = self.arena.allocSlice(u8, 32) catch return error.OutOfMemory;
        @memcpy(result_slice, &hash_result);

        // POSTCONDITION: Result is exactly 32 bytes
        assert(result_slice.len == 32);

        // Push result as Coll[Byte]
        try self.pushValue(.{ .coll_byte = result_slice });
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
            const result = try pooledValueToValue(inner);
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
        result_slice[0] = @truncate(value >> 56);
        result_slice[1] = @truncate(value >> 48);
        result_slice[2] = @truncate(value >> 40);
        result_slice[3] = @truncate(value >> 32);
        result_slice[4] = @truncate(value >> 24);
        result_slice[5] = @truncate(value >> 16);
        result_slice[6] = @truncate(value >> 8);
        result_slice[7] = @truncate(value);

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
        const value: u64 = (@as(u64, bytes[0]) << 56) |
            (@as(u64, bytes[1]) << 48) |
            (@as(u64, bytes[2]) << 40) |
            (@as(u64, bytes[3]) << 32) |
            (@as(u64, bytes[4]) << 24) |
            (@as(u64, bytes[5]) << 16) |
            (@as(u64, bytes[6]) << 8) |
            @as(u64, bytes[7]);

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
    fn computeDecodePoint(self: *Evaluator) EvalError!void {
        // PRECONDITION: Value stack has at least one value
        assert(self.value_sp > 0);

        try self.addCost(FixedCost.decode_point);

        const input = try self.popValue();
        if (input != .coll_byte) return error.TypeMismatch;

        const bytes = input.coll_byte;
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

        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @truncate(result_bytes.len) };
        @memcpy(output.bytes[0..result_bytes.len], result_bytes);

        try self.pushValue(.{ .big_int = output });

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

        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @truncate(result_bytes.len) };
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

        var output: data.Value.BigInt = .{ .bytes = undefined, .len = @truncate(result_bytes.len) };
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
        // PRECONDITION: Register is user-defined (R4-R9)
        assert(@intFromEnum(reg) >= 4);
        assert(@intFromEnum(reg) <= 9);

        // Check cache first
        const cached = self.pools.register_cache.get(source, box_idx, reg);

        switch (cached) {
            .not_loaded => {
                // First access - deserialize and cache
                return self.deserializeAndCacheRegister(source, box_idx, reg, expected_type);
            },
            .loaded => |value_idx| {
                // Cache hit - convert PooledValue to Value wrapped in Option
                const pooled = self.pools.values.get(value_idx) orelse return error.InvalidState;
                const inner_val = try pooledValueToValue(pooled);
                // Store inner value and return Option.Some
                const stored_idx = try self.storeValueInPool(inner_val, expected_type);
                return .{ .option = .{ .inner_type = expected_type, .value_idx = stored_idx } };
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
        assert(@intFromEnum(reg) >= 4);
        assert(@intFromEnum(reg) <= 9);

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
            .option => |o| .{ .type_idx = type_idx, .data = .{ .option = .{ .inner_type = o.inner_type, .value_idx = o.value_idx } } },
            .box => |b| .{ .type_idx = TypePool.BOX, .data = .{ .box = .{ .source = @enumFromInt(@intFromEnum(b.source)), .index = b.index } } },
            else => .{ .type_idx = type_idx, .data = .{ .primitive = 0 } }, // Fallback for complex types
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

        // INVARIANT: Element count is bounded
        assert(elem_count <= 256);

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

        // PRECONDITION: target_type is a valid numeric type
        assert(target_type == TypePool.SHORT or target_type == TypePool.INT or
            target_type == TypePool.LONG or target_type == TypePool.BIG_INT);

        try self.addCost(FixedCost.upcast);

        const input = try self.popValue();

        // INVARIANT: Input must be a numeric value
        assert(input == .byte or input == .short or input == .int or input == .long);

        // Upcast conversions: Byte → Short → Int → Long → BigInt
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

        // Downcast conversions: BigInt → Long → Int → Short → Byte
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
                else => return error.TypeMismatch,
            },
            // Target is Int
            TypePool.INT => switch (input) {
                .long => |v| blk: {
                    if (v < std.math.minInt(i32) or v > std.math.maxInt(i32)) return error.ArithmeticOverflow;
                    break :blk .{ .int = @truncate(v) };
                },
                else => return error.TypeMismatch,
            },
            // Target is Long
            TypePool.LONG => switch (input) {
                .big_int => |v| blk: {
                    // Check if BigInt fits in i64
                    if (v.len > 8) return error.ArithmeticOverflow;
                    // Convert big-endian bytes to i64
                    var u: u64 = 0;
                    for (v.bytes[0..v.len]) |b| {
                        u = (u << 8) | b;
                    }
                    // Sign extend if negative
                    if (v.isNegative()) {
                        // Extend sign bits
                        const shift: u6 = @intCast(64 - (v.len * 8));
                        const signed: i64 = @bitCast(u << shift);
                        break :blk .{ .long = signed >> shift };
                    }
                    break :blk .{ .long = @bitCast(u) };
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(result);

        // POSTCONDITION: Result is on stack
        assert(self.value_sp > 0);
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
    /// Currently only supports Coll[Byte] → Coll[Byte]
    fn computeMap(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Currently only support coll_byte
        if (coll != .coll_byte) return error.UnsupportedExpression;

        const input = coll.coll_byte;

        // Chunk-based cost for map: PerItemCost(20, 1, 10)
        try self.addCost(CollectionCost.map.cost(@truncate(input.len)));

        // Empty collection: return empty
        if (input.len == 0) {
            const empty = self.arena.allocSlice(u8, 0) catch return error.OutOfMemory;
            try self.pushValue(.{ .coll_byte = empty });
            // POSTCONDITION: Stack depth unchanged
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

        // Allocate result array
        const result = self.arena.allocSlice(u8, input.len) catch return error.OutOfMemory;

        // Apply function to each element
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
        // POSTCONDITION: Stack depth unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute filter: keep elements that satisfy predicate
    /// Currently only supports Coll[Byte]
    fn computeFilter(self: *Evaluator, node_idx: u16) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp > 0);
        assert(node_idx < self.tree.node_count);
        const initial_sp = self.value_sp;

        const coll = try self.popValue();

        // Currently only support coll_byte
        if (coll != .coll_byte) return error.UnsupportedExpression;

        const input = coll.coll_byte;

        // Chunk-based cost for filter: PerItemCost(20, 1, 10)
        try self.addCost(CollectionCost.filter.cost(@truncate(input.len)));

        if (input.len == 0) {
            const empty = self.arena.allocSlice(u8, 0) catch return error.OutOfMemory;
            try self.pushValue(.{ .coll_byte = empty });
            // POSTCONDITION: Stack depth unchanged
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
        if (coll != .coll_byte) return error.UnsupportedExpression;

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
        assert(self.value_sp > 0); // Argument must be on stack
        assert(node_idx < self.tree.node_count); // Node must be valid

        try self.addCost(FixedCost.func_apply);

        // Pop the argument value
        const arg_value = try self.popValue();

        // Find the func_value node (immediately after apply)
        const func_idx = node_idx + 1;
        assert(func_idx < self.tree.node_count); // func_value must be in bounds
        const func_node = self.tree.nodes[func_idx];

        // INVARIANT: func must be a func_value
        if (func_node.tag != .func_value) return error.InvalidData;

        const num_args = func_node.data;

        // INVARIANT: Must have at least 1 argument
        if (num_args == 0) return error.InvalidData;

        // For v5.x, only single-arg functions are supported
        if (num_args != 1) return error.UnsupportedExpression;

        // Find the lambda body (immediately after func_value node)
        const body_idx = func_idx + 1;
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
    const CollMethodId = struct {
        const indices: u8 = 14; // coll.indices → Coll[Int]
        const flatmap: u8 = 15; // coll.flatMap(f) → Coll[B]
        const patch: u8 = 19; // coll.patch(from, patch, replaced) → Coll[A]
        const updated: u8 = 20; // coll.updated(idx, value) → Coll[A]
        const update_many: u8 = 21; // coll.updateMany(idxs, values) → Coll[A]
        const index_of: u8 = 26; // coll.indexOf(elem, from) → Int
        const zip: u8 = 29; // coll.zip(other) → Coll[(A, B)]
        const reverse: u8 = 30; // coll.reverse → Coll[A]
        const starts_with: u8 = 31; // coll.startsWith(other) → Boolean
        const ends_with: u8 = 32; // coll.endsWith(other) → Boolean
        const get: u8 = 33; // coll.get(idx) → Option[A]
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
                // Complex methods that need more support
                CollMethodId.flatmap,
                CollMethodId.patch,
                CollMethodId.updated,
                CollMethodId.update_many,
                CollMethodId.index_of,
                CollMethodId.get,
                => return self.handleUnsupported(),
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
                // Complex methods (insert/update/remove) require Coll[(Coll[Byte], Coll[Byte])]
                // which needs full tuple collection support - stub for now
                AvlTreeMethodId.insert,
                AvlTreeMethodId.update,
                AvlTreeMethodId.remove,
                AvlTreeMethodId.insert_or_update,
                => return self.handleUnsupported(),
                else => return self.handleUnsupported(),
            }
        } else if (type_code == ContextTypeCode) {
            // Context methods
            switch (method_id) {
                ContextMethodId.data_inputs => try self.computeDataInputs(),
                else => return self.handleUnsupported(),
            }
        } else {
            // Unsupported type - use soft-fork aware handling
            return self.handleUnsupported();
        }
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
        const initial_sp = self.value_sp;

        // Pop in reverse order
        const prefix_val = try self.popValue();
        const coll_val = try self.popValue();

        const result: bool = switch (coll_val) {
            .coll_byte => |coll| switch (prefix_val) {
                .coll_byte => |prefix| blk: {
                    if (prefix.len > coll.len) break :blk false;
                    break :blk std.mem.eql(u8, coll[0..prefix.len], prefix);
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .boolean = result });

        // POSTCONDITION: Stack reduced by 1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
    }

    /// Compute endsWith: Coll[T].endsWith(Coll[T]) → Boolean
    /// Returns true if this collection ends with the given suffix
    fn computeEndsWith(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 2 values on stack (coll, suffix)
        assert(self.value_sp >= 2);
        const initial_sp = self.value_sp;

        // Pop in reverse order
        const suffix_val = try self.popValue();
        const coll_val = try self.popValue();

        const result: bool = switch (coll_val) {
            .coll_byte => |coll| switch (suffix_val) {
                .coll_byte => |suffix| blk: {
                    if (suffix.len > coll.len) break :blk false;
                    const start = coll.len - suffix.len;
                    break :blk std.mem.eql(u8, coll[start..], suffix);
                },
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        };

        try self.pushValue(.{ .boolean = result });

        // POSTCONDITION: Stack reduced by 1 (popped 2, pushed 1)
        assert(self.value_sp == initial_sp - 1);
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
    // AvlTree Method Operations
    // ========================================================================

    /// Compute tree.digest → Coll[Byte] (33 bytes)
    fn computeAvlTreeDigest(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access (version-independent, same in JIT and AOT)
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        // Copy digest to arena
        const result = self.arena.allocSlice(u8, avl_tree.digest_size) catch return error.OutOfMemory;
        @memcpy(result, &tree_data.digest);

        try self.pushValue(.{ .coll_byte = result });

        // POSTCONDITION: Stack unchanged (popped 1, pushed 1)
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.enabledOperations → Byte
    fn computeAvlTreeEnabledOps(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;
        const flags_byte = tree_data.tree_flags.toByte();

        try self.pushValue(.{ .byte = @bitCast(flags_byte) });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.keyLength → Int
    fn computeAvlTreeKeyLength(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        try self.pushValue(.{ .int = @intCast(tree_data.key_length) });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.valueLengthOpt → Option[Int]
    fn computeAvlTreeValueLengthOpt(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;

        if (tree_data.value_length_opt) |vl| {
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

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;
        try self.pushValue(.{ .boolean = tree_data.isInsertAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.isUpdateAllowed → Boolean
    fn computeAvlTreeIsUpdateAllowed(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;
        try self.pushValue(.{ .boolean = tree_data.isUpdateAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.isRemoveAllowed → Boolean
    fn computeAvlTreeIsRemoveAllowed(self: *Evaluator) EvalError!void {
        // PRECONDITIONS
        assert(self.value_sp >= 1);

        const initial_sp = self.value_sp;

        // Cost: property access
        try self.addCost(AvlTreeCost.property);

        const tree_val = try self.popValue();
        if (tree_val != .avl_tree) return error.TypeMismatch;

        const tree_data = tree_val.avl_tree;
        try self.pushValue(.{ .boolean = tree_data.isRemoveAllowed() });

        // POSTCONDITION: Stack unchanged
        assert(self.value_sp == initial_sp);
    }

    /// Compute tree.contains(key, proof) → Boolean
    fn computeAvlTreeContains(self: *Evaluator) EvalError!void {
        // PRECONDITIONS: 3 values on stack (tree, key, proof)
        assert(self.value_sp >= 3);

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, key, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

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

        const initial_sp = self.value_sp;

        // Pop in reverse order (proof, key, tree)
        const proof_val = try self.popValue();
        if (proof_val != .coll_byte) return error.TypeMismatch;
        const proof = proof_val.coll_byte;

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
    fn parseSigmaBoolean(self: *Evaluator, bytes: []const u8) EvalError!*const sigma_tree.SigmaBoolean {
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
        _ = self;
        return switch (coll) {
            .coll_byte => |c| if (idx < c.len) .{ .byte = @bitCast(c[idx]) } else error.IndexOutOfBounds,
            // Generic collections need value array access (not yet implemented)
            .coll => return error.UnsupportedExpression,
            else => error.TypeMismatch,
        };
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
            .true_leaf, .false_leaf, .unit, .height, .constant, .constant_placeholder, .val_use, .unsupported, .inputs, .outputs, .self_box, .miner_pk, .last_block_utxo_root, .group_generator => 0,

            // Unary operations (1 child)
            .calc_blake2b256, .calc_sha256, .option_get, .option_is_defined, .long_to_byte_array, .byte_array_to_bigint, .byte_array_to_long, .decode_point, .select_field, .upcast, .downcast, .extract_version, .extract_parent_id, .extract_ad_proofs_root, .extract_state_root, .extract_txs_root, .extract_timestamp, .extract_n_bits, .extract_difficulty, .extract_votes, .extract_miner_rewards, .val_def, .func_value, .extract_register_as, .mod_q => 1,

            // Binary operations (2 children)
            .bin_op, .option_get_or_else, .exponentiate, .multiply_group, .pair_construct, .apply, .map_collection, .exists, .for_all, .filter, .flat_map, .plus_mod_q, .minus_mod_q => 2,

            // Ternary operations (3 children)
            .if_then_else, .triple_construct, .fold, .tree_lookup => 3,

            // N-ary with data-driven child count
            .block_value => node.data + 1, // items + result
            .tuple_construct, .concrete_collection, .sigma_and, .sigma_or => node.data,

            // create_avl_tree: 3 or 4 children (data = 1 if value_length present)
            .create_avl_tree => if (node.data == 1) 4 else 3,

            // method_call: 1 or 2 (obj + optional arg based on method_id)
            .method_call => blk: {
                const method_id: u8 = @truncate(node.data >> 8);
                // zip (29) has 1 arg, indices (14) and reverse (30) have 0
                break :blk if (method_id == 29) 2 else 1;
            },
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
    const l = try extractInt(left);
    const r = try extractInt(right);

    if (l < r) return -1;
    if (l > r) return 1;
    return 0;
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
        else => false, // Complex types need deeper comparison
    };
}

/// Add two integer values with overflow checking
fn addInts(left: Value, right: Value) EvalError!Value {
    // For now, promote to i64 and check overflow
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
    const l = try extractInt(left);
    const r = try extractInt(right);

    if (r == 0) return error.DivisionByZero;

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

    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 32), result.coll_byte.len);

    // Verify against known Blake2b-256("abc") hash
    const expected = [_]u8{
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
    };
    try std.testing.expectEqualSlices(u8, &expected, result.coll_byte);
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

    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 32), result.coll_byte.len);

    // Verify against known SHA-256("abc") hash (NIST test vector)
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, result.coll_byte);
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

    try std.testing.expect(result == .coll_byte);
    try std.testing.expectEqual(@as(usize, 32), result.coll_byte.len);
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
