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
const expr = @import("../serialization/expr_serializer.zig");
const data = @import("../serialization/data_serializer.zig");
const types = @import("../core/types.zig");
const hash = @import("../crypto/hash.zig");
const crypto_ops = @import("ops/crypto.zig");

const Context = context.Context;
const ExprTree = expr.ExprTree;
const ExprNode = expr.ExprNode;
const ExprTag = expr.ExprTag;
const BinOpKind = expr.BinOpKind;
const Value = data.Value;
const TypePool = types.TypePool;
const BumpAllocator = memory.BumpAllocator;

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

// Compile-time sanity checks
comptime {
    assert(max_work_stack >= 64);
    assert(max_value_stack >= 64);
    assert(default_cost_limit > 0);
}

// ============================================================================
// Evaluation Errors
// ============================================================================

pub const EvalError = error{
    /// Cost budget exceeded
    CostLimitExceeded,
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
// Fixed Costs (v4 model)
// ============================================================================

const FixedCost = struct {
    pub const comparison: u32 = 36;
    pub const arithmetic: u32 = 36;
    pub const logical: u32 = 36;
    pub const height: u32 = 5;
    pub const constant: u32 = 5;
    pub const self_box: u32 = 10;
    pub const inputs: u32 = 10;
    pub const outputs: u32 = 10;
    pub const blake2b256_base: u32 = 59; // Base cost for CalcBlake2b256
    pub const sha256_base: u32 = 64; // Base cost for CalcSha256
    pub const hash_per_byte: u32 = 1; // Per-byte cost for hashing
    // Group element operation costs (from opcodes.zig)
    pub const decode_point: u32 = 1100;
    pub const group_generator: u32 = 10;
    pub const exponentiate: u32 = 5100;
    pub const multiply_group: u32 = 250;
    // Tuple operation costs (from opcodes.zig)
    pub const select_field: u32 = 10;
    pub const tuple_construct: u32 = 10;
    // Type cast costs
    pub const upcast: u32 = 10;
    pub const downcast: u32 = 10;
    // Header extraction costs (all low-cost field access)
    pub const extract_header_field: u32 = 10;
};

// ============================================================================
// Evaluator
// ============================================================================

/// Main expression evaluator
pub const Evaluator = struct {
    /// Expression tree being evaluated
    tree: *const ExprTree,

    /// Execution context (read-only blockchain state)
    ctx: *const Context,

    /// Work stack (iterative processing)
    work_stack: [max_work_stack]WorkItem = undefined,
    work_sp: u16 = 0,

    /// Value stack (intermediate results)
    value_stack: [max_value_stack]Value = undefined,
    value_sp: u16 = 0,

    /// Cost accounting
    cost_used: u64 = 0,
    cost_limit: u64 = default_cost_limit,

    /// Arena for temporary allocations (hash results, etc.)
    arena: BumpAllocator(eval_arena_size) = BumpAllocator(eval_arena_size).init(),

    /// Variable bindings (varId -> Value)
    /// null = unbound, non-null = bound value
    var_bindings: [max_var_bindings]?Value = [_]?Value{null} ** max_var_bindings,

    /// Values array for tuple storage
    /// Tuples reference ranges in this array
    values: [max_value_stack]Value = undefined,
    values_sp: u16 = 0,

    pub fn init(tree: *const ExprTree, ctx: *const Context) Evaluator {
        return .{
            .tree = tree,
            .ctx = ctx,
        };
    }

    /// Set cost limit for this evaluation
    pub fn setCostLimit(self: *Evaluator, limit: u64) void {
        assert(limit > 0);
        self.cost_limit = limit;
    }

    /// Evaluate the expression tree to produce a result
    pub fn evaluate(self: *Evaluator) EvalError!Value {
        // Must have at least one node
        assert(self.tree.node_count > 0);

        // Reset state
        self.work_sp = 0;
        self.value_sp = 0;
        self.cost_used = 0;
        self.arena.reset();
        self.var_bindings = [_]?Value{null} ** max_var_bindings;

        // Push root node for evaluation (index 0)
        try self.pushWork(.{ .node_idx = 0, .phase = .evaluate });

        // Main evaluation loop
        while (self.work_sp > 0) {
            const work = self.popWork();

            switch (work.phase) {
                .evaluate => try self.evaluateNode(work.node_idx),
                .compute => try self.computeNode(work.node_idx),
            }
        }

        // Result is on value stack
        if (self.value_sp == 0) {
            return error.ValueStackUnderflow;
        }

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

            .func_value, .apply => {
                // Function values and application - not yet implemented
                return error.UnsupportedExpression;
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

            .unsupported => {
                return error.UnsupportedExpression;
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

                if (opt_val.option.value_idx) |_| {
                    // Some(x) - need to get the inner value
                    // For now we don't have proper Option value storage, error out
                    return error.UnsupportedExpression;
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

            .exponentiate => {
                try self.computeExponentiate();
            },

            .multiply_group => {
                try self.computeMultiplyGroup();
            },

            .select_field => {
                try self.computeSelectField(node.data);
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

        if (opt_val.option.value_idx) |_| {
            // Some(x) - need to get the inner value
            // For now we don't have proper Option value storage
            // This would require storing values in a separate array
            return error.UnsupportedExpression;
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

        const is_defined = opt_val.option.value_idx != null;
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

        // Create tuple reference
        try self.pushValue(.{ .tuple = .{
            .start = @truncate(start),
            .len = @truncate(elem_count),
        } });

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
        try self.addCost(FixedCost.comparison);

        // Pop right then left (stack order)
        const right = try self.popValue();
        const left = try self.popValue();

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
    // Stack operations
    // ========================================================================

    fn pushWork(self: *Evaluator, item: WorkItem) EvalError!void {
        if (self.work_sp >= max_work_stack) return error.WorkStackOverflow;
        self.work_stack[self.work_sp] = item;
        self.work_sp += 1;
    }

    fn popWork(self: *Evaluator) WorkItem {
        assert(self.work_sp > 0);
        self.work_sp -= 1;
        return self.work_stack[self.work_sp];
    }

    fn pushValue(self: *Evaluator, value: Value) EvalError!void {
        if (self.value_sp >= max_value_stack) return error.ValueStackOverflow;
        self.value_stack[self.value_sp] = value;
        self.value_sp += 1;
    }

    fn popValue(self: *Evaluator) EvalError!Value {
        if (self.value_sp == 0) return error.ValueStackUnderflow;
        self.value_sp -= 1;
        return self.value_stack[self.value_sp];
    }

    fn addCost(self: *Evaluator, cost: u32) EvalError!void {
        self.cost_used +|= cost; // Saturating add
        if (self.cost_used > self.cost_limit) {
            return error.CostLimitExceeded;
        }
    }

    /// Find the index after a subtree (next sibling position)
    /// This walks the tree structure to find where a subtree ends.
    fn findSubtreeEnd(self: *const Evaluator, node_idx: u16) u16 {
        if (node_idx >= self.tree.node_count) return self.tree.node_count;

        const node = self.tree.nodes[node_idx];
        var next = node_idx + 1;

        switch (node.tag) {
            // Leaf nodes - no children
            .true_leaf, .false_leaf, .unit, .height, .constant, .constant_placeholder, .val_use, .unsupported, .inputs, .outputs, .self_box, .miner_pk, .last_block_utxo_root, .group_generator => {},

            // One child
            .calc_blake2b256,
            .calc_sha256,
            .option_get,
            .option_is_defined,
            .long_to_byte_array,
            .byte_array_to_bigint,
            .byte_array_to_long,
            .decode_point,
            .select_field,
            .upcast,
            .downcast,
            // Header extraction (all take one Header child)
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
                next = self.findSubtreeEnd(next);
            },

            // val_def has one child (RHS)
            .val_def => {
                next = self.findSubtreeEnd(next);
            },

            // Two children
            .bin_op, .option_get_or_else, .exponentiate, .multiply_group, .pair_construct => {
                next = self.findSubtreeEnd(next); // Left / Option / Point / First
                next = self.findSubtreeEnd(next); // Right / Default / Scalar/Point / Second
            },

            // Three children
            .if_then_else, .triple_construct => {
                next = self.findSubtreeEnd(next); // Condition
                next = self.findSubtreeEnd(next); // Then
                next = self.findSubtreeEnd(next); // Else
            },

            // block_value: item_count children + result
            .block_value => {
                const item_count = node.data;
                var i: u16 = 0;
                while (i < item_count) : (i += 1) {
                    next = self.findSubtreeEnd(next);
                }
                next = self.findSubtreeEnd(next); // Result
            },

            // tuple_construct: elem_count children
            .tuple_construct => {
                const elem_count = node.data;
                var i: u16 = 0;
                while (i < elem_count) : (i += 1) {
                    next = self.findSubtreeEnd(next);
                }
            },

            // concrete_collection: elem_count children (same as tuple_construct)
            .concrete_collection => {
                const elem_count = node.data;
                var i: u16 = 0;
                while (i < elem_count) : (i += 1) {
                    next = self.findSubtreeEnd(next);
                }
            },

            // func_value: body expression
            .func_value => {
                next = self.findSubtreeEnd(next);
            },

            // apply: function + 1 arg (v5.x only single-arg)
            .apply => {
                next = self.findSubtreeEnd(next); // Function
                next = self.findSubtreeEnd(next); // Arg
            },
        }

        return next;
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
    // None value
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null } };
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
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_is_defined };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 2;
    // Some value (value_idx is non-null)
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = 1 } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
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
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null } };
    tree.value_count = 1;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    try std.testing.expectError(error.OptionNone, eval.evaluate());
}

test "evaluator: option_get_or_else on None uses default" {
    // OptionGetOrElse(None, 42) should return 42
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .option_get_or_else };
    tree.nodes[1] = .{ .tag = .constant, .data = 0 }; // None
    tree.nodes[2] = .{ .tag = .constant, .data = 1 }; // Default: 42
    tree.node_count = 3;
    tree.values[0] = .{ .option = .{ .inner_type = types.TypePool.INT, .value_idx = null } };
    tree.values[1] = .{ .int = 42 };
    tree.value_count = 2;

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try eval.evaluate();

    try std.testing.expect(result == .int);
    try std.testing.expectEqual(@as(i32, 42), result.int);
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
