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

            .inputs, .outputs, .self_box => {
                // Context accessors - minimal support for now
                try self.addCost(FixedCost.inputs);
                return error.UnsupportedExpression; // TODO: implement collections
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
        try self.addCost(15); // OptionGet cost from opcodes

        const opt_val = try self.popValue();
        if (opt_val != .option) return error.TypeMismatch;

        if (opt_val.option.value_idx) |_| {
            // Some(x) - need to get the inner value
            // For now we don't have proper Option value storage
            // This would require storing values in a separate array
            return error.UnsupportedExpression;
        } else {
            // None - error
            return error.OptionNone;
        }
    }

    /// Compute OptionIsDefined - return true if Some, false if None
    fn computeOptionIsDefined(self: *Evaluator) EvalError!void {
        try self.addCost(15); // OptionIsDefined cost from opcodes

        const opt_val = try self.popValue();
        if (opt_val != .option) return error.TypeMismatch;

        const is_defined = opt_val.option.value_idx != null;
        try self.pushValue(.{ .boolean = is_defined });
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
            .true_leaf, .false_leaf, .unit, .height, .constant, .constant_placeholder, .val_use, .unsupported, .inputs, .outputs, .self_box => {},

            // One child
            .calc_blake2b256, .calc_sha256, .option_get, .option_is_defined => {
                next = self.findSubtreeEnd(next);
            },

            // val_def has one child (RHS)
            .val_def => {
                next = self.findSubtreeEnd(next);
            },

            // Two children
            .bin_op, .option_get_or_else => {
                next = self.findSubtreeEnd(next); // Left / Option
                next = self.findSubtreeEnd(next); // Right / Default
            },

            // Three children
            .if_then_else => {
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
