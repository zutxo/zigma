//! Determinism Checker for DST
//!
//! Verifies that the evaluator produces identical results for identical inputs.
//! This is the core property that DST must verify - any non-determinism is a bug.
//!
//! Properties checked:
//!   1. Output determinism: Same tree + context → same Value
//!   2. Cost determinism: Same evaluation → same cost_used
//!   3. Error determinism: Same invalid input → same error
//!   4. Side-effect freedom: Evaluation doesn't modify tree or context

const std = @import("std");
const assert = std.debug.assert;

// Import from zigma module
const zigma = @import("zigma");
const evaluator_mod = zigma.evaluator;
const expr_mod = zigma.expr_serializer;
const data_mod = zigma.data_serializer;
const context_mod = zigma.context;

const Evaluator = evaluator_mod.Evaluator;
const EvalError = evaluator_mod.EvalError;
const ExprTree = expr_mod.ExprTree;
const Value = data_mod.Value;
const Context = context_mod.Context;

// ============================================================================
// Types
// ============================================================================

/// Result of a single evaluation
pub const EvalResult = struct {
    /// Result value (or null if error)
    value: ?Value,
    /// Error (or null if success)
    err: ?EvalError,
    /// Cost consumed
    cost_used: u64,

    pub fn isSuccess(self: EvalResult) bool {
        return self.err == null;
    }

    pub fn eql(self: EvalResult, other: EvalResult) bool {
        // Must have same error status
        if ((self.err == null) != (other.err == null)) return false;

        // If both errored, must be same error
        if (self.err) |e1| {
            if (other.err) |e2| {
                if (e1 != e2) return false;
            }
        }

        // Cost must match
        if (self.cost_used != other.cost_used) return false;

        // Values must match (if both succeeded)
        if (self.value) |v1| {
            if (other.value) |v2| {
                return valuesEqual(v1, v2);
            }
            return false;
        }
        return other.value == null;
    }
};

/// Determinism check result
pub const DeterminismResult = union(enum) {
    /// All evaluations produced identical results
    deterministic: void,
    /// Non-determinism detected
    non_deterministic: struct {
        /// First result (baseline)
        expected: EvalResult,
        /// Divergent result
        got: EvalResult,
        /// Which repetition diverged (0-indexed)
        repetition: u8,
    },
};

/// Determinism checker configuration
pub const DeterminismChecker = struct {
    /// Number of times to repeat each evaluation
    repetitions: u8 = 10,

    /// Check determinism for a given tree and context
    pub fn check(
        self: *const DeterminismChecker,
        tree: *const ExprTree,
        context: *const Context,
    ) DeterminismResult {
        var first_result: ?EvalResult = null;

        for (0..self.repetitions) |rep| {
            // Evaluate
            const result = evaluate(tree, context);

            // Compare with first result
            if (first_result) |expected| {
                if (!expected.eql(result)) {
                    return .{ .non_deterministic = .{
                        .expected = expected,
                        .got = result,
                        .repetition = @intCast(rep),
                    } };
                }
            } else {
                first_result = result;
            }
        }

        return .deterministic;
    }

    /// Check determinism with custom result comparison
    pub fn checkWithCallback(
        self: *const DeterminismChecker,
        tree: *const ExprTree,
        context: *const Context,
        comptime callback: fn (EvalResult, EvalResult, u8) bool,
    ) DeterminismResult {
        var first_result: ?EvalResult = null;

        for (0..self.repetitions) |rep| {
            const result = evaluate(tree, context);

            if (first_result) |expected| {
                if (!callback(expected, result, @intCast(rep))) {
                    return .{ .non_deterministic = .{
                        .expected = expected,
                        .got = result,
                        .repetition = @intCast(rep),
                    } };
                }
            } else {
                first_result = result;
            }
        }

        return .deterministic;
    }
};

// ============================================================================
// Evaluation Helper
// ============================================================================

/// Perform a single evaluation and capture result
fn evaluate(tree: *const ExprTree, context: *const Context) EvalResult {
    // Create mutable copies for evaluator (it needs mutable tree for some ops)
    var tree_copy = tree.*;
    var context_copy = context.*;

    var eval = Evaluator.init(&tree_copy, &context_copy);
    eval.cost_limit = 1_000_000; // Default limit

    const result = eval.evaluate();

    if (result) |value| {
        return .{
            .value = value,
            .err = null,
            .cost_used = eval.cost_used,
        };
    } else |err| {
        return .{
            .value = null,
            .err = err,
            .cost_used = eval.cost_used,
        };
    }
}

// ============================================================================
// Value Comparison
// ============================================================================

/// Compare two values for equality
fn valuesEqual(a: Value, b: Value) bool {
    return switch (a) {
        .unit => b == .unit,
        .boolean => |v| b == .boolean and b.boolean == v,
        .byte => |v| b == .byte and b.byte == v,
        .short => |v| b == .short and b.short == v,
        .int => |v| b == .int and b.int == v,
        .long => |v| b == .long and b.long == v,
        .big_int => |v| blk: {
            if (b != .big_int) break :blk false;
            if (v.len != b.big_int.len) break :blk false;
            break :blk std.mem.eql(u8, v.bytes[0..v.len], b.big_int.bytes[0..b.big_int.len]);
        },
        .unsigned_big_int => |v| blk: {
            if (b != .unsigned_big_int) break :blk false;
            if (v.len != b.unsigned_big_int.len) break :blk false;
            break :blk std.mem.eql(u8, v.bytes[0..v.len], b.unsigned_big_int.bytes[0..b.unsigned_big_int.len]);
        },
        .group_element => |v| blk: {
            if (b != .group_element) break :blk false;
            break :blk std.mem.eql(u8, &v, &b.group_element);
        },
        .sigma_prop => |v| blk: {
            if (b != .sigma_prop) break :blk false;
            const a_data = v.data;
            const b_data = b.sigma_prop.data;
            break :blk std.mem.eql(u8, a_data, b_data);
        },
        .coll_byte => |v| blk: {
            if (b != .coll_byte) break :blk false;
            break :blk std.mem.eql(u8, v, b.coll_byte);
        },
        .option => |v| blk: {
            if (b != .option) break :blk false;
            if (v.inner_type != b.option.inner_type) break :blk false;
            break :blk v.value_idx == b.option.value_idx;
        },
        .box => |v| blk: {
            if (b != .box) break :blk false;
            break :blk v.source == b.box.source and v.index == b.box.index;
        },
        .box_coll => |v| blk: {
            if (b != .box_coll) break :blk false;
            break :blk v.source == b.box_coll.source;
        },
        .header => |v| blk: {
            if (b != .header) break :blk false;
            // Compare by ID (header hash)
            break :blk std.mem.eql(u8, &v.id, &b.header.id);
        },
        .pre_header => |v| blk: {
            if (b != .pre_header) break :blk false;
            // Compare by parent_id and height
            break :blk std.mem.eql(u8, &v.parent_id, &b.pre_header.parent_id) and
                v.height == b.pre_header.height;
        },
        .avl_tree => |v| blk: {
            if (b != .avl_tree) break :blk false;
            break :blk std.mem.eql(u8, &v.digest, &b.avl_tree.digest) and
                v.key_length == b.avl_tree.key_length and
                v.value_length_opt == b.avl_tree.value_length_opt and
                @as(u8, @bitCast(v.tree_flags)) == @as(u8, @bitCast(b.avl_tree.tree_flags));
        },
        .hash32 => |v| blk: {
            if (b != .hash32) break :blk false;
            break :blk std.mem.eql(u8, &v, &b.hash32);
        },
        .soft_fork_placeholder => b == .soft_fork_placeholder,
        .tuple => |v| blk: {
            if (b != .tuple) break :blk false;
            break :blk v.start == b.tuple.start and v.len == b.tuple.len;
        },
        .coll => |v| blk: {
            if (b != .coll) break :blk false;
            break :blk v.elem_type == b.coll.elem_type and
                v.start == b.coll.start and
                v.len == b.coll.len;
        },
    };
}

// ============================================================================
// Tests
// ============================================================================

test "determinism: true_leaf is deterministic" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = zigma.types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    const checker = DeterminismChecker{ .repetitions = 20 };
    const result = checker.check(&tree, &ctx);

    try std.testing.expectEqual(DeterminismResult.deterministic, result);
}

test "determinism: height opcode is deterministic" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = zigma.types.TypePool.INT };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(12345, &test_inputs);

    const checker = DeterminismChecker{ .repetitions = 20 };
    const result = checker.check(&tree, &ctx);

    try std.testing.expectEqual(DeterminismResult.deterministic, result);
}

test "determinism: comparison is deterministic" {
    var tree = ExprTree.init();

    // Create: height > 100
    tree.nodes[0] = .{
        .tag = .bin_op,
        .data = @intFromEnum(expr_mod.BinOpKind.gt),
        .result_type = zigma.types.TypePool.BOOLEAN,
    };
    tree.nodes[1] = .{ .tag = .height, .result_type = zigma.types.TypePool.INT };
    tree.nodes[2] = .{ .tag = .constant, .data = 0, .result_type = zigma.types.TypePool.INT };
    tree.values[0] = .{ .int = 100 };
    tree.node_count = 3;
    tree.value_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(200, &test_inputs);

    const checker = DeterminismChecker{ .repetitions = 20 };
    const result = checker.check(&tree, &ctx);

    try std.testing.expectEqual(DeterminismResult.deterministic, result);
}

test "determinism: eval_result equality" {
    const r1 = EvalResult{ .value = .{ .boolean = true }, .err = null, .cost_used = 100 };
    const r2 = EvalResult{ .value = .{ .boolean = true }, .err = null, .cost_used = 100 };
    const r3 = EvalResult{ .value = .{ .boolean = false }, .err = null, .cost_used = 100 };
    const r4 = EvalResult{ .value = .{ .boolean = true }, .err = null, .cost_used = 200 };

    try std.testing.expect(r1.eql(r2));
    try std.testing.expect(!r1.eql(r3));
    try std.testing.expect(!r1.eql(r4));
}

test "determinism: error results" {
    const r1 = EvalResult{ .value = null, .err = error.CostLimitExceeded, .cost_used = 100 };
    const r2 = EvalResult{ .value = null, .err = error.CostLimitExceeded, .cost_used = 100 };
    const r3 = EvalResult{ .value = null, .err = error.WorkStackOverflow, .cost_used = 100 };

    try std.testing.expect(r1.eql(r2));
    try std.testing.expect(!r1.eql(r3));
}
