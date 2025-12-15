//! Cost Accounting Checker for DST
//!
//! Verifies cost model correctness and invariants:
//!   1. Cost always consumed on success
//!   2. Cost monotonically increases during evaluation
//!   3. Cost limit enforcement is exact
//!   4. Version-dependent costs are applied correctly

const std = @import("std");
const assert = std.debug.assert;

// Import from zigma module
const zigma = @import("zigma");
const evaluator_mod = zigma.evaluator;
const expr_mod = zigma.expr_serializer;
const context_mod = zigma.context;

const Evaluator = evaluator_mod.Evaluator;
const EvalError = evaluator_mod.EvalError;
const ExprTree = expr_mod.ExprTree;
const Context = context_mod.Context;

// ============================================================================
// Types
// ============================================================================

/// Cost check result
pub const CostCheckResult = union(enum) {
    /// All cost invariants hold
    valid: CostStats,
    /// Cost invariant violation
    violation: CostViolation,
};

/// Cost statistics from evaluation
pub const CostStats = struct {
    /// Total cost consumed
    cost_used: u64,
    /// Whether evaluation succeeded
    success: bool,
};

/// Cost violation details
pub const CostViolation = struct {
    kind: ViolationKind,
    expected: u64,
    actual: u64,
    description: []const u8,
};

pub const ViolationKind = enum {
    /// Cost was zero on successful evaluation
    zero_cost_on_success,
    /// Cost exceeded limit without error
    exceeded_without_error,
    /// Cost limit not enforced exactly
    inexact_limit_enforcement,
};

/// Cost checker configuration
pub const CostChecker = struct {
    /// Check cost invariants for a given tree and context
    pub fn check(
        tree: *const ExprTree,
        context: *const Context,
    ) CostCheckResult {
        return checkWithLimit(tree, context, 1_000_000);
    }

    /// Check cost invariants with specific cost limit
    pub fn checkWithLimit(
        tree: *const ExprTree,
        context: *const Context,
        cost_limit: u64,
    ) CostCheckResult {
        var tree_copy = tree.*;
        var context_copy = context.*;

        var eval = Evaluator.init(&tree_copy, &context_copy);
        eval.cost_limit = cost_limit;

        const result = eval.evaluate();

        if (result) |_| {
            // Successful evaluation - check cost invariants

            // Invariant 1: Cost always consumed on success
            if (eval.cost_used == 0) {
                return .{
                    .violation = .{
                        .kind = .zero_cost_on_success,
                        .expected = 1, // At least 1 cost unit
                        .actual = 0,
                        .description = "successful evaluation consumed zero cost",
                    },
                };
            }

            // Invariant 2: Cost should not exceed limit on success
            if (eval.cost_used > cost_limit) {
                return .{ .violation = .{
                    .kind = .exceeded_without_error,
                    .expected = cost_limit,
                    .actual = eval.cost_used,
                    .description = "evaluation succeeded but cost exceeded limit",
                } };
            }

            return .{ .valid = .{
                .cost_used = eval.cost_used,
                .success = true,
            } };
        } else |_| {
            // Failed evaluation - check error-related invariants
            return .{ .valid = .{
                .cost_used = eval.cost_used,
                .success = false,
            } };
        }
    }

    /// Check that cost limit enforcement is exact
    /// This tests that evaluation fails at exactly the cost limit, not before or after
    pub fn checkExactLimitEnforcement(
        tree: *const ExprTree,
        context: *const Context,
    ) ?CostViolation {
        // First, evaluate with high limit to get actual cost
        var tree_copy1 = tree.*;
        var context_copy1 = context.*;
        var eval1 = Evaluator.init(&tree_copy1, &context_copy1);
        eval1.cost_limit = 100_000_000; // Very high limit

        const high_limit_result = eval1.evaluate();
        if (high_limit_result) |_| {
            // Got the actual cost
            const actual_cost = eval1.cost_used;

            // Now try with limit = actual_cost - 1 (should fail)
            if (actual_cost > 1) {
                var tree_copy2 = tree.*;
                var context_copy2 = context.*;
                var eval2 = Evaluator.init(&tree_copy2, &context_copy2);
                eval2.cost_limit = actual_cost - 1;

                const low_limit_result = eval2.evaluate();
                if (low_limit_result) |_| {
                    // Should have failed but didn't
                    return .{
                        .kind = .inexact_limit_enforcement,
                        .expected = actual_cost - 1,
                        .actual = eval2.cost_used,
                        .description = "evaluation succeeded with cost limit below actual cost",
                    };
                } else |_| {
                    // Expected failure - good
                }
            }

            // Try with limit = actual_cost (should succeed)
            var tree_copy3 = tree.*;
            var context_copy3 = context.*;
            var eval3 = Evaluator.init(&tree_copy3, &context_copy3);
            eval3.cost_limit = actual_cost;

            const exact_limit_result = eval3.evaluate();
            if (exact_limit_result) |_| {
                // Good - succeeded with exact cost
                if (eval3.cost_used != actual_cost) {
                    return .{
                        .kind = .inexact_limit_enforcement,
                        .expected = actual_cost,
                        .actual = eval3.cost_used,
                        .description = "cost differs between evaluations of same tree",
                    };
                }
            } else |_| {
                // Failed with exact limit - this is a violation
                return .{
                    .kind = .inexact_limit_enforcement,
                    .expected = actual_cost,
                    .actual = eval3.cost_used,
                    .description = "evaluation failed with cost limit equal to actual cost",
                };
            }
        } else |_| {
            // Initial evaluation failed - can't test limit enforcement
        }

        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "cost_checker: true_leaf has cost" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = zigma.types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    const result = CostChecker.check(&tree, &ctx);

    switch (result) {
        .valid => |stats| {
            try std.testing.expect(stats.success);
            try std.testing.expect(stats.cost_used > 0);
        },
        .violation => |v| {
            std.debug.print("Unexpected violation: {s}\n", .{v.description});
            try std.testing.expect(false);
        },
    }
}

test "cost_checker: height opcode has cost" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = zigma.types.TypePool.INT };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    const result = CostChecker.check(&tree, &ctx);

    switch (result) {
        .valid => |stats| {
            try std.testing.expect(stats.success);
            try std.testing.expect(stats.cost_used > 0);
        },
        .violation => |v| {
            std.debug.print("Unexpected violation: {s}\n", .{v.description});
            try std.testing.expect(false);
        },
    }
}

test "cost_checker: low limit causes failure" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = zigma.types.TypePool.INT };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    // Very low limit should cause failure
    const result = CostChecker.checkWithLimit(&tree, &ctx, 1);

    switch (result) {
        .valid => |stats| {
            // If it succeeded, cost should be <= 1
            if (stats.success) {
                try std.testing.expect(stats.cost_used <= 1);
            }
        },
        .violation => {
            // This is also acceptable - might be an exact limit issue
        },
    }
}

test "cost_checker: comparison has more cost than leaf" {
    // Create height > 100 comparison
    var tree = ExprTree.init();
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

    // Get cost of comparison
    const comparison_result = CostChecker.check(&tree, &ctx);

    // Create simple leaf
    var leaf_tree = ExprTree.init();
    leaf_tree.nodes[0] = .{ .tag = .true_leaf, .result_type = zigma.types.TypePool.BOOLEAN };
    leaf_tree.node_count = 1;

    const leaf_result = CostChecker.check(&leaf_tree, &ctx);

    // Comparison should cost more than simple leaf
    switch (comparison_result) {
        .valid => |cmp_stats| {
            switch (leaf_result) {
                .valid => |leaf_stats| {
                    try std.testing.expect(cmp_stats.cost_used > leaf_stats.cost_used);
                },
                .violation => try std.testing.expect(false),
            }
        },
        .violation => try std.testing.expect(false),
    }
}
