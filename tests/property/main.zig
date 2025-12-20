//! Property-Based Tests for Zigma
//!
//! Tests invariants and metamorphic properties that should hold
//! for all valid inputs, using deterministic pseudo-random generation.
//!
//! Reference: EXPERT_REVIEW.md recommendations

const std = @import("std");
const testing = std.testing;
const zigma = @import("zigma");
const expr = zigma.expr_serializer;
const data = zigma.data_serializer;
const ctx_mod = zigma.context;

const Evaluator = zigma.evaluator.Evaluator;
const ExprTree = expr.ExprTree;
const ExprTag = expr.ExprTag;
const Value = data.Value;
const Context = ctx_mod.Context;

// ============================================================================
// Random Expression Generator
// ============================================================================

/// Generate a simple boolean expression tree
fn generateBooleanExpr(prng: *std.Random.DefaultPrng, tree: *ExprTree, base_idx: u16) u16 {
    const choice = prng.random().intRangeAtMost(u8, 0, 3);

    return switch (choice) {
        0 => blk: {
            // true_leaf
            tree.nodes[base_idx] = .{ .tag = .true_leaf };
            break :blk base_idx + 1;
        },
        1 => blk: {
            // false_leaf
            tree.nodes[base_idx] = .{ .tag = .false_leaf };
            break :blk base_idx + 1;
        },
        2 => blk: {
            // height (returns int, but we can use it for testing evaluation)
            tree.nodes[base_idx] = .{ .tag = .height };
            break :blk base_idx + 1;
        },
        else => blk: {
            // unit
            tree.nodes[base_idx] = .{ .tag = .unit };
            break :blk base_idx + 1;
        },
    };
}

// ============================================================================
// Property Tests
// ============================================================================

test "property: true_leaf evaluates to true consistently" {
    // Property: Evaluating true_leaf N times always returns boolean true
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};

    for (0..100) |i| {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .true_leaf };
        tree.node_count = 1;

        var ctx = Context.forHeight(@intCast(i + 1), &test_inputs);
        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;

        // Add randomness to verify determinism isn't affected by PRNG state
        _ = prng.random().int(u32);

        const result = try eval.evaluate();
        try testing.expectEqual(Value{ .boolean = true }, result);
    }
}

test "property: false_leaf evaluates to false consistently" {
    // Property: Evaluating false_leaf N times always returns boolean false
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};

    for (0..100) |i| {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .false_leaf };
        tree.node_count = 1;

        var ctx = Context.forHeight(@intCast(i + 1), &test_inputs);
        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;

        const result = try eval.evaluate();
        try testing.expectEqual(Value{ .boolean = false }, result);
    }
}

test "property: height returns context height for various heights" {
    // Property: HEIGHT opcode returns the block height from context
    var prng = std.Random.DefaultPrng.init(0xCAFEBABE);
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};

    for (0..50) |_| {
        const random_height = prng.random().intRangeAtMost(u32, 1, 1_000_000);

        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .height };
        tree.node_count = 1;

        var ctx = Context.forHeight(random_height, &test_inputs);
        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;

        const result = try eval.evaluate();
        try testing.expect(result == .int);
        try testing.expectEqual(@as(i32, @intCast(random_height)), result.int);
    }
}

test "property: evaluation is deterministic (same tree + context = same result)" {
    // Property: Given identical tree and context, evaluation always produces same result
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const heights = [_]u32{ 1, 100, 12345, 999999 };

    for (heights) |h| {
        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = .height };
        tree.node_count = 1;

        // Evaluate same tree 10 times
        var first_result: ?Value = null;
        for (0..10) |_| {
            var ctx = Context.forHeight(h, &test_inputs);
            var eval = Evaluator.init(&tree, &ctx);
            eval.cost_limit = 10000;

            const result = try eval.evaluate();
            if (first_result) |fr| {
                try testing.expectEqual(fr, result);
            } else {
                first_result = result;
            }
        }
    }
}

test "property: cost is always consumed on successful evaluation" {
    // Property: After successful evaluation, cost_used > 0
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};

    const tags = [_]ExprTag{ .true_leaf, .false_leaf, .height, .unit };

    for (0..50) |_| {
        const tag_idx = prng.random().intRangeAtMost(usize, 0, tags.len - 1);
        const tag = tags[tag_idx];

        var tree = ExprTree.init();
        tree.nodes[0] = .{ .tag = tag };
        tree.node_count = 1;

        var ctx = Context.forHeight(100, &test_inputs);
        var eval = Evaluator.init(&tree, &ctx);
        eval.cost_limit = 10000;

        _ = try eval.evaluate();

        // After evaluation, cost should be consumed
        try testing.expect(eval.cost_used > 0);
    }
}

test "property: cost limit of 1 always fails for non-trivial operations" {
    // Property: With cost_limit=1, operations that consume cost should fail
    const test_inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height };
    tree.node_count = 1;

    var ctx = Context.forHeight(100, &test_inputs);
    var eval = Evaluator.init(&tree, &ctx);
    eval.cost_limit = 1;

    const result = eval.evaluate();
    try testing.expectError(error.CostLimitExceeded, result);
}
