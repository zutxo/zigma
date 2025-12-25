//! ErgoTree Reduction
//!
//! Reduces an ErgoTree expression to a SigmaBoolean proposition.
//! This is the bridge between expression evaluation and cryptographic proof verification.
//!
//! "Reduction" evaluates the expression tree to produce:
//! - TrivialProp (true/false): Decidable without proof
//! - SigmaBoolean tree: Requires cryptographic proof (ProveDlog, ProveDHTuple, CAND, COR, CTHRESHOLD)
//!
//! Reference: Scala Interpreter.fullReduction, Rust reduce_to_crypto

const std = @import("std");
const assert = std.debug.assert;
const sigma_tree = @import("../sigma/sigma_tree.zig");
const evaluator_mod = @import("evaluator.zig");

const SigmaBoolean = sigma_tree.SigmaBoolean;
const Evaluator = evaluator_mod.Evaluator;
const EvalError = evaluator_mod.EvalError;
pub const EvalDiagnostics = evaluator_mod.EvalDiagnostics;
const Value = @import("../serialization/data_serializer.zig").Value;

// ============================================================================
// Reduction Result
// ============================================================================

/// Result of reducing an ErgoTree to a cryptographic proposition.
/// Contains the SigmaBoolean (pointer into evaluator's arena) and cost consumed.
///
/// IMPORTANT: The sigma_boolean pointer is valid only while the evaluator's
/// arena has not been reset. Process the result before resetting the evaluator.
pub const ReductionResult = struct {
    /// The reduced proposition (points into evaluator's arena for complex trees)
    sigma_boolean: *const SigmaBoolean,

    /// Total cost consumed during reduction (evaluation + parsing)
    cost: u64,

    // Compile-time assertions
    comptime {
        // Result should be small (two machine words)
        assert(@sizeOf(ReductionResult) <= 24);
    }

    /// Check if the proposition is trivially true (no proof needed, always valid)
    pub fn isTrivialTrue(self: ReductionResult) bool {
        return self.sigma_boolean.isTrue();
    }

    /// Check if the proposition is trivially false (no proof possible, always invalid)
    pub fn isTrivialFalse(self: ReductionResult) bool {
        return self.sigma_boolean.isFalse();
    }

    /// Check if the proposition requires a cryptographic proof
    pub fn requiresProof(self: ReductionResult) bool {
        return self.sigma_boolean.requiresProof();
    }

    /// Check if the proposition is trivial (true or false, no proof needed)
    pub fn isTrivial(self: ReductionResult) bool {
        return self.sigma_boolean.isTrivial();
    }
};

// ============================================================================
// Reduction Errors
// ============================================================================

pub const ReductionError = error{
    /// Cost budget exceeded during evaluation
    CostLimitExceeded,

    /// Wall-clock timeout exceeded
    TimeoutExceeded,

    /// Expression did not evaluate to a SigmaProp or Boolean
    NotSigmaProp,

    /// Failed to parse SigmaBoolean from evaluated value
    InvalidSigmaStructure,

    /// Evaluation failed for other reasons
    EvaluationFailed,
};

// ============================================================================
// Core Reduction Function
// ============================================================================

/// Reduce an ErgoTree expression to a SigmaBoolean proposition.
///
/// This function:
/// 1. Runs the evaluator to get a Value (must be boolean or sigma_prop)
/// 2. Extracts/parses the SigmaBoolean from the Value
/// 3. Normalizes trivial branches using SigmaBoolean.reduce()
/// 4. Returns the result with accumulated cost
///
/// The returned SigmaBoolean pointer is valid until the evaluator's arena is reset.
///
/// # Arguments
/// - `eval`: Initialized evaluator with expression tree and context
/// - `cost_limit`: Maximum cost budget for evaluation
///
/// # Returns
/// ReductionResult containing the normalized SigmaBoolean and cost consumed.
pub fn reduceToCrypto(eval: *Evaluator, cost_limit: u64) ReductionError!ReductionResult {
    // PRECONDITION: evaluator is initialized
    assert(cost_limit > 0);

    // Set cost limit
    eval.setCostLimit(cost_limit);

    // Step 1: Evaluate expression to get final Value
    const value = eval.evaluate() catch |err| {
        return switch (err) {
            error.CostLimitExceeded => error.CostLimitExceeded,
            error.TimeoutExceeded => error.TimeoutExceeded,
            else => error.EvaluationFailed,
        };
    };

    // Step 2: Extract SigmaBoolean from Value
    const sigma_ptr = valueToSigmaBoolean(eval, value) catch {
        return error.NotSigmaProp;
    };

    // INVARIANT: sigma_ptr is valid (non-null pointer)

    // Step 3: Normalize the tree (simplify trivial branches)
    const normalized = sigma_ptr.reduce();

    // Store normalized result back in arena (reduce returns by value)
    const result_ptr = eval.arena.alloc(SigmaBoolean, 1) catch {
        return error.EvaluationFailed;
    };
    result_ptr[0] = normalized;

    // POSTCONDITION: cost was consumed
    assert(eval.cost_used > 0 or value == .boolean); // Boolean constants may have 0 cost

    return ReductionResult{
        .sigma_boolean = &result_ptr[0],
        .cost = eval.cost_used,
    };
}

/// Get evaluation diagnostics from evaluator after reduction fails.
/// Call this after reduceToCrypto returns an error to get detailed error info.
pub fn getEvalDiagnostics(eval: *const Evaluator) EvalDiagnostics {
    return eval.diag;
}

/// Convert evaluated Value to SigmaBoolean.
/// Handles both direct boolean values and serialized sigma_prop bytes.
fn valueToSigmaBoolean(eval: *Evaluator, value: Value) EvalError!*const SigmaBoolean {
    switch (value) {
        .sigma_prop => |sp| {
            // Parse SigmaBoolean from serialized bytes
            return eval.parseSigmaBoolean(sp.data);
        },
        .boolean => |b| {
            // Boolean constant becomes trivial_true or trivial_false
            const node_ptr = eval.arena.alloc(SigmaBoolean, 1) catch return error.OutOfMemory;
            node_ptr[0] = if (b) sigma_tree.sigma_true else sigma_tree.sigma_false;
            return &node_ptr[0];
        },
        else => return error.TypeMismatch,
    }
}

// ============================================================================
// Tests
// ============================================================================

test "reducer: trivial true from boolean constant" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: constant true
    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .boolean = true };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    try std.testing.expect(result.isTrivialTrue());
    try std.testing.expect(!result.requiresProof());
    try std.testing.expect(result.cost > 0);
}

test "reducer: trivial false from boolean constant" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: constant false
    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .boolean = false };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    try std.testing.expect(result.isTrivialFalse());
    try std.testing.expect(!result.requiresProof());
}

test "reducer: ProveDlog requires proof" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: constant sigma_prop containing ProveDlog
    // ProveDlog serialization: 0xCD + 33-byte public key
    var sigma_bytes: [34]u8 = undefined;
    sigma_bytes[0] = 0xCD; // ProveDlog marker
    sigma_bytes[1] = 0x02; // Compressed point prefix
    @memset(sigma_bytes[2..34], 0xAA); // Rest of public key

    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .sigma_prop = .{ .data = &sigma_bytes } };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    try std.testing.expect(!result.isTrivial());
    try std.testing.expect(result.requiresProof());
    try std.testing.expect(result.sigma_boolean.* == .prove_dlog);
}

test "reducer: AND with false child reduces to trivial false" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: sigma_and(trivial_true, trivial_false)
    // CAND serialization: 0x98 + count + children
    const sigma_bytes = [_]u8{
        0x98, // CAND marker
        0x02, // 2 children
        0x01, // trivial_true
        0x00, // trivial_false
    };

    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .sigma_prop = .{ .data = &sigma_bytes } };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    // AND(true, false) = false after normalization
    try std.testing.expect(result.isTrivialFalse());
    try std.testing.expect(!result.requiresProof());
}

test "reducer: OR with true child reduces to trivial true" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: sigma_or(trivial_false, trivial_true)
    // COR serialization: 0x99 + count + children
    const sigma_bytes = [_]u8{
        0x99, // COR marker
        0x02, // 2 children
        0x00, // trivial_false
        0x01, // trivial_true
    };

    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .sigma_prop = .{ .data = &sigma_bytes } };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    // OR(false, true) = true after normalization
    try std.testing.expect(result.isTrivialTrue());
    try std.testing.expect(!result.requiresProof());
}

test "reducer: cost limit exceeded returns error" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: constant true
    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .boolean = true };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);

    // Set a very low cost limit (1 unit, but constant costs more)
    const result = reduceToCrypto(&eval, 1);

    // Should fail with cost limit exceeded
    try std.testing.expectError(error.CostLimitExceeded, result);
}

test "reducer: non-sigma value returns NotSigmaProp" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: constant integer (not a sigma prop)
    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .int = 42 };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = reduceToCrypto(&eval, 1_000_000);

    try std.testing.expectError(error.NotSigmaProp, result);
}

test "reducer: THRESHOLD 2-of-3 with 2 true reduces to trivial true" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: CTHRESHOLD(2, [true, false, true])
    // CTHRESHOLD serialization: 0x9A + k (2 bytes BE) + count + children
    const sigma_bytes = [_]u8{
        0x9A, // CTHRESHOLD marker
        0x00,
        0x02, // k=2 (big-endian)
        0x03, // 3 children
        0x01, // trivial_true
        0x00, // trivial_false
        0x01, // trivial_true
    };

    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .sigma_prop = .{ .data = &sigma_bytes } };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    // THRESHOLD(2, [true, false, true]) = true (2 >= 2)
    try std.testing.expect(result.isTrivialTrue());
}

test "reducer: AND(true, pk) normalizes to pk (non-trivial)" {
    const expr = @import("../serialization/expr_serializer.zig");
    const ctx_mod = @import("context.zig");

    // Expression: sigma_and(trivial_true, ProveDlog)
    // This doesn't reduce to trivial because ProveDlog isn't trivial
    var sigma_bytes: [38]u8 = undefined;
    sigma_bytes[0] = 0x98; // CAND marker
    sigma_bytes[1] = 0x02; // 2 children
    sigma_bytes[2] = 0x01; // trivial_true
    sigma_bytes[3] = 0xCD; // ProveDlog marker
    sigma_bytes[4] = 0x02; // Compressed point prefix
    @memset(sigma_bytes[5..37], 0xBB); // Rest of public key
    sigma_bytes[37] = 0x00; // Extra byte to fill

    // Use only the correct 37 bytes
    const correct_bytes = sigma_bytes[0..37];

    var tree = expr.ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0 };
    tree.node_count = 1;
    tree.values[0] = .{ .sigma_prop = .{ .data = correct_bytes } };
    tree.value_count = 1;

    const inputs = [_]ctx_mod.BoxView{ctx_mod.testBox()};
    const ctx = ctx_mod.Context.forHeight(100, &inputs);

    var eval = Evaluator.init(&tree, &ctx);
    const result = try reduceToCrypto(&eval, 1_000_000);

    // AND(true, pk) doesn't fully reduce because pk is non-trivial
    // The tree remains as CAND but won't simplify to trivial
    try std.testing.expect(!result.isTrivial());
    try std.testing.expect(result.requiresProof());
}
