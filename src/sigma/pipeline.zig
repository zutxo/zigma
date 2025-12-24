//! Sigma Protocol Pipeline
//!
//! End-to-end workflow combining:
//! 1. ErgoTree reduction to SigmaBoolean
//! 2. Proof generation (prover)
//! 3. Proof verification (verifier)
//!
//! This module provides high-level functions for the complete
//! signing and verification flow.

const std = @import("std");
const assert = std.debug.assert;

const evaluator_mod = @import("../interpreter/evaluator.zig");
const reducer = @import("../interpreter/reducer.zig");
const context_mod = @import("../interpreter/context.zig");
const expr_serializer = @import("../serialization/expr_serializer.zig");
const prover_mod = @import("prover.zig");
const verifier_mod = @import("verifier.zig");
const sigma_tree = @import("sigma_tree.zig");
const private_input = @import("private_input.zig");

const Evaluator = evaluator_mod.Evaluator;
const Context = context_mod.Context;
const ExprTree = expr_serializer.ExprTree;
const Prover = prover_mod.Prover;
const Proof = prover_mod.Proof;
const SigmaBoolean = sigma_tree.SigmaBoolean;
const PrivateInput = private_input.PrivateInput;
const ReductionResult = reducer.ReductionResult;

// ============================================================================
// Configuration
// ============================================================================

/// Default cost limit for evaluation
pub const DEFAULT_COST_LIMIT: u64 = 1_000_000;

/// Maximum proof size in bytes
pub const MAX_PROOF_SIZE: usize = 1024;

// ============================================================================
// Error Types
// ============================================================================

pub const PipelineError = error{
    /// Cost limit exceeded during reduction
    CostLimitExceeded,
    /// Reduction timeout
    TimeoutExceeded,
    /// Expression did not reduce to SigmaBoolean
    NotSigmaProp,
    /// Invalid sigma structure
    InvalidSigmaStructure,
    /// Evaluation failed
    EvaluationFailed,
    /// Prover doesn't have required secrets
    InsufficientSecrets,
    /// Proof generation failed
    ProvingFailed,
    /// Proof verification failed
    VerificationFailed,
    /// Proposition is trivially false (cannot prove)
    TriviallyFalse,
};

// ============================================================================
// Result Types
// ============================================================================

/// Result of proof generation
pub const ProveResult = struct {
    /// Serialized proof bytes
    proof: [MAX_PROOF_SIZE]u8,
    /// Length of proof
    proof_len: u16,
    /// Total cost consumed (reduction + proving)
    cost: u64,

    /// Get proof as a slice
    pub fn proofSlice(self: *const ProveResult) []const u8 {
        return self.proof[0..self.proof_len];
    }
};

/// Result of verification
pub const VerifyResult = struct {
    /// Whether the proof is valid
    valid: bool,
    /// Total cost consumed (reduction + verification)
    cost: u64,
};

// ============================================================================
// Pipeline Functions
// ============================================================================

/// Reduce an ErgoTree expression to a SigmaBoolean proposition, then prove it.
///
/// This function:
/// 1. Evaluates the expression tree using the provided context
/// 2. Reduces the result to a SigmaBoolean
/// 3. Generates a zero-knowledge proof using the provided secrets
///
/// # Arguments
/// - `eval`: Initialized evaluator with expression tree and context
/// - `secrets`: Private inputs (secret keys) for proof generation
/// - `message`: Message to sign (typically transaction bytes)
/// - `cost_limit`: Maximum cost budget for evaluation
///
/// # Returns
/// ProveResult containing the proof bytes and cost consumed.
pub fn reduceAndProve(
    eval: *Evaluator,
    secrets: []const PrivateInput,
    message: []const u8,
    cost_limit: u64,
) PipelineError!ProveResult {
    // PRECONDITION: valid inputs
    assert(cost_limit > 0);
    assert(message.len > 0);

    // Step 1: Reduce to SigmaBoolean
    const reduction = reducer.reduceToCrypto(eval, cost_limit) catch |err| {
        return switch (err) {
            error.CostLimitExceeded => error.CostLimitExceeded,
            error.TimeoutExceeded => error.TimeoutExceeded,
            error.NotSigmaProp => error.NotSigmaProp,
            error.InvalidSigmaStructure => error.InvalidSigmaStructure,
            error.EvaluationFailed => error.EvaluationFailed,
        };
    };

    // Handle trivial cases
    if (reduction.isTrivialTrue()) {
        // Trivially true: empty proof
        return ProveResult{
            .proof = [_]u8{0} ** MAX_PROOF_SIZE,
            .proof_len = 0,
            .cost = reduction.cost,
        };
    }

    if (reduction.isTrivialFalse()) {
        // Trivially false: cannot prove
        return error.TriviallyFalse;
    }

    // Step 2: Generate proof
    var prover = Prover.init(secrets);
    const proof = prover.prove(reduction.sigma_boolean.*, message) catch |err| {
        return switch (err) {
            prover_mod.ProverError.RootNotReal => error.InsufficientSecrets,
            else => error.ProvingFailed,
        };
    };

    // Step 3: Build result
    var result = ProveResult{
        .proof = [_]u8{0} ** MAX_PROOF_SIZE,
        .proof_len = proof.len,
        .cost = reduction.cost, // TODO: Add proving cost when available
    };
    @memcpy(result.proof[0..proof.len], proof.toSlice());

    // POSTCONDITION: proof length is valid
    assert(result.proof_len <= MAX_PROOF_SIZE);

    return result;
}

/// Reduce an ErgoTree expression to a SigmaBoolean proposition, then verify a proof.
///
/// This function:
/// 1. Evaluates the expression tree using the provided context
/// 2. Reduces the result to a SigmaBoolean
/// 3. Verifies the proof against the proposition and message
///
/// # Arguments
/// - `eval`: Initialized evaluator with expression tree and context
/// - `proof`: Proof bytes to verify
/// - `message`: Message that was signed (typically transaction bytes)
/// - `cost_limit`: Maximum cost budget for evaluation
///
/// # Returns
/// VerifyResult containing validity and cost consumed.
pub fn reduceAndVerify(
    eval: *Evaluator,
    proof: []const u8,
    message: []const u8,
    cost_limit: u64,
) PipelineError!VerifyResult {
    // PRECONDITION: valid inputs
    assert(cost_limit > 0);
    assert(message.len > 0);

    // Step 1: Reduce to SigmaBoolean
    const reduction = reducer.reduceToCrypto(eval, cost_limit) catch |err| {
        return switch (err) {
            error.CostLimitExceeded => error.CostLimitExceeded,
            error.TimeoutExceeded => error.TimeoutExceeded,
            error.NotSigmaProp => error.NotSigmaProp,
            error.InvalidSigmaStructure => error.InvalidSigmaStructure,
            error.EvaluationFailed => error.EvaluationFailed,
        };
    };

    // Handle trivial cases
    if (reduction.isTrivialTrue()) {
        // Trivially true: valid without proof
        return VerifyResult{
            .valid = proof.len == 0, // Must be empty proof
            .cost = reduction.cost,
        };
    }

    if (reduction.isTrivialFalse()) {
        // Trivially false: always invalid
        return VerifyResult{
            .valid = false,
            .cost = reduction.cost,
        };
    }

    // Step 2: Verify proof
    const verify_result = verifier_mod.verifySignatureWithCost(
        reduction.sigma_boolean.*,
        proof,
        message,
    ) catch {
        return error.VerificationFailed;
    };

    return VerifyResult{
        .valid = verify_result.valid,
        .cost = reduction.cost + verify_result.cost,
    };
}

/// Prove a SigmaBoolean proposition directly (without reduction).
///
/// Use this when you already have a SigmaBoolean proposition.
pub fn prove(
    proposition: SigmaBoolean,
    secrets: []const PrivateInput,
    message: []const u8,
) PipelineError!ProveResult {
    // Handle trivial cases
    if (proposition.isTrue()) {
        return ProveResult{
            .proof = [_]u8{0} ** MAX_PROOF_SIZE,
            .proof_len = 0,
            .cost = 0,
        };
    }

    if (proposition.isFalse()) {
        return error.TriviallyFalse;
    }

    // Generate proof
    var prover = Prover.init(secrets);
    const proof = prover.prove(proposition, message) catch |err| {
        return switch (err) {
            prover_mod.ProverError.RootNotReal => error.InsufficientSecrets,
            else => error.ProvingFailed,
        };
    };

    var result = ProveResult{
        .proof = [_]u8{0} ** MAX_PROOF_SIZE,
        .proof_len = proof.len,
        .cost = 0, // No reduction cost
    };
    @memcpy(result.proof[0..proof.len], proof.toSlice());

    return result;
}

/// Verify a proof against a SigmaBoolean proposition directly (without reduction).
///
/// Use this when you already have a SigmaBoolean proposition.
pub fn verify(
    proposition: SigmaBoolean,
    proof: []const u8,
    message: []const u8,
) PipelineError!VerifyResult {
    // Handle trivial cases
    if (proposition.isTrue()) {
        return VerifyResult{
            .valid = proof.len == 0,
            .cost = 0,
        };
    }

    if (proposition.isFalse()) {
        return VerifyResult{
            .valid = false,
            .cost = 0,
        };
    }

    // Verify proof
    const verify_result = verifier_mod.verifySignatureWithCost(
        proposition,
        proof,
        message,
    ) catch {
        return error.VerificationFailed;
    };

    return VerifyResult{
        .valid = verify_result.valid,
        .cost = verify_result.cost,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "pipeline: prove and verify ProveDlog" {
    const DlogProverInput = private_input.DlogProverInput;

    // Create secret and public key
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 42;

    const dlog_input = try DlogProverInput.init(secret);
    const pub_image = dlog_input.publicImage();

    // Create proposition
    const prop = SigmaBoolean{ .prove_dlog = pub_image };

    // Prove
    const message = "test message";
    const prove_result = try prove(prop, &[_]PrivateInput{.{ .dlog = dlog_input }}, message);

    try std.testing.expect(prove_result.proof_len > 0);

    // Verify
    const verify_result = try verify(prop, prove_result.proofSlice(), message);

    try std.testing.expect(verify_result.valid);
}

test "pipeline: prove and verify AND" {
    const DlogProverInput = private_input.DlogProverInput;

    // Create two secrets
    var secret1: [32]u8 = [_]u8{0} ** 32;
    secret1[31] = 1;
    var secret2: [32]u8 = [_]u8{0} ** 32;
    secret2[31] = 2;

    const dlog1 = try DlogProverInput.init(secret1);
    const dlog2 = try DlogProverInput.init(secret2);
    const pk1 = dlog1.publicImage();
    const pk2 = dlog2.publicImage();

    // Create AND proposition
    const child1 = SigmaBoolean{ .prove_dlog = pk1 };
    const child2 = SigmaBoolean{ .prove_dlog = pk2 };
    const children = [_]*const SigmaBoolean{ &child1, &child2 };
    const prop = SigmaBoolean{ .cand = .{ .children = &children } };

    // Prove with both secrets
    const message = "and test";
    const secrets = [_]PrivateInput{ .{ .dlog = dlog1 }, .{ .dlog = dlog2 } };
    const prove_result = try prove(prop, &secrets, message);

    // Verify
    const verify_result = try verify(prop, prove_result.proofSlice(), message);
    try std.testing.expect(verify_result.valid);
}

test "pipeline: prove OR with one secret" {
    const DlogProverInput = private_input.DlogProverInput;

    // Create two secrets but only use one
    var secret1: [32]u8 = [_]u8{0} ** 32;
    secret1[31] = 10;
    var secret2: [32]u8 = [_]u8{0} ** 32;
    secret2[31] = 20;

    const dlog1 = try DlogProverInput.init(secret1);
    const dlog2 = try DlogProverInput.init(secret2);
    const pk1 = dlog1.publicImage();
    const pk2 = dlog2.publicImage();

    // Create OR proposition
    const child1 = SigmaBoolean{ .prove_dlog = pk1 };
    const child2 = SigmaBoolean{ .prove_dlog = pk2 };
    const children = [_]*const SigmaBoolean{ &child1, &child2 };
    const prop = SigmaBoolean{ .cor = .{ .children = &children } };

    // Prove with only first secret
    const message = "or test";
    const prove_result = try prove(prop, &[_]PrivateInput{.{ .dlog = dlog1 }}, message);

    // Verify
    const verify_result = try verify(prop, prove_result.proofSlice(), message);
    try std.testing.expect(verify_result.valid);
}

test "pipeline: trivial true needs no proof" {
    const prop = sigma_tree.sigma_true;

    const message = "trivial";
    const prove_result = try prove(prop, &[_]PrivateInput{}, message);

    try std.testing.expectEqual(@as(u16, 0), prove_result.proof_len);

    const verify_result = try verify(prop, prove_result.proofSlice(), message);
    try std.testing.expect(verify_result.valid);
}

test "pipeline: trivial false cannot be proven" {
    const prop = sigma_tree.sigma_false;

    const message = "trivial";
    const result = prove(prop, &[_]PrivateInput{}, message);

    try std.testing.expectError(error.TriviallyFalse, result);
}

test "pipeline: wrong message fails verification" {
    const DlogProverInput = private_input.DlogProverInput;

    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 99;

    const dlog_input = try DlogProverInput.init(secret);
    const pub_image = dlog_input.publicImage();
    const prop = SigmaBoolean{ .prove_dlog = pub_image };

    // Prove with one message
    const prove_result = try prove(prop, &[_]PrivateInput{.{ .dlog = dlog_input }}, "original");

    // Verify with different message
    const verify_result = try verify(prop, prove_result.proofSlice(), "different");
    try std.testing.expect(!verify_result.valid);
}

test "pipeline: AND fails without all secrets" {
    const DlogProverInput = private_input.DlogProverInput;

    var secret1: [32]u8 = [_]u8{0} ** 32;
    secret1[31] = 50;
    var secret2: [32]u8 = [_]u8{0} ** 32;
    secret2[31] = 51;

    const dlog1 = try DlogProverInput.init(secret1);
    const dlog2 = try DlogProverInput.init(secret2);
    const pk1 = dlog1.publicImage();
    const pk2 = dlog2.publicImage();

    const child1 = SigmaBoolean{ .prove_dlog = pk1 };
    const child2 = SigmaBoolean{ .prove_dlog = pk2 };
    const children = [_]*const SigmaBoolean{ &child1, &child2 };
    const prop = SigmaBoolean{ .cand = .{ .children = &children } };

    // Try to prove with only one secret
    const result = prove(prop, &[_]PrivateInput{.{ .dlog = dlog1 }}, "test");
    try std.testing.expectError(error.InsufficientSecrets, result);
}
