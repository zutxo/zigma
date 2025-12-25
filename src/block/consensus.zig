//! Consensus Rule Verification
//!
//! Validates transaction consensus rules:
//! - Value conservation: sum(inputs) == sum(outputs) (ERG exactly preserved)
//! - Token conservation: per-token balance >= 0 (output <= input)
//! - Token minting: only from first input's box ID

const std = @import("std");
const context = @import("../interpreter/context.zig");
const transaction = @import("transaction.zig");

pub const BoxView = context.BoxView;
pub const Token = context.Token;
pub const Input = transaction.Input;
pub const Output = transaction.Output;
pub const Transaction = transaction.Transaction;

/// Maximum distinct tokens across inputs/outputs
pub const MAX_DISTINCT_TOKENS: u16 = 256;

// ============================================================================
// Consensus Result
// ============================================================================

/// Result of consensus rule verification
pub const ConsensusResult = struct {
    /// Overall validity
    valid: bool,
    /// Value balance check passed
    value_balance_ok: bool,
    /// Token conservation check passed
    token_conservation_ok: bool,
    /// Computed fee (input_sum - output_sum)
    fee: i64,
    /// Input value sum
    input_sum: i64,
    /// Output value sum
    output_sum: i64,
    /// Specific errors encountered
    errors: [8]?ConsensusError,
    /// Number of errors
    error_count: u8,

    /// Create success result
    pub fn success(input_sum: i64, output_sum: i64) ConsensusResult {
        return .{
            .valid = true,
            .value_balance_ok = true,
            .token_conservation_ok = true,
            .fee = input_sum - output_sum,
            .input_sum = input_sum,
            .output_sum = output_sum,
            .errors = [_]?ConsensusError{null} ** 8,
            .error_count = 0,
        };
    }

    /// Create failure result
    pub fn failure(err: ConsensusError) ConsensusResult {
        var result = ConsensusResult{
            .valid = false,
            .value_balance_ok = false,
            .token_conservation_ok = false,
            .fee = 0,
            .input_sum = 0,
            .output_sum = 0,
            .errors = [_]?ConsensusError{null} ** 8,
            .error_count = 1,
        };
        result.errors[0] = err;
        return result;
    }

    /// Add error to result
    pub fn addError(self: *ConsensusResult, err: ConsensusError) void {
        if (self.error_count < 8) {
            self.errors[self.error_count] = err;
            self.error_count += 1;
        }
        self.valid = false;
    }
};

/// Consensus rule violation types
pub const ConsensusError = error{
    /// Inputs and outputs don't balance (ERG not preserved)
    ValueImbalance,
    /// Token destroyed without authorization
    TokenDestroyed,
    /// Token created without authorization (not from first input)
    UnauthorizedTokenMint,
    /// Negative value in box
    NegativeValue,
    /// Value overflow during summation
    ValueOverflow,
    /// Too many distinct tokens
    TooManyTokens,
};

// ============================================================================
// Value Conservation
// ============================================================================

/// Verify ERG preservation: sum(inputs) == sum(outputs).
/// In Ergo, ERG must be exactly preserved (txErgPreservation rule).
/// Returns (ok, input_sum, output_sum).
pub fn verifyValueBalance(
    input_boxes: []const BoxView,
    outputs: []const Output,
) struct { ok: bool, input_sum: i64, output_sum: i64, err: ?ConsensusError } {
    var input_sum: i64 = 0;
    var output_sum: i64 = 0;

    // Sum input values (with overflow check)
    for (input_boxes) |box| {
        if (box.value < 0) {
            return .{ .ok = false, .input_sum = 0, .output_sum = 0, .err = ConsensusError.NegativeValue };
        }
        const overflow = @addWithOverflow(input_sum, box.value);
        if (overflow[1] != 0) {
            return .{ .ok = false, .input_sum = 0, .output_sum = 0, .err = ConsensusError.ValueOverflow };
        }
        input_sum = overflow[0];
    }

    // Sum output values (with overflow check)
    for (outputs) |out| {
        if (out.value < 0) {
            return .{ .ok = false, .input_sum = input_sum, .output_sum = 0, .err = ConsensusError.NegativeValue };
        }
        const overflow = @addWithOverflow(output_sum, out.value);
        if (overflow[1] != 0) {
            return .{ .ok = false, .input_sum = input_sum, .output_sum = 0, .err = ConsensusError.ValueOverflow };
        }
        output_sum = overflow[0];
    }

    // Check ERG preservation (must be exactly equal)
    const ok = input_sum == output_sum;
    const err: ?ConsensusError = if (ok) null else ConsensusError.ValueImbalance;

    return .{ .ok = ok, .input_sum = input_sum, .output_sum = output_sum, .err = err };
}

// ============================================================================
// Token Conservation
// ============================================================================

/// Token balance tracker (pre-allocated, fixed size)
const TokenBalanceMap = struct {
    /// Token IDs
    ids: [MAX_DISTINCT_TOKENS][32]u8,
    /// Balances (positive = in, negative = out)
    balances: [MAX_DISTINCT_TOKENS]i64,
    /// Count of tracked tokens
    count: u16,

    fn init() TokenBalanceMap {
        return .{
            .ids = undefined,
            .balances = undefined,
            .count = 0,
        };
    }

    /// Add to token balance (positive or negative)
    fn addBalance(self: *TokenBalanceMap, token_id: [32]u8, amount: i64) !void {
        // Find existing
        for (self.ids[0..self.count], 0..) |id, i| {
            if (std.mem.eql(u8, &id, &token_id)) {
                const overflow = @addWithOverflow(self.balances[i], amount);
                if (overflow[1] != 0) {
                    return ConsensusError.ValueOverflow;
                }
                self.balances[i] = overflow[0];
                return;
            }
        }

        // Add new
        if (self.count >= MAX_DISTINCT_TOKENS) {
            return ConsensusError.TooManyTokens;
        }
        self.ids[self.count] = token_id;
        self.balances[self.count] = amount;
        self.count += 1;
    }

    /// Check all balances are >= 0 (conservation)
    fn checkConservation(self: *const TokenBalanceMap) bool {
        for (self.balances[0..self.count]) |balance| {
            if (balance < 0) return false;
        }
        return true;
    }

    /// Get deficit tokens (those with negative balance)
    fn getDeficits(self: *const TokenBalanceMap, out: *[MAX_DISTINCT_TOKENS][32]u8) u16 {
        var count: u16 = 0;
        for (self.ids[0..self.count], self.balances[0..self.count]) |id, balance| {
            if (balance < 0) {
                out[count] = id;
                count += 1;
            }
        }
        return count;
    }
};

/// Verify token conservation: for each token, sum(inputs) >= sum(outputs).
/// Exception: First input's box ID can be used as a new token ID (minting).
pub fn verifyTokenConservation(
    input_boxes: []const BoxView,
    outputs: []const Output,
    first_input_id: ?[32]u8,
) struct { ok: bool, err: ?ConsensusError } {
    var balances = TokenBalanceMap.init();

    // Add input tokens (positive)
    for (input_boxes) |box| {
        for (box.tokens) |token| {
            balances.addBalance(token.id, token.amount) catch |e| {
                return .{ .ok = false, .err = e };
            };
        }
    }

    // Subtract output tokens (negative)
    for (outputs) |out| {
        for (out.tokens) |token| {
            balances.addBalance(token.id, -token.amount) catch |e| {
                return .{ .ok = false, .err = e };
            };
        }
    }

    // Check conservation
    if (!balances.checkConservation()) {
        // Check if deficit is due to allowed minting
        if (first_input_id) |mint_id| {
            var deficits: [MAX_DISTINCT_TOKENS][32]u8 = undefined;
            const deficit_count = balances.getDeficits(&deficits);

            for (deficits[0..deficit_count]) |deficit_id| {
                // Only first input's box ID can be minted
                if (!std.mem.eql(u8, &deficit_id, &mint_id)) {
                    return .{ .ok = false, .err = ConsensusError.UnauthorizedTokenMint };
                }
            }
            // All deficits are authorized minting
            return .{ .ok = true, .err = null };
        }
        return .{ .ok = false, .err = ConsensusError.TokenDestroyed };
    }

    return .{ .ok = true, .err = null };
}

// ============================================================================
// Full Consensus Verification
// ============================================================================

/// Verify all consensus rules for a transaction.
/// Requires resolved input boxes.
pub fn verifyConsensus(
    input_boxes: []const BoxView,
    tx: *const Transaction,
) ConsensusResult {
    // Verify ERG preservation (inputs == outputs)
    const value_result = verifyValueBalance(input_boxes, tx.outputs);
    if (!value_result.ok) {
        var result = ConsensusResult.failure(value_result.err.?);
        result.input_sum = value_result.input_sum;
        result.output_sum = value_result.output_sum;
        return result;
    }

    // Get first input box ID for token minting rule
    const first_input_id: ?[32]u8 = if (tx.inputs.len > 0) tx.inputs[0].box_id else null;

    // Verify token conservation
    const token_result = verifyTokenConservation(input_boxes, tx.outputs, first_input_id);
    if (!token_result.ok) {
        var result = ConsensusResult.failure(token_result.err.?);
        result.input_sum = value_result.input_sum;
        result.output_sum = value_result.output_sum;
        result.value_balance_ok = true;
        return result;
    }

    // All checks passed
    return ConsensusResult.success(value_result.input_sum, value_result.output_sum);
}

// ============================================================================
// Tests
// ============================================================================

test "consensus: ERG preservation success (exact balance)" {
    var inputs = [_]BoxView{
        std.mem.zeroes(BoxView),
        std.mem.zeroes(BoxView),
    };
    inputs[0].value = 1000;
    inputs[1].value = 2000;

    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{
        Output.init(3000, &ergo_tree, 100), // Exact match: 1000 + 2000 = 3000
    };

    const result = verifyValueBalance(&inputs, &outputs);
    try std.testing.expect(result.ok);
    try std.testing.expectEqual(@as(i64, 3000), result.input_sum);
    try std.testing.expectEqual(@as(i64, 3000), result.output_sum);
}

test "consensus: ERG preservation failure (inputs > outputs)" {
    var inputs = [_]BoxView{
        std.mem.zeroes(BoxView),
        std.mem.zeroes(BoxView),
    };
    inputs[0].value = 1000;
    inputs[1].value = 2000;

    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{
        Output.init(2500, &ergo_tree, 100), // Not equal: 3000 != 2500
    };

    const result = verifyValueBalance(&inputs, &outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.ValueImbalance, result.err.?);
}

test "consensus: ERG preservation failure (outputs > inputs)" {
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].value = 1000;

    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{
        Output.init(1500, &ergo_tree, 100), // outputs > inputs
    };

    const result = verifyValueBalance(&inputs, &outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.ValueImbalance, result.err.?);
}

test "consensus: negative value rejected" {
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].value = -100;

    const result = verifyValueBalance(&inputs, &[_]Output{});
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.NegativeValue, result.err.?);
}

test "consensus: token conservation success" {
    const token_id = [_]u8{0xAA} ** 32;
    const tokens = [_]Token{.{ .id = token_id, .amount = 100 }};

    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].tokens = &tokens;

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(0, &ergo_tree, 100)};
    outputs[0].tokens = &tokens; // Same amount out

    const result = verifyTokenConservation(&inputs, &outputs, null);
    try std.testing.expect(result.ok);
}

test "consensus: token destruction rejected" {
    const token_id = [_]u8{0xAA} ** 32;
    const in_tokens = [_]Token{.{ .id = token_id, .amount = 100 }};
    const out_tokens = [_]Token{.{ .id = token_id, .amount = 150 }}; // More out than in

    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].tokens = &in_tokens;

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(0, &ergo_tree, 100)};
    outputs[0].tokens = &out_tokens;

    const result = verifyTokenConservation(&inputs, &outputs, null);
    try std.testing.expect(!result.ok);
}

test "consensus: token minting from first input allowed" {
    const first_input_id = [_]u8{0xBB} ** 32;
    const new_token = [_]Token{.{ .id = first_input_id, .amount = 1000 }};

    const inputs = [_]BoxView{std.mem.zeroes(BoxView)};

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(0, &ergo_tree, 100)};
    outputs[0].tokens = &new_token;

    const result = verifyTokenConservation(&inputs, &outputs, first_input_id);
    try std.testing.expect(result.ok);
}

test "consensus: token minting from wrong id rejected" {
    const first_input_id = [_]u8{0xBB} ** 32;
    const wrong_token_id = [_]u8{0xCC} ** 32;
    const new_token = [_]Token{.{ .id = wrong_token_id, .amount = 1000 }};

    const inputs = [_]BoxView{std.mem.zeroes(BoxView)};

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(0, &ergo_tree, 100)};
    outputs[0].tokens = &new_token;

    const result = verifyTokenConservation(&inputs, &outputs, first_input_id);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.UnauthorizedTokenMint, result.err.?);
}

test "consensus: full verification success" {
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].value = 1000;

    var box_id: [32]u8 = undefined;
    @memset(&box_id, 0xAA);

    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{Output.init(1000, &ergo_tree, 100)}; // ERG preserved: 1000 = 1000

    const tx_input = transaction.Input.fromBoxId(box_id);
    const tx = Transaction.init([_]u8{0} ** 32, &[_]transaction.Input{tx_input}, &outputs);

    const result = verifyConsensus(&inputs, &tx);
    try std.testing.expect(result.valid);
    try std.testing.expect(result.value_balance_ok);
    try std.testing.expect(result.token_conservation_ok);
    try std.testing.expectEqual(@as(i64, 0), result.fee); // Fee is always 0 with ERG preservation
}
