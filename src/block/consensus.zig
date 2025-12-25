//! Consensus Rule Verification
//!
//! Validates transaction consensus rules per Ergo protocol:
//! - Value conservation: sum(inputs) == sum(outputs) (ERG exactly preserved)
//! - Token conservation: per-token balance >= 0 (output <= input)
//! - Token minting: only from first input's box ID
//! - Dust prevention: minimum box value based on size
//! - Creation height: must be valid relative to current height
//! - Box size limits: max 4KB per box, max 4KB proposition
//! - Token limits: max 127 tokens per box, positive amounts only

const std = @import("std");
const context = @import("../interpreter/context.zig");
const transaction = @import("transaction.zig");
const vlq = @import("../serialization/vlq.zig");

pub const BoxView = context.BoxView;
pub const Token = context.Token;
pub const Input = transaction.Input;
pub const Output = transaction.Output;
pub const Transaction = transaction.Transaction;

// ============================================================================
// Protocol Constants
// ============================================================================

/// Maximum distinct tokens across inputs/outputs
pub const MAX_DISTINCT_TOKENS: u16 = 256;

/// Maximum tokens per box (ValidationRules.scala:109 - txAssetsInOneBox)
pub const MAX_TOKENS_PER_BOX: u8 = 127;

/// Maximum box size in bytes (ValidationRules.scala:121 - txBoxSize)
pub const MAX_BOX_SIZE: usize = 4096;

/// Maximum proposition (ErgoTree) size in bytes (ValidationRules.scala:122 - txBoxPropositionSize)
pub const MAX_PROPOSITION_SIZE: usize = 4096;

/// Minimum value per byte in nanoErgs (BoxUtils.scala:40-41)
/// Default from Ergo parameters
pub const MIN_VALUE_PER_BYTE: i64 = 360;

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
    /// Too many distinct tokens across transaction
    TooManyTokens,
    /// Box value below minimum (dust) - txDust
    DustOutput,
    /// Output creation height is in the future - txFuture
    FutureCreationHeight,
    /// Output creation height is negative - txNegHeight (v1 only)
    NegativeCreationHeight,
    /// Output creation height below max input height - txMonotonicHeight (v5+)
    NonMonotonicHeight,
    /// Box exceeds maximum size - txBoxSize
    BoxTooLarge,
    /// Proposition exceeds maximum size - txBoxPropositionSize
    PropositionTooLarge,
    /// Too many tokens in single box - txAssetsInOneBox
    TooManyTokensInBox,
    /// Token amount is not positive - txPositiveAssets
    NonPositiveTokenAmount,
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
// Dust Prevention (txDust)
// ============================================================================

/// Estimate serialized box size for dust calculation.
/// This is an approximation based on box contents.
pub fn estimateBoxSize(output: *const Output) usize {
    var size: usize = 0;

    // Value: VLQ encoded (1-9 bytes typically)
    var vlq_buf: [vlq.max_vlq_bytes]u8 = undefined;
    size += vlq.encodeU64(@bitCast(output.value), &vlq_buf);

    // ErgoTree: length prefix + bytes
    size += vlq.encodeU64(output.ergo_tree.len, &vlq_buf);
    size += output.ergo_tree.len;

    // Creation height: VLQ encoded
    size += vlq.encodeU64(output.creation_height, &vlq_buf);

    // Token count (1 byte) + tokens
    size += 1;
    for (output.tokens) |token| {
        size += 32; // token ID
        size += vlq.encodeU64(@bitCast(token.amount), &vlq_buf);
    }

    // Register count (1 byte) + register bytes
    size += 1;
    for (output.registers) |reg| {
        if (reg) |reg_bytes| {
            size += reg_bytes.len;
        }
    }

    return size;
}

/// Calculate minimum ERG value for a box based on its size.
/// Reference: BoxUtils.scala:40-41 - minimalErgoAmount
pub fn minimalErgoAmount(box_size: usize) i64 {
    return @as(i64, @intCast(box_size)) * MIN_VALUE_PER_BYTE;
}

/// Verify no outputs are dust (below minimum value for their size).
/// Reference: ValidationRules.scala:111 - txDust
pub fn verifyNoDust(outputs: []const Output) struct { ok: bool, err: ?ConsensusError, output_index: ?usize } {
    for (outputs, 0..) |*out, i| {
        const box_size = estimateBoxSize(out);
        const min_value = minimalErgoAmount(box_size);
        if (out.value < min_value) {
            return .{ .ok = false, .err = ConsensusError.DustOutput, .output_index = i };
        }
    }
    return .{ .ok = true, .err = null, .output_index = null };
}

// ============================================================================
// Creation Height Validation
// ============================================================================

/// Verify output creation heights are valid.
/// - txFuture: creation height must not exceed current block height
/// - txMonotonicHeight (v5+): creation height must be >= max input creation height
///
/// Reference: ErgoTransaction.scala:171-173
pub fn verifyCreationHeights(
    outputs: []const Output,
    input_boxes: []const BoxView,
    current_height: u32,
    protocol_version: u8,
) struct { ok: bool, err: ?ConsensusError, output_index: ?usize } {
    // Find max input creation height for monotonic check
    var max_input_height: u32 = 0;
    for (input_boxes) |box| {
        if (box.creation_height > max_input_height) {
            max_input_height = box.creation_height;
        }
    }

    for (outputs, 0..) |out, i| {
        // txFuture: creation height cannot be in the future
        if (out.creation_height > current_height) {
            return .{ .ok = false, .err = ConsensusError.FutureCreationHeight, .output_index = i };
        }

        // txMonotonicHeight (v5+): creation height must be monotonically increasing
        if (protocol_version >= 5 and out.creation_height < max_input_height) {
            return .{ .ok = false, .err = ConsensusError.NonMonotonicHeight, .output_index = i };
        }
    }

    return .{ .ok = true, .err = null, .output_index = null };
}

// ============================================================================
// Box Size Limits
// ============================================================================

/// Verify box and proposition size limits.
/// - txBoxSize: box must not exceed MAX_BOX_SIZE (4KB)
/// - txBoxPropositionSize: proposition must not exceed MAX_PROPOSITION_SIZE (4KB)
///
/// Reference: ValidationRules.scala:121-122
pub fn verifyBoxSizes(outputs: []const Output) struct { ok: bool, err: ?ConsensusError, output_index: ?usize } {
    for (outputs, 0..) |*out, i| {
        // Check proposition size
        if (out.ergo_tree.len > MAX_PROPOSITION_SIZE) {
            return .{ .ok = false, .err = ConsensusError.PropositionTooLarge, .output_index = i };
        }

        // Check total box size
        const box_size = estimateBoxSize(out);
        if (box_size > MAX_BOX_SIZE) {
            return .{ .ok = false, .err = ConsensusError.BoxTooLarge, .output_index = i };
        }
    }

    return .{ .ok = true, .err = null, .output_index = null };
}

// ============================================================================
// Token Limits
// ============================================================================

/// Verify token constraints on outputs.
/// - txAssetsInOneBox: max 127 tokens per box
/// - txPositiveAssets: all token amounts must be positive
///
/// Reference: ValidationRules.scala:108-109
pub fn verifyTokenConstraints(outputs: []const Output) struct { ok: bool, err: ?ConsensusError, output_index: ?usize } {
    for (outputs, 0..) |out, i| {
        // Check token count per box
        if (out.tokens.len > MAX_TOKENS_PER_BOX) {
            return .{ .ok = false, .err = ConsensusError.TooManyTokensInBox, .output_index = i };
        }

        // Check all token amounts are positive
        for (out.tokens) |token| {
            if (token.amount <= 0) {
                return .{ .ok = false, .err = ConsensusError.NonPositiveTokenAmount, .output_index = i };
            }
        }
    }

    return .{ .ok = true, .err = null, .output_index = null };
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

// ============================================================================
// Dust Prevention Tests
// ============================================================================

test "consensus: dust check passes for sufficient value" {
    const ergo_tree = [_]u8{0x00} ** 10; // Small ErgoTree
    // Box size estimate: ~15 bytes, min value ~5400 nanoErgs
    const outputs = [_]Output{Output.init(10000, &ergo_tree, 100)};

    const result = verifyNoDust(&outputs);
    try std.testing.expect(result.ok);
}

test "consensus: dust check fails for insufficient value" {
    const ergo_tree = [_]u8{0x00} ** 100; // Larger ErgoTree
    // Box size estimate: ~105 bytes, min value ~37800 nanoErgs
    const outputs = [_]Output{Output.init(100, &ergo_tree, 100)}; // Way below minimum

    const result = verifyNoDust(&outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.DustOutput, result.err.?);
    try std.testing.expectEqual(@as(usize, 0), result.output_index.?);
}

test "consensus: minimalErgoAmount calculation" {
    const min_100 = minimalErgoAmount(100);
    try std.testing.expectEqual(@as(i64, 36000), min_100); // 100 * 360

    const min_1000 = minimalErgoAmount(1000);
    try std.testing.expectEqual(@as(i64, 360000), min_1000); // 1000 * 360
}

// ============================================================================
// Creation Height Tests
// ============================================================================

test "consensus: creation height valid" {
    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{Output.init(1000000, &ergo_tree, 100)};
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].creation_height = 50;

    // Current height 200, output height 100 - valid
    const result = verifyCreationHeights(&outputs, &inputs, 200, 5);
    try std.testing.expect(result.ok);
}

test "consensus: creation height in future rejected" {
    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{Output.init(1000000, &ergo_tree, 500)}; // Height 500
    const inputs = [_]BoxView{std.mem.zeroes(BoxView)};

    // Current height 100, output height 500 - invalid (future)
    const result = verifyCreationHeights(&outputs, &inputs, 100, 5);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.FutureCreationHeight, result.err.?);
}

test "consensus: non-monotonic height rejected (v5+)" {
    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{Output.init(1000000, &ergo_tree, 50)}; // Height 50
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].creation_height = 100; // Input from height 100

    // Output height 50 < input height 100 - invalid for v5+
    const result = verifyCreationHeights(&outputs, &inputs, 200, 5);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.NonMonotonicHeight, result.err.?);
}

test "consensus: non-monotonic height allowed (v4)" {
    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{Output.init(1000000, &ergo_tree, 50)}; // Height 50
    var inputs = [_]BoxView{std.mem.zeroes(BoxView)};
    inputs[0].creation_height = 100; // Input from height 100

    // Output height 50 < input height 100 - allowed for v4
    const result = verifyCreationHeights(&outputs, &inputs, 200, 4);
    try std.testing.expect(result.ok);
}

// ============================================================================
// Box Size Tests
// ============================================================================

test "consensus: box size within limit" {
    const ergo_tree = [_]u8{0x00} ** 100; // 100 byte ErgoTree
    const outputs = [_]Output{Output.init(1000000, &ergo_tree, 100)};

    const result = verifyBoxSizes(&outputs);
    try std.testing.expect(result.ok);
}

test "consensus: proposition too large rejected" {
    // Create ErgoTree larger than 4KB
    var large_tree: [4097]u8 = undefined;
    @memset(&large_tree, 0x00);
    const outputs = [_]Output{Output.init(1000000, &large_tree, 100)};

    const result = verifyBoxSizes(&outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.PropositionTooLarge, result.err.?);
}

// ============================================================================
// Token Constraint Tests
// ============================================================================

test "consensus: token constraints valid" {
    const token_id = [_]u8{0xAA} ** 32;
    const tokens = [_]Token{.{ .id = token_id, .amount = 100 }};

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(1000000, &ergo_tree, 100)};
    outputs[0].tokens = &tokens;

    const result = verifyTokenConstraints(&outputs);
    try std.testing.expect(result.ok);
}

test "consensus: non-positive token amount rejected" {
    const token_id = [_]u8{0xAA} ** 32;
    const tokens = [_]Token{.{ .id = token_id, .amount = 0 }}; // Zero amount

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(1000000, &ergo_tree, 100)};
    outputs[0].tokens = &tokens;

    const result = verifyTokenConstraints(&outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.NonPositiveTokenAmount, result.err.?);
}

test "consensus: negative token amount rejected" {
    const token_id = [_]u8{0xAA} ** 32;
    const tokens = [_]Token{.{ .id = token_id, .amount = -50 }}; // Negative amount

    const ergo_tree = [_]u8{0x00};
    var outputs = [_]Output{Output.init(1000000, &ergo_tree, 100)};
    outputs[0].tokens = &tokens;

    const result = verifyTokenConstraints(&outputs);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqual(ConsensusError.NonPositiveTokenAmount, result.err.?);
}
