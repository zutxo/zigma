//! Transaction Cost Accounting
//!
//! Provides cost calculation for Ergo transactions according to protocol rules.
//!
//! Cost Types:
//! - JitCost: 10x more accurate scale used by JITC interpreter internally
//! - BlockCost: Scale used for block-level cost limits
//!
//! Initial Transaction Cost Formula:
//!   initialCost = interpreterInitCost
//!               + (inputs.size * inputCost)
//!               + (dataInputs.size * dataInputCost)
//!               + (outputs.size * outputCost)
//!
//! References:
//! - JitCost.scala: sigma/ast/JitCost.scala
//! - Parameters.scala: org/ergoplatform/settings/Parameters.scala
//! - ErgoTransaction.scala:370-374

const std = @import("std");
const transaction = @import("transaction.zig");

pub const Transaction = transaction.Transaction;

// ============================================================================
// Protocol Cost Constants (Default Values)
// ============================================================================

/// Interpreter initialization cost (block cost units)
/// Reference: ErgoInterpreter.scala:96, Interpreter.scala:514
pub const INTERPRETER_INIT_COST: u64 = 10000;

/// Cost per transaction input (block cost units)
/// Reference: Parameters.scala:308
pub const INPUT_COST_DEFAULT: u64 = 2000;

/// Cost per data input (block cost units)
/// Reference: Parameters.scala:310
pub const DATA_INPUT_COST_DEFAULT: u64 = 100;

/// Cost per transaction output (block cost units)
/// Reference: Parameters.scala:312
pub const OUTPUT_COST_DEFAULT: u64 = 100;

/// JIT cost scale factor (JIT units are 10x block cost)
/// Reference: JitCost.scala:29
pub const JIT_COST_SCALE: u64 = 10;

/// Default maximum block cost
/// Reference: Parameters.scala
pub const MAX_BLOCK_COST_DEFAULT: u64 = 1_000_000;

// ============================================================================
// JitCost Type
// ============================================================================

/// Represents cost in JIT (Just-In-Time compiler) scale.
/// JIT costs are 10x more accurate than block costs.
///
/// Reference: JitCost.scala
pub const JitCost = struct {
    /// Cost value in JIT units
    value: u64,

    /// Create a JitCost from a raw value
    pub fn init(value: u64) JitCost {
        return .{ .value = value };
    }

    /// Create JitCost from block cost (scales up by 10x)
    /// Reference: JitCost.scala:34
    pub fn fromBlockCost(block_cost: u64) JitCost {
        return .{ .value = block_cost * JIT_COST_SCALE };
    }

    /// Convert to block cost (scales down by 10x)
    /// Reference: JitCost.scala:29
    pub fn toBlockCost(self: JitCost) u64 {
        return self.value / JIT_COST_SCALE;
    }

    /// Add two JitCost values
    pub fn add(self: JitCost, other: JitCost) JitCost {
        return .{ .value = self.value + other.value };
    }

    /// Multiply by an integer
    pub fn mul(self: JitCost, n: u64) JitCost {
        return .{ .value = self.value * n };
    }

    /// Divide by an integer
    pub fn div(self: JitCost, n: u64) JitCost {
        return .{ .value = self.value / n };
    }

    /// Check if greater than another JitCost
    pub fn greaterThan(self: JitCost, other: JitCost) bool {
        return self.value > other.value;
    }

    /// Check if greater than or equal to another JitCost
    pub fn greaterThanOrEqual(self: JitCost, other: JitCost) bool {
        return self.value >= other.value;
    }
};

// ============================================================================
// Cost Parameters
// ============================================================================

/// Configurable cost parameters for transaction validation.
/// These can be updated via soft-fork protocol changes.
pub const CostParameters = struct {
    /// Cost per input box
    input_cost: u64,
    /// Cost per data input (read-only)
    data_input_cost: u64,
    /// Cost per output box
    output_cost: u64,
    /// Interpreter initialization cost
    interpreter_init_cost: u64,
    /// Maximum cost per transaction
    max_tx_cost: u64,
    /// Maximum cost per block
    max_block_cost: u64,

    /// Create with default mainnet values
    pub fn defaults() CostParameters {
        return .{
            .input_cost = INPUT_COST_DEFAULT,
            .data_input_cost = DATA_INPUT_COST_DEFAULT,
            .output_cost = OUTPUT_COST_DEFAULT,
            .interpreter_init_cost = INTERPRETER_INIT_COST,
            .max_tx_cost = MAX_BLOCK_COST_DEFAULT / 10, // Typical limit
            .max_block_cost = MAX_BLOCK_COST_DEFAULT,
        };
    }

    /// Create with custom values
    pub fn init(
        input_cost: u64,
        data_input_cost: u64,
        output_cost: u64,
        interpreter_init_cost: u64,
        max_tx_cost: u64,
        max_block_cost: u64,
    ) CostParameters {
        return .{
            .input_cost = input_cost,
            .data_input_cost = data_input_cost,
            .output_cost = output_cost,
            .interpreter_init_cost = interpreter_init_cost,
            .max_tx_cost = max_tx_cost,
            .max_block_cost = max_block_cost,
        };
    }
};

// ============================================================================
// Initial Transaction Cost
// ============================================================================

/// Compute the initial cost for a transaction before script evaluation.
/// This is the baseline cost based on transaction structure.
///
/// Formula: interpreterInitCost + (inputs * inputCost) + (dataInputs * dataInputCost) + (outputs * outputCost)
///
/// Reference: ErgoTransaction.scala:370-374
pub fn computeInitialTxCost(
    input_count: usize,
    data_input_count: usize,
    output_count: usize,
    params: *const CostParameters,
) u64 {
    return params.interpreter_init_cost +
        (@as(u64, @intCast(input_count)) * params.input_cost) +
        (@as(u64, @intCast(data_input_count)) * params.data_input_cost) +
        (@as(u64, @intCast(output_count)) * params.output_cost);
}

/// Compute initial cost using default parameters
pub fn computeInitialTxCostDefault(
    input_count: usize,
    data_input_count: usize,
    output_count: usize,
) u64 {
    return INTERPRETER_INIT_COST +
        (@as(u64, @intCast(input_count)) * INPUT_COST_DEFAULT) +
        (@as(u64, @intCast(data_input_count)) * DATA_INPUT_COST_DEFAULT) +
        (@as(u64, @intCast(output_count)) * OUTPUT_COST_DEFAULT);
}

/// Compute initial cost for a Transaction struct
pub fn computeTxInitialCost(tx: *const Transaction, params: *const CostParameters) u64 {
    return computeInitialTxCost(
        tx.inputs.len,
        tx.data_inputs.len,
        tx.outputs.len,
        params,
    );
}

/// Compute initial cost for a Transaction using defaults
pub fn computeTxInitialCostDefault(tx: *const Transaction) u64 {
    return computeInitialTxCostDefault(
        tx.inputs.len,
        tx.data_inputs.len,
        tx.outputs.len,
    );
}

// ============================================================================
// Cost Estimation
// ============================================================================

/// Estimate total transaction cost including script evaluation.
/// Returns (initial_cost, estimated_script_cost, total_estimated).
///
/// Script cost estimation is approximate - actual cost depends on execution.
pub fn estimateTxCost(
    tx: *const Transaction,
    avg_script_cost_per_input: u64,
    params: *const CostParameters,
) struct { initial: u64, script_estimate: u64, total: u64 } {
    const initial = computeTxInitialCost(tx, params);
    const script_estimate = @as(u64, @intCast(tx.inputs.len)) * avg_script_cost_per_input;
    return .{
        .initial = initial,
        .script_estimate = script_estimate,
        .total = initial + script_estimate,
    };
}

/// Check if estimated cost exceeds limit
pub fn wouldExceedCostLimit(
    tx: *const Transaction,
    current_cost: u64,
    params: *const CostParameters,
) bool {
    const initial = computeTxInitialCost(tx, params);
    return (current_cost + initial) > params.max_block_cost;
}

// ============================================================================
// Tests
// ============================================================================

test "cost: JitCost toBlockCost" {
    const jit = JitCost.init(1000);
    try std.testing.expectEqual(@as(u64, 100), jit.toBlockCost());
}

test "cost: JitCost fromBlockCost roundtrip" {
    const block_cost: u64 = 500;
    const jit = JitCost.fromBlockCost(block_cost);
    try std.testing.expectEqual(@as(u64, 5000), jit.value);
    try std.testing.expectEqual(block_cost, jit.toBlockCost());
}

test "cost: JitCost arithmetic" {
    const a = JitCost.init(100);
    const b = JitCost.init(50);

    const sum = a.add(b);
    try std.testing.expectEqual(@as(u64, 150), sum.value);

    const product = a.mul(3);
    try std.testing.expectEqual(@as(u64, 300), product.value);

    const quotient = a.div(2);
    try std.testing.expectEqual(@as(u64, 50), quotient.value);
}

test "cost: JitCost comparison" {
    const a = JitCost.init(100);
    const b = JitCost.init(50);

    try std.testing.expect(a.greaterThan(b));
    try std.testing.expect(a.greaterThanOrEqual(b));
    try std.testing.expect(a.greaterThanOrEqual(a));
    try std.testing.expect(!b.greaterThan(a));
}

test "cost: default parameters" {
    const params = CostParameters.defaults();
    try std.testing.expectEqual(INPUT_COST_DEFAULT, params.input_cost);
    try std.testing.expectEqual(DATA_INPUT_COST_DEFAULT, params.data_input_cost);
    try std.testing.expectEqual(OUTPUT_COST_DEFAULT, params.output_cost);
    try std.testing.expectEqual(INTERPRETER_INIT_COST, params.interpreter_init_cost);
}

test "cost: initial tx cost calculation" {
    const params = CostParameters.defaults();

    // 2 inputs, 1 data input, 3 outputs
    const cost = computeInitialTxCost(2, 1, 3, &params);

    // Expected: 10000 + (2 * 2000) + (1 * 100) + (3 * 100)
    // = 10000 + 4000 + 100 + 300 = 14400
    try std.testing.expectEqual(@as(u64, 14400), cost);
}

test "cost: initial tx cost default" {
    // Same calculation with default function
    const cost = computeInitialTxCostDefault(2, 1, 3);
    try std.testing.expectEqual(@as(u64, 14400), cost);
}

test "cost: empty tx has interpreter init cost" {
    const cost = computeInitialTxCostDefault(0, 0, 0);
    try std.testing.expectEqual(INTERPRETER_INIT_COST, cost);
}

test "cost: tx initial cost from struct" {
    const input = transaction.Input.fromBoxId([_]u8{0x11} ** 32);
    const ergo_tree = [_]u8{0x00};
    const output = transaction.Output.init(1000, &ergo_tree, 100);

    const tx = Transaction.init(
        [_]u8{0xAA} ** 32,
        &[_]transaction.Input{ input, input }, // 2 inputs
        &[_]transaction.Output{ output, output, output }, // 3 outputs
    );

    const params = CostParameters.defaults();
    const cost = computeTxInitialCost(&tx, &params);

    // Expected: 10000 + (2 * 2000) + (0 * 100) + (3 * 100) = 14300
    try std.testing.expectEqual(@as(u64, 14300), cost);
}

test "cost: estimate includes script cost" {
    const input = transaction.Input.fromBoxId([_]u8{0x11} ** 32);
    const ergo_tree = [_]u8{0x00};
    const output = transaction.Output.init(1000, &ergo_tree, 100);

    const tx = Transaction.init(
        [_]u8{0xAA} ** 32,
        &[_]transaction.Input{input}, // 1 input
        &[_]transaction.Output{output}, // 1 output
    );

    const params = CostParameters.defaults();
    const avg_script_cost: u64 = 5000;
    const estimate = estimateTxCost(&tx, avg_script_cost, &params);

    // Initial: 10000 + 2000 + 0 + 100 = 12100
    try std.testing.expectEqual(@as(u64, 12100), estimate.initial);
    // Script: 1 * 5000 = 5000
    try std.testing.expectEqual(@as(u64, 5000), estimate.script_estimate);
    // Total: 17100
    try std.testing.expectEqual(@as(u64, 17100), estimate.total);
}
