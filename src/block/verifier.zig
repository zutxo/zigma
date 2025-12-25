//! Block Verifier
//!
//! Main verification logic for blocks and transactions.
//! Uses data-oriented design with pre-allocated pools for batch processing.

const std = @import("std");
const context_mod = @import("../interpreter/context.zig");
const evaluator_mod = @import("../interpreter/evaluator.zig");
const pipeline_mod = @import("../sigma/pipeline.zig");
const ergotree_serializer = @import("../serialization/ergotree_serializer.zig");
const types_mod = @import("../core/types.zig");
const memory_mod = @import("../interpreter/memory.zig");
const transaction = @import("transaction.zig");
const block_mod = @import("block.zig");
const utxo_mod = @import("utxo.zig");
const merkle = @import("merkle.zig");
const consensus = @import("consensus.zig");

pub const Context = context_mod.Context;
pub const BoxView = context_mod.BoxView;
pub const HeaderView = context_mod.HeaderView;
pub const PreHeaderView = context_mod.PreHeaderView;
pub const VersionContext = context_mod.VersionContext;
pub const Evaluator = evaluator_mod.Evaluator;
pub const Transaction = transaction.Transaction;
pub const Input = transaction.Input;
pub const Output = transaction.Output;
pub const Block = block_mod.Block;
pub const UtxoSource = utxo_mod.UtxoSource;
pub const ConsensusResult = consensus.ConsensusResult;

/// Maximum inputs per transaction for verification
pub const MAX_INPUTS: u16 = 256;

/// Maximum transactions per block for verification
pub const MAX_TRANSACTIONS: u16 = 512;

/// Default cost limit per transaction (10M)
pub const DEFAULT_TX_COST_LIMIT: u64 = 10_000_000;

// ============================================================================
// Verification Errors
// ============================================================================

/// Verification error types
pub const VerificationError = error{
    // Script verification
    ScriptEvaluationFailed,
    ProofVerificationFailed,
    CostLimitExceeded,
    ScriptDeserializationFailed,

    // Consensus rules
    ValueImbalance,
    TokenConservationViolation,
    InvalidMerkleRoot,

    // Structural
    EmptyBlock,
    TooManyTransactions,
    TooManyInputs,
    DuplicateInput,

    // UTXO
    UtxoNotFound,
    UtxoLookupFailed,

    // Internal
    InternalError,
};

// ============================================================================
// Result Types
// ============================================================================

/// Result of verifying a single input
pub const InputVerifyResult = struct {
    /// Input index in transaction
    input_index: u16,
    /// Whether verification passed
    valid: bool,
    /// Error if invalid
    err: ?VerificationError,
    /// Cost consumed
    cost: u64,

    /// Create success result
    pub fn success(input_index: u16, cost: u64) InputVerifyResult {
        return .{
            .input_index = input_index,
            .valid = true,
            .err = null,
            .cost = cost,
        };
    }

    /// Create failure result
    pub fn failure(input_index: u16, err: VerificationError) InputVerifyResult {
        return .{
            .input_index = input_index,
            .valid = false,
            .err = err,
            .cost = 0,
        };
    }
};

/// Result of verifying a transaction
pub const TxVerifyResult = struct {
    /// Transaction index in block
    tx_index: u16,
    /// Whether all verifications passed
    valid: bool,
    /// First error encountered (if any)
    first_error: ?VerificationError,
    /// Per-input results
    input_results: [MAX_INPUTS]InputVerifyResult,
    /// Number of inputs verified
    input_count: u16,
    /// Total cost consumed
    total_cost: u64,
    /// Consensus check results
    consensus_result: ?ConsensusResult,

    /// Create empty result
    pub fn init(tx_index: u16) TxVerifyResult {
        return .{
            .tx_index = tx_index,
            .valid = true,
            .first_error = null,
            .input_results = undefined,
            .input_count = 0,
            .total_cost = 0,
            .consensus_result = null,
        };
    }

    /// Add input result
    pub fn addInputResult(self: *TxVerifyResult, result: InputVerifyResult) void {
        if (self.input_count < MAX_INPUTS) {
            self.input_results[self.input_count] = result;
            self.input_count += 1;
            self.total_cost += result.cost;

            if (!result.valid) {
                self.valid = false;
                if (self.first_error == null) {
                    self.first_error = result.err;
                }
            }
        }
    }

    /// Set consensus result
    pub fn setConsensusResult(self: *TxVerifyResult, result: ConsensusResult) void {
        self.consensus_result = result;
        if (!result.valid) {
            self.valid = false;
            if (self.first_error == null) {
                // Convert consensus error
                if (result.errors[0]) |err| {
                    self.first_error = switch (err) {
                        consensus.ConsensusError.ValueImbalance => VerificationError.ValueImbalance,
                        consensus.ConsensusError.TokenDestroyed, consensus.ConsensusError.UnauthorizedTokenMint => VerificationError.TokenConservationViolation,
                        else => VerificationError.InternalError,
                    };
                }
            }
        }
    }
};

/// Result of verifying a block
pub const BlockVerifyResult = struct {
    /// Block ID
    block_id: [32]u8,
    /// Block height
    height: u32,
    /// Overall validity
    valid: bool,
    /// First error encountered (if any)
    first_error: ?VerificationError,
    /// Per-transaction results
    tx_results: [MAX_TRANSACTIONS]TxVerifyResult,
    /// Number of transactions verified
    tx_count: u16,
    /// Merkle root verification passed
    merkle_valid: bool,
    /// Total cost across all transactions
    total_cost: u64,
    /// Verification time in nanoseconds
    verification_time_ns: u64,

    /// Create empty result for block
    pub fn init(blk: *const Block) BlockVerifyResult {
        return .{
            .block_id = blk.id(),
            .height = blk.height(),
            .valid = true,
            .first_error = null,
            .tx_results = undefined,
            .tx_count = 0,
            .merkle_valid = false,
            .total_cost = 0,
            .verification_time_ns = 0,
        };
    }

    /// Add transaction result
    pub fn addTxResult(self: *BlockVerifyResult, result: TxVerifyResult) void {
        if (self.tx_count < MAX_TRANSACTIONS) {
            self.tx_results[self.tx_count] = result;
            self.tx_count += 1;
            self.total_cost += result.total_cost;

            if (!result.valid) {
                self.valid = false;
                if (self.first_error == null) {
                    self.first_error = result.first_error;
                }
            }
        }
    }

    /// Set Merkle verification result
    pub fn setMerkleResult(self: *BlockVerifyResult, valid: bool) void {
        self.merkle_valid = valid;
        if (!valid) {
            self.valid = false;
            if (self.first_error == null) {
                self.first_error = VerificationError.InvalidMerkleRoot;
            }
        }
    }

    /// Get summary statistics
    pub fn stats(self: *const BlockVerifyResult) struct {
        total_txs: u16,
        valid_txs: u16,
        failed_txs: u16,
        total_inputs: u32,
        total_cost: u64,
    } {
        var valid_txs: u16 = 0;
        var total_inputs: u32 = 0;

        for (self.tx_results[0..self.tx_count]) |tx| {
            if (tx.valid) valid_txs += 1;
            total_inputs += tx.input_count;
        }

        return .{
            .total_txs = self.tx_count,
            .valid_txs = valid_txs,
            .failed_txs = self.tx_count - valid_txs,
            .total_inputs = total_inputs,
            .total_cost = self.total_cost,
        };
    }
};

// ============================================================================
// Block Verifier
// ============================================================================

/// Block verifier with pre-allocated resources.
/// Designed for batch processing with O(1) reset between blocks.
pub const BlockVerifier = struct {
    /// UTXO source for input box lookup
    utxo_source: UtxoSource,

    /// Cost limit per transaction
    tx_cost_limit: u64,

    /// Protocol version context
    version: VersionContext,

    /// Pre-allocated storage for resolved input boxes
    resolved_inputs: [MAX_INPUTS]BoxView,
    resolved_count: u16,

    /// Pre-allocated storage for output boxes (as BoxView for context)
    output_boxes: [MAX_INPUTS]BoxView,
    output_count: u16,

    /// Expression tree buffer for deserialization
    expr_buffer: [64 * 1024]u8,

    /// Statistics
    blocks_verified: u64,
    txs_verified: u64,
    inputs_verified: u64,
    total_cost: u64,

    /// Initialize verifier with UTXO source
    pub fn init(utxo_source: UtxoSource) BlockVerifier {
        return .{
            .utxo_source = utxo_source,
            .tx_cost_limit = DEFAULT_TX_COST_LIMIT,
            .version = VersionContext.v2(),
            .resolved_inputs = undefined,
            .resolved_count = 0,
            .output_boxes = undefined,
            .output_count = 0,
            .expr_buffer = undefined,
            .blocks_verified = 0,
            .txs_verified = 0,
            .inputs_verified = 0,
            .total_cost = 0,
        };
    }

    /// Reset state for new block (O(1))
    pub fn reset(self: *BlockVerifier) void {
        self.resolved_count = 0;
        self.output_count = 0;
    }

    /// Set cost limit per transaction
    pub fn setCostLimit(self: *BlockVerifier, limit: u64) void {
        self.tx_cost_limit = limit;
    }

    /// Set protocol version
    pub fn setVersion(self: *BlockVerifier, version: VersionContext) void {
        self.version = version;
    }

    /// Get verification statistics
    pub fn getStats(self: *const BlockVerifier) struct {
        blocks: u64,
        txs: u64,
        inputs: u64,
        cost: u64,
    } {
        return .{
            .blocks = self.blocks_verified,
            .txs = self.txs_verified,
            .inputs = self.inputs_verified,
            .cost = self.total_cost,
        };
    }

    /// Reset statistics
    pub fn resetStats(self: *BlockVerifier) void {
        self.blocks_verified = 0;
        self.txs_verified = 0;
        self.inputs_verified = 0;
        self.total_cost = 0;
    }

    // ========================================================================
    // Block Verification
    // ========================================================================

    /// Verify a complete block
    pub fn verifyBlock(self: *BlockVerifier, blk: *const Block) BlockVerifyResult {
        const start_time = std.time.nanoTimestamp();
        var result = BlockVerifyResult.init(blk);

        // Check for empty block
        if (blk.transactions.len == 0) {
            result.valid = false;
            result.first_error = VerificationError.EmptyBlock;
            return result;
        }

        // Check transaction count
        if (blk.transactions.len > MAX_TRANSACTIONS) {
            result.valid = false;
            result.first_error = VerificationError.TooManyTransactions;
            return result;
        }

        // Verify Merkle root
        const merkle_valid = merkle.verifyTxMerkleRoot(blk);
        result.setMerkleResult(merkle_valid);

        // Verify each transaction
        for (blk.transactions, 0..) |tx, i| {
            self.reset(); // Reset per-transaction state
            const tx_result = self.verifyTransaction(&tx, blk.height(), @intCast(i));
            result.addTxResult(tx_result);
        }

        // Record timing
        const end_time = std.time.nanoTimestamp();
        result.verification_time_ns = @intCast(end_time - start_time);

        // Update statistics
        self.blocks_verified += 1;
        self.txs_verified += blk.transactions.len;
        self.total_cost += result.total_cost;

        return result;
    }

    // ========================================================================
    // Transaction Verification
    // ========================================================================

    /// Verify a single transaction
    pub fn verifyTransaction(
        self: *BlockVerifier,
        tx: *const Transaction,
        height: u32,
        tx_index: u16,
    ) TxVerifyResult {
        var result = TxVerifyResult.init(tx_index);

        // Check input count
        if (tx.inputs.len > MAX_INPUTS) {
            result.valid = false;
            result.first_error = VerificationError.TooManyInputs;
            return result;
        }

        // Resolve all input boxes from UTXO set
        for (tx.inputs, 0..) |input, i| {
            const lookup = self.utxo_source.lookup(&input.box_id);
            switch (lookup) {
                .found => |box| {
                    self.resolved_inputs[i] = box;
                    self.resolved_count += 1;
                },
                .not_found => {
                    result.addInputResult(InputVerifyResult.failure(@intCast(i), VerificationError.UtxoNotFound));
                    return result;
                },
                .err => {
                    result.addInputResult(InputVerifyResult.failure(@intCast(i), VerificationError.UtxoLookupFailed));
                    return result;
                },
            }
        }

        // Convert outputs to BoxView format for context
        for (tx.outputs, 0..) |out, i| {
            self.output_boxes[i] = outputToBoxView(&out, tx.id, @intCast(i), height);
            self.output_count += 1;
        }

        // Verify consensus rules
        const consensus_result = consensus.verifyConsensus(
            self.resolved_inputs[0..self.resolved_count],
            tx,
        );
        result.setConsensusResult(consensus_result);

        if (!consensus_result.valid) {
            return result;
        }

        // Verify each input script
        const message = &tx.id; // Transaction ID is the message
        for (tx.inputs, 0..) |input, i| {
            const input_result = self.verifyInput(
                &input,
                &self.resolved_inputs[i],
                @intCast(i),
                height,
                message,
            );
            result.addInputResult(input_result);
            self.inputs_verified += 1;
        }

        return result;
    }

    // ========================================================================
    // Input Verification
    // ========================================================================

    /// Verify a single input (script + proof)
    pub fn verifyInput(
        self: *BlockVerifier,
        input: *const Input,
        input_box: *const BoxView,
        input_index: u16,
        height: u32,
        message: []const u8,
    ) InputVerifyResult {
        // Build execution context
        const ctx = Context{
            .inputs = self.resolved_inputs[0..self.resolved_count],
            .outputs = self.output_boxes[0..self.output_count],
            .data_inputs = &[_]BoxView{}, // TODO: resolve data inputs
            .self_index = input_index,
            .height = height,
            .headers = &[_]HeaderView{}, // TODO: populate headers
            .pre_header = std.mem.zeroes(PreHeaderView),
            .context_vars = [_]?[]const u8{null} ** 256,
            .extension_cache = null,
        };

        // Deserialize ErgoTree
        var type_pool = types_mod.TypePool.init();
        var tree = ergotree_serializer.ErgoTree.init(&type_pool);
        var arena = memory_mod.BumpAllocator(4096).init();

        ergotree_serializer.deserialize(&tree, input_box.proposition_bytes, &arena) catch {
            return InputVerifyResult.failure(input_index, VerificationError.ScriptDeserializationFailed);
        };

        // Create evaluator
        var eval = Evaluator.init(&tree.expr_tree, &ctx);
        eval.setCostLimit(self.tx_cost_limit);

        // Verify: reduce to SigmaBoolean and verify proof
        const verify_result = pipeline_mod.reduceAndVerify(
            &eval,
            input.spending_proof.slice(),
            message,
            self.tx_cost_limit,
        ) catch |err| {
            return InputVerifyResult.failure(input_index, switch (err) {
                pipeline_mod.PipelineError.CostLimitExceeded => VerificationError.CostLimitExceeded,
                pipeline_mod.PipelineError.VerificationFailed => VerificationError.ProofVerificationFailed,
                else => VerificationError.ScriptEvaluationFailed,
            });
        };

        if (!verify_result.valid) {
            return InputVerifyResult.failure(input_index, VerificationError.ProofVerificationFailed);
        }

        return InputVerifyResult.success(input_index, verify_result.cost);
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert Output to BoxView for context building
fn outputToBoxView(out: *const Output, tx_id: [32]u8, index: u16, height: u32) BoxView {
    return BoxView{
        .id = computeBoxId(tx_id, index),
        .value = out.value,
        .proposition_bytes = out.ergo_tree,
        .creation_height = height,
        .tx_id = tx_id,
        .index = index,
        .tokens = out.tokens,
        .registers = out.registers,
    };
}

/// Compute box ID from transaction ID and output index
/// BoxId = Blake2b256(tx_id || output_index_as_u16_be)
fn computeBoxId(tx_id: [32]u8, index: u16) [32]u8 {
    const hash = @import("../crypto/hash.zig");
    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(&tx_id);
    const idx_bytes = [2]u8{
        @intCast((index >> 8) & 0xFF),
        @intCast(index & 0xFF),
    };
    hasher.update(&idx_bytes);
    return hasher.finalize();
}

// ============================================================================
// Tests
// ============================================================================

test "verifier: InputVerifyResult creation" {
    const success = InputVerifyResult.success(5, 1000);
    try std.testing.expect(success.valid);
    try std.testing.expectEqual(@as(u16, 5), success.input_index);
    try std.testing.expectEqual(@as(u64, 1000), success.cost);

    const failure = InputVerifyResult.failure(3, VerificationError.UtxoNotFound);
    try std.testing.expect(!failure.valid);
    try std.testing.expectEqual(@as(u16, 3), failure.input_index);
    try std.testing.expectEqual(VerificationError.UtxoNotFound, failure.err.?);
}

test "verifier: TxVerifyResult accumulates" {
    var result = TxVerifyResult.init(0);

    result.addInputResult(InputVerifyResult.success(0, 100));
    result.addInputResult(InputVerifyResult.success(1, 200));

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(u16, 2), result.input_count);
    try std.testing.expectEqual(@as(u64, 300), result.total_cost);
}

test "verifier: TxVerifyResult marks invalid on failure" {
    var result = TxVerifyResult.init(0);

    result.addInputResult(InputVerifyResult.success(0, 100));
    result.addInputResult(InputVerifyResult.failure(1, VerificationError.ProofVerificationFailed));

    try std.testing.expect(!result.valid);
    try std.testing.expectEqual(VerificationError.ProofVerificationFailed, result.first_error.?);
}

test "verifier: BlockVerifyResult stats" {
    var header = std.mem.zeroes(HeaderView);
    header.height = 100;

    const blk = Block.init(header, &[_]Transaction{});
    var result = BlockVerifyResult.init(&blk);

    var tx_result = TxVerifyResult.init(0);
    tx_result.addInputResult(InputVerifyResult.success(0, 500));
    tx_result.addInputResult(InputVerifyResult.success(1, 500));
    result.addTxResult(tx_result);

    const s = result.stats();
    try std.testing.expectEqual(@as(u16, 1), s.total_txs);
    try std.testing.expectEqual(@as(u16, 1), s.valid_txs);
    try std.testing.expectEqual(@as(u32, 2), s.total_inputs);
    try std.testing.expectEqual(@as(u64, 1000), s.total_cost);
}

test "verifier: computeBoxId deterministic" {
    const tx_id = [_]u8{0xAB} ** 32;
    const id1 = computeBoxId(tx_id, 0);
    const id2 = computeBoxId(tx_id, 0);

    try std.testing.expectEqualSlices(u8, &id1, &id2);
}

test "verifier: computeBoxId different for different index" {
    const tx_id = [_]u8{0xAB} ** 32;
    const id0 = computeBoxId(tx_id, 0);
    const id1 = computeBoxId(tx_id, 1);

    try std.testing.expect(!std.mem.eql(u8, &id0, &id1));
}

test "verifier: BlockVerifier init and reset" {
    var box_ids = [_][32]u8{[_]u8{0xAA} ** 32};
    var boxes = [_]BoxView{std.mem.zeroes(BoxView)};
    var utxo_set = utxo_mod.MemoryUtxoSet.init(&boxes, &box_ids);

    var verifier = BlockVerifier.init(utxo_set.asSource());
    verifier.resolved_count = 10;

    verifier.reset();

    try std.testing.expectEqual(@as(u16, 0), verifier.resolved_count);
}
