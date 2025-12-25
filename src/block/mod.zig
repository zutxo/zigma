//! Block Verification Module
//!
//! Provides data-oriented block and transaction verification for Ergo blockchain.
//!
//! Features:
//! - Full validation: script verification + consensus rules
//! - Pre-allocated pools for batch processing
//! - HTTP client for node API or JSON input
//!
//! Usage:
//! ```zig
//! const block = @import("block");
//! var verifier = block.BlockVerifier.init(utxo_source);
//! const result = verifier.verifyBlock(&blk);
//! ```

pub const transaction = @import("transaction.zig");
pub const block = @import("block.zig");
pub const utxo = @import("utxo.zig");
pub const merkle = @import("merkle.zig");
pub const consensus = @import("consensus.zig");
pub const verifier = @import("verifier.zig");
pub const http = @import("http.zig");
pub const json_parser = @import("json_parser.zig");
pub const cost = @import("cost.zig");
pub const http_utxo = @import("http_utxo.zig");

// Re-export commonly used types
pub const Transaction = transaction.Transaction;
pub const Input = transaction.Input;
pub const Output = transaction.Output;
pub const SpendingProof = transaction.SpendingProof;
pub const Block = block.Block;
pub const BlockStorage = block.BlockStorage;
pub const Extension = block.Extension;
pub const UtxoSource = utxo.UtxoSource;
pub const MemoryUtxoSet = utxo.MemoryUtxoSet;
pub const UtxoStorage = utxo.UtxoStorage;
pub const computeBoxId = utxo.computeBoxId;
pub const BlockVerifier = verifier.BlockVerifier;
pub const BlockVerifyResult = verifier.BlockVerifyResult;
pub const TxVerifyResult = verifier.TxVerifyResult;
pub const InputVerifyResult = verifier.InputVerifyResult;
pub const VerificationError = verifier.VerificationError;
pub const BugCategory = verifier.BugCategory;
pub const ErgoNodeClient = http.ErgoNodeClient;
pub const HttpUtxoSource = http_utxo.HttpUtxoSource;

// Consensus validation exports
pub const ConsensusError = consensus.ConsensusError;
pub const verifyNoDust = consensus.verifyNoDust;
pub const verifyCreationHeights = consensus.verifyCreationHeights;
pub const verifyBoxSizes = consensus.verifyBoxSizes;
pub const verifyTokenConstraints = consensus.verifyTokenConstraints;
pub const minimalErgoAmount = consensus.minimalErgoAmount;
pub const estimateBoxSize = consensus.estimateBoxSize;

// Protocol constants
pub const MAX_TOKENS_PER_BOX = consensus.MAX_TOKENS_PER_BOX;
pub const MAX_BOX_SIZE = consensus.MAX_BOX_SIZE;
pub const MAX_PROPOSITION_SIZE = consensus.MAX_PROPOSITION_SIZE;
pub const MIN_VALUE_PER_BYTE = consensus.MIN_VALUE_PER_BYTE;

// Merkle v2+ exports
pub const computeWitnessId = merkle.computeWitnessId;
pub const computeWitnessIds = merkle.computeWitnessIds;
pub const computeTxMerkleRootV2 = merkle.computeTxMerkleRootV2;
pub const computeVersionedMerkleRoot = merkle.computeVersionedMerkleRoot;
pub const verifyTxMerkleRootVersioned = merkle.verifyTxMerkleRootVersioned;
pub const INITIAL_VERSION = merkle.INITIAL_VERSION;
pub const WITNESS_ID_SIZE = merkle.WITNESS_ID_SIZE;

// Cost accounting exports
pub const JitCost = cost.JitCost;
pub const CostParameters = cost.CostParameters;
pub const computeInitialTxCost = cost.computeInitialTxCost;
pub const computeInitialTxCostDefault = cost.computeInitialTxCostDefault;
pub const computeTxInitialCost = cost.computeTxInitialCost;
pub const computeTxInitialCostDefault = cost.computeTxInitialCostDefault;
pub const estimateTxCost = cost.estimateTxCost;
pub const wouldExceedCostLimit = cost.wouldExceedCostLimit;
pub const INTERPRETER_INIT_COST = cost.INTERPRETER_INIT_COST;
pub const INPUT_COST_DEFAULT = cost.INPUT_COST_DEFAULT;
pub const DATA_INPUT_COST_DEFAULT = cost.DATA_INPUT_COST_DEFAULT;
pub const OUTPUT_COST_DEFAULT = cost.OUTPUT_COST_DEFAULT;
pub const JIT_COST_SCALE = cost.JIT_COST_SCALE;
pub const MAX_BLOCK_COST_DEFAULT = cost.MAX_BLOCK_COST_DEFAULT;

test {
    @import("std").testing.refAllDecls(@This());
}
