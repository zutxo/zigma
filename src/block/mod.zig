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
pub const ErgoNodeClient = http.ErgoNodeClient;

test {
    @import("std").testing.refAllDecls(@This());
}
