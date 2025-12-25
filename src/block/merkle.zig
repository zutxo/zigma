//! Merkle Tree Computation
//!
//! Computes and verifies Merkle roots for block transactions.
//! Uses Blake2b256 for hashing, matching Ergo protocol.
//!
//! Block version differences:
//! - v1 (InitialVersion): merkle tree of txIds only
//! - v2+: merkle tree of (txIds ++ witnessIds)
//!
//! Witness IDs are 248-bit (31 bytes) hashes of concatenated spending proofs,
//! used to distinguish from 256-bit transaction IDs in the merkle tree.
//!
//! Reference: BlockTransactions.scala:59-63

const std = @import("std");
const hash = @import("../crypto/hash.zig");
const block_mod = @import("block.zig");
const transaction_mod = @import("transaction.zig");

pub const Block = block_mod.Block;
pub const Transaction = transaction_mod.Transaction;
pub const Input = transaction_mod.Input;

/// Block version that uses only txIds (no witness IDs)
pub const INITIAL_VERSION: u8 = 1;

/// Size of witness ID (248 bits = 31 bytes)
pub const WITNESS_ID_SIZE: usize = 31;

/// Maximum tree depth (log2 of max transactions)
pub const MAX_TREE_DEPTH: u16 = 10; // 2^10 = 1024 transactions

/// Maximum nodes at any level
pub const MAX_LEVEL_NODES: u16 = 512;

// ============================================================================
// Witness ID Computation (v2+)
// ============================================================================

/// Compute witness ID for a transaction.
/// Witness ID = Blake2b256(concat(all spending proof bytes)).tail
/// Returns 31 bytes (248 bits) to distinguish from 32-byte tx IDs.
///
/// Reference: ErgoTransaction.scala:74-77
pub fn computeWitnessId(tx: *const Transaction) [WITNESS_ID_SIZE]u8 {
    var hasher = hash.Blake2b256Hasher.init();

    // Concatenate all spending proof bytes
    for (tx.inputs) |input| {
        const proof_bytes = input.spending_proof.slice();
        hasher.update(proof_bytes);
    }

    // Hash and take tail (skip first byte)
    const full_hash = hasher.finalize();
    var witness_id: [WITNESS_ID_SIZE]u8 = undefined;
    @memcpy(&witness_id, full_hash[1..32]);
    return witness_id;
}

/// Compute witness IDs for all transactions in a block.
/// Returns slice of witness IDs (each 31 bytes).
pub fn computeWitnessIds(
    transactions: []const Transaction,
    out: *[MAX_LEVEL_NODES][WITNESS_ID_SIZE]u8,
) []const [WITNESS_ID_SIZE]u8 {
    const count = @min(transactions.len, MAX_LEVEL_NODES);
    for (transactions[0..count], 0..) |*tx, i| {
        out[i] = computeWitnessId(tx);
    }
    return out[0..count];
}

// ============================================================================
// Merkle Root Computation
// ============================================================================

/// Compute Merkle root from a list of transaction IDs.
/// Returns Blake2b256 hash at the root.
///
/// Algorithm:
/// 1. If empty, return all zeros
/// 2. If single tx, return its ID
/// 3. Otherwise, build tree bottom-up:
///    - Hash pairs: Blake2b256(left || right)
///    - Odd node at end is promoted unchanged
///    - Repeat until single root
pub fn computeTxMerkleRoot(tx_ids: []const [32]u8) [32]u8 {
    // Empty case
    if (tx_ids.len == 0) {
        return [_]u8{0} ** 32;
    }

    // Single transaction case
    if (tx_ids.len == 1) {
        return tx_ids[0];
    }

    // Pre-allocated work buffer for Merkle computation
    // Two levels: current and next
    var level_a: [MAX_LEVEL_NODES][32]u8 = undefined;
    var level_b: [MAX_LEVEL_NODES][32]u8 = undefined;
    var current: *[MAX_LEVEL_NODES][32]u8 = &level_a;
    var next: *[MAX_LEVEL_NODES][32]u8 = &level_b;

    // Copy initial leaves (truncate if too many)
    const initial_count = @min(tx_ids.len, MAX_LEVEL_NODES);
    @memcpy(current[0..initial_count], tx_ids[0..initial_count]);
    var level_size: usize = initial_count;

    // Build tree bottom-up
    while (level_size > 1) {
        const pairs = level_size / 2;
        const has_odd = (level_size % 2) == 1;

        // Hash pairs
        for (0..pairs) |i| {
            var hasher = hash.Blake2b256Hasher.init();
            hasher.update(&current[i * 2]);
            hasher.update(&current[i * 2 + 1]);
            next[i] = hasher.finalize();
        }

        // Handle odd node (promote to next level)
        if (has_odd) {
            next[pairs] = current[level_size - 1];
            level_size = pairs + 1;
        } else {
            level_size = pairs;
        }

        // Swap buffers
        const tmp = current;
        current = next;
        next = tmp;
    }

    return current[0];
}

/// Compute Merkle root for v2+ blocks using txIds ++ witnessIds.
/// Witness IDs are padded to 32 bytes (prepending a zero byte).
///
/// For v1 blocks, call computeTxMerkleRoot directly with just tx_ids.
///
/// Reference: BlockTransactions.scala:59-63
pub fn computeTxMerkleRootV2(
    tx_ids: []const [32]u8,
    witness_ids: []const [WITNESS_ID_SIZE]u8,
) [32]u8 {
    std.debug.assert(tx_ids.len == witness_ids.len);

    // Empty case
    if (tx_ids.len == 0) {
        return [_]u8{0} ** 32;
    }

    // Build combined leaf array: txIds ++ witnessIds
    // Witness IDs are padded to 32 bytes with leading zero
    const total_leaves = tx_ids.len * 2;
    if (total_leaves > MAX_LEVEL_NODES) {
        // Truncate if too many (shouldn't happen in practice)
        return computeTxMerkleRootV2(tx_ids[0 .. MAX_LEVEL_NODES / 2], witness_ids[0 .. MAX_LEVEL_NODES / 2]);
    }

    var leaves: [MAX_LEVEL_NODES][32]u8 = undefined;

    // First half: transaction IDs (32 bytes each)
    @memcpy(leaves[0..tx_ids.len], tx_ids);

    // Second half: witness IDs padded to 32 bytes (0x00 || witnessId)
    for (witness_ids, 0..) |wid, i| {
        leaves[tx_ids.len + i][0] = 0x00; // Leading zero byte
        @memcpy(leaves[tx_ids.len + i][1..32], &wid);
    }

    return computeTxMerkleRoot(leaves[0..total_leaves]);
}

/// Compute Merkle root based on block version.
/// - v1: merkle(txIds)
/// - v2+: merkle(txIds ++ witnessIds)
pub fn computeVersionedMerkleRoot(
    transactions: []const Transaction,
    block_version: u8,
) [32]u8 {
    // Collect transaction IDs
    var tx_ids: [MAX_LEVEL_NODES][32]u8 = undefined;
    const tx_count = @min(transactions.len, MAX_LEVEL_NODES);

    for (transactions[0..tx_count], 0..) |tx, i| {
        tx_ids[i] = tx.id;
    }

    if (block_version <= INITIAL_VERSION) {
        // v1: only transaction IDs
        return computeTxMerkleRoot(tx_ids[0..tx_count]);
    }

    // v2+: include witness IDs
    var witness_ids: [MAX_LEVEL_NODES][WITNESS_ID_SIZE]u8 = undefined;
    _ = computeWitnessIds(transactions[0..tx_count], &witness_ids);

    return computeTxMerkleRootV2(tx_ids[0..tx_count], witness_ids[0..tx_count]);
}

/// Verify that block's transactions_root matches computed Merkle root.
/// Uses v1 merkle computation (txIds only).
/// For v2+ verification, use verifyTxMerkleRootVersioned.
pub fn verifyTxMerkleRoot(blk: *const Block) bool {
    // Collect transaction IDs
    var tx_ids: [MAX_LEVEL_NODES][32]u8 = undefined;
    const tx_count = @min(blk.transactions.len, MAX_LEVEL_NODES);

    for (blk.transactions[0..tx_count], 0..) |tx, i| {
        tx_ids[i] = tx.id;
    }

    // Compute and compare (v1 style)
    const computed = computeTxMerkleRoot(tx_ids[0..tx_count]);
    return std.mem.eql(u8, &computed, &blk.header.transactions_root);
}

/// Verify block's transactions_root using version-appropriate merkle computation.
/// - v1: merkle(txIds)
/// - v2+: merkle(txIds ++ witnessIds)
pub fn verifyTxMerkleRootVersioned(blk: *const Block, block_version: u8) bool {
    const computed = computeVersionedMerkleRoot(blk.transactions, block_version);
    return std.mem.eql(u8, &computed, &blk.header.transactions_root);
}

// ============================================================================
// Merkle Proof Verification (for individual transactions)
// ============================================================================

/// Merkle proof for a single transaction
pub const MerkleProof = struct {
    /// Sibling hashes from leaf to root
    siblings: [MAX_TREE_DEPTH][32]u8,
    /// Number of siblings
    depth: u8,
    /// Leaf index (position in bottom level)
    leaf_index: u16,

    /// Verify that tx_id is included with this proof producing expected root
    pub fn verify(self: *const MerkleProof, tx_id: [32]u8, expected_root: [32]u8) bool {
        var current = tx_id;
        var index = self.leaf_index;

        for (0..self.depth) |i| {
            var hasher = hash.Blake2b256Hasher.init();

            // Order depends on position: left child (even index) or right child (odd index)
            if (index % 2 == 0) {
                // Current is left child
                hasher.update(&current);
                hasher.update(&self.siblings[i]);
            } else {
                // Current is right child
                hasher.update(&self.siblings[i]);
                hasher.update(&current);
            }

            current = hasher.finalize();
            index /= 2;
        }

        return std.mem.eql(u8, &current, &expected_root);
    }
};

/// Build Merkle proof for a transaction at given index
pub fn buildMerkleProof(tx_ids: []const [32]u8, tx_index: usize) ?MerkleProof {
    if (tx_index >= tx_ids.len) return null;
    if (tx_ids.len == 0) return null;

    // Single tx has empty proof
    if (tx_ids.len == 1) {
        return MerkleProof{
            .siblings = undefined,
            .depth = 0,
            .leaf_index = 0,
        };
    }

    var proof = MerkleProof{
        .siblings = undefined,
        .depth = 0,
        .leaf_index = @intCast(tx_index),
    };

    // Work buffers
    var level_a: [MAX_LEVEL_NODES][32]u8 = undefined;
    var level_b: [MAX_LEVEL_NODES][32]u8 = undefined;
    var current: *[MAX_LEVEL_NODES][32]u8 = &level_a;
    var next: *[MAX_LEVEL_NODES][32]u8 = &level_b;

    // Copy initial leaves
    const initial_count = @min(tx_ids.len, MAX_LEVEL_NODES);
    @memcpy(current[0..initial_count], tx_ids[0..initial_count]);
    var level_size: usize = initial_count;
    var target_index: usize = tx_index;

    // Build tree, collecting sibling at each level
    while (level_size > 1) {
        const pairs = level_size / 2;
        const has_odd = (level_size % 2) == 1;

        // Record sibling
        if (target_index % 2 == 0) {
            // We're left child, sibling is right
            if (target_index + 1 < level_size) {
                proof.siblings[proof.depth] = current[target_index + 1];
            } else {
                // No sibling (we're the odd one)
                proof.siblings[proof.depth] = current[target_index];
            }
        } else {
            // We're right child, sibling is left
            proof.siblings[proof.depth] = current[target_index - 1];
        }
        proof.depth += 1;

        // Hash pairs for next level
        for (0..pairs) |i| {
            var hasher = hash.Blake2b256Hasher.init();
            hasher.update(&current[i * 2]);
            hasher.update(&current[i * 2 + 1]);
            next[i] = hasher.finalize();
        }

        if (has_odd) {
            next[pairs] = current[level_size - 1];
            level_size = pairs + 1;
        } else {
            level_size = pairs;
        }

        // Update target index for next level
        target_index /= 2;

        // Swap buffers
        const tmp = current;
        current = next;
        next = tmp;
    }

    return proof;
}

// ============================================================================
// Tests
// ============================================================================

test "merkle: empty input returns zero" {
    const result = computeTxMerkleRoot(&[_][32]u8{});
    const expected = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle: single tx returns tx id" {
    const tx_id = [_]u8{0xAB} ** 32;
    const result = computeTxMerkleRoot(&[_][32]u8{tx_id});
    try std.testing.expectEqualSlices(u8, &tx_id, &result);
}

test "merkle: two txs computes hash" {
    const tx1 = [_]u8{0x11} ** 32;
    const tx2 = [_]u8{0x22} ** 32;

    // Manual computation: Blake2b256(tx1 || tx2)
    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(&tx1);
    hasher.update(&tx2);
    const expected = hasher.finalize();

    const result = computeTxMerkleRoot(&[_][32]u8{ tx1, tx2 });
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle: three txs handles odd node" {
    const tx1 = [_]u8{0x11} ** 32;
    const tx2 = [_]u8{0x22} ** 32;
    const tx3 = [_]u8{0x33} ** 32;

    // Level 1: hash(tx1, tx2), tx3 (promoted)
    var h12 = hash.Blake2b256Hasher.init();
    h12.update(&tx1);
    h12.update(&tx2);
    const node12 = h12.finalize();

    // Level 2: hash(node12, tx3)
    var h_root = hash.Blake2b256Hasher.init();
    h_root.update(&node12);
    h_root.update(&tx3);
    const expected = h_root.finalize();

    const result = computeTxMerkleRoot(&[_][32]u8{ tx1, tx2, tx3 });
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle: four txs balanced tree" {
    const tx1 = [_]u8{0x11} ** 32;
    const tx2 = [_]u8{0x22} ** 32;
    const tx3 = [_]u8{0x33} ** 32;
    const tx4 = [_]u8{0x44} ** 32;

    // Level 1
    var h12 = hash.Blake2b256Hasher.init();
    h12.update(&tx1);
    h12.update(&tx2);
    const node12 = h12.finalize();

    var h34 = hash.Blake2b256Hasher.init();
    h34.update(&tx3);
    h34.update(&tx4);
    const node34 = h34.finalize();

    // Level 2 (root)
    var h_root = hash.Blake2b256Hasher.init();
    h_root.update(&node12);
    h_root.update(&node34);
    const expected = h_root.finalize();

    const result = computeTxMerkleRoot(&[_][32]u8{ tx1, tx2, tx3, tx4 });
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle: deterministic" {
    var tx_ids: [10][32]u8 = undefined;
    for (&tx_ids, 0..) |*id, i| {
        @memset(id, @intCast(i));
    }

    const result1 = computeTxMerkleRoot(&tx_ids);
    const result2 = computeTxMerkleRoot(&tx_ids);

    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "merkle: proof verify single tx" {
    const tx_id = [_]u8{0xAB} ** 32;
    const root = computeTxMerkleRoot(&[_][32]u8{tx_id});

    const proof = buildMerkleProof(&[_][32]u8{tx_id}, 0).?;
    try std.testing.expectEqual(@as(u8, 0), proof.depth);
    try std.testing.expect(proof.verify(tx_id, root));
}

test "merkle: proof verify two txs" {
    const tx1 = [_]u8{0x11} ** 32;
    const tx2 = [_]u8{0x22} ** 32;
    const tx_ids = [_][32]u8{ tx1, tx2 };
    const root = computeTxMerkleRoot(&tx_ids);

    // Proof for tx1 (index 0)
    const proof1 = buildMerkleProof(&tx_ids, 0).?;
    try std.testing.expectEqual(@as(u8, 1), proof1.depth);
    try std.testing.expect(proof1.verify(tx1, root));

    // Proof for tx2 (index 1)
    const proof2 = buildMerkleProof(&tx_ids, 1).?;
    try std.testing.expectEqual(@as(u8, 1), proof2.depth);
    try std.testing.expect(proof2.verify(tx2, root));
}

test "merkle: proof rejects wrong tx" {
    const tx1 = [_]u8{0x11} ** 32;
    const tx2 = [_]u8{0x22} ** 32;
    const fake_tx = [_]u8{0xFF} ** 32;
    const tx_ids = [_][32]u8{ tx1, tx2 };
    const root = computeTxMerkleRoot(&tx_ids);

    const proof = buildMerkleProof(&tx_ids, 0).?;
    try std.testing.expect(!proof.verify(fake_tx, root));
}

// ============================================================================
// Witness ID and v2+ Merkle Tests
// ============================================================================

test "merkle: witness ID is 31 bytes" {
    try std.testing.expectEqual(@as(usize, 31), WITNESS_ID_SIZE);
}

test "merkle: witness ID deterministic" {
    // Create a transaction with spending proofs
    const SpendingProof = transaction_mod.SpendingProof;
    var proof1 = SpendingProof.empty();
    proof1.len = 5;
    proof1.bytes[0] = 0xAA;
    proof1.bytes[1] = 0xBB;
    proof1.bytes[2] = 0xCC;
    proof1.bytes[3] = 0xDD;
    proof1.bytes[4] = 0xEE;

    const input = Input.init([_]u8{0x11} ** 32, proof1);
    const tx = Transaction.init([_]u8{0x22} ** 32, &[_]Input{input}, &[_]transaction_mod.Output{});

    const wid1 = computeWitnessId(&tx);
    const wid2 = computeWitnessId(&tx);

    try std.testing.expectEqualSlices(u8, &wid1, &wid2);
}

test "merkle: witness ID skips first byte of hash" {
    // Empty proofs should still produce consistent witness ID
    const input = Input.fromBoxId([_]u8{0x11} ** 32);
    const tx = Transaction.init([_]u8{0x22} ** 32, &[_]Input{input}, &[_]transaction_mod.Output{});

    const wid = computeWitnessId(&tx);

    // Manually compute what it should be
    var hasher = hash.Blake2b256Hasher.init();
    // Empty proof contributes nothing to hash
    const full_hash = hasher.finalize();

    // Witness ID should be bytes [1..32] (tail)
    try std.testing.expectEqualSlices(u8, full_hash[1..32], &wid);
}

test "merkle: v2 merkle root includes witness IDs" {
    const tx_id1 = [_]u8{0x11} ** 32;
    const tx_id2 = [_]u8{0x22} ** 32;
    const tx_ids = [_][32]u8{ tx_id1, tx_id2 };

    const wid1 = [_]u8{0xAA} ** WITNESS_ID_SIZE;
    const wid2 = [_]u8{0xBB} ** WITNESS_ID_SIZE;
    const witness_ids = [_][WITNESS_ID_SIZE]u8{ wid1, wid2 };

    // v2 root should be different from v1 root
    const v1_root = computeTxMerkleRoot(&tx_ids);
    const v2_root = computeTxMerkleRootV2(&tx_ids, &witness_ids);

    try std.testing.expect(!std.mem.eql(u8, &v1_root, &v2_root));
}

test "merkle: v2 merkle root structure" {
    // Single tx case: merkle tree of [txId, paddedWitnessId]
    const tx_id = [_]u8{0x11} ** 32;
    const wid = [_]u8{0xAA} ** WITNESS_ID_SIZE;

    // Build padded witness ID (0x00 || wid)
    var padded_wid: [32]u8 = undefined;
    padded_wid[0] = 0x00;
    @memcpy(padded_wid[1..32], &wid);

    // v2 root should be hash(tx_id || padded_wid)
    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(&tx_id);
    hasher.update(&padded_wid);
    const expected = hasher.finalize();

    const v2_root = computeTxMerkleRootV2(&[_][32]u8{tx_id}, &[_][WITNESS_ID_SIZE]u8{wid});
    try std.testing.expectEqualSlices(u8, &expected, &v2_root);
}

test "merkle: versioned merkle v1 equals non-versioned" {
    // Create simple transactions
    const input = Input.fromBoxId([_]u8{0x11} ** 32);
    const tx1 = Transaction.init([_]u8{0xAA} ** 32, &[_]Input{input}, &[_]transaction_mod.Output{});
    const tx2 = Transaction.init([_]u8{0xBB} ** 32, &[_]Input{input}, &[_]transaction_mod.Output{});
    const transactions = [_]Transaction{ tx1, tx2 };

    // v1 versioned should equal direct tx_ids computation
    const v1_root = computeVersionedMerkleRoot(&transactions, 1);

    var tx_ids: [2][32]u8 = undefined;
    tx_ids[0] = tx1.id;
    tx_ids[1] = tx2.id;
    const direct_root = computeTxMerkleRoot(&tx_ids);

    try std.testing.expectEqualSlices(u8, &direct_root, &v1_root);
}

test "merkle: versioned merkle v2 differs from v1" {
    // Create transactions with proofs
    const SpendingProof = transaction_mod.SpendingProof;
    var proof = SpendingProof.empty();
    proof.len = 3;
    proof.bytes[0] = 0x12;
    proof.bytes[1] = 0x34;
    proof.bytes[2] = 0x56;

    const input = Input.init([_]u8{0x11} ** 32, proof);
    const tx = Transaction.init([_]u8{0xAA} ** 32, &[_]Input{input}, &[_]transaction_mod.Output{});
    const transactions = [_]Transaction{tx};

    const v1_root = computeVersionedMerkleRoot(&transactions, 1);
    const v2_root = computeVersionedMerkleRoot(&transactions, 2);

    // v1 and v2 should produce different roots
    try std.testing.expect(!std.mem.eql(u8, &v1_root, &v2_root));
}
