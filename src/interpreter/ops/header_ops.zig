//! Header Operations for ErgoTree Interpreter
//!
//! Implements header field extraction operations:
//! - ExtractVersion (0xE9): Header → Byte
//! - ExtractParentId (0xEA): Header → Coll[Byte] 32b
//! - ExtractAdProofsRoot (0xEB): Header → Coll[Byte] 32b
//! - ExtractStateRoot (0xEC): Header → AvlTree digest 44b
//! - ExtractTransactionsRoot (0xED): Header → Coll[Byte] 32b
//! - ExtractTimestamp (0xEE): Header → Long
//! - ExtractNBits (0xEF): Header → Long
//! - ExtractDifficulty (0xF0): Header → BigInt
//! - ExtractVotes (0xF1): Header → Coll[Byte] 3b
//! - ExtractMinerRewards (0xF2): Header → Coll[Byte] 33b
//!
//! Reference: sigmastate/src/main/scala/sigma/ast/methods.scala (SHeaderMethods)

const std = @import("std");
const assert = std.debug.assert;
const ctx = @import("../context.zig");

const HeaderView = ctx.HeaderView;

// ============================================================================
// Error Types
// ============================================================================

pub const HeaderError = error{
    /// Invalid header data
    InvalidHeader,
};

// ============================================================================
// Cost Constants
// ============================================================================

pub const FixedCost = struct {
    pub const extract_version: u32 = 10;
    pub const extract_parent_id: u32 = 10;
    pub const extract_ad_proofs_root: u32 = 10;
    pub const extract_state_root: u32 = 10;
    pub const extract_txs_root: u32 = 10;
    pub const extract_timestamp: u32 = 10;
    pub const extract_n_bits: u32 = 10;
    pub const extract_difficulty: u32 = 10;
    pub const extract_votes: u32 = 10;
    pub const extract_miner_rewards: u32 = 10;
};

// ============================================================================
// Header Field Extraction Operations
// ============================================================================

/// ExtractVersion (0xE9): Header → Byte
/// Returns the protocol version byte from the header.
pub fn extractVersion(header: *const HeaderView) i8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: version is a valid byte value
    assert(header.version <= 127);

    const result: i8 = @intCast(header.version);

    // POSTCONDITION: result is non-negative
    assert(result >= 0);

    return result;
}

/// ExtractParentId (0xEA): Header → Coll[Byte] (32 bytes)
/// Returns the parent block's ID (hash).
pub fn extractParentId(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: parent_id is 32 bytes
    assert(header.parent_id.len == 32);

    const result = header.parent_id;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// ExtractAdProofsRoot (0xEB): Header → Coll[Byte] (32 bytes)
/// Returns the root hash of the AD (Authenticated Data) proofs tree.
pub fn extractAdProofsRoot(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: ad_proofs_root is 32 bytes
    assert(header.ad_proofs_root.len == 32);

    const result = header.ad_proofs_root;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// ExtractStateRoot (0xEC): Header → AvlTree digest (44 bytes)
/// Returns the root digest of the state AVL+ tree.
/// Format: 32-byte digest + 1-byte flags + 4-byte key length + 4-byte value length (optional)
pub fn extractStateRoot(header: *const HeaderView) [44]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: state_root is 44 bytes (AVL+ tree digest format)
    assert(header.state_root.len == 44);

    const result = header.state_root;

    // POSTCONDITION: result is 44 bytes
    assert(result.len == 44);

    return result;
}

/// ExtractTransactionsRoot (0xED): Header → Coll[Byte] (32 bytes)
/// Returns the root hash of the transactions Merkle tree.
pub fn extractTransactionsRoot(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: transactions_root is 32 bytes
    assert(header.transactions_root.len == 32);

    const result = header.transactions_root;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// ExtractTimestamp (0xEE): Header → Long
/// Returns the block timestamp in milliseconds since Unix epoch.
pub fn extractTimestamp(header: *const HeaderView) i64 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: timestamp is non-negative (represents valid time)
    assert(header.timestamp > 0);

    const result: i64 = @intCast(header.timestamp);

    // POSTCONDITION: result is positive
    assert(result > 0);

    return result;
}

/// ExtractNBits (0xEF): Header → Long
/// Returns the encoded difficulty target (nBits).
pub fn extractNBits(header: *const HeaderView) i64 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: n_bits is non-negative
    assert(header.n_bits > 0);

    const result: i64 = @intCast(header.n_bits);

    // POSTCONDITION: result is positive
    assert(result > 0);

    return result;
}

/// ExtractDifficulty (0xF0): Header → BigInt (32 bytes)
/// Returns the mining difficulty as a BigInt.
/// Note: Difficulty is derived from nBits but returned as pow_distance.
pub fn extractDifficulty(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: pow_distance is 32 bytes
    assert(header.pow_distance.len == 32);

    const result = header.pow_distance;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// ExtractVotes (0xF1): Header → Coll[Byte] (3 bytes)
/// Returns the miner's votes on protocol changes.
pub fn extractVotes(header: *const HeaderView) [3]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: votes is 3 bytes
    assert(header.votes.len == 3);

    const result = header.votes;

    // POSTCONDITION: result is 3 bytes
    assert(result.len == 3);

    return result;
}

/// ExtractMinerRewards (0xF2): Header → Coll[Byte] (33 bytes)
/// Returns the miner's public key for reward collection.
pub fn extractMinerPk(header: *const HeaderView) [33]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: miner_pk is 33 bytes (compressed EC point)
    assert(header.miner_pk.len == 33);

    const result = header.miner_pk;

    // POSTCONDITION: result is 33 bytes
    assert(result.len == 33);

    return result;
}

// ============================================================================
// Additional Header Accessors
// ============================================================================

/// Extract block height from header
pub fn extractHeight(header: *const HeaderView) u32 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: height is reasonable
    assert(header.height > 0);

    const result = header.height;

    // POSTCONDITION: result is positive
    assert(result > 0);

    return result;
}

/// Extract block ID (hash) from header
pub fn extractId(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: id is 32 bytes
    assert(header.id.len == 32);

    const result = header.id;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// Extract extension root from header
pub fn extractExtensionRoot(header: *const HeaderView) [32]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: extension_root is 32 bytes
    assert(header.extension_root.len == 32);

    const result = header.extension_root;

    // POSTCONDITION: result is 32 bytes
    assert(result.len == 32);

    return result;
}

/// Extract PoW one-time public key from header
pub fn extractPowOnetimePk(header: *const HeaderView) [33]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: pow_onetime_pk is 33 bytes
    assert(header.pow_onetime_pk.len == 33);

    const result = header.pow_onetime_pk;

    // POSTCONDITION: result is 33 bytes
    assert(result.len == 33);

    return result;
}

/// Extract PoW nonce from header
pub fn extractPowNonce(header: *const HeaderView) [8]u8 {
    // PRECONDITION: header is valid
    assert(@intFromPtr(header) != 0);

    // INVARIANT: pow_nonce is 8 bytes
    assert(header.pow_nonce.len == 8);

    const result = header.pow_nonce;

    // POSTCONDITION: result is 8 bytes
    assert(result.len == 8);

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "header_ops: extractVersion" {
    var header = ctx.testHeader();
    header.version = 3;

    const result = extractVersion(&header);
    try std.testing.expectEqual(@as(i8, 3), result);
}

test "header_ops: extractParentId" {
    var header = ctx.testHeader();
    header.parent_id = [_]u8{0xAB} ** 32;

    const result = extractParentId(&header);
    try std.testing.expectEqual(@as(u8, 0xAB), result[0]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "header_ops: extractAdProofsRoot" {
    var header = ctx.testHeader();
    header.ad_proofs_root = [_]u8{0xCD} ** 32;

    const result = extractAdProofsRoot(&header);
    try std.testing.expectEqual(@as(u8, 0xCD), result[0]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "header_ops: extractStateRoot" {
    var header = ctx.testHeader();
    header.state_root = [_]u8{0xEF} ** 44;

    const result = extractStateRoot(&header);
    try std.testing.expectEqual(@as(u8, 0xEF), result[0]);
    try std.testing.expectEqual(@as(usize, 44), result.len);
}

test "header_ops: extractTransactionsRoot" {
    var header = ctx.testHeader();
    header.transactions_root = [_]u8{0x12} ** 32;

    const result = extractTransactionsRoot(&header);
    try std.testing.expectEqual(@as(u8, 0x12), result[0]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "header_ops: extractTimestamp" {
    var header = ctx.testHeader();
    header.timestamp = 1700000000000; // Nov 2023

    const result = extractTimestamp(&header);
    try std.testing.expectEqual(@as(i64, 1700000000000), result);
}

test "header_ops: extractNBits" {
    var header = ctx.testHeader();
    header.n_bits = 0x1A2B3C4D;

    const result = extractNBits(&header);
    try std.testing.expectEqual(@as(i64, 0x1A2B3C4D), result);
}

test "header_ops: extractDifficulty" {
    var header = ctx.testHeader();
    header.pow_distance = [_]u8{0x00} ** 31 ++ [_]u8{0xFF};

    const result = extractDifficulty(&header);
    try std.testing.expectEqual(@as(u8, 0xFF), result[31]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "header_ops: extractVotes" {
    var header = ctx.testHeader();
    header.votes = [_]u8{ 0x01, 0x02, 0x03 };

    const result = extractVotes(&header);
    try std.testing.expectEqual([3]u8{ 0x01, 0x02, 0x03 }, result);
}

test "header_ops: extractMinerPk" {
    var header = ctx.testHeader();
    header.miner_pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;

    const result = extractMinerPk(&header);
    try std.testing.expectEqual(@as(u8, 0x02), result[0]);
    try std.testing.expectEqual(@as(usize, 33), result.len);
}

test "header_ops: extractHeight" {
    var header = ctx.testHeader();
    header.height = 1234567;

    const result = extractHeight(&header);
    try std.testing.expectEqual(@as(u32, 1234567), result);
}

test "header_ops: extractExtensionRoot" {
    var header = ctx.testHeader();
    header.extension_root = [_]u8{0x99} ** 32;

    const result = extractExtensionRoot(&header);
    try std.testing.expectEqual(@as(u8, 0x99), result[0]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}
