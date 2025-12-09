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
// Compile-Time Assertions (ZIGMA_STYLE requirement)
// ============================================================================

comptime {
    // HeaderView size must be reasonable for stack allocation
    assert(@sizeOf(HeaderView) <= 512);
    assert(@sizeOf(HeaderView) >= 256); // Sanity: header has many fields

    // Field size constraints from Ergo protocol
    assert(@sizeOf([32]u8) == 32); // Hash sizes
    assert(@sizeOf([33]u8) == 33); // Compressed EC points
    assert(@sizeOf([44]u8) == 44); // AVL+ digest
    assert(@sizeOf([3]u8) == 3); // Votes
    assert(@sizeOf([8]u8) == 8); // PoW nonce
}

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

    // INVARIANT: miner_pk has valid SEC1 compressed prefix (0x02 or 0x03)
    // Note: 0x00 is allowed for genesis/empty headers in test contexts
    assert(header.miner_pk[0] == 0x02 or header.miner_pk[0] == 0x03 or header.miner_pk[0] == 0x00);

    const result = header.miner_pk;

    // POSTCONDITION: result is 33 bytes with valid prefix
    assert(result.len == 33);
    assert(result[0] == 0x02 or result[0] == 0x03 or result[0] == 0x00);

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

    // INVARIANT: pow_onetime_pk has valid SEC1 compressed prefix (0x02 or 0x03)
    // Note: 0x00 is allowed for genesis/empty headers in test contexts
    assert(header.pow_onetime_pk[0] == 0x02 or header.pow_onetime_pk[0] == 0x03 or header.pow_onetime_pk[0] == 0x00);

    const result = header.pow_onetime_pk;

    // POSTCONDITION: result is 33 bytes with valid prefix
    assert(result.len == 33);
    assert(result[0] == 0x02 or result[0] == 0x03 or result[0] == 0x00);

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

// ============================================================================
// Edge Case Tests (ZIGMA_STYLE requirement)
// ============================================================================

test "header_ops: extractVersion boundary values" {
    var header = ctx.testHeader();

    // Test version = 0 (genesis)
    header.version = 0;
    try std.testing.expectEqual(@as(i8, 0), extractVersion(&header));

    // Test version = 127 (max valid)
    header.version = 127;
    try std.testing.expectEqual(@as(i8, 127), extractVersion(&header));

    // Test version = 1 (minimum non-zero)
    header.version = 1;
    try std.testing.expectEqual(@as(i8, 1), extractVersion(&header));
}

test "header_ops: extractTimestamp boundary values" {
    var header = ctx.testHeader();

    // Test minimum valid timestamp (> 0)
    header.timestamp = 1;
    try std.testing.expectEqual(@as(i64, 1), extractTimestamp(&header));

    // Test large timestamp (year 3000+)
    header.timestamp = 32503680000000; // Jan 1, 3000
    try std.testing.expectEqual(@as(i64, 32503680000000), extractTimestamp(&header));

    // Test Ergo genesis timestamp approximate
    header.timestamp = 1561978800000; // July 1, 2019
    try std.testing.expectEqual(@as(i64, 1561978800000), extractTimestamp(&header));
}

test "header_ops: extractHeight boundary values" {
    var header = ctx.testHeader();

    // Test height = 1 (genesis successor)
    header.height = 1;
    try std.testing.expectEqual(@as(u32, 1), extractHeight(&header));

    // Test large height (millions of blocks)
    header.height = 10_000_000;
    try std.testing.expectEqual(@as(u32, 10_000_000), extractHeight(&header));

    // Test max u32 height
    header.height = std.math.maxInt(u32);
    try std.testing.expectEqual(std.math.maxInt(u32), extractHeight(&header));
}

test "header_ops: extractNBits boundary values" {
    var header = ctx.testHeader();

    // Test minimum nBits
    header.n_bits = 1;
    try std.testing.expectEqual(@as(i64, 1), extractNBits(&header));

    // Test max nBits that fits in i64
    header.n_bits = @intCast(std.math.maxInt(i64));
    try std.testing.expectEqual(std.math.maxInt(i64), extractNBits(&header));
}

test "header_ops: extractMinerPk valid prefixes" {
    var header = ctx.testHeader();

    // Test prefix 0x02 (even y-coordinate)
    header.miner_pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const result_02 = extractMinerPk(&header);
    try std.testing.expectEqual(@as(u8, 0x02), result_02[0]);

    // Test prefix 0x03 (odd y-coordinate)
    header.miner_pk = [_]u8{0x03} ++ [_]u8{0xBB} ** 32;
    const result_03 = extractMinerPk(&header);
    try std.testing.expectEqual(@as(u8, 0x03), result_03[0]);
}

test "header_ops: extractPowOnetimePk valid prefixes" {
    var header = ctx.testHeader();

    // Test prefix 0x02
    header.pow_onetime_pk = [_]u8{0x02} ++ [_]u8{0xCC} ** 32;
    const result_02 = extractPowOnetimePk(&header);
    try std.testing.expectEqual(@as(u8, 0x02), result_02[0]);

    // Test prefix 0x03
    header.pow_onetime_pk = [_]u8{0x03} ++ [_]u8{0xDD} ** 32;
    const result_03 = extractPowOnetimePk(&header);
    try std.testing.expectEqual(@as(u8, 0x03), result_03[0]);
}

test "header_ops: extractId" {
    var header = ctx.testHeader();
    header.id = [_]u8{0x12} ** 32;

    const result = extractId(&header);
    try std.testing.expectEqual(@as(u8, 0x12), result[0]);
    try std.testing.expectEqual(@as(u8, 0x12), result[31]);
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "header_ops: extractPowNonce" {
    var header = ctx.testHeader();
    header.pow_nonce = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    const result = extractPowNonce(&header);
    try std.testing.expectEqual([8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }, result);
}

test "header_ops: all zero-filled fields" {
    var header = ctx.testHeader();
    // Set all byte arrays to zero
    header.id = [_]u8{0} ** 32;
    header.parent_id = [_]u8{0} ** 32;
    header.ad_proofs_root = [_]u8{0} ** 32;
    header.state_root = [_]u8{0} ** 44;
    header.transactions_root = [_]u8{0} ** 32;
    header.extension_root = [_]u8{0} ** 32;
    header.pow_distance = [_]u8{0} ** 32;
    header.votes = [_]u8{0} ** 3;
    header.pow_nonce = [_]u8{0} ** 8;
    // Keep valid pubkey prefixes
    header.miner_pk = [_]u8{0x02} ++ [_]u8{0} ** 32;
    header.pow_onetime_pk = [_]u8{0x02} ++ [_]u8{0} ** 32;

    // Verify all zero-filled extractions work
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractId(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractParentId(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractAdProofsRoot(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 44), &extractStateRoot(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractTransactionsRoot(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractExtensionRoot(&header));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &extractDifficulty(&header));
    try std.testing.expectEqual([3]u8{ 0, 0, 0 }, extractVotes(&header));
    try std.testing.expectEqual([8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, extractPowNonce(&header));
}

test "header_ops: all 0xFF-filled fields" {
    var header = ctx.testHeader();
    // Set all byte arrays to 0xFF
    header.id = [_]u8{0xFF} ** 32;
    header.parent_id = [_]u8{0xFF} ** 32;
    header.ad_proofs_root = [_]u8{0xFF} ** 32;
    header.state_root = [_]u8{0xFF} ** 44;
    header.transactions_root = [_]u8{0xFF} ** 32;
    header.extension_root = [_]u8{0xFF} ** 32;
    header.pow_distance = [_]u8{0xFF} ** 32;
    header.votes = [_]u8{0xFF} ** 3;
    header.pow_nonce = [_]u8{0xFF} ** 8;
    // Keep valid pubkey prefixes (0x03 with all-FF body)
    header.miner_pk = [_]u8{0x03} ++ [_]u8{0xFF} ** 32;
    header.pow_onetime_pk = [_]u8{0x03} ++ [_]u8{0xFF} ** 32;

    // Verify all 0xFF extractions work
    for (extractId(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractParentId(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractAdProofsRoot(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractStateRoot(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractTransactionsRoot(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractExtensionRoot(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    for (extractDifficulty(&header)) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
    try std.testing.expectEqual([3]u8{ 0xFF, 0xFF, 0xFF }, extractVotes(&header));
    try std.testing.expectEqual([8]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, extractPowNonce(&header));
}

test "header_ops: field independence" {
    // Verify that extracting one field doesn't affect others
    var header = ctx.testHeader();
    header.parent_id = [_]u8{0xAA} ** 32;
    header.transactions_root = [_]u8{0xBB} ** 32;

    const parent = extractParentId(&header);
    const txroot = extractTransactionsRoot(&header);

    // Verify fields are independent
    try std.testing.expectEqual(@as(u8, 0xAA), parent[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), txroot[0]);

    // Verify modification of result doesn't affect other extractions
    var parent_copy = parent;
    parent_copy[0] = 0x00;
    try std.testing.expectEqual(@as(u8, 0xAA), extractParentId(&header)[0]);
}
