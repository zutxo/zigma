//! Fiat-Shamir Challenge Computation
//!
//! Implements the Fiat-Shamir heuristic for converting interactive Sigma protocols
//! into non-interactive proofs. The challenge is computed as:
//!   challenge = Blake2b256(tree_bytes || message).take(24)
//!
//! Key constants:
//! - SOUNDNESS_BYTES = 24 (192 bits) - Must be 192 for GF(2^192) threshold polynomials
//! - GROUP_SIZE = 32 bytes for secp256k1 scalars
//!
//! Reference: sigmastate/src/main/scala/sigmastate/UnprovenTree.scala (FiatShamirTree)

const std = @import("std");
const assert = std.debug.assert;
const hash = @import("../crypto/hash.zig");
const sigma_tree = @import("sigma_tree.zig");

const SigmaBoolean = sigma_tree.SigmaBoolean;
const ProveDlog = sigma_tree.ProveDlog;
const ProveDHTuple = sigma_tree.ProveDHTuple;

// ============================================================================
// Constants
// ============================================================================

/// Challenge size in bits (must be 192 for threshold polynomials over GF(2^192))
pub const SOUNDNESS_BITS: usize = 192;

/// Challenge size in bytes
pub const SOUNDNESS_BYTES: usize = SOUNDNESS_BITS / 8;

/// Group element size (secp256k1 compressed point)
pub const GROUP_SIZE: usize = 33;

/// Scalar size (secp256k1 order)
pub const SCALAR_SIZE: usize = 32;

// Compile-time assertions per reference implementation
comptime {
    // Challenge must be less than curve order
    assert(SOUNDNESS_BITS < 256);
    // Must fit in Blake2b output
    assert(SOUNDNESS_BYTES * 8 <= 512);
    // Must be byte-aligned
    assert(SOUNDNESS_BYTES % 8 == 0);
    // Exact expected size
    assert(SOUNDNESS_BYTES == 24);
}

// ============================================================================
// Challenge Type
// ============================================================================

/// 192-bit challenge for Sigma protocols
/// XOR-combinable for challenge distribution in AND/OR/THRESHOLD
pub const Challenge = struct {
    bytes: [SOUNDNESS_BYTES]u8,

    /// Zero challenge (identity for XOR)
    pub const zero = Challenge{ .bytes = [_]u8{0} ** SOUNDNESS_BYTES };

    /// Create from bytes
    pub fn fromBytes(bytes: [SOUNDNESS_BYTES]u8) Challenge {
        return Challenge{ .bytes = bytes };
    }

    /// Create from slice (must be exactly SOUNDNESS_BYTES)
    pub fn fromSlice(slice: []const u8) error{InvalidLength}!Challenge {
        // PRECONDITION 1: slice length must be exact
        if (slice.len != SOUNDNESS_BYTES) return error.InvalidLength;
        // PRECONDITION 2: slice pointer is valid (redundant but defensive)
        assert(slice.len > 0);

        var result: Challenge = undefined;
        @memcpy(&result.bytes, slice);

        // POSTCONDITION 1: result has correct length
        assert(result.bytes.len == SOUNDNESS_BYTES);
        // POSTCONDITION 2: bytes were copied correctly
        assert(std.mem.eql(u8, &result.bytes, slice));

        return result;
    }

    /// XOR two challenges (commutative, associative)
    /// Used for challenge distribution in connectives:
    /// - AND: child_challenges XOR to parent_challenge
    /// - OR: real_challenge = parent_challenge XOR sum(simulated_challenges)
    pub fn xor(self: Challenge, other: Challenge) Challenge {
        assert(self.bytes.len == SOUNDNESS_BYTES);
        assert(other.bytes.len == SOUNDNESS_BYTES);

        var result: [SOUNDNESS_BYTES]u8 = undefined;
        for (0..SOUNDNESS_BYTES) |i| {
            result[i] = self.bytes[i] ^ other.bytes[i];
        }

        const c = Challenge{ .bytes = result };
        assert(c.bytes.len == SOUNDNESS_BYTES);
        return c;
    }

    /// Check equality
    pub fn eql(self: Challenge, other: Challenge) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Check if zero
    pub fn isZero(self: Challenge) bool {
        for (self.bytes) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    /// Convert to bytes
    pub fn toBytes(self: Challenge) [SOUNDNESS_BYTES]u8 {
        return self.bytes;
    }
};

// ============================================================================
// Fiat-Shamir Hash Function
// ============================================================================

/// Compute Fiat-Shamir challenge from arbitrary input
/// Returns first 24 bytes of Blake2b256 hash
pub fn fiatShamirHash(input: []const u8) Challenge {
    // PRECONDITION 1: input length is bounded
    assert(input.len <= std.math.maxInt(usize));
    // PRECONDITION 2: blake2b256 produces 32 bytes (enough for 24)
    assert(32 >= SOUNDNESS_BYTES);

    const full_hash = hash.blake2b256(input);

    // INVARIANT: hash output has expected length
    assert(full_hash.len == 32);

    var result: [SOUNDNESS_BYTES]u8 = undefined;
    @memcpy(&result, full_hash[0..SOUNDNESS_BYTES]);

    // POSTCONDITION 1: result is correct length
    assert(result.len == SOUNDNESS_BYTES);
    // POSTCONDITION 2: result matches hash prefix
    assert(std.mem.eql(u8, &result, full_hash[0..SOUNDNESS_BYTES]));

    return Challenge{ .bytes = result };
}

/// Compute challenge from proposition tree and message
/// This is the main entry point for verification:
///   challenge = Blake2b256(tree_bytes || message).take(24)
pub fn computeChallenge(tree_bytes: []const u8, message: []const u8) Challenge {
    // PRECONDITION 1: combined length is bounded (no overflow)
    assert(tree_bytes.len <= std.math.maxInt(usize) - message.len);
    // PRECONDITION 2: tree_bytes is not unreasonably large
    assert(tree_bytes.len <= MAX_FS_TREE_BYTES);

    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(tree_bytes);
    hasher.update(message);

    const full_hash = hasher.finalize();

    // INVARIANT: hash output has expected length
    assert(full_hash.len == 32);

    var result: [SOUNDNESS_BYTES]u8 = undefined;
    @memcpy(&result, full_hash[0..SOUNDNESS_BYTES]);

    // POSTCONDITION 1: result is valid challenge length
    assert(result.len == SOUNDNESS_BYTES);
    // POSTCONDITION 2: result matches hash prefix
    assert(std.mem.eql(u8, &result, full_hash[0..SOUNDNESS_BYTES]));

    return Challenge{ .bytes = result };
}

// ============================================================================
// Fiat-Shamir Tree Serialization
// ============================================================================

/// Prefix for internal nodes (AND/OR/THRESHOLD)
pub const INTERNAL_NODE_PREFIX: u8 = 0;

/// Prefix for leaf nodes (ProveDlog/ProveDHTuple)
pub const LEAF_PREFIX: u8 = 1;

/// Conjecture type IDs (matches Scala OpCodes)
pub const ConjectureType = enum(u8) {
    and_connective = 0,
    or_connective = 1,
    threshold = 2,
};

/// First prover message (commitment) for Schnorr protocol
pub const FirstDlogMessage = struct {
    /// Commitment a = g^r (compressed EC point, 33 bytes)
    a: [GROUP_SIZE]u8,

    pub fn toBytes(self: FirstDlogMessage) []const u8 {
        return &self.a;
    }
};

/// First prover message for DH tuple protocol
pub const FirstDHTupleMessage = struct {
    /// Commitment a = g^r
    a: [GROUP_SIZE]u8,
    /// Commitment b = h^r
    b: [GROUP_SIZE]u8,

    pub fn toBytes(self: *const FirstDHTupleMessage, buffer: *[GROUP_SIZE * 2]u8) []const u8 {
        @memcpy(buffer[0..GROUP_SIZE], &self.a);
        @memcpy(buffer[GROUP_SIZE .. GROUP_SIZE * 2], &self.b);
        return buffer;
    }
};

/// Union of first messages
pub const FirstMessage = union(enum) {
    dlog: FirstDlogMessage,
    dh_tuple: FirstDHTupleMessage,

    pub fn bytes(self: *const FirstMessage, buffer: *[GROUP_SIZE * 2]u8) []const u8 {
        return switch (self.*) {
            .dlog => |m| m.toBytes(),
            .dh_tuple => |*m| m.toBytes(buffer),
        };
    }
};

/// Maximum buffer size for Fiat-Shamir tree serialization
/// Estimated: depth * (1 + 1 + 2 + children * (1 + 2 + 100 + 2 + 66))
pub const MAX_FS_TREE_BYTES: usize = 8192;

/// Serialization error
pub const SerializeError = error{
    BufferTooSmall,
    MissingCommitment,
    InvalidProposition,
};

/// Serialize a proposition leaf for Fiat-Shamir
/// Format: LEAF_PREFIX || propBytesLen(i16) || propBytes || commitmentLen(i16) || commitment
pub fn serializeLeaf(
    proposition: SigmaBoolean,
    commitment: ?FirstMessage,
    buffer: []u8,
) SerializeError![]u8 {
    // PRECONDITION 1: buffer has minimum size for header
    assert(buffer.len >= 1);
    // PRECONDITION 2: commitment is provided
    const commit = commitment orelse return error.MissingCommitment;
    // PRECONDITION 3: proposition is a valid leaf type
    assert(proposition == .prove_dlog or proposition == .prove_dh_tuple);

    // Serialize proposition as minimal ErgoTree
    // For ProveDlog: 0x08cd || public_key (35 bytes total)
    // For ProveDHTuple: more complex, ~140 bytes
    var prop_bytes: [150]u8 = undefined;
    var prop_len: usize = 0;

    switch (proposition) {
        .prove_dlog => |dlog| {
            // Minimal ErgoTree for SigmaProp constant: header(1) + SigmaProp opcode(1) + ProveDlog marker(1) + pk(33)
            // Ergo uses: 0x08 (v0 header, segregated) || 0xcd (SigmaPropConstant) || public_key
            // Actually simpler: 0x08cd || compressed_pk
            prop_bytes[0] = 0x08; // ErgoTree header v0, constant segregation
            prop_bytes[1] = 0xcd; // SigmaProp constant opcode
            @memcpy(prop_bytes[2 .. 2 + 33], &dlog.public_key);
            prop_len = 35;
        },
        .prove_dh_tuple => |dht| {
            // DHT is more complex: header + opcode + 4 group elements
            // 0x08 || opcode || g || h || u || v
            prop_bytes[0] = 0x08;
            prop_bytes[1] = 0xce; // ProveDHTuple opcode (placeholder, need to verify)
            @memcpy(prop_bytes[2 .. 2 + 33], &dht.g);
            @memcpy(prop_bytes[35 .. 35 + 33], &dht.h);
            @memcpy(prop_bytes[68 .. 68 + 33], &dht.u);
            @memcpy(prop_bytes[101 .. 101 + 33], &dht.v);
            prop_len = 134;
        },
        else => return error.InvalidProposition,
    }

    // Get commitment bytes
    var commit_buffer: [GROUP_SIZE * 2]u8 = undefined;
    const commit_bytes = commit.bytes(&commit_buffer);

    // Calculate total size
    const total_size = 1 + 2 + prop_len + 2 + commit_bytes.len;
    if (buffer.len < total_size) return error.BufferTooSmall;

    var pos: usize = 0;

    // Write leaf prefix
    buffer[pos] = LEAF_PREFIX;
    pos += 1;

    // Write proposition length (big-endian i16)
    const prop_len_i16: i16 = @intCast(prop_len);
    buffer[pos] = @intCast((prop_len_i16 >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(prop_len_i16 & 0xFF);
    pos += 2;

    // Write proposition bytes
    @memcpy(buffer[pos .. pos + prop_len], prop_bytes[0..prop_len]);
    pos += prop_len;

    // Write commitment length (big-endian i16)
    const commit_len_i16: i16 = @intCast(commit_bytes.len);
    buffer[pos] = @intCast((commit_len_i16 >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(commit_len_i16 & 0xFF);
    pos += 2;

    // Write commitment bytes
    @memcpy(buffer[pos .. pos + commit_bytes.len], commit_bytes);
    pos += commit_bytes.len;

    // POSTCONDITION 1: wrote expected number of bytes
    assert(pos == total_size);
    // POSTCONDITION 2: first byte is leaf prefix
    assert(buffer[0] == LEAF_PREFIX);

    return buffer[0..pos];
}

// ============================================================================
// Tests
// ============================================================================

test "challenge: zero is identity for XOR" {
    const a = Challenge{ .bytes = [_]u8{0xAB} ++ [_]u8{0} ** 23 };
    const result = a.xor(Challenge.zero);

    try std.testing.expect(result.eql(a));
}

test "challenge: XOR is self-inverse" {
    const a = Challenge{ .bytes = [_]u8{0xAB} ++ [_]u8{0xCD} ** 23 };
    const result = a.xor(a);

    try std.testing.expect(result.isZero());
}

test "challenge: XOR is commutative" {
    const a = Challenge{ .bytes = [_]u8{0x12} ++ [_]u8{0x34} ** 23 };
    const b = Challenge{ .bytes = [_]u8{0x56} ++ [_]u8{0x78} ** 23 };

    const ab = a.xor(b);
    const ba = b.xor(a);

    try std.testing.expect(ab.eql(ba));
}

test "challenge: fiatShamirHash produces 24 bytes" {
    const input = "test input for Fiat-Shamir";
    const challenge = fiatShamirHash(input);

    try std.testing.expectEqual(@as(usize, SOUNDNESS_BYTES), challenge.bytes.len);
}

test "challenge: fiatShamirHash is deterministic" {
    const input = "determinism test";
    const c1 = fiatShamirHash(input);
    const c2 = fiatShamirHash(input);

    try std.testing.expect(c1.eql(c2));
}

test "challenge: fiatShamirHash is prefix of Blake2b256" {
    const input = "prefix test";
    const challenge = fiatShamirHash(input);
    const full_hash = hash.blake2b256(input);

    try std.testing.expectEqualSlices(u8, full_hash[0..SOUNDNESS_BYTES], &challenge.bytes);
}

test "challenge: computeChallenge combines tree and message" {
    const tree_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const message = [_]u8{ 0x04, 0x05, 0x06 };

    const c1 = computeChallenge(&tree_bytes, &message);

    // Same as concatenated hash
    var combined: [6]u8 = undefined;
    @memcpy(combined[0..3], &tree_bytes);
    @memcpy(combined[3..6], &message);
    const c2 = fiatShamirHash(&combined);

    try std.testing.expect(c1.eql(c2));
}

test "challenge: fromSlice validates length" {
    const valid = [_]u8{0xAA} ** SOUNDNESS_BYTES;
    const c = try Challenge.fromSlice(&valid);
    try std.testing.expect(!c.isZero());

    const invalid = [_]u8{0xBB} ** 10;
    try std.testing.expectError(error.InvalidLength, Challenge.fromSlice(&invalid));
}

test "challenge: constants match reference" {
    // These must match sigmastate-interpreter exactly
    try std.testing.expectEqual(@as(usize, 192), SOUNDNESS_BITS);
    try std.testing.expectEqual(@as(usize, 24), SOUNDNESS_BYTES);
    try std.testing.expectEqual(@as(usize, 33), GROUP_SIZE);
}

test "challenge: serializeLeaf for ProveDlog" {
    const pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const dlog = ProveDlog.init(pk);
    const prop = SigmaBoolean{ .prove_dlog = dlog };

    const commitment = FirstMessage{ .dlog = FirstDlogMessage{ .a = [_]u8{0x03} ++ [_]u8{0xBB} ** 32 } };

    var buffer: [200]u8 = undefined;
    const result = try serializeLeaf(prop, commitment, &buffer);

    // Check prefix
    try std.testing.expectEqual(@as(u8, LEAF_PREFIX), result[0]);

    // Check proposition length (big-endian, should be 35 for ProveDlog)
    const prop_len = (@as(u16, result[1]) << 8) | @as(u16, result[2]);
    try std.testing.expectEqual(@as(u16, 35), prop_len);

    // Check ErgoTree header
    try std.testing.expectEqual(@as(u8, 0x08), result[3]); // v0 header
    try std.testing.expectEqual(@as(u8, 0xcd), result[4]); // SigmaProp opcode
}

test "challenge: conjecture types match reference" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(ConjectureType.and_connective));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(ConjectureType.or_connective));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(ConjectureType.threshold));
}
