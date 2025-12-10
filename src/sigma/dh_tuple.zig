//! Diffie-Hellman Tuple Verification (Chaum-Pedersen Protocol)
//!
//! Implements verification for ProveDHTuple proofs using the Chaum-Pedersen
//! protocol transformed via Fiat-Shamir.
//!
//! Protocol:
//! - Statement: (g, h, u, v) where u = g^x and v = h^x for secret x
//! - Commitment: (a, b) = (g^r, h^r) where r is random nonce
//! - Challenge: e = H(tree || message) (192 bits)
//! - Response: z = r + e*x (mod q)
//!
//! Verification:
//! - Compute a' = g^z * u^(-e)
//! - Compute b' = h^z * v^(-e)
//! - Verify a' == a and b' == b
//!
//! Reference: sigmastate/src/main/scala/sigmastate/crypto/DiffieHellmanTupleProtocol.scala

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const timing = @import("../crypto/timing.zig");
const challenge_mod = @import("challenge.zig");
const sigma_tree = @import("sigma_tree.zig");

const Point = secp256k1.Point;
const Challenge = challenge_mod.Challenge;
const ProveDHTuple = sigma_tree.ProveDHTuple;
const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;
const GROUP_SIZE = challenge_mod.GROUP_SIZE;
const SCALAR_SIZE = challenge_mod.SCALAR_SIZE;

// ============================================================================
// DH Tuple Error Types
// ============================================================================

pub const DHTupleError = error{
    /// One of the group elements is not a valid curve point
    InvalidGroupElement,
    /// Response scalar is invalid (>= curve order)
    InvalidResponse,
    /// Point decoding failed
    PointDecodingFailed,
    /// Commitment computation failed
    CommitmentFailed,
};

// ============================================================================
// DH Tuple Proof Types
// ============================================================================

/// First message (commitments) in DH tuple protocol
pub const FirstDHTupleMessage = struct {
    /// Commitment a = g^r (Point on curve)
    a: Point,
    /// Commitment b = h^r (Point on curve)
    b: Point,

    /// Encode both commitments to bytes
    pub fn encode(self: FirstDHTupleMessage) [GROUP_SIZE * 2]u8 {
        var result: [GROUP_SIZE * 2]u8 = undefined;
        const a_bytes = self.a.encode();
        const b_bytes = self.b.encode();
        @memcpy(result[0..GROUP_SIZE], &a_bytes);
        @memcpy(result[GROUP_SIZE .. GROUP_SIZE * 2], &b_bytes);
        return result;
    }
};

/// Second message (response) in DH tuple protocol
pub const SecondMessage = struct {
    /// Response z = r + e*x (mod q)
    z: [SCALAR_SIZE]u8,

    /// Convert response to scalar (4 x u64 limbs, little-endian)
    pub fn toScalar(self: SecondMessage) [4]u64 {
        var limbs: [4]u64 = undefined;
        // Big-endian bytes to little-endian limbs
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, self.z[offset..][0..8], .big);
        }
        return limbs;
    }
};

/// Complete DH tuple proof (unchecked)
pub const UncheckedDHTuple = struct {
    /// Proposition being proven
    proposition: ProveDHTuple,
    /// First message (commitments) - filled during verification
    first_message: ?FirstDHTupleMessage,
    /// Second message (response)
    second_message: SecondMessage,
    /// Challenge (computed or assigned)
    challenge: Challenge,
};

// ============================================================================
// Curve Order
// ============================================================================

/// secp256k1 curve order (n)
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const CURVE_ORDER: [4]u64 = .{
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
};

// ============================================================================
// DH Tuple Verification
// ============================================================================

/// Compute commitments (a, b) for DH tuple verification
///
/// Given:
/// - Proposition (g, h, u, v)
/// - Challenge e
/// - Response z
///
/// Compute:
/// - a = g^z * u^(-e)
/// - b = h^z * v^(-e)
///
/// This reconstructs the original commitment from the response
pub fn computeCommitment(
    proposition: ProveDHTuple,
    challenge: Challenge,
    response: SecondMessage,
) DHTupleError!FirstDHTupleMessage {
    // PRECONDITION 1: response has valid size
    assert(response.z.len == SCALAR_SIZE);
    // PRECONDITION 2: challenge has valid size
    assert(challenge.bytes.len == SOUNDNESS_BYTES);

    // Decode all 4 points from proposition
    const g = Point.decode(&proposition.g) catch return error.InvalidGroupElement;
    const h = Point.decode(&proposition.h) catch return error.InvalidGroupElement;
    const u = Point.decode(&proposition.u) catch return error.InvalidGroupElement;
    const v = Point.decode(&proposition.v) catch return error.InvalidGroupElement;

    // Get response scalar z
    const z = response.toScalar();

    // Validate z < n (curve order)
    if (cmpLimbs(z, CURVE_ORDER) != .lt) {
        return error.InvalidResponse;
    }

    // Get challenge scalar e (padded to 32 bytes)
    const e = challengeToScalar(challenge);

    // Compute g^z and h^z using constant-time multiplication
    const g_z = g.mulConstantTime(z);
    const h_z = h.mulConstantTime(z);

    // Compute u^e and v^e using constant-time multiplication
    const u_e = u.mulConstantTime(e);
    const v_e = v.mulConstantTime(e);

    // Compute u^(-e) and v^(-e) by negating the points
    const u_neg_e = u_e.neg();
    const v_neg_e = v_e.neg();

    // Compute a = g^z * u^(-e) = g^z + (-(u^e))
    const a = g_z.add(u_neg_e);
    // Compute b = h^z * v^(-e) = h^z + (-(v^e))
    const b = h_z.add(v_neg_e);

    // POSTCONDITION: both results are valid points
    assert(a.is_infinity or a.isValid());
    assert(b.is_infinity or b.isValid());

    return FirstDHTupleMessage{ .a = a, .b = b };
}

/// Verify DH tuple proof and return computed commitments
///
/// This performs the same computation as computeCommitment but also
/// validates all inputs and returns the computed commitments for
/// use in Fiat-Shamir challenge derivation.
pub fn verifyAndGetCommitment(
    proposition: ProveDHTuple,
    challenge: Challenge,
    response: SecondMessage,
) DHTupleError!FirstDHTupleMessage {
    // PRECONDITION 1: response has valid size
    assert(response.z.len == SCALAR_SIZE);
    // PRECONDITION 2: challenge has valid size
    assert(challenge.bytes.len == SOUNDNESS_BYTES);

    const z = response.toScalar();

    // Validate z < n
    if (cmpLimbs(z, CURVE_ORDER) != .lt) {
        return error.InvalidResponse;
    }

    const result = try computeCommitment(proposition, challenge, response);

    // POSTCONDITION: result commitments are valid points
    assert(result.a.is_infinity or result.a.isValid());
    assert(result.b.is_infinity or result.b.isValid());
    return result;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 24-byte challenge to 32-byte scalar (zero-padded, big-endian)
fn challengeToScalar(challenge: Challenge) [4]u64 {
    // PRECONDITION 1: challenge is 24 bytes
    assert(challenge.bytes.len == SOUNDNESS_BYTES);
    // PRECONDITION 2: 192-bit challenge fits in 256-bit scalar with room to spare
    assert(SOUNDNESS_BYTES < 32);

    // Create 32-byte array, zero-padded at the start (big-endian)
    var scalar_bytes: [32]u8 = [_]u8{0} ** 32;
    // Copy 24 bytes to the end (bytes 8-31)
    @memcpy(scalar_bytes[8..32], &challenge.bytes);

    // INVARIANT: first 8 bytes are zero (padding)
    assert(std.mem.eql(u8, scalar_bytes[0..8], &[_]u8{0} ** 8));

    // Convert to limbs (little-endian)
    var limbs: [4]u64 = undefined;
    for (0..4) |i| {
        const offset = 32 - (i + 1) * 8;
        limbs[i] = std.mem.readInt(u64, scalar_bytes[offset..][0..8], .big);
    }

    // POSTCONDITION 1: high limb has only 56 bits (since challenge is 192 bits)
    assert(limbs[3] >> 56 == 0);
    // POSTCONDITION 2: result is less than curve order (192 bits < 256 bits)
    assert(cmpLimbs(limbs, CURVE_ORDER) == .lt);

    return limbs;
}

/// Compare 4-limb values
fn cmpLimbs(a: [4]u64, b: [4]u64) std.math.Order {
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        if (a[i] > b[i]) return .gt;
        if (a[i] < b[i]) return .lt;
    }
    return .eq;
}

// ============================================================================
// Tests
// ============================================================================

test "dh_tuple: challengeToScalar pads correctly" {
    const chal = Challenge{ .bytes = [_]u8{0xFF} ** SOUNDNESS_BYTES };
    const scalar = challengeToScalar(chal);

    // Challenge is 24 bytes (192 bits), zero-padded at start to 32 bytes
    // When converted to little-endian limbs:
    // - limb[0] = scalar_bytes[24..32] = challenge[16..24] = 0xFFFFFFFFFFFFFFFF
    // - limb[1] = scalar_bytes[16..24] = challenge[8..16] = 0xFFFFFFFFFFFFFFFF
    // - limb[2] = scalar_bytes[8..16] = challenge[0..8] = 0xFFFFFFFFFFFFFFFF
    // - limb[3] = scalar_bytes[0..8] = padding = 0x0000000000000000
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[0]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[1]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[2]);
    try std.testing.expectEqual(@as(u64, 0), scalar[3]);
}

test "dh_tuple: SecondMessage toScalar" {
    var z_bytes: [32]u8 = [_]u8{0} ** 32;
    z_bytes[31] = 0x42; // LSB in big-endian

    const msg = SecondMessage{ .z = z_bytes };
    const scalar = msg.toScalar();

    // 0x42 should be in the lowest limb
    try std.testing.expectEqual(@as(u64, 0x42), scalar[0]);
    try std.testing.expectEqual(@as(u64, 0), scalar[1]);
    try std.testing.expectEqual(@as(u64, 0), scalar[2]);
    try std.testing.expectEqual(@as(u64, 0), scalar[3]);
}

test "dh_tuple: FirstDHTupleMessage encode" {
    const msg = FirstDHTupleMessage{
        .a = Point.G,
        .b = Point.G.double(),
    };

    const encoded = msg.encode();
    try std.testing.expectEqual(@as(usize, 66), encoded.len);

    // First 33 bytes should be G encoded
    const g_encoded = Point.G.encode();
    try std.testing.expectEqualSlices(u8, &g_encoded, encoded[0..33]);
}

test "dh_tuple: cmpLimbs ordering" {
    const a: [4]u64 = .{ 1, 0, 0, 0 };
    const b: [4]u64 = .{ 2, 0, 0, 0 };
    const c: [4]u64 = .{ 0, 1, 0, 0 };

    try std.testing.expectEqual(std.math.Order.lt, cmpLimbs(a, b));
    try std.testing.expectEqual(std.math.Order.gt, cmpLimbs(b, a));
    try std.testing.expectEqual(std.math.Order.eq, cmpLimbs(a, a));
    try std.testing.expectEqual(std.math.Order.lt, cmpLimbs(b, c));
}

test "dh_tuple: computeCommitment with valid inputs" {
    // Create a valid DH tuple: g, h, u=g^x, v=h^x for some x
    // For simplicity, use x=1, so u=g and v=h
    const g_bytes = Point.G.encode();
    const h_bytes = Point.G.double().encode(); // h = 2G
    const u_bytes = g_bytes; // u = g^1 = g
    const v_bytes = h_bytes; // v = h^1 = h

    const proposition = ProveDHTuple.init(g_bytes, h_bytes, u_bytes, v_bytes);

    // Use a zero challenge and response for testing
    const challenge = Challenge.zero;
    var response_bytes: [32]u8 = [_]u8{0} ** 32;
    response_bytes[31] = 1; // z = 1
    const response = SecondMessage{ .z = response_bytes };

    // Should not error
    const result = try computeCommitment(proposition, challenge, response);

    // With z=1 and e=0: a = g^1 * u^0 = g, b = h^1 * v^0 = h
    try std.testing.expect(result.a.eql(Point.G));
    try std.testing.expect(result.b.eql(Point.G.double()));
}

test "dh_tuple: rejects invalid response (z >= n)" {
    const g_bytes = Point.G.encode();
    const h_bytes = Point.G.double().encode();

    const proposition = ProveDHTuple.init(g_bytes, h_bytes, g_bytes, h_bytes);

    const challenge = Challenge.zero;
    // Set z = curve order (invalid, must be < n)
    var response_bytes: [32]u8 = undefined;
    std.mem.writeInt(u64, response_bytes[0..8], CURVE_ORDER[3], .big);
    std.mem.writeInt(u64, response_bytes[8..16], CURVE_ORDER[2], .big);
    std.mem.writeInt(u64, response_bytes[16..24], CURVE_ORDER[1], .big);
    std.mem.writeInt(u64, response_bytes[24..32], CURVE_ORDER[0], .big);
    const response = SecondMessage{ .z = response_bytes };

    const result = computeCommitment(proposition, challenge, response);
    try std.testing.expectError(error.InvalidResponse, result);
}
