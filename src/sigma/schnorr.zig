//! Schnorr Signature Verification (ProveDlog)
//!
//! Implements verification for discrete log proofs (ProveDlog) using
//! the Schnorr identification protocol transformed via Fiat-Shamir.
//!
//! Protocol:
//! - Public key: h = g^x (prover knows secret x)
//! - Commitment: a = g^r (random nonce r)
//! - Challenge: e = H(tree || message) (192 bits)
//! - Response: z = r + e*x (mod q)
//!
//! Verification: g^z == a * h^e
//! Equivalently: a == g^z * h^(-e)
//!
//! Reference: sigmastate/src/main/scala/sigmastate/crypto/DLogProtocol.scala

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const challenge_mod = @import("challenge.zig");
const sigma_tree = @import("sigma_tree.zig");

const Point = secp256k1.Point;
const FieldElement = secp256k1.FieldElement;
const Challenge = challenge_mod.Challenge;
const ProveDlog = sigma_tree.ProveDlog;
const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;
const GROUP_SIZE = challenge_mod.GROUP_SIZE;
const SCALAR_SIZE = challenge_mod.SCALAR_SIZE;

// ============================================================================
// Schnorr Proof Types
// ============================================================================

/// Error types for Schnorr verification
pub const SchnorrError = error{
    /// Public key is not a valid curve point
    InvalidPublicKey,
    /// Commitment is not a valid curve point
    InvalidCommitment,
    /// Response scalar is invalid (>= curve order)
    InvalidResponse,
    /// Verification failed (signature is invalid)
    VerificationFailed,
    /// Point decoding failed
    PointDecodingFailed,
};

/// First message (commitment) in Schnorr protocol
pub const FirstMessage = struct {
    /// Commitment a = g^r (compressed EC point, 33 bytes)
    a: [GROUP_SIZE]u8,

    /// Decode commitment to curve point
    pub fn toPoint(self: FirstMessage) SchnorrError!Point {
        return Point.decode(&self.a) catch return error.PointDecodingFailed;
    }
};

/// Second message (response) in Schnorr protocol
pub const SecondMessage = struct {
    /// Response z = r + e*x (mod q)
    z: [SCALAR_SIZE]u8,

    /// Convert response to scalar (4 x u64 limbs, little-endian)
    pub fn toScalar(self: SecondMessage) [4]u64 {
        var limbs: [4]u64 = undefined;
        // Big-endian to little-endian limbs
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, self.z[offset..][0..8], .big);
        }
        return limbs;
    }
};

/// Complete Schnorr proof (unchecked)
pub const UncheckedSchnorr = struct {
    /// Proposition being proven
    proposition: ProveDlog,
    /// First message (commitment)
    first_message: FirstMessage,
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

// Compile-time assertions
comptime {
    // Curve order is slightly less than 2^256
    assert(CURVE_ORDER[3] == 0xFFFFFFFFFFFFFFFF);
    assert(CURVE_ORDER[2] == 0xFFFFFFFFFFFFFFFE);
}

// ============================================================================
// Schnorr Verification
// ============================================================================

/// Verify a Schnorr proof (ProveDlog)
///
/// Given:
/// - Public key h (from proposition)
/// - Challenge e (from proof)
/// - Response z (from proof)
/// - Commitment a (from proof)
///
/// Verify: g^z == a * h^e
///
/// This is computed as: a' = g^z * h^(-e), verify a' == a
pub fn verify(proof: UncheckedSchnorr) SchnorrError!bool {
    // Precondition: proof has all required components
    assert(proof.first_message.a.len == GROUP_SIZE);
    assert(proof.second_message.z.len == SCALAR_SIZE);
    assert(proof.challenge.bytes.len == SOUNDNESS_BYTES);

    // 1. Decode public key from proposition
    const h = Point.decode(&proof.proposition.public_key) catch {
        return error.InvalidPublicKey;
    };

    // 2. Decode commitment
    const a = proof.first_message.toPoint() catch {
        return error.InvalidCommitment;
    };

    // 3. Get response scalar
    const z = proof.second_message.toScalar();

    // Validate z < n (curve order)
    if (cmpLimbs(z, CURVE_ORDER) != .lt) {
        return error.InvalidResponse;
    }

    // 4. Compute g^z
    const g = Point.G;
    const g_z = g.mul(z);

    // 5. Compute challenge as scalar (pad 24 bytes to 32 bytes)
    const e = challengeToScalar(proof.challenge);

    // 6. Compute h^e
    const h_e = h.mul(e);

    // 7. Compute h^(-e) = -(h^e)
    const h_neg_e = h_e.neg();

    // 8. Compute a' = g^z * h^(-e) = g^z + (-(h^e))
    const a_computed = g_z.add(h_neg_e);

    // 9. Verify a' == a
    // Postcondition: verification result is deterministic
    return a_computed.eql(a);
}

/// Compute expected commitment from response and challenge
/// a = g^z * h^(-e)
/// Used when verifier needs to reconstruct commitment
pub fn computeCommitment(
    proposition: ProveDlog,
    challenge: Challenge,
    response: SecondMessage,
) SchnorrError!Point {
    // Precondition: inputs are valid
    assert(response.z.len == SCALAR_SIZE);
    assert(challenge.bytes.len == SOUNDNESS_BYTES);

    const h = Point.decode(&proposition.public_key) catch {
        return error.InvalidPublicKey;
    };

    const z = response.toScalar();
    const e = challengeToScalar(challenge);

    const g_z = Point.G.mul(z);
    const h_e = h.mul(e);
    const h_neg_e = h_e.neg();

    const result = g_z.add(h_neg_e);

    // Postcondition: result is a valid point
    assert(result.is_infinity or result.isValid());
    return result;
}

/// Verify using challenge + response only (commitment computed)
/// Returns the computed commitment if verification passes
pub fn verifyAndGetCommitment(
    proposition: ProveDlog,
    challenge: Challenge,
    response: SecondMessage,
) SchnorrError!Point {
    // Precondition: inputs are valid
    assert(response.z.len == SCALAR_SIZE);

    const z = response.toScalar();

    // Validate z < n
    if (cmpLimbs(z, CURVE_ORDER) != .lt) {
        return error.InvalidResponse;
    }

    return computeCommitment(proposition, challenge, response);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 24-byte challenge to 32-byte scalar (zero-padded, big-endian)
fn challengeToScalar(challenge: Challenge) [4]u64 {
    // Precondition: challenge is 24 bytes
    assert(challenge.bytes.len == SOUNDNESS_BYTES);

    // Create 32-byte array, zero-padded at the start (big-endian)
    var scalar_bytes: [32]u8 = [_]u8{0} ** 32;
    // Copy 24 bytes to the end (bytes 8-31)
    @memcpy(scalar_bytes[8..32], &challenge.bytes);

    // Convert to limbs (little-endian)
    var limbs: [4]u64 = undefined;
    for (0..4) |i| {
        const offset = 32 - (i + 1) * 8;
        limbs[i] = std.mem.readInt(u64, scalar_bytes[offset..][0..8], .big);
    }

    // Postcondition: high limb has only 56 bits (since challenge is 192 bits)
    assert(limbs[3] >> 56 == 0);
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

test "schnorr: challengeToScalar pads correctly" {
    const chal = Challenge{ .bytes = [_]u8{0xFF} ** SOUNDNESS_BYTES };
    const scalar = challengeToScalar(chal);

    // Challenge is 24 bytes (192 bits), zero-padded at start to 32 bytes.
    // Scalar bytes layout (big-endian): [0x00 * 8] || challenge[0..24]
    // When converted to little-endian limbs:
    // - limb[0] = scalar_bytes[24..32] = challenge[16..24] = 0xFFFFFFFFFFFFFFFF
    // - limb[1] = scalar_bytes[16..24] = challenge[8..16] = 0xFFFFFFFFFFFFFFFF
    // - limb[2] = scalar_bytes[8..16] = challenge[0..8] = 0xFFFFFFFFFFFFFFFF
    // - limb[3] = scalar_bytes[0..8] = padding = 0x0000000000000000
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[0]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[1]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), scalar[2]);
    // Top limb is zero (padding)
    try std.testing.expectEqual(@as(u64, 0), scalar[3]);
}

test "schnorr: challengeToScalar zero challenge" {
    const challenge = Challenge.zero;
    const scalar = challengeToScalar(challenge);

    try std.testing.expectEqual(@as(u64, 0), scalar[0]);
    try std.testing.expectEqual(@as(u64, 0), scalar[1]);
    try std.testing.expectEqual(@as(u64, 0), scalar[2]);
    try std.testing.expectEqual(@as(u64, 0), scalar[3]);
}

test "schnorr: cmpLimbs ordering" {
    const a: [4]u64 = .{ 1, 0, 0, 0 };
    const b: [4]u64 = .{ 2, 0, 0, 0 };
    const c: [4]u64 = .{ 0, 1, 0, 0 };

    try std.testing.expectEqual(std.math.Order.lt, cmpLimbs(a, b));
    try std.testing.expectEqual(std.math.Order.gt, cmpLimbs(b, a));
    try std.testing.expectEqual(std.math.Order.eq, cmpLimbs(a, a));
    try std.testing.expectEqual(std.math.Order.lt, cmpLimbs(b, c)); // c has higher limb set
}

test "schnorr: SecondMessage toScalar" {
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

test "schnorr: FirstMessage decodes valid point" {
    // Generator point G in compressed form
    const g_bytes = Point.G.encode();
    const msg = FirstMessage{ .a = g_bytes };

    const point = try msg.toPoint();
    try std.testing.expect(point.eql(Point.G));
}

test "schnorr: verify rejects invalid public key" {
    // All zeros is NOT a valid point (except for infinity which is 33 zeros)
    const bad_pk: [33]u8 = [_]u8{0x02} ++ [_]u8{0} ** 32;

    const proof = UncheckedSchnorr{
        .proposition = ProveDlog{ .public_key = bad_pk },
        .first_message = FirstMessage{ .a = Point.G.encode() },
        .second_message = SecondMessage{ .z = [_]u8{1} ++ [_]u8{0} ** 31 },
        .challenge = Challenge.zero,
    };

    const result = verify(proof);
    try std.testing.expectError(error.InvalidPublicKey, result);
}

test "schnorr: CURVE_ORDER is less than 2^256" {
    const max: [4]u64 = .{ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
    try std.testing.expectEqual(std.math.Order.lt, cmpLimbs(CURVE_ORDER, max));
}

test "schnorr: zero response is valid (edge case)" {
    // z = 0 is technically valid, produces g^0 = infinity
    const z_zero = SecondMessage{ .z = [_]u8{0} ** 32 };
    const scalar = z_zero.toScalar();

    try std.testing.expect(cmpLimbs(scalar, CURVE_ORDER) == .lt);
}
