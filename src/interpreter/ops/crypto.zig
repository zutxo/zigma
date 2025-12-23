//! Crypto Operations for ErgoTree Interpreter
//!
//! Provides cryptographic operations as interpreter operations.
//! Wraps the underlying implementations from crypto/hash.zig and crypto/secp256k1.zig.
//!
//! Hash Operations:
//! - CalcBlake2b256 (0xCB): Blake2b-256 hash
//! - CalcSha256 (0xCC): SHA-256 hash
//!
//! Group Element Operations:
//! - DecodePoint (0xD0): Decode Coll[Byte] to GroupElement
//! - GroupGenerator (0xD2): Return generator point G
//! - Exponentiate (0xD3): Scalar multiplication (point * scalar)
//! - MultiplyGroup (0xD4): Point addition (point + point)
//!
//! Reference: sigmastate CalcBlake2b256, CalcSha256, GroupElement operations

const std = @import("std");
const assert = std.debug.assert;
const hash = @import("../../crypto/hash.zig");
const secp256k1 = @import("../../crypto/secp256k1.zig");

// ============================================================================
// Configuration
// ============================================================================

/// Output size for both hash functions
pub const hash_output_size: usize = 32;

/// GroupElement compressed size (SEC1)
pub const group_element_size: usize = 33;

// Re-export Point and error types
pub const Point = secp256k1.Point;
pub const Secp256k1Error = secp256k1.Secp256k1Error;

// Compile-time sanity checks
comptime {
    assert(hash_output_size == hash.blake2b256_digest_length);
    assert(hash_output_size == hash.sha256_digest_length);
    assert(group_element_size == 33);
}

// ============================================================================
// Hash Operations
// ============================================================================

/// Compute Blake2b-256 hash of input bytes
/// Input: Coll[Byte] of any length
/// Output: Coll[Byte] of length 32
pub fn calcBlake2b256(input: []const u8) [32]u8 {
    // PRECONDITION: input is valid (can be empty)
    // No size limit - hash functions handle any input size

    const result = hash.blake2b256(input);

    // POSTCONDITION: result is exactly 32 bytes
    assert(result.len == 32);
    return result;
}

/// Compute SHA-256 hash of input bytes
/// Input: Coll[Byte] of any length
/// Output: Coll[Byte] of length 32
pub fn calcSha256(input: []const u8) [32]u8 {
    // PRECONDITION: input is valid (can be empty)

    const result = hash.sha256(input);

    // POSTCONDITION: result is exactly 32 bytes
    assert(result.len == 32);
    return result;
}

// ============================================================================
// Group Element Operations
// ============================================================================

/// Error for group element operations
pub const GroupOpError = error{
    /// Input is wrong size
    InvalidLength,
    /// Point is not on curve or invalid encoding
    InvalidPoint,
};

/// Decode compressed SEC1 bytes to a Point
/// Input: Coll[Byte] of length 33
/// Output: Point on secp256k1
pub fn decodePoint(input: []const u8) GroupOpError!Point {
    // PRECONDITION: input must be exactly 33 bytes
    if (input.len != 33) return error.InvalidLength;

    // INVARIANT: We have exactly 33 bytes for SEC1 compressed format
    assert(input.len == group_element_size);

    const point = Point.decode(input[0..33]) catch return error.InvalidPoint;

    // POSTCONDITION: returned point is valid (on curve or infinity)
    assert(point.is_infinity or point.isValid());
    return point;
}

/// Get the generator point G
/// Output: GroupElement (33 bytes compressed SEC1)
pub fn groupGenerator() [group_element_size]u8 {
    // PRECONDITION: Generator G is well-defined (always true)

    const encoded = Point.G.encode();

    // POSTCONDITION: result is exactly 33 bytes
    assert(encoded.len == group_element_size);
    // POSTCONDITION: generator is non-infinity
    assert(encoded[0] == 0x02 or encoded[0] == 0x03);
    return encoded;
}

/// Scalar multiplication: point * scalar
/// Input: GroupElement (33 bytes), BigInt scalar (up to 32 bytes big-endian)
/// Output: GroupElement (33 bytes)
pub fn exponentiate(point_bytes: *const [33]u8, scalar: []const u8) GroupOpError![group_element_size]u8 {
    // PRECONDITION: scalar is at most 32 bytes (256 bits)
    if (scalar.len > 32) return error.InvalidLength;

    // Decode the point
    const point = Point.decode(point_bytes) catch return error.InvalidPoint;

    // INVARIANT: point is valid (on curve or infinity)
    assert(point.is_infinity or point.isValid());

    // Convert scalar bytes to 4 x u64 limbs (little-endian limb order, big-endian bytes)
    var scalar_limbs: [4]u64 = .{ 0, 0, 0, 0 };
    if (scalar.len > 0) {
        // BigInt is stored as big-endian (MSB first)
        // We need to convert to little-endian limbs
        var padded: [32]u8 = [_]u8{0} ** 32;
        const offset = 32 - scalar.len;
        @memcpy(padded[offset..], scalar);

        // Convert big-endian bytes to little-endian limbs
        scalar_limbs[3] = std.mem.readInt(u64, padded[0..8], .big);
        scalar_limbs[2] = std.mem.readInt(u64, padded[8..16], .big);
        scalar_limbs[1] = std.mem.readInt(u64, padded[16..24], .big);
        scalar_limbs[0] = std.mem.readInt(u64, padded[24..32], .big);
    }

    // Perform scalar multiplication
    const result = point.mul(scalar_limbs);

    // POSTCONDITION: result is valid (on curve or infinity)
    assert(result.is_infinity or result.isValid());

    return result.encode();
}

/// Point addition: point1 + point2 (group operation)
/// Note: Named "multiply" in ErgoTree but it's actually point addition
/// Input: Two GroupElements (33 bytes each)
/// Output: GroupElement (33 bytes)
pub fn multiplyGroup(point1_bytes: *const [33]u8, point2_bytes: *const [33]u8) GroupOpError![group_element_size]u8 {
    // Decode both points
    const point1 = Point.decode(point1_bytes) catch return error.InvalidPoint;
    const point2 = Point.decode(point2_bytes) catch return error.InvalidPoint;

    // INVARIANT: both points are valid (on curve or infinity)
    assert(point1.is_infinity or point1.isValid());
    assert(point2.is_infinity or point2.isValid());

    // Perform point addition (the "group multiplication")
    const result = point1.add(point2);

    // POSTCONDITION: result is valid (on curve or infinity)
    assert(result.is_infinity or result.isValid());

    return result.encode();
}

/// Point negation: -point (inverse in the group)
/// Input: GroupElement (33 bytes)
/// Output: GroupElement (33 bytes)
/// Reference: Scala SGroupElement.negate / Rust GroupElement.negate
pub fn negatePoint(point_bytes: *const [33]u8) GroupOpError![group_element_size]u8 {
    // Decode the point
    const point = Point.decode(point_bytes) catch return error.InvalidPoint;

    // INVARIANT: point is valid (on curve or infinity)
    assert(point.is_infinity or point.isValid());

    // Negate the point (-P has same x but negated y)
    const result = point.neg();

    // POSTCONDITION: result is valid (on curve or infinity)
    assert(result.is_infinity or result.isValid());

    return result.encode();
}

// ============================================================================
// Tests
// ============================================================================

test "crypto: calcBlake2b256 empty input" {
    const result = calcBlake2b256(&[_]u8{});

    // Known hash of empty input (same as hash.zig test)
    const expected = [_]u8{
        0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
        0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
        0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
        0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "crypto: calcBlake2b256 abc" {
    const result = calcBlake2b256("abc");

    const expected = [_]u8{
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "crypto: calcSha256 empty input" {
    const result = calcSha256(&[_]u8{});

    // NIST test vector for empty input
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "crypto: calcSha256 abc" {
    const result = calcSha256("abc");

    // NIST test vector for "abc"
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "crypto: determinism" {
    const data = "test data for determinism";

    const blake1 = calcBlake2b256(data);
    const blake2 = calcBlake2b256(data);
    const sha1 = calcSha256(data);
    const sha2 = calcSha256(data);

    try std.testing.expectEqualSlices(u8, &blake1, &blake2);
    try std.testing.expectEqualSlices(u8, &sha1, &sha2);

    // Blake2b and SHA256 should produce different results
    try std.testing.expect(!std.mem.eql(u8, &blake1, &sha1));
}

// ============================================================================
// Group Operation Tests
// ============================================================================

test "crypto: groupGenerator returns valid point" {
    const g = groupGenerator();
    // Should be a valid compressed point (0x02 or 0x03 prefix)
    try std.testing.expect(g[0] == 0x02 or g[0] == 0x03);
    // Should decode back to G
    const point = try decodePoint(&g);
    try std.testing.expect(point.eql(Point.G));
}

test "crypto: decodePoint rejects wrong length" {
    var short: [32]u8 = undefined;
    @memset(&short, 0);
    try std.testing.expectError(error.InvalidLength, decodePoint(&short));

    var long: [34]u8 = undefined;
    @memset(&long, 0);
    try std.testing.expectError(error.InvalidLength, decodePoint(&long));
}

test "crypto: decodePoint accepts infinity (33 zeros)" {
    var infinity_bytes: [33]u8 = [_]u8{0} ** 33;
    const point = try decodePoint(&infinity_bytes);
    try std.testing.expect(point.is_infinity);
}

test "crypto: decodePoint rejects invalid encoding" {
    var bad: [33]u8 = undefined;
    bad[0] = 0x04; // Uncompressed prefix not supported
    @memset(bad[1..], 0);
    try std.testing.expectError(error.InvalidPoint, decodePoint(&bad));
}

test "crypto: exponentiate by 1 returns same point" {
    const g = groupGenerator();
    const scalar_one: [1]u8 = .{1};
    const result = try exponentiate(&g, &scalar_one);
    try std.testing.expectEqualSlices(u8, &g, &result);
}

test "crypto: exponentiate by 2 equals G + G" {
    const g = groupGenerator();
    const scalar_two: [1]u8 = .{2};
    const exp_result = try exponentiate(&g, &scalar_two);

    // G + G using multiplyGroup
    const add_result = try multiplyGroup(&g, &g);
    try std.testing.expectEqualSlices(u8, &exp_result, &add_result);
}

test "crypto: exponentiate by 0 returns infinity" {
    const g = groupGenerator();
    const scalar_zero: [1]u8 = .{0};
    const result = try exponentiate(&g, &scalar_zero);
    // Infinity is encoded as 33 zeros
    const expected_infinity: [33]u8 = [_]u8{0} ** 33;
    try std.testing.expectEqualSlices(u8, &expected_infinity, &result);
}

test "crypto: multiplyGroup is commutative" {
    const g = groupGenerator();
    const scalar_two: [1]u8 = .{2};
    const two_g = try exponentiate(&g, &scalar_two);

    // G + 2G should equal 2G + G
    const result1 = try multiplyGroup(&g, &two_g);
    const result2 = try multiplyGroup(&two_g, &g);
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "crypto: multiplyGroup with infinity is identity" {
    const g = groupGenerator();
    const infinity: [33]u8 = [_]u8{0} ** 33;

    // G + O = G
    const result = try multiplyGroup(&g, &infinity);
    try std.testing.expectEqualSlices(u8, &g, &result);
}

test "crypto: group operations determinism" {
    const g = groupGenerator();
    const g2 = groupGenerator();
    try std.testing.expectEqualSlices(u8, &g, &g2);

    const scalar: [1]u8 = .{42};
    const exp1 = try exponentiate(&g, &scalar);
    const exp2 = try exponentiate(&g, &scalar);
    try std.testing.expectEqualSlices(u8, &exp1, &exp2);
}
