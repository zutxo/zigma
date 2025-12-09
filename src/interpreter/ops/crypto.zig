//! Crypto Operations for ErgoTree Interpreter
//!
//! Provides cryptographic hash functions as interpreter operations.
//! Wraps the underlying hash implementations from crypto/hash.zig.
//!
//! Operations:
//! - CalcBlake2b256 (0xCB): Blake2b-256 hash
//! - CalcSha256 (0xCC): SHA-256 hash
//!
//! Reference: sigmastate CalcBlake2b256, CalcSha256

const std = @import("std");
const assert = std.debug.assert;
const hash = @import("../../crypto/hash.zig");

// ============================================================================
// Configuration
// ============================================================================

/// Output size for both hash functions
pub const hash_output_size: usize = 32;

// Compile-time sanity checks
comptime {
    assert(hash_output_size == hash.blake2b256_digest_length);
    assert(hash_output_size == hash.sha256_digest_length);
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
