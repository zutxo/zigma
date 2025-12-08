//! Cryptographic Hash Functions
//!
//! Provides Blake2b-256 and SHA-256 hashing for ErgoTree operations.
//! Uses Zig standard library implementations for correctness and determinism.
//!
//! Blake2b-256: Used for box IDs, transaction IDs, general hashing
//! SHA-256: Used for compatibility with Bitcoin-style proofs
//!
//! Reference: Ergo uses Blake2b-256 as primary hash function

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Configuration
// ============================================================================

/// Blake2b-256 output size in bytes
pub const blake2b256_digest_length: usize = 32;

/// SHA-256 output size in bytes
pub const sha256_digest_length: usize = 32;

// Compile-time sanity checks
comptime {
    assert(blake2b256_digest_length == 32);
    assert(sha256_digest_length == 32);
}

// ============================================================================
// One-shot Hash Functions
// ============================================================================

/// Compute Blake2b-256 hash of data (32 bytes output)
/// Used for: Box IDs, Transaction IDs, general hashing in Ergo
pub fn blake2b256(data: []const u8) [32]u8 {
    assert(data.len <= std.math.maxInt(usize));

    var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
    hasher.update(data);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

/// Compute SHA-256 hash of data (32 bytes output)
/// Used for: Bitcoin compatibility, merkle trees, certain proofs
pub fn sha256(data: []const u8) [32]u8 {
    assert(data.len <= std.math.maxInt(usize));

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

// ============================================================================
// Streaming Hashers (for large data)
// ============================================================================

/// Streaming Blake2b-256 hasher for incremental updates
pub const Blake2b256Hasher = struct {
    state: std.crypto.hash.blake2.Blake2b256,

    pub fn init() Blake2b256Hasher {
        return .{ .state = std.crypto.hash.blake2.Blake2b256.init(.{}) };
    }

    pub fn update(self: *Blake2b256Hasher, data: []const u8) void {
        assert(data.len <= std.math.maxInt(usize));
        self.state.update(data);
    }

    pub fn finalize(self: *Blake2b256Hasher) [32]u8 {
        var result: [32]u8 = undefined;
        self.state.final(&result);
        return result;
    }

    /// Reset hasher for reuse
    pub fn reset(self: *Blake2b256Hasher) void {
        self.state = std.crypto.hash.blake2.Blake2b256.init(.{});
    }
};

/// Streaming SHA-256 hasher for incremental updates
pub const Sha256Hasher = struct {
    state: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha256Hasher {
        return .{ .state = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha256Hasher, data: []const u8) void {
        assert(data.len <= std.math.maxInt(usize));
        self.state.update(data);
    }

    pub fn finalize(self: *Sha256Hasher) [32]u8 {
        var result: [32]u8 = undefined;
        self.state.final(&result);
        return result;
    }

    /// Reset hasher for reuse
    pub fn reset(self: *Sha256Hasher) void {
        self.state = std.crypto.hash.sha2.Sha256.init(.{});
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert hash bytes to hex string (for debugging/display)
pub fn toHex(hash: [32]u8) [64]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [64]u8 = undefined;

    for (hash, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "hash: blake2b256 empty input" {
    // Blake2b-256 of empty string
    // Reference: https://blake2.net/blake2_test_vectors.txt
    const result = blake2b256(&[_]u8{});

    // Known hash of empty input
    const expected = [_]u8{
        0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
        0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
        0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
        0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash: blake2b256 abc" {
    // Blake2b-256 of "abc"
    const result = blake2b256("abc");

    const expected = [_]u8{
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash: sha256 empty input" {
    // SHA-256 of empty string (NIST test vector)
    const result = sha256(&[_]u8{});

    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash: sha256 abc" {
    // SHA-256 of "abc" (NIST test vector)
    const result = sha256("abc");

    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };

    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash: blake2b256 streaming matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";

    // One-shot
    const oneshot = blake2b256(data);

    // Streaming
    var hasher = Blake2b256Hasher.init();
    hasher.update(data[0..10]);
    hasher.update(data[10..20]);
    hasher.update(data[20..]);
    const streamed = hasher.finalize();

    try std.testing.expectEqualSlices(u8, &oneshot, &streamed);
}

test "hash: sha256 streaming matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";

    // One-shot
    const oneshot = sha256(data);

    // Streaming
    var hasher = Sha256Hasher.init();
    hasher.update(data[0..15]);
    hasher.update(data[15..30]);
    hasher.update(data[30..]);
    const streamed = hasher.finalize();

    try std.testing.expectEqualSlices(u8, &oneshot, &streamed);
}

test "hash: hasher reset" {
    var hasher = Blake2b256Hasher.init();
    hasher.update("first");
    hasher.reset();
    hasher.update("abc");
    const result = hasher.finalize();

    const expected = blake2b256("abc");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash: toHex" {
    const hash = sha256("abc");
    const hex = toHex(hash);

    // First few bytes should be "ba7816bf..."
    try std.testing.expectEqualSlices(u8, "ba7816bf", hex[0..8]);
}

test "hash: deterministic across calls" {
    const data = "test data for determinism check";

    const hash1 = blake2b256(data);
    const hash2 = blake2b256(data);
    const hash3 = sha256(data);
    const hash4 = sha256(data);

    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
    try std.testing.expectEqualSlices(u8, &hash3, &hash4);
}
