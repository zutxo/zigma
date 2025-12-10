//! Constant-Time Cryptographic Utilities
//!
//! Provides timing-safe operations for cryptographic comparisons and selections.
//! These functions execute in constant time regardless of input values,
//! preventing timing side-channel attacks.
//!
//! CRITICAL: These functions must NEVER use:
//! - Early returns based on data
//! - Conditional branches based on secret data
//! - Short-circuit boolean evaluation
//!
//! Reference: libsodium crypto_verify, Go subtle.ConstantTimeCompare

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Constant-Time Comparison
// ============================================================================

/// Constant-time byte array equality comparison.
/// Returns true if arrays are equal, false otherwise.
/// CRITICAL: Always examines all bytes - no early exit.
///
/// Time complexity: O(n) regardless of where arrays differ
///
/// Example:
/// ```zig
/// const a = [_]u8{ 0x01, 0x02, 0x03 };
/// const b = [_]u8{ 0x01, 0x02, 0x03 };
/// const eq = constantTimeEql(&a, &b); // true
/// ```
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    // PRECONDITION 1: slices must have same length for meaningful comparison
    assert(a.len == b.len);
    // PRECONDITION 2: slices are not unreasonably large
    assert(a.len <= 1024 * 1024); // 1MB max

    var diff: u8 = 0;

    // XOR accumulator - no early exit
    for (a, b) |x, y| {
        diff |= x ^ y;
    }

    // POSTCONDITION: diff is 0 iff all bytes matched
    // Convert to bool without branching on actual value
    return diff == 0;
}

/// Constant-time equality for fixed-size arrays.
/// Compile-time known size allows better optimization.
pub fn constantTimeEqlFixed(comptime N: usize, a: *const [N]u8, b: *const [N]u8) bool {
    // PRECONDITION: N is reasonable size
    comptime assert(N <= 1024 * 1024);

    var diff: u8 = 0;

    inline for (0..N) |i| {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}

// ============================================================================
// Constant-Time Selection
// ============================================================================

/// Constant-time conditional selection for u8.
/// Returns `a` if `choice == 0`, `b` if `choice == 1`.
/// CRITICAL: No branch on choice value.
///
/// Example:
/// ```zig
/// const result = constantTimeSelect(u8, 0xAA, 0xBB, 1); // returns 0xBB
/// ```
pub fn constantTimeSelect(comptime T: type, a: T, b: T, choice: u1) T {
    // PRECONDITION: T must be an integer type
    comptime assert(@typeInfo(T) == .int);

    // Create mask: 0 if choice == 0, all 1s if choice == 1
    // -choice in two's complement: 0 -> 0, 1 -> 0xFF...FF
    const mask = @as(T, 0) -% @as(T, choice);

    // Select: a XOR (mask AND (a XOR b))
    // If mask == 0: a XOR 0 = a
    // If mask == all 1s: a XOR (a XOR b) = b
    return a ^ (mask & (a ^ b));
}

/// Constant-time conditional selection for u64.
pub fn constantTimeSelectU64(a: u64, b: u64, choice: u1) u64 {
    return constantTimeSelect(u64, a, b, choice);
}

/// Constant-time conditional swap.
/// Swaps a and b if choice == 1, leaves unchanged if choice == 0.
/// CRITICAL: No branch on choice value.
pub fn constantTimeSwap(comptime T: type, a: *T, b: *T, choice: u1) void {
    comptime assert(@typeInfo(T) == .int);

    const mask = @as(T, 0) -% @as(T, choice);
    const diff = mask & (a.* ^ b.*);

    a.* ^= diff;
    b.* ^= diff;
}

/// Constant-time conditional swap for byte arrays.
pub fn constantTimeSwapBytes(comptime N: usize, a: *[N]u8, b: *[N]u8, choice: u1) void {
    const mask = @as(u8, 0) -% @as(u8, choice);

    for (0..N) |i| {
        const diff = mask & (a[i] ^ b[i]);
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

// ============================================================================
// Constant-Time Comparison (Ordering)
// ============================================================================

/// Constant-time less-than comparison for u64.
/// Returns 1 if a < b, 0 otherwise.
/// Uses bit manipulation to detect a < b without branching.
pub fn constantTimeLtU64(a: u64, b: u64) u1 {
    // Compute a - b with wraparound
    // If a < b, the subtraction will wrap around (borrow occurs)
    const diff = a -% b;

    // Check if a < b using the formula:
    // a < b iff (~a & b) | ((~(a ^ b)) & diff) has MSB set
    // - (~a & b): captures cases where b has a 1 where a has 0
    // - ((~(a ^ b)) & diff): captures borrow propagation
    const lt = @as(u1, @truncate((~a & b) >> 63)) |
        @as(u1, @truncate(((~(a ^ b)) & diff) >> 63));

    return lt;
}

/// Constant-time equality comparison for u64.
/// Returns 1 if a == b, 0 otherwise.
pub fn constantTimeEqU64(a: u64, b: u64) u1 {
    const diff = a ^ b;
    // diff is 0 iff a == b
    // Reduce to single bit using OR cascade
    const reduced = diff | (diff >> 32);
    const reduced2 = reduced | (reduced >> 16);
    const reduced3 = reduced2 | (reduced2 >> 8);
    const reduced4 = reduced3 | (reduced3 >> 4);
    const reduced5 = reduced4 | (reduced4 >> 2);
    const reduced6 = reduced5 | (reduced5 >> 1);

    // Invert: 0 -> 1, non-zero -> 0
    return @as(u1, @truncate(~reduced6));
}

// ============================================================================
// Tests
// ============================================================================

test "timing: constantTimeEql equal arrays" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    try std.testing.expect(constantTimeEql(&a, &b));
}

test "timing: constantTimeEql different arrays" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x05 }; // Last byte differs

    try std.testing.expect(!constantTimeEql(&a, &b));
}

test "timing: constantTimeEql empty arrays" {
    const a = [_]u8{};
    const b = [_]u8{};

    try std.testing.expect(constantTimeEql(&a, &b));
}

test "timing: constantTimeEql all zeros vs all ones" {
    const a = [_]u8{0x00} ** 32;
    const b = [_]u8{0xFF} ** 32;

    try std.testing.expect(!constantTimeEql(&a, &b));
}

test "timing: constantTimeEqlFixed" {
    const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const c = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };

    try std.testing.expect(constantTimeEqlFixed(4, &a, &b));
    try std.testing.expect(!constantTimeEqlFixed(4, &a, &c));
}

test "timing: constantTimeSelect u8" {
    const a: u8 = 0xAA;
    const b: u8 = 0xBB;

    try std.testing.expectEqual(a, constantTimeSelect(u8, a, b, 0));
    try std.testing.expectEqual(b, constantTimeSelect(u8, a, b, 1));
}

test "timing: constantTimeSelect u64" {
    const a: u64 = 0xDEADBEEFCAFEBABE;
    const b: u64 = 0x1234567890ABCDEF;

    try std.testing.expectEqual(a, constantTimeSelectU64(a, b, 0));
    try std.testing.expectEqual(b, constantTimeSelectU64(a, b, 1));
}

test "timing: constantTimeSwap" {
    var a: u64 = 100;
    var b: u64 = 200;

    // No swap
    constantTimeSwap(u64, &a, &b, 0);
    try std.testing.expectEqual(@as(u64, 100), a);
    try std.testing.expectEqual(@as(u64, 200), b);

    // Swap
    constantTimeSwap(u64, &a, &b, 1);
    try std.testing.expectEqual(@as(u64, 200), a);
    try std.testing.expectEqual(@as(u64, 100), b);
}

test "timing: constantTimeSwapBytes" {
    var a = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // No swap
    constantTimeSwapBytes(4, &a, &b, 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, &a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, &b);

    // Swap
    constantTimeSwapBytes(4, &a, &b, 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, &a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, &b);
}

test "timing: constantTimeLtU64" {
    // Basic comparisons
    try std.testing.expectEqual(@as(u1, 1), constantTimeLtU64(5, 10));
    try std.testing.expectEqual(@as(u1, 0), constantTimeLtU64(10, 5));
    try std.testing.expectEqual(@as(u1, 0), constantTimeLtU64(5, 5));

    // Edge cases
    try std.testing.expectEqual(@as(u1, 1), constantTimeLtU64(0, 1));
    try std.testing.expectEqual(@as(u1, 0), constantTimeLtU64(0, 0));
    try std.testing.expectEqual(@as(u1, 1), constantTimeLtU64(0, std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u1, 0), constantTimeLtU64(std.math.maxInt(u64), 0));
}

test "timing: constantTimeEqU64" {
    try std.testing.expectEqual(@as(u1, 1), constantTimeEqU64(42, 42));
    try std.testing.expectEqual(@as(u1, 0), constantTimeEqU64(42, 43));
    try std.testing.expectEqual(@as(u1, 1), constantTimeEqU64(0, 0));
    try std.testing.expectEqual(@as(u1, 0), constantTimeEqU64(0, 1));
    try std.testing.expectEqual(@as(u1, 1), constantTimeEqU64(std.math.maxInt(u64), std.math.maxInt(u64)));
}
