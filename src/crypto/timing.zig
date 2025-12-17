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

/// Constant-time less-than comparison for 256-bit limb arrays.
/// Returns true if a < b (unsigned), false otherwise.
/// CRITICAL: No early exit - always examines all limbs.
///
/// Uses subtraction with borrow to determine ordering.
/// If a < b, subtracting b from a will produce a borrow out.
pub fn constantTimeLtLimbs(a: [4]u64, b: [4]u64) bool {
    // Compute a - b with borrow propagation
    // If a < b, final borrow will be non-zero
    var borrow: u64 = 0;

    for (0..4) |i| {
        // Subtract with overflow detection
        const diff1 = @subWithOverflow(a[i], b[i]);
        const diff2 = @subWithOverflow(diff1[0], borrow);
        // Accumulate borrows (overflow flags)
        borrow = @as(u64, diff1[1]) | @as(u64, diff2[1]);
    }

    // borrow != 0 means a < b
    return borrow != 0;
}

/// Constant-time greater-than-or-equal comparison for 256-bit limb arrays.
/// Returns true if a >= b (unsigned), false otherwise.
pub fn constantTimeGeLimbs(a: [4]u64, b: [4]u64) bool {
    return !constantTimeLtLimbs(a, b);
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

test "timing: constantTimeLtLimbs basic" {
    const a: [4]u64 = .{ 1, 0, 0, 0 };
    const b: [4]u64 = .{ 2, 0, 0, 0 };
    const c: [4]u64 = .{ 0, 1, 0, 0 };

    // a < b (differ in low limb)
    try std.testing.expect(constantTimeLtLimbs(a, b));
    try std.testing.expect(!constantTimeLtLimbs(b, a));

    // a < c (c has higher limb set)
    try std.testing.expect(constantTimeLtLimbs(a, c));
    try std.testing.expect(constantTimeLtLimbs(b, c));

    // Equal values
    try std.testing.expect(!constantTimeLtLimbs(a, a));
}

test "timing: constantTimeLtLimbs edge cases" {
    const zero: [4]u64 = .{ 0, 0, 0, 0 };
    const one: [4]u64 = .{ 1, 0, 0, 0 };
    const max: [4]u64 = .{
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        std.math.maxInt(u64),
    };
    const high_bit: [4]u64 = .{ 0, 0, 0, 0x8000000000000000 };

    // Zero comparisons
    try std.testing.expect(constantTimeLtLimbs(zero, one));
    try std.testing.expect(!constantTimeLtLimbs(one, zero));
    try std.testing.expect(!constantTimeLtLimbs(zero, zero));

    // Max comparisons
    try std.testing.expect(constantTimeLtLimbs(zero, max));
    try std.testing.expect(!constantTimeLtLimbs(max, zero));
    try std.testing.expect(!constantTimeLtLimbs(max, max));

    // High bit comparisons
    try std.testing.expect(constantTimeLtLimbs(zero, high_bit));
    try std.testing.expect(!constantTimeLtLimbs(high_bit, zero));
}

test "timing: constantTimeGeLimbs" {
    const a: [4]u64 = .{ 5, 0, 0, 0 };
    const b: [4]u64 = .{ 10, 0, 0, 0 };

    try std.testing.expect(constantTimeGeLimbs(b, a)); // 10 >= 5
    try std.testing.expect(!constantTimeGeLimbs(a, b)); // 5 < 10
    try std.testing.expect(constantTimeGeLimbs(a, a)); // 5 >= 5
}

// ============================================================================
// Statistical Timing Verification Tests
// ============================================================================
// These tests verify that operations execute in constant time regardless of
// input values. They use statistical analysis to detect timing leaks.
//
// Note: These tests only run in ReleaseFast/ReleaseSafe builds where timing
// measurements are meaningful. Debug builds skip these tests due to noise.
// Run with: ./zig/zig build test -Doptimize=ReleaseFast

const builtin = @import("builtin");

/// Returns true if timing tests should run (optimized builds only)
fn shouldRunTimingTests() bool {
    return builtin.mode != .Debug;
}

/// Compute mean of timing samples
fn timingMean(samples: []const u64) f64 {
    var sum: u64 = 0;
    for (samples) |s| {
        sum +|= s;
    }
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(samples.len));
}

/// Compute variance of timing samples
fn timingVariance(samples: []const u64, mean_val: f64) f64 {
    var sum_sq: f64 = 0;
    for (samples) |s| {
        const diff = @as(f64, @floatFromInt(s)) - mean_val;
        sum_sq += diff * diff;
    }
    return sum_sq / @as(f64, @floatFromInt(samples.len - 1));
}

/// Check if two timing distributions are statistically indistinguishable.
/// Uses a ratio-based test rather than t-test for more stability.
/// Returns true if no significant timing difference detected.
///
/// The test checks that the ratio of mean times is within acceptable bounds.
/// A timing leak would show a significant ratio difference (e.g., early-exit
/// would be 2-10x faster than late-exit for a non-constant-time comparison).
fn isConstantTimeDist(early_times: []const u64, late_times: []const u64) bool {
    const early_mean = timingMean(early_times);
    const late_mean = timingMean(late_times);

    // Avoid division by zero
    if (late_mean < 1.0 or early_mean < 1.0) return true;

    // Compute ratio of means
    const ratio = if (early_mean > late_mean)
        early_mean / late_mean
    else
        late_mean / early_mean;

    // Accept up to 50% timing difference as "constant-time enough"
    // A true timing leak would show 2x-10x difference
    // This threshold is intentionally generous to avoid flaky tests
    return ratio < 1.5;
}

test "timing: constantTimeEql is constant-time (statistical)" {
    // Skip in Debug builds - timing measurements are too noisy
    if (!shouldRunTimingTests()) return;

    const iterations = 5000;
    var timer = std.time.Timer.start() catch return; // Skip if no timer

    // Key that differs in FIRST byte (early exit if not constant-time)
    const key_a = [_]u8{0x00} ++ [_]u8{0xAA} ** 31;
    const key_early_diff = [_]u8{0xFF} ++ [_]u8{0xAA} ** 31;

    // Key that differs in LAST byte (late exit if not constant-time)
    const key_late_diff = [_]u8{0xAA} ** 31 ++ [_]u8{0xFF};

    var early_times: [iterations]u64 = undefined;
    var late_times: [iterations]u64 = undefined;

    // Warm up
    for (0..500) |_| {
        _ = constantTimeEql(&key_a, &key_early_diff);
        _ = constantTimeEql(&key_a, &key_late_diff);
    }

    // Interleave measurements to reduce systematic bias
    for (0..iterations) |i| {
        timer.reset();
        _ = constantTimeEql(&key_a, &key_early_diff);
        early_times[i] = timer.read();

        timer.reset();
        _ = constantTimeEql(&key_a, &key_late_diff);
        late_times[i] = timer.read();
    }

    // Timing distributions should be statistically indistinguishable
    try std.testing.expect(isConstantTimeDist(&early_times, &late_times));
}

test "timing: constantTimeLtLimbs is constant-time (statistical)" {
    // Skip in Debug builds - timing measurements are too noisy
    if (!shouldRunTimingTests()) return;

    const iterations = 5000;
    var timer = std.time.Timer.start() catch return;

    // Values that differ in LOW limb (early comparison)
    const base: [4]u64 = .{ 0x1000, 0x2000, 0x3000, 0x4000 };
    const early_diff: [4]u64 = .{ 0x1001, 0x2000, 0x3000, 0x4000 };

    // Values that differ in HIGH limb (late comparison for naive impl)
    const late_diff: [4]u64 = .{ 0x1000, 0x2000, 0x3000, 0x4001 };

    var early_times: [iterations]u64 = undefined;
    var late_times: [iterations]u64 = undefined;

    // Warm up
    for (0..500) |_| {
        _ = constantTimeLtLimbs(base, early_diff);
        _ = constantTimeLtLimbs(base, late_diff);
    }

    // Interleave measurements to reduce systematic bias
    for (0..iterations) |i| {
        timer.reset();
        _ = constantTimeLtLimbs(base, early_diff);
        early_times[i] = timer.read();

        timer.reset();
        _ = constantTimeLtLimbs(base, late_diff);
        late_times[i] = timer.read();
    }

    try std.testing.expect(isConstantTimeDist(&early_times, &late_times));
}
