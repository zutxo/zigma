//! 256-bit Signed Integer Arithmetic
//!
//! Implements arbitrary precision integer operations capped at 256 bits,
//! matching Scala BigInt semantics for ErgoTree evaluation.
//!
//! Internal representation:
//! - 4 x u64 limbs in little-endian order (limbs[0] is LSB)
//! - Separate sign flag (magnitude + sign representation)
//!
//! Serialization:
//! - Big-endian two's complement (Scala/Java compatible)
//! - Minimal encoding (no redundant leading bytes)
//!
//! Reference: sigmastate BigInt operations

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Error Types
// ============================================================================

pub const BigIntError = error{
    /// Result exceeds 256-bit range
    Overflow,
    /// Division by zero
    DivisionByZero,
    /// Input bytes too large (>32 bytes)
    ValueTooLarge,
    /// Invalid encoding
    InvalidEncoding,
};

// ============================================================================
// BigInt256
// ============================================================================

/// 256-bit signed integer
pub const BigInt256 = struct {
    /// Magnitude as 4 x u64 limbs, little-endian (limbs[0] is LSB)
    limbs: [4]u64,
    /// Sign: false = non-negative, true = negative
    /// Note: zero is always non-negative (negative = false)
    negative: bool,

    // ========================================================================
    // Constants
    // ========================================================================

    /// Zero
    pub const zero = BigInt256{ .limbs = .{ 0, 0, 0, 0 }, .negative = false };

    /// One
    pub const one = BigInt256{ .limbs = .{ 1, 0, 0, 0 }, .negative = false };

    /// Negative one
    pub const neg_one = BigInt256{ .limbs = .{ 1, 0, 0, 0 }, .negative = true };

    /// Maximum positive value: 2^255 - 1
    pub const max_value = BigInt256{
        .limbs = .{
            std.math.maxInt(u64),
            std.math.maxInt(u64),
            std.math.maxInt(u64),
            std.math.maxInt(u64) >> 1, // Clear top bit for positive
        },
        .negative = false,
    };

    /// Minimum negative value: -2^255
    pub const min_value = BigInt256{
        .limbs = .{
            0,
            0,
            0,
            @as(u64, 1) << 63, // 2^255 magnitude
        },
        .negative = true,
    };

    // ========================================================================
    // Construction
    // ========================================================================

    /// Create from i64
    pub fn fromInt(value: i64) BigInt256 {
        if (value == 0) return zero;

        if (value > 0) {
            return .{
                .limbs = .{ @intCast(value), 0, 0, 0 },
                .negative = false,
            };
        } else if (value == std.math.minInt(i64)) {
            // Special case: -MIN = MIN magnitude
            return .{
                .limbs = .{ @as(u64, 1) << 63, 0, 0, 0 },
                .negative = true,
            };
        } else {
            return .{
                .limbs = .{ @intCast(-value), 0, 0, 0 },
                .negative = true,
            };
        }
    }

    /// Create from u64 (always non-negative)
    pub fn fromUint(value: u64) BigInt256 {
        return .{
            .limbs = .{ value, 0, 0, 0 },
            .negative = false,
        };
    }

    /// Create from big-endian bytes (two's complement, signed)
    /// This matches Scala BigInt serialization format
    pub fn fromBytes(bytes: []const u8) BigIntError!BigInt256 {
        if (bytes.len == 0) return zero;
        if (bytes.len > 32) return error.ValueTooLarge;

        assert(bytes.len <= 32);

        // Determine sign from MSB
        const is_negative = (bytes[0] & 0x80) != 0;

        // Pad to 32 bytes with sign extension
        var padded: [32]u8 = if (is_negative) [_]u8{0xFF} ** 32 else [_]u8{0} ** 32;
        @memcpy(padded[32 - bytes.len ..], bytes);

        // Convert big-endian bytes to little-endian u64 limbs
        var limbs: [4]u64 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, padded[offset..][0..8], .big);
        }

        if (!is_negative) {
            // Positive: limbs are the magnitude directly
            return .{ .limbs = limbs, .negative = false };
        } else {
            // Negative: convert from two's complement
            // Two's complement: value = -magnitude, so magnitude = -value = ~value + 1
            var result = BigInt256{ .limbs = limbs, .negative = false };
            result = result.bitwiseNot();
            result = result.addOne() catch return error.Overflow;
            result.negative = true;

            // Normalize: zero is never negative
            if (result.isZero()) {
                result.negative = false;
            }

            return result;
        }
    }

    /// Convert to big-endian bytes (two's complement, signed)
    /// Returns slice of buffer containing minimal encoding
    pub fn toBytes(self: BigInt256, buffer: *[33]u8) []u8 {
        assert(buffer.len >= 33);

        if (self.isZero()) {
            buffer[0] = 0;
            return buffer[0..1];
        }

        // Convert magnitude to big-endian
        var full: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, full[offset..][0..8], self.limbs[i], .big);
        }

        if (!self.negative) {
            // Positive: find minimal encoding, ensure MSB sign bit is 0
            var start: usize = 0;
            while (start < 31 and full[start] == 0) : (start += 1) {}

            // If MSB has sign bit set, prepend 0x00
            if ((full[start] & 0x80) != 0) {
                if (start > 0) {
                    start -= 1;
                } else {
                    // Need extra byte
                    buffer[0] = 0;
                    @memcpy(buffer[1..33], &full);
                    return buffer[0..33];
                }
            }

            const len = 32 - start;
            @memcpy(buffer[0..len], full[start..]);
            return buffer[0..len];
        } else {
            // Negative: convert to two's complement
            // value = -magnitude, so two's comp = ~magnitude + 1
            var tc = self.bitwiseNot();
            tc = tc.addOne() catch {
                // Overflow on negate means we're at MIN, handle specially
                // -(-2^255) overflows, but we're encoding, not negating
                // For MIN value (-2^255), two's complement is 0x80 00 ... 00
                buffer[0] = 0x80;
                @memset(buffer[1..32], 0);
                return buffer[0..32];
            };

            // Convert negated magnitude to bytes
            for (0..4) |i| {
                const offset = 32 - (i + 1) * 8;
                std.mem.writeInt(u64, full[offset..][0..8], tc.limbs[i], .big);
            }

            // Find minimal encoding, ensure MSB sign bit is 1
            var start: usize = 0;
            while (start < 31 and full[start] == 0xFF) : (start += 1) {}

            // If MSB doesn't have sign bit set, prepend 0xFF
            if ((full[start] & 0x80) == 0) {
                if (start > 0) {
                    start -= 1;
                } else {
                    buffer[0] = 0xFF;
                    @memcpy(buffer[1..33], &full);
                    return buffer[0..33];
                }
            }

            const len = 32 - start;
            @memcpy(buffer[0..len], full[start..]);
            return buffer[0..len];
        }
    }

    // ========================================================================
    // Predicates
    // ========================================================================

    /// Check if zero
    pub fn isZero(self: BigInt256) bool {
        return self.limbs[0] == 0 and
            self.limbs[1] == 0 and
            self.limbs[2] == 0 and
            self.limbs[3] == 0;
    }

    /// Check if negative
    pub fn isNegative(self: BigInt256) bool {
        return self.negative and !self.isZero();
    }

    /// Check if positive (> 0)
    pub fn isPositive(self: BigInt256) bool {
        return !self.negative and !self.isZero();
    }

    // ========================================================================
    // Comparison
    // ========================================================================

    /// Compare two BigInt256 values
    pub fn compare(a: BigInt256, b: BigInt256) std.math.Order {
        // Handle sign differences
        const a_neg = a.isNegative();
        const b_neg = b.isNegative();

        if (a_neg and !b_neg) return .lt;
        if (!a_neg and b_neg) return .gt;

        // Same sign: compare magnitudes
        const mag_order = compareMagnitude(a.limbs, b.limbs);

        if (a_neg) {
            // Both negative: larger magnitude = smaller value
            return switch (mag_order) {
                .lt => .gt,
                .gt => .lt,
                .eq => .eq,
            };
        } else {
            // Both non-negative: larger magnitude = larger value
            return mag_order;
        }
    }

    /// Check equality
    pub fn eql(a: BigInt256, b: BigInt256) bool {
        return a.compare(b) == .eq;
    }

    // ========================================================================
    // Arithmetic Operations
    // ========================================================================

    /// Addition
    pub fn add(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        if (a.negative == b.negative) {
            // Same sign: add magnitudes
            const result_limbs = addLimbs(a.limbs, b.limbs);
            if (result_limbs.overflow) return error.Overflow;

            var result = BigInt256{ .limbs = result_limbs.limbs, .negative = a.negative };
            if (result.isZero()) result.negative = false;

            // Check for overflow (exceeds 255-bit signed range)
            // Positive: magnitude must have top bit clear (< 2^255)
            // Negative: magnitude must be <= 2^255
            if (!result.negative and (result.limbs[3] & (@as(u64, 1) << 63)) != 0) {
                return error.Overflow;
            }
            if (result.negative) {
                // Magnitude > 2^255 is overflow
                // 2^255 = {0, 0, 0, 2^63}
                const max_neg_magnitude = [4]u64{ 0, 0, 0, @as(u64, 1) << 63 };
                if (compareMagnitude(result.limbs, max_neg_magnitude) == .gt) {
                    return error.Overflow;
                }
            }

            return result;
        } else {
            // Different signs: subtract magnitudes
            const mag_cmp = compareMagnitude(a.limbs, b.limbs);

            if (mag_cmp == .eq) return zero;

            if (mag_cmp == .gt) {
                // |a| > |b|: result = |a| - |b| with sign of a
                const result_limbs = subLimbs(a.limbs, b.limbs);
                var result = BigInt256{ .limbs = result_limbs, .negative = a.negative };
                if (result.isZero()) result.negative = false;
                return result;
            } else {
                // |b| > |a|: result = |b| - |a| with sign of b
                const result_limbs = subLimbs(b.limbs, a.limbs);
                var result = BigInt256{ .limbs = result_limbs, .negative = b.negative };
                if (result.isZero()) result.negative = false;
                return result;
            }
        }
    }

    /// Subtraction
    pub fn sub(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // a - b = a + (-b)
        var neg_b = b;
        neg_b.negative = !b.negative;
        if (neg_b.isZero()) neg_b.negative = false;
        return add(a, neg_b);
    }

    /// Negation
    pub fn negate(self: BigInt256) BigIntError!BigInt256 {
        if (self.isZero()) return zero;

        // Check for MIN value overflow: -(-2^255) doesn't fit
        if (self.negative and self.limbs[3] == (@as(u64, 1) << 63) and
            self.limbs[0] == 0 and self.limbs[1] == 0 and self.limbs[2] == 0)
        {
            return error.Overflow;
        }

        return .{
            .limbs = self.limbs,
            .negative = !self.negative,
        };
    }

    /// Multiplication
    pub fn mul(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        if (a.isZero() or b.isZero()) return zero;

        const result_limbs = try mulLimbs(a.limbs, b.limbs);
        const result_negative = a.negative != b.negative;

        var result = BigInt256{ .limbs = result_limbs, .negative = result_negative };
        if (result.isZero()) result.negative = false;

        // Check overflow
        if (!result.negative and (result.limbs[3] & (@as(u64, 1) << 63)) != 0) {
            return error.Overflow;
        }

        return result;
    }

    /// Division (truncating toward zero)
    pub fn div(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        if (b.isZero()) return error.DivisionByZero;
        if (a.isZero()) return zero;

        // Check MIN / -1 overflow
        if (a.eql(min_value) and b.eql(neg_one)) {
            return error.Overflow;
        }

        const result_limbs = try divLimbs(a.limbs, b.limbs);
        const result_negative = a.negative != b.negative;

        var result = BigInt256{ .limbs = result_limbs.quotient, .negative = result_negative };
        if (result.isZero()) result.negative = false;
        return result;
    }

    /// Modulo (sign matches dividend, follows truncating division)
    pub fn mod(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        if (b.isZero()) return error.DivisionByZero;
        if (a.isZero()) return zero;

        const result_limbs = try divLimbs(a.limbs, b.limbs);

        var result = BigInt256{ .limbs = result_limbs.remainder, .negative = a.negative };
        if (result.isZero()) result.negative = false;
        return result;
    }

    // ========================================================================
    // Bitwise Operations (on magnitude)
    // ========================================================================

    /// Bitwise NOT (on limbs, internal use for two's complement conversion)
    fn bitwiseNot(self: BigInt256) BigInt256 {
        return .{
            .limbs = .{
                ~self.limbs[0],
                ~self.limbs[1],
                ~self.limbs[2],
                ~self.limbs[3],
            },
            .negative = self.negative,
        };
    }

    /// Add one to magnitude (for two's complement conversion)
    fn addOne(self: BigInt256) BigIntError!BigInt256 {
        const result = addLimbs(self.limbs, .{ 1, 0, 0, 0 });
        if (result.overflow) return error.Overflow;
        return .{ .limbs = result.limbs, .negative = self.negative };
    }

    /// Right shift magnitude by n bits
    pub fn shiftRight(self: BigInt256, n: u8) BigInt256 {
        if (n == 0) return self;
        if (n >= 256) return zero;

        var result: [4]u64 = .{ 0, 0, 0, 0 };
        const limb_shift = n / 64;
        const bit_shift: u6 = @intCast(n % 64);

        for (limb_shift..4) |i| {
            result[i - limb_shift] = self.limbs[i] >> bit_shift;
            if (bit_shift > 0 and i < 3) {
                result[i - limb_shift] |= self.limbs[i + 1] << @intCast(64 - @as(u7, bit_shift));
            }
        }

        var r = BigInt256{ .limbs = result, .negative = self.negative };
        if (r.isZero()) r.negative = false;
        return r;
    }

    // ========================================================================
    // Internal Limb Operations
    // ========================================================================

    const LimbAddResult = struct {
        limbs: [4]u64,
        overflow: bool,
    };

    fn addLimbs(a: [4]u64, b: [4]u64) LimbAddResult {
        var result: [4]u64 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            const sum1 = @addWithOverflow(a[i], b[i]);
            const sum2 = @addWithOverflow(sum1[0], carry);
            result[i] = sum2[0];
            carry = sum1[1] + sum2[1];
        }

        return .{ .limbs = result, .overflow = carry != 0 };
    }

    fn subLimbs(a: [4]u64, b: [4]u64) [4]u64 {
        // Assumes a >= b (magnitude comparison done before calling)
        var result: [4]u64 = undefined;
        var borrow: u64 = 0;

        for (0..4) |i| {
            const diff1 = @subWithOverflow(a[i], b[i]);
            const diff2 = @subWithOverflow(diff1[0], borrow);
            result[i] = diff2[0];
            borrow = diff1[1] + diff2[1];
        }

        // borrow should be 0 if a >= b
        assert(borrow == 0);
        return result;
    }

    fn compareMagnitude(a: [4]u64, b: [4]u64) std.math.Order {
        // Compare from MSB to LSB
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (a[i] > b[i]) return .gt;
            if (a[i] < b[i]) return .lt;
        }
        return .eq;
    }

    fn mulLimbs(a: [4]u64, b: [4]u64) BigIntError![4]u64 {
        // Schoolbook multiplication with overflow checking
        // Result must fit in 256 bits

        var result: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };

        for (0..4) |i| {
            var carry: u64 = 0;
            for (0..4) |j| {
                // a[i] * b[j] is up to 128 bits
                const prod: u128 = @as(u128, a[i]) * @as(u128, b[j]);
                const sum: u128 = @as(u128, result[i + j]) + prod + @as(u128, carry);
                result[i + j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
            result[i + 4] = carry;
        }

        // Check overflow: high limbs must be zero
        if (result[4] != 0 or result[5] != 0 or result[6] != 0 or result[7] != 0) {
            return error.Overflow;
        }

        return .{ result[0], result[1], result[2], result[3] };
    }

    const DivResult = struct {
        quotient: [4]u64,
        remainder: [4]u64,
    };

    fn divLimbs(a: [4]u64, b: [4]u64) BigIntError!DivResult {
        // Simple binary long division
        // This is not optimal but correct and avoids complexity

        if (compareMagnitude(b, .{ 0, 0, 0, 0 }) == .eq) {
            return error.DivisionByZero;
        }

        if (compareMagnitude(a, b) == .lt) {
            return .{
                .quotient = .{ 0, 0, 0, 0 },
                .remainder = a,
            };
        }

        var quotient: [4]u64 = .{ 0, 0, 0, 0 };
        var remainder: [4]u64 = .{ 0, 0, 0, 0 };

        // Process each bit of a from MSB to LSB
        var bit: i32 = 255;
        while (bit >= 0) : (bit -= 1) {
            // Shift remainder left by 1
            remainder = shiftLeftOneLimbs(remainder);

            // Bring down next bit of a
            const limb_idx: usize = @intCast(@divTrunc(bit, 64));
            const bit_idx: u6 = @intCast(@mod(bit, 64));
            const a_bit = (a[limb_idx] >> bit_idx) & 1;
            remainder[0] |= a_bit;

            // If remainder >= b, subtract b and set quotient bit
            if (compareMagnitude(remainder, b) != .lt) {
                remainder = subLimbs(remainder, b);
                const q_limb_idx: usize = @intCast(@divTrunc(bit, 64));
                const q_bit_idx: u6 = @intCast(@mod(bit, 64));
                quotient[q_limb_idx] |= @as(u64, 1) << q_bit_idx;
            }
        }

        return .{ .quotient = quotient, .remainder = remainder };
    }

    fn shiftLeftOneLimbs(a: [4]u64) [4]u64 {
        var result: [4]u64 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            result[i] = (a[i] << 1) | carry;
            carry = a[i] >> 63;
        }

        return result;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "bigint: zero" {
    const z = BigInt256.zero;
    try std.testing.expect(z.isZero());
    try std.testing.expect(!z.isNegative());
    try std.testing.expect(!z.isPositive());
}

test "bigint: fromInt" {
    const pos = BigInt256.fromInt(42);
    try std.testing.expect(pos.isPositive());
    try std.testing.expectEqual(@as(u64, 42), pos.limbs[0]);

    const neg = BigInt256.fromInt(-42);
    try std.testing.expect(neg.isNegative());
    try std.testing.expectEqual(@as(u64, 42), neg.limbs[0]);

    const min_i64 = BigInt256.fromInt(std.math.minInt(i64));
    try std.testing.expect(min_i64.isNegative());
}

test "bigint: compare" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(50);
    const c = BigInt256.fromInt(-50);

    try std.testing.expectEqual(std.math.Order.gt, a.compare(b));
    try std.testing.expectEqual(std.math.Order.gt, b.compare(c));
    try std.testing.expectEqual(std.math.Order.lt, c.compare(b));
    try std.testing.expectEqual(std.math.Order.eq, a.compare(a));
}

test "bigint: add basic" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(50);

    const sum = try a.add(b);
    try std.testing.expect(sum.eql(BigInt256.fromInt(150)));
}

test "bigint: add negative" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(-150);

    const sum = try a.add(b);
    try std.testing.expect(sum.eql(BigInt256.fromInt(-50)));
}

test "bigint: sub basic" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(30);

    const diff = try a.sub(b);
    try std.testing.expect(diff.eql(BigInt256.fromInt(70)));
}

test "bigint: mul basic" {
    const a = BigInt256.fromInt(6);
    const b = BigInt256.fromInt(7);

    const prod = try a.mul(b);
    try std.testing.expect(prod.eql(BigInt256.fromInt(42)));
}

test "bigint: mul negative" {
    const a = BigInt256.fromInt(-6);
    const b = BigInt256.fromInt(7);

    const prod = try a.mul(b);
    try std.testing.expect(prod.eql(BigInt256.fromInt(-42)));

    const prod2 = try a.mul(BigInt256.fromInt(-7));
    try std.testing.expect(prod2.eql(BigInt256.fromInt(42)));
}

test "bigint: div basic" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(30);

    const quot = try a.div(b);
    try std.testing.expect(quot.eql(BigInt256.fromInt(3)));
}

test "bigint: div truncates toward zero" {
    // -7 / 3 = -2 (not -3)
    const a = BigInt256.fromInt(-7);
    const b = BigInt256.fromInt(3);

    const quot = try a.div(b);
    try std.testing.expect(quot.eql(BigInt256.fromInt(-2)));
}

test "bigint: div by zero" {
    const a = BigInt256.fromInt(100);
    try std.testing.expectError(error.DivisionByZero, a.div(BigInt256.zero));
}

test "bigint: mod basic" {
    const a = BigInt256.fromInt(7);
    const b = BigInt256.fromInt(3);

    const rem = try a.mod(b);
    try std.testing.expect(rem.eql(BigInt256.fromInt(1)));
}

test "bigint: mod sign matches dividend" {
    // -7 % 3 = -1 (sign matches dividend -7)
    const a = BigInt256.fromInt(-7);
    const b = BigInt256.fromInt(3);

    const rem = try a.mod(b);
    try std.testing.expect(rem.eql(BigInt256.fromInt(-1)));
}

test "bigint: negate" {
    const a = BigInt256.fromInt(42);
    const neg = try a.negate();
    try std.testing.expect(neg.eql(BigInt256.fromInt(-42)));

    const neg_neg = try neg.negate();
    try std.testing.expect(neg_neg.eql(a));
}

test "bigint: negate MIN overflow" {
    try std.testing.expectError(error.Overflow, BigInt256.min_value.negate());
}

test "bigint: fromBytes positive" {
    // 256 = 0x0100
    const bytes = [_]u8{ 0x01, 0x00 };
    const val = try BigInt256.fromBytes(&bytes);
    try std.testing.expect(val.eql(BigInt256.fromInt(256)));
}

test "bigint: fromBytes negative" {
    // -1 in two's complement = 0xFF
    const bytes = [_]u8{0xFF};
    const val = try BigInt256.fromBytes(&bytes);
    try std.testing.expect(val.eql(BigInt256.fromInt(-1)));

    // -128 = 0x80
    const bytes2 = [_]u8{0x80};
    const val2 = try BigInt256.fromBytes(&bytes2);
    try std.testing.expect(val2.eql(BigInt256.fromInt(-128)));
}

test "bigint: toBytes positive" {
    const val = BigInt256.fromInt(256);
    var buf: [33]u8 = undefined;
    const bytes = val.toBytes(&buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, bytes);
}

test "bigint: toBytes negative" {
    const val = BigInt256.fromInt(-1);
    var buf: [33]u8 = undefined;
    const bytes = val.toBytes(&buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF}, bytes);
}

test "bigint: roundtrip" {
    const values = [_]i64{ 0, 1, -1, 127, -128, 255, 256, -256, 32767, -32768, std.math.maxInt(i64), std.math.minInt(i64) };

    for (values) |v| {
        const original = BigInt256.fromInt(v);
        var buf: [33]u8 = undefined;
        const bytes = original.toBytes(&buf);
        const restored = try BigInt256.fromBytes(bytes);
        try std.testing.expect(original.eql(restored));
    }
}

test "bigint: overflow detection" {
    // MAX + 1 overflows
    try std.testing.expectError(error.Overflow, BigInt256.max_value.add(BigInt256.one));

    // MIN - 1 overflows
    try std.testing.expectError(error.Overflow, BigInt256.min_value.sub(BigInt256.one));
}

test "bigint: MIN div -1 overflow" {
    try std.testing.expectError(error.Overflow, BigInt256.min_value.div(BigInt256.neg_one));
}
