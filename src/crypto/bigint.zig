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

    /// secp256k1 group order q (for ModQ operations)
    /// q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    /// This is used for threshold signature scripts and sigma protocols.
    /// Reference: CryptoConstants.groupOrder in Scala sigmastate
    pub const GROUP_ORDER = BigInt256{
        .limbs = .{
            0xBFD25E8CD0364141, // LSB
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF, // MSB
        },
        .negative = false,
    };

    /// 2^256 - GROUP_ORDER (used for modular reduction when overflow occurs)
    /// This is the additive inverse of GROUP_ORDER mod 2^256
    /// Used in plusModQ when sum overflows but limbs < GROUP_ORDER
    pub const ORDER_COMPLEMENT = BigInt256{
        .limbs = .{
            0x402DA1732FC9BEBF, // LSB
            0x4551231950B75FC4,
            0x0000000000000001,
            0x0000000000000000, // MSB
        },
        .negative = false,
    };

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

    // Compile-time assertions for constant correctness
    comptime {
        // max_value must have top bit clear (positive, < 2^255)
        assert(max_value.limbs[3] >> 63 == 0);
        // min_value must have magnitude = 2^255 exactly
        assert(min_value.limbs[3] == (@as(u64, 1) << 63));
        assert(min_value.limbs[0] == 0 and min_value.limbs[1] == 0 and min_value.limbs[2] == 0);
        // zero must be non-negative
        assert(!zero.negative);
        // one must be positive with value 1
        assert(one.limbs[0] == 1 and !one.negative);
    }

    // ========================================================================
    // Construction
    // ========================================================================

    /// Create from i64
    pub fn fromInt(value: i64) BigInt256 {
        if (value == 0) return zero;

        var result: BigInt256 = undefined;
        if (value > 0) {
            result = .{
                .limbs = .{ @intCast(value), 0, 0, 0 },
                .negative = false,
            };
        } else if (value == std.math.minInt(i64)) {
            // Special case: -MIN = MIN magnitude
            result = .{
                .limbs = .{ @as(u64, 1) << 63, 0, 0, 0 },
                .negative = true,
            };
        } else {
            result = .{
                .limbs = .{ @intCast(-value), 0, 0, 0 },
                .negative = true,
            };
        }

        // Postcondition: result fits in first limb only
        assert(result.limbs[1] == 0 and result.limbs[2] == 0 and result.limbs[3] == 0);
        // Postcondition: sign matches input sign
        assert((value < 0) == result.negative or value == 0);
        return result;
    }

    /// Create from u64 (always non-negative)
    pub fn fromUint(value: u64) BigInt256 {
        const result = BigInt256{
            .limbs = .{ value, 0, 0, 0 },
            .negative = false,
        };
        // Postcondition: result is non-negative
        assert(!result.negative);
        // Postcondition: result fits in first limb only
        assert(result.limbs[1] == 0 and result.limbs[2] == 0 and result.limbs[3] == 0);
        return result;
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

        if (!self.negative) {
            return toPositiveBytes(self, buffer);
        } else {
            return toNegativeBytes(self, buffer);
        }
    }

    /// Helper: encode positive BigInt to minimal two's complement
    fn toPositiveBytes(self: BigInt256, buffer: *[33]u8) []u8 {
        assert(!self.negative);
        var full = limbsToBigEndian(self.limbs);

        // Find minimal encoding, ensure MSB sign bit is 0
        var start: usize = 0;
        while (start < 31 and full[start] == 0) : (start += 1) {}

        // If MSB has sign bit set, prepend 0x00
        if ((full[start] & 0x80) != 0) {
            if (start > 0) {
                start -= 1;
            } else {
                buffer[0] = 0;
                @memcpy(buffer[1..33], &full);
                return buffer[0..33];
            }
        }

        const len = 32 - start;
        @memcpy(buffer[0..len], full[start..]);
        return buffer[0..len];
    }

    /// Helper: encode negative BigInt to minimal two's complement
    fn toNegativeBytes(self: BigInt256, buffer: *[33]u8) []u8 {
        assert(self.negative);

        // Convert to two's complement: ~magnitude + 1
        var tc = self.bitwiseNot();
        tc = tc.addOne() catch {
            // MIN value (-2^255) two's complement is 0x80 00 ... 00
            buffer[0] = 0x80;
            @memset(buffer[1..32], 0);
            return buffer[0..32];
        };

        var full = limbsToBigEndian(tc.limbs);

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

    /// Helper: convert 4 limbs to 32-byte big-endian array
    fn limbsToBigEndian(limbs: [4]u64) [32]u8 {
        var result: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, result[offset..][0..8], limbs[i], .big);
        }
        return result;
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
        // Precondition: zero is never marked negative
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

        // Handle sign differences
        const a_neg = a.isNegative();
        const b_neg = b.isNegative();

        if (a_neg and !b_neg) return .lt;
        if (!a_neg and b_neg) return .gt;

        // Same sign: compare magnitudes
        const mag_order = compareMagnitude(a.limbs, b.limbs);

        // Invariant: if both same sign, magnitude comparison determines result
        const result = if (a_neg) switch (mag_order) {
            // Both negative: larger magnitude = smaller value
            .lt => std.math.Order.gt,
            .gt => std.math.Order.lt,
            .eq => std.math.Order.eq,
        } else mag_order;

        // Postcondition: equality is symmetric
        assert((result == .eq) == (compareMagnitude(a.limbs, b.limbs) == .eq and a_neg == b_neg));
        return result;
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
        // Precondition: zero values are non-negative
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

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

            // Postcondition: zero result is non-negative
            assert(!result.isZero() or !result.negative);
            return result;
        } else {
            // Different signs: subtract magnitudes
            const mag_cmp = compareMagnitude(a.limbs, b.limbs);

            if (mag_cmp == .eq) return zero;

            var result: BigInt256 = undefined;
            if (mag_cmp == .gt) {
                // |a| > |b|: result = |a| - |b| with sign of a
                const result_limbs = subLimbs(a.limbs, b.limbs);
                result = BigInt256{ .limbs = result_limbs, .negative = a.negative };
            } else {
                // |b| > |a|: result = |b| - |a| with sign of b
                const result_limbs = subLimbs(b.limbs, a.limbs);
                result = BigInt256{ .limbs = result_limbs, .negative = b.negative };
            }
            if (result.isZero()) result.negative = false;

            // Postcondition: zero result is non-negative
            assert(!result.isZero() or !result.negative);
            return result;
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
        // Precondition: zero is non-negative
        assert(!self.isZero() or !self.negative);

        if (self.isZero()) return zero;

        // Check for MIN value overflow: -(-2^255) doesn't fit
        if (self.negative and self.limbs[3] == (@as(u64, 1) << 63) and
            self.limbs[0] == 0 and self.limbs[1] == 0 and self.limbs[2] == 0)
        {
            return error.Overflow;
        }

        const result = BigInt256{
            .limbs = self.limbs,
            .negative = !self.negative,
        };

        // Postcondition: sign flipped, magnitude unchanged
        assert(result.negative != self.negative);
        assert(compareMagnitude(result.limbs, self.limbs) == .eq);
        return result;
    }

    /// Multiplication
    pub fn mul(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // Precondition: zero values are non-negative
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

        if (a.isZero() or b.isZero()) return zero;

        const result_limbs = try mulLimbs(a.limbs, b.limbs);
        const result_negative = a.negative != b.negative;

        var result = BigInt256{ .limbs = result_limbs, .negative = result_negative };
        if (result.isZero()) result.negative = false;

        // Check overflow
        if (!result.negative and (result.limbs[3] & (@as(u64, 1) << 63)) != 0) {
            return error.Overflow;
        }

        // Postcondition: sign follows multiplication rules (neg*neg=pos, pos*neg=neg)
        assert(!result.isZero() or !result.negative);
        assert(result.isZero() or result.negative == (a.negative != b.negative));
        return result;
    }

    /// Division (truncating toward zero)
    pub fn div(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // Precondition: divisor is not zero (also checked via error)
        assert(!b.isZero() or true); // Will error, but assert documents intent

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

        // Postcondition: |quotient| <= |dividend| (integer division)
        assert(compareMagnitude(result.limbs, a.limbs) != .gt);
        // Postcondition: zero result is non-negative
        assert(!result.isZero() or !result.negative);
        return result;
    }

    /// Modulo (sign matches dividend, follows truncating division)
    pub fn mod(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // Precondition: divisor is not zero
        if (b.isZero()) return error.DivisionByZero;
        if (a.isZero()) return zero;

        const result_limbs = try divLimbs(a.limbs, b.limbs);

        var result = BigInt256{ .limbs = result_limbs.remainder, .negative = a.negative };
        if (result.isZero()) result.negative = false;

        // Postcondition: |remainder| < |divisor|
        assert(compareMagnitude(result.limbs, b.limbs) == .lt or result.isZero());
        // Postcondition: remainder sign matches dividend (truncating division)
        assert(result.isZero() or result.negative == a.negative);
        return result;
    }

    /// Modular multiplicative inverse using Extended Euclidean Algorithm
    /// Returns x such that (self * x) ≡ 1 (mod m)
    /// Requires: gcd(self, m) = 1 (coprime)
    /// Reference: Java BigInteger.modInverse behavior
    pub fn modInverse(self: BigInt256, m: BigInt256) BigIntError!BigInt256 {
        // Precondition: modulus must be positive
        if (m.isZero() or m.isNegative()) return error.DivisionByZero;
        // Precondition: self must not be zero
        if (self.isZero()) return error.DivisionByZero;

        // Work with absolute value of self
        const a_abs = BigInt256{ .limbs = self.limbs, .negative = false };

        // Extended Euclidean Algorithm
        // Finds x, y such that: a*x + m*y = gcd(a, m)
        // If gcd = 1, then x is the modular inverse

        var old_r = m;
        var r = try a_abs.mod(m); // Reduce a mod m first
        if (r.isZero()) return error.DivisionByZero; // a ≡ 0 (mod m), no inverse

        var old_s = zero;
        var s = one;

        // Invariant: old_r = old_s * a + old_t * m (we don't track t)
        // Invariant: r = s * a + t * m
        while (!r.isZero()) {
            const quotient = try old_r.div(r);

            // (old_r, r) = (r, old_r - quotient * r)
            const temp_r = r;
            const qr = try quotient.mul(r);
            r = try old_r.sub(qr);
            old_r = temp_r;

            // (old_s, s) = (s, old_s - quotient * s)
            const temp_s = s;
            const qs = try quotient.mul(s);
            s = try old_s.sub(qs);
            old_s = temp_s;
        }

        // old_r is now the GCD
        // Postcondition: GCD must be 1 for inverse to exist
        if (!old_r.eql(one)) return error.DivisionByZero;

        // old_s is the coefficient, may be negative
        // Normalize to range [0, m-1]
        var result = old_s;
        if (result.isNegative()) {
            result = try result.add(m);
        }

        // If original self was negative, negate result and normalize
        if (self.isNegative()) {
            result = try m.sub(result);
        }

        // Postcondition: result is in range [0, m-1]
        assert(!result.isNegative());
        assert(result.compare(m) == .lt);
        // Postcondition: (self * result) mod m == 1
        // (Verified by tests, not checked here for performance)
        return result;
    }

    // ========================================================================
    // ModQ Operations (mod secp256k1 group order)
    // ========================================================================

    /// Reduce value mod q (secp256k1 group order)
    /// Returns value in range [0, q-1]
    /// Used by threshold signature scripts
    /// Reference: Scala SBigInt.modQ
    pub fn modQ(self: BigInt256) BigIntError!BigInt256 {
        // PRECONDITION: GROUP_ORDER is positive
        assert(!GROUP_ORDER.negative);
        assert(!GROUP_ORDER.isZero());

        var result = try self.mod(GROUP_ORDER);

        // Handle negative remainders: convert to positive range
        // Scala semantics: result should be in [0, q-1]
        if (result.isNegative()) {
            result = try result.add(GROUP_ORDER);
        }

        // POSTCONDITION: result is in range [0, q-1]
        assert(!result.isNegative());
        assert(result.compare(GROUP_ORDER) == .lt);
        return result;
    }

    /// Add two values mod q (secp256k1 group order)
    /// Returns (a + b) mod q in range [0, q-1]
    /// Reference: Scala SBigInt.plusModQ
    pub fn plusModQ(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // PRECONDITION: inputs are valid BigInt256
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

        // Reduce inputs to [0, q-1] first to avoid overflow
        const a_mod = try a.modQ();
        const b_mod = try b.modQ();

        // Now both are in [0, q-1], so sum is in [0, 2q-2]
        // Since q is very close to 2^256, sum may still overflow signed BigInt256
        // Use unsigned limb addition and compare with q
        const sum_result = addLimbs(a_mod.limbs, b_mod.limbs);

        if (sum_result.overflow) {
            // true_sum = limbs + 2^256, we want (true_sum - q)
            const cmp = compareMagnitude(sum_result.limbs, GROUP_ORDER.limbs);
            if (cmp != .lt) {
                // limbs >= q: subtract directly
                const result_limbs = subLimbs(sum_result.limbs, GROUP_ORDER.limbs);
                return BigInt256{ .limbs = result_limbs, .negative = false };
            } else {
                // limbs < q: use identity (limbs + 2^256) - q = limbs + (2^256 - q)
                const add_result = addLimbs(sum_result.limbs, ORDER_COMPLEMENT.limbs);
                // Result < q < 2^256, so no overflow
                assert(!add_result.overflow);
                return BigInt256{ .limbs = add_result.limbs, .negative = false };
            }
        } else {
            // No overflow, but may still be >= q
            const result = BigInt256{ .limbs = sum_result.limbs, .negative = false };
            if (compareMagnitude(result.limbs, GROUP_ORDER.limbs) != .lt) {
                // result >= q, subtract q
                const final_limbs = subLimbs(result.limbs, GROUP_ORDER.limbs);
                return BigInt256{ .limbs = final_limbs, .negative = false };
            }
            return result;
        }
    }

    /// Subtract two values mod q (secp256k1 group order)
    /// Returns (a - b) mod q in range [0, q-1]
    /// Reference: Scala SBigInt.minusModQ
    pub fn minusModQ(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // PRECONDITION: inputs are valid BigInt256
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

        // Reduce inputs to [0, q-1] first
        const a_mod = try a.modQ();
        const b_mod = try b.modQ();

        // Compare magnitudes to determine sign
        const cmp = compareMagnitude(a_mod.limbs, b_mod.limbs);

        if (cmp == .eq) {
            return zero;
        } else if (cmp == .gt) {
            // a_mod > b_mod, result is positive: a_mod - b_mod
            const result_limbs = subLimbs(a_mod.limbs, b_mod.limbs);
            return BigInt256{ .limbs = result_limbs, .negative = false };
        } else {
            // a_mod < b_mod, result would be negative: need to add q
            // (a - b) mod q = q - (b - a) when a < b
            const diff_limbs = subLimbs(b_mod.limbs, a_mod.limbs);
            const neg_result = BigInt256{ .limbs = diff_limbs, .negative = false };
            // q - diff
            const result_limbs = subLimbs(GROUP_ORDER.limbs, neg_result.limbs);
            return BigInt256{ .limbs = result_limbs, .negative = false };
        }
    }

    /// Multiply two values mod q (secp256k1 group order)
    /// Returns (a * b) mod q in range [0, q-1]
    /// Reference: Scala SBigInt.multModQ (v3+ only)
    pub fn multModQ(a: BigInt256, b: BigInt256) BigIntError!BigInt256 {
        // PRECONDITION: inputs are valid BigInt256
        assert(!a.isZero() or !a.negative);
        assert(!b.isZero() or !b.negative);

        // Reduce inputs first, then multiply, then reduce again
        const a_mod = try a.modQ();
        const b_mod = try b.modQ();

        // For multiplication, we need to handle larger intermediate values
        // Since both a_mod, b_mod < q < 2^256, product can be up to 2^512
        // We use the full 8-limb multiplication result and reduce mod q
        const product = try mulLimbsFull(a_mod.limbs, b_mod.limbs);

        // Reduce 512-bit result mod q using Barrett reduction or repeated subtraction
        // For correctness over speed, use repeated halving/subtraction
        return reduceModQ512(product);
    }

    /// Full 8-limb multiplication (returns 512-bit result)
    fn mulLimbsFull(a: [4]u64, b: [4]u64) BigIntError![8]u64 {
        var result: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };

        for (0..4) |i| {
            var carry: u64 = 0;
            for (0..4) |j| {
                const prod: u128 = @as(u128, a[i]) * @as(u128, b[j]);
                const sum: u128 = @as(u128, result[i + j]) + prod + @as(u128, carry);
                result[i + j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
            result[i + 4] = carry;
        }

        return result;
    }

    /// Reduce 512-bit value mod q to 256-bit result
    fn reduceModQ512(value: [8]u64) BigIntError!BigInt256 {
        // Check if high limbs are all zero (fits in 256 bits)
        if (value[4] == 0 and value[5] == 0 and value[6] == 0 and value[7] == 0) {
            const result = BigInt256{ .limbs = .{ value[0], value[1], value[2], value[3] }, .negative = false };
            return result.modQ();
        }

        // Use shift-and-subtract method for larger values
        // This is not the fastest but is correct
        var rem: [8]u64 = value;
        const q_extended: [8]u64 = .{ GROUP_ORDER.limbs[0], GROUP_ORDER.limbs[1], GROUP_ORDER.limbs[2], GROUP_ORDER.limbs[3], 0, 0, 0, 0 };

        // Find highest set bit in remainder
        var highest_bit: i32 = 511;
        while (highest_bit >= 256) : (highest_bit -= 1) {
            const limb_idx: usize = @intCast(@divTrunc(highest_bit, 64));
            const bit_idx: u6 = @intCast(@mod(highest_bit, 64));
            if ((rem[limb_idx] >> bit_idx) & 1 != 0) break;
        }

        // Repeatedly subtract shifted q
        while (highest_bit >= 256) {
            const shift: u32 = @intCast(highest_bit - 255);
            const q_shifted = shiftLeft512(q_extended, @intCast(shift));

            if (compare512(rem, q_shifted) != .lt) {
                rem = sub512(rem, q_shifted);
            }

            highest_bit -= 1;
            // Recompute highest bit
            while (highest_bit >= 256) : (highest_bit -= 1) {
                const limb_idx: usize = @intCast(@divTrunc(highest_bit, 64));
                const bit_idx: u6 = @intCast(@mod(highest_bit, 64));
                if ((rem[limb_idx] >> bit_idx) & 1 != 0) break;
            }
        }

        // Now result fits in 256 bits
        const result = BigInt256{
            .limbs = .{ rem[0], rem[1], rem[2], rem[3] },
            .negative = false,
        };
        return result.modQ();
    }

    /// Shift 512-bit value left by n bits
    fn shiftLeft512(a: [8]u64, n: u16) [8]u64 {
        if (n == 0) return a;
        if (n >= 512) return .{ 0, 0, 0, 0, 0, 0, 0, 0 };

        var result: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
        const limb_shift = n / 64;
        const bit_shift: u6 = @intCast(n % 64);

        for (0..8) |i| {
            if (i + limb_shift < 8) {
                result[i + limb_shift] |= a[i] << bit_shift;
                if (bit_shift > 0 and i + limb_shift + 1 < 8) {
                    result[i + limb_shift + 1] |= a[i] >> @intCast(64 - @as(u7, bit_shift));
                }
            }
        }

        return result;
    }

    /// Compare two 512-bit values
    fn compare512(a: [8]u64, b: [8]u64) std.math.Order {
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            if (a[i] > b[i]) return .gt;
            if (a[i] < b[i]) return .lt;
        }
        return .eq;
    }

    /// Subtract 512-bit values (a - b, assumes a >= b)
    fn sub512(a: [8]u64, b: [8]u64) [8]u64 {
        var result: [8]u64 = undefined;
        var borrow: u64 = 0;

        for (0..8) |i| {
            const diff1 = @subWithOverflow(a[i], b[i]);
            const diff2 = @subWithOverflow(diff1[0], borrow);
            result[i] = diff2[0];
            borrow = diff1[1] + diff2[1];
        }

        assert(borrow == 0);
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

test "bigint: modInverse basic" {
    // 3 * 5 = 15 ≡ 1 (mod 7)
    const a = BigInt256.fromInt(3);
    const m = BigInt256.fromInt(7);

    const inv = try a.modInverse(m);
    try std.testing.expect(inv.eql(BigInt256.fromInt(5)));

    // Verify: (a * inv) mod m == 1
    const product = try a.mul(inv);
    const check = try product.mod(m);
    try std.testing.expect(check.eql(BigInt256.one));
}

test "bigint: modInverse larger values" {
    // Test with larger numbers
    const a = BigInt256.fromInt(17);
    const m = BigInt256.fromInt(43);

    const inv = try a.modInverse(m);

    // Verify: (a * inv) mod m == 1
    const product = try a.mul(inv);
    const check = try product.mod(m);
    try std.testing.expect(check.eql(BigInt256.one));
}

test "bigint: modInverse when a > m" {
    // a = 10, m = 7, effective a = 3
    const a = BigInt256.fromInt(10);
    const m = BigInt256.fromInt(7);

    const inv = try a.modInverse(m);

    // Verify: (a * inv) mod m == 1
    const product = try a.mul(inv);
    const check = try product.mod(m);
    try std.testing.expect(check.eql(BigInt256.one));
}

test "bigint: modInverse no inverse exists" {
    // gcd(6, 9) = 3 ≠ 1, no inverse
    const a = BigInt256.fromInt(6);
    const m = BigInt256.fromInt(9);

    try std.testing.expectError(error.DivisionByZero, a.modInverse(m));
}

test "bigint: modInverse zero modulus" {
    const a = BigInt256.fromInt(3);
    try std.testing.expectError(error.DivisionByZero, a.modInverse(BigInt256.zero));
}

test "bigint: modInverse zero value" {
    const m = BigInt256.fromInt(7);
    try std.testing.expectError(error.DivisionByZero, BigInt256.zero.modInverse(m));
}

test "bigint: modInverse negative value" {
    // -3 mod 7: inverse of -3 ≡ 4 (mod 7) is 2 (since 4*2 = 8 ≡ 1)
    const a = BigInt256.fromInt(-3);
    const m = BigInt256.fromInt(7);

    const inv = try a.modInverse(m);

    // Verify: (a * inv) mod m == 1
    // -3 * inv should give result ≡ 1 (mod 7)
    const product = try a.mul(inv);
    var check = try product.mod(m);
    // Normalize negative result
    if (check.isNegative()) {
        check = try check.add(m);
    }
    try std.testing.expect(check.eql(BigInt256.one));
}

// ============================================================================
// ModQ Tests (secp256k1 group order)
// ============================================================================

test "bigint: GROUP_ORDER matches secp256k1 N" {
    // Verify GROUP_ORDER constant matches expected hex value
    // q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    const q = BigInt256.GROUP_ORDER;

    // Check it's positive and non-zero
    try std.testing.expect(!q.negative);
    try std.testing.expect(!q.isZero());

    // Verify limb values match secp256k1.N
    try std.testing.expectEqual(@as(u64, 0xBFD25E8CD0364141), q.limbs[0]);
    try std.testing.expectEqual(@as(u64, 0xBAAEDCE6AF48A03B), q.limbs[1]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFE), q.limbs[2]);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), q.limbs[3]);
}

test "bigint: modQ reduces value to [0, q-1]" {
    // Small positive: unchanged
    const small = BigInt256.fromInt(42);
    const small_mod = try small.modQ();
    try std.testing.expect(small_mod.eql(small));

    // q mod q = 0
    const q_mod = try BigInt256.GROUP_ORDER.modQ();
    try std.testing.expect(q_mod.isZero());

    // Negative value: normalized to positive range
    const neg = BigInt256.fromInt(-1);
    const neg_mod = try neg.modQ();
    // -1 mod q = q - 1
    const expected = try BigInt256.GROUP_ORDER.sub(BigInt256.one);
    try std.testing.expect(neg_mod.eql(expected));
}

test "bigint: plusModQ basic" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(50);

    const result = try a.plusModQ(b);
    try std.testing.expect(result.eql(BigInt256.fromInt(150)));
}

test "bigint: plusModQ with wrap" {
    // (q - 1) + 2 = q + 1 mod q = 1
    const q_minus_1 = try BigInt256.GROUP_ORDER.sub(BigInt256.one);
    const two = BigInt256.fromInt(2);

    const result = try q_minus_1.plusModQ(two);
    try std.testing.expect(result.eql(BigInt256.one));
}

test "bigint: plusModQ overflow with small limbs" {
    // Test case that triggers overflow where limbs < GROUP_ORDER
    // (q-1) + (q-1) = 2q - 2, which overflows 256 bits
    // Result should be (2q - 2) mod q = q - 2
    const q_minus_1 = try BigInt256.GROUP_ORDER.sub(BigInt256.one);
    const result = try q_minus_1.plusModQ(q_minus_1);

    const expected = try BigInt256.GROUP_ORDER.sub(BigInt256.fromInt(2));
    try std.testing.expect(result.eql(expected));
}

test "bigint: ORDER_COMPLEMENT is correct" {
    // Verify: GROUP_ORDER + ORDER_COMPLEMENT = 2^256
    // Since 2^256 can't be represented in 256 bits, verify by computing
    // the limb-by-limb sum and checking it equals 0 with overflow
    const q = BigInt256.GROUP_ORDER.limbs;
    const c = BigInt256.ORDER_COMPLEMENT.limbs;

    // Manual limb addition to verify
    var carry: u64 = 0;
    var result: [4]u64 = undefined;
    for (0..4) |i| {
        const sum1: u128 = @as(u128, q[i]) + @as(u128, c[i]) + @as(u128, carry);
        result[i] = @truncate(sum1);
        carry = @truncate(sum1 >> 64);
    }

    // All limbs should be 0, with carry out of 1 (meaning result = 2^256)
    try std.testing.expectEqual([4]u64{ 0, 0, 0, 0 }, result);
    try std.testing.expectEqual(@as(u64, 1), carry);
}

test "bigint: minusModQ basic" {
    const a = BigInt256.fromInt(100);
    const b = BigInt256.fromInt(30);

    const result = try a.minusModQ(b);
    try std.testing.expect(result.eql(BigInt256.fromInt(70)));
}

test "bigint: minusModQ with wrap to negative" {
    // 1 - 2 = -1 mod q = q - 1
    const one = BigInt256.one;
    const two = BigInt256.fromInt(2);

    const result = try one.minusModQ(two);
    const expected = try BigInt256.GROUP_ORDER.sub(BigInt256.one);
    try std.testing.expect(result.eql(expected));
}

test "bigint: multModQ basic" {
    const a = BigInt256.fromInt(6);
    const b = BigInt256.fromInt(7);

    const result = try a.multModQ(b);
    try std.testing.expect(result.eql(BigInt256.fromInt(42)));
}

test "bigint: modQ result always in valid range" {
    // Test various values
    const test_cases = [_]i64{ 0, 1, -1, 100, -100, std.math.maxInt(i64), std.math.minInt(i64) };

    for (test_cases) |v| {
        const val = BigInt256.fromInt(v);
        const result = try val.modQ();

        // Result must be non-negative
        try std.testing.expect(!result.isNegative());
        // Result must be < q
        try std.testing.expect(result.compare(BigInt256.GROUP_ORDER) == .lt);
    }
}

// ============================================================================
// UnsignedBigInt256 - 256-bit Unsigned Integer (v6+)
// ============================================================================

/// 256-bit unsigned integer for ErgoTree v6+.
/// Range: [0, 2^256 - 1]
/// Used for cryptographic operations without sign extension issues.
pub const UnsignedBigInt256 = struct {
    /// Magnitude as 4 x u64 limbs, little-endian (limbs[0] is LSB)
    limbs: [4]u64,

    // ========================================================================
    // Constants
    // ========================================================================

    pub const zero = UnsignedBigInt256{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one = UnsignedBigInt256{ .limbs = .{ 1, 0, 0, 0 } };

    /// Maximum value: 2^256 - 1
    pub const max_value = UnsignedBigInt256{
        .limbs = .{
            std.math.maxInt(u64),
            std.math.maxInt(u64),
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        },
    };

    // ========================================================================
    // Construction
    // ========================================================================

    /// Create from u64
    pub fn fromUint(value: u64) UnsignedBigInt256 {
        return .{ .limbs = .{ value, 0, 0, 0 } };
    }

    /// Create from big-endian bytes (unsigned)
    pub fn fromBytes(bytes: []const u8) BigIntError!UnsignedBigInt256 {
        if (bytes.len == 0) return zero;
        if (bytes.len > 32) return error.ValueTooLarge;

        // Pad to 32 bytes (zero-extend)
        var padded: [32]u8 = [_]u8{0} ** 32;
        @memcpy(padded[32 - bytes.len ..], bytes);

        // Convert big-endian bytes to little-endian u64 limbs
        var limbs: [4]u64 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, padded[offset..][0..8], .big);
        }

        return .{ .limbs = limbs };
    }

    /// Convert to big-endian bytes (minimal encoding)
    pub fn toBytes(self: UnsignedBigInt256, buffer: *[32]u8) []u8 {
        // Convert limbs to big-endian
        var full: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, full[offset..][0..8], self.limbs[i], .big);
        }

        // Find minimal encoding (skip leading zeros)
        var start: usize = 0;
        while (start < 31 and full[start] == 0) : (start += 1) {}

        const len = 32 - start;
        if (len == 0) {
            buffer[0] = 0;
            return buffer[0..1];
        }
        @memcpy(buffer[0..len], full[start..]);
        return buffer[0..len];
    }

    // ========================================================================
    // Comparison
    // ========================================================================

    pub fn isZero(self: UnsignedBigInt256) bool {
        return self.limbs[0] == 0 and self.limbs[1] == 0 and
            self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    pub fn eql(self: UnsignedBigInt256, other: UnsignedBigInt256) bool {
        return self.limbs[0] == other.limbs[0] and self.limbs[1] == other.limbs[1] and
            self.limbs[2] == other.limbs[2] and self.limbs[3] == other.limbs[3];
    }

    pub const Order = enum { lt, eq, gt };

    pub fn compare(self: UnsignedBigInt256, other: UnsignedBigInt256) Order {
        // Compare from MSB to LSB
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (self.limbs[i] < other.limbs[i]) return .lt;
            if (self.limbs[i] > other.limbs[i]) return .gt;
        }
        return .eq;
    }

    // ========================================================================
    // Arithmetic
    // ========================================================================

    /// Add two unsigned BigInts
    pub fn add(a: UnsignedBigInt256, b: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        var result: UnsignedBigInt256 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            const sum1 = @addWithOverflow(a.limbs[i], b.limbs[i]);
            const sum2 = @addWithOverflow(sum1[0], carry);
            result.limbs[i] = sum2[0];
            carry = sum1[1] + sum2[1];
        }

        if (carry != 0) return error.Overflow;
        return result;
    }

    /// Subtract b from a (a >= b required)
    pub fn sub(a: UnsignedBigInt256, b: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (a.compare(b) == .lt) return error.Overflow; // Would underflow

        var result: UnsignedBigInt256 = undefined;
        var borrow: u64 = 0;

        for (0..4) |i| {
            const diff1 = @subWithOverflow(a.limbs[i], b.limbs[i]);
            const diff2 = @subWithOverflow(diff1[0], borrow);
            result.limbs[i] = diff2[0];
            borrow = diff1[1] + diff2[1];
        }

        assert(borrow == 0); // Guaranteed by compare check above
        return result;
    }

    /// Multiply two unsigned BigInts
    pub fn mul(a: UnsignedBigInt256, b: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        // Use 512-bit intermediate result
        var result: [8]u64 = [_]u64{0} ** 8;

        for (0..4) |i| {
            var carry: u64 = 0;
            for (0..4) |j| {
                const wide = @as(u128, a.limbs[i]) * @as(u128, b.limbs[j]);
                const sum = @as(u128, result[i + j]) + wide + @as(u128, carry);
                result[i + j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
            result[i + 4] = carry;
        }

        // Check for overflow (high limbs must be zero)
        if (result[4] != 0 or result[5] != 0 or result[6] != 0 or result[7] != 0) {
            return error.Overflow;
        }

        return .{ .limbs = result[0..4].* };
    }

    /// Divide a by b (truncating division)
    pub fn div(a: UnsignedBigInt256, b: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (b.isZero()) return error.DivisionByZero;
        if (a.compare(b) == .lt) return zero;
        if (a.eql(b)) return one;

        // Binary long division
        var quotient = zero;
        var remainder = zero;

        // Process bits from MSB to LSB
        var bit: i32 = 255;
        while (bit >= 0) : (bit -= 1) {
            // Shift remainder left by 1
            remainder = remainder.shiftLeft(1);

            // Bring down next bit from dividend
            const limb_idx: usize = @intCast(@divTrunc(bit, 64));
            const bit_idx: u6 = @intCast(@mod(bit, 64));
            const a_bit = (a.limbs[limb_idx] >> bit_idx) & 1;
            remainder.limbs[0] |= a_bit;

            // If remainder >= divisor, subtract and set quotient bit
            if (remainder.compare(b) != .lt) {
                remainder = remainder.sub(b) catch unreachable;
                const q_limb_idx: usize = @intCast(@divTrunc(bit, 64));
                const q_bit_idx: u6 = @intCast(@mod(bit, 64));
                quotient.limbs[q_limb_idx] |= @as(u64, 1) << q_bit_idx;
            }
        }

        return quotient;
    }

    /// Modulo operation (remainder after division)
    pub fn mod(a: UnsignedBigInt256, b: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (b.isZero()) return error.DivisionByZero;
        if (a.compare(b) == .lt) return a;

        // Binary long division to get remainder
        var remainder = zero;

        var bit: i32 = 255;
        while (bit >= 0) : (bit -= 1) {
            remainder = remainder.shiftLeft(1);

            const limb_idx: usize = @intCast(@divTrunc(bit, 64));
            const bit_idx: u6 = @intCast(@mod(bit, 64));
            const a_bit = (a.limbs[limb_idx] >> bit_idx) & 1;
            remainder.limbs[0] |= a_bit;

            if (remainder.compare(b) != .lt) {
                remainder = remainder.sub(b) catch unreachable;
            }
        }

        return remainder;
    }

    /// Shift left by 1 bit
    fn shiftLeft(self: UnsignedBigInt256, n: u32) UnsignedBigInt256 {
        assert(n <= 1); // Only used for shift by 1
        if (n == 0) return self;

        var result: UnsignedBigInt256 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            result.limbs[i] = (self.limbs[i] << 1) | carry;
            carry = self.limbs[i] >> 63;
        }

        return result;
    }

    // ========================================================================
    // Modular Arithmetic
    // ========================================================================

    /// (a + b) mod m
    pub fn addMod(a: UnsignedBigInt256, b: UnsignedBigInt256, m: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (m.isZero()) return error.DivisionByZero;

        // Compute a + b (may overflow 256 bits)
        // Use add with overflow detection, then mod
        const sum = a.add(b) catch {
            // Overflow: compute (a mod m + b mod m) mod m instead
            const a_mod = try a.mod(m);
            const b_mod = try b.mod(m);
            const sum2 = try a_mod.add(b_mod);
            return try sum2.mod(m);
        };
        return try sum.mod(m);
    }

    /// (a - b) mod m (result is always non-negative)
    pub fn subMod(a: UnsignedBigInt256, b: UnsignedBigInt256, m: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (m.isZero()) return error.DivisionByZero;

        const a_mod = try a.mod(m);
        const b_mod = try b.mod(m);

        if (a_mod.compare(b_mod) != .lt) {
            return try (try a_mod.sub(b_mod)).mod(m);
        } else {
            // a < b: result = m - (b - a)
            const diff = try b_mod.sub(a_mod);
            return try m.sub(diff);
        }
    }

    /// (a * b) mod m
    pub fn mulMod(a: UnsignedBigInt256, b: UnsignedBigInt256, m: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (m.isZero()) return error.DivisionByZero;

        // For safety, reduce inputs first
        const a_mod = try a.mod(m);
        const b_mod = try b.mod(m);

        // Multiply with overflow handling via 512-bit intermediate
        const product = a_mod.mul(b_mod) catch {
            // Overflow in 256 bits - need 512-bit multiplication
            // For simplicity, use repeated doubling
            return try mulModSlow(a_mod, b_mod, m);
        };

        return try product.mod(m);
    }

    /// Slow but safe modular multiplication via repeated addition
    fn mulModSlow(a: UnsignedBigInt256, b: UnsignedBigInt256, m: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        var result = zero;
        var base = a;

        var bit: usize = 0;
        while (bit < 256) : (bit += 1) {
            const limb_idx = bit / 64;
            const bit_idx: u6 = @intCast(bit % 64);

            if ((b.limbs[limb_idx] >> bit_idx) & 1 != 0) {
                result = try result.addMod(base, m);
            }
            base = try base.addMod(base, m); // base = base * 2 mod m
        }

        return result;
    }

    /// Modular inverse: a^(-1) mod m using extended Euclidean algorithm
    pub fn modInverse(self: UnsignedBigInt256, m: UnsignedBigInt256) BigIntError!UnsignedBigInt256 {
        if (m.isZero()) return error.DivisionByZero;
        if (self.isZero()) return error.DivisionByZero;

        // Convert to signed BigInt256 for extended GCD
        const a_signed = BigInt256{ .limbs = self.limbs, .negative = false };
        const m_signed = BigInt256{ .limbs = m.limbs, .negative = false };

        const inv_signed = try a_signed.modInverse(m_signed);

        // Result should be non-negative
        if (inv_signed.negative) {
            const m_copy = BigInt256{ .limbs = m.limbs, .negative = false };
            const adjusted = try inv_signed.add(m_copy);
            return .{ .limbs = adjusted.limbs };
        }

        return .{ .limbs = inv_signed.limbs };
    }
};

// ============================================================================
// UnsignedBigInt256 Tests
// ============================================================================

test "unsigned_bigint: zero and one" {
    try std.testing.expect(UnsignedBigInt256.zero.isZero());
    try std.testing.expect(!UnsignedBigInt256.one.isZero());
    try std.testing.expect(UnsignedBigInt256.one.eql(UnsignedBigInt256.fromUint(1)));
}

test "unsigned_bigint: fromBytes roundtrip" {
    const bytes = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const val = try UnsignedBigInt256.fromBytes(&bytes);

    var buf: [32]u8 = undefined;
    const out = val.toBytes(&buf);

    try std.testing.expectEqualSlices(u8, &bytes, out);
}

test "unsigned_bigint: add basic" {
    const a = UnsignedBigInt256.fromUint(100);
    const b = UnsignedBigInt256.fromUint(200);
    const sum = try a.add(b);
    try std.testing.expect(sum.eql(UnsignedBigInt256.fromUint(300)));
}

test "unsigned_bigint: add overflow" {
    const max = UnsignedBigInt256.max_value;
    try std.testing.expectError(error.Overflow, max.add(UnsignedBigInt256.one));
}

test "unsigned_bigint: sub basic" {
    const a = UnsignedBigInt256.fromUint(300);
    const b = UnsignedBigInt256.fromUint(100);
    const diff = try a.sub(b);
    try std.testing.expect(diff.eql(UnsignedBigInt256.fromUint(200)));
}

test "unsigned_bigint: sub underflow" {
    const a = UnsignedBigInt256.fromUint(100);
    const b = UnsignedBigInt256.fromUint(200);
    try std.testing.expectError(error.Overflow, a.sub(b));
}

test "unsigned_bigint: mul basic" {
    const a = UnsignedBigInt256.fromUint(100);
    const b = UnsignedBigInt256.fromUint(200);
    const prod = try a.mul(b);
    try std.testing.expect(prod.eql(UnsignedBigInt256.fromUint(20000)));
}

test "unsigned_bigint: div basic" {
    const a = UnsignedBigInt256.fromUint(100);
    const b = UnsignedBigInt256.fromUint(30);
    const quot = try a.div(b);
    try std.testing.expect(quot.eql(UnsignedBigInt256.fromUint(3)));
}

test "unsigned_bigint: mod basic" {
    const a = UnsignedBigInt256.fromUint(100);
    const b = UnsignedBigInt256.fromUint(30);
    const rem = try a.mod(b);
    try std.testing.expect(rem.eql(UnsignedBigInt256.fromUint(10)));
}

test "unsigned_bigint: addMod" {
    const a = UnsignedBigInt256.fromUint(7);
    const b = UnsignedBigInt256.fromUint(5);
    const m = UnsignedBigInt256.fromUint(10);
    const result = try a.addMod(b, m);
    try std.testing.expect(result.eql(UnsignedBigInt256.fromUint(2)));
}

test "unsigned_bigint: subMod" {
    const a = UnsignedBigInt256.fromUint(3);
    const b = UnsignedBigInt256.fromUint(7);
    const m = UnsignedBigInt256.fromUint(10);
    // 3 - 7 mod 10 = -4 mod 10 = 6
    const result = try a.subMod(b, m);
    try std.testing.expect(result.eql(UnsignedBigInt256.fromUint(6)));
}

test "unsigned_bigint: mulMod" {
    const a = UnsignedBigInt256.fromUint(7);
    const b = UnsignedBigInt256.fromUint(8);
    const m = UnsignedBigInt256.fromUint(10);
    // 7 * 8 mod 10 = 56 mod 10 = 6
    const result = try a.mulMod(b, m);
    try std.testing.expect(result.eql(UnsignedBigInt256.fromUint(6)));
}

test "unsigned_bigint: modInverse" {
    const a = UnsignedBigInt256.fromUint(3);
    const m = UnsignedBigInt256.fromUint(7);
    const inv = try a.modInverse(m);
    // 3 * inv mod 7 = 1, inv = 5 (since 3*5=15, 15 mod 7 = 1)
    try std.testing.expect(inv.eql(UnsignedBigInt256.fromUint(5)));
}
