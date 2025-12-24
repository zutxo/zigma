//! GF(2^192) Galois Field Arithmetic
//!
//! Implements arithmetic in GF(2^192) for THRESHOLD signature challenge distribution.
//! Uses irreducible polynomial: x^192 + x^7 + x^2 + x + 1
//!
//! Based on Leonid Reyzin's implementation from sigmastate-interpreter.
//! Reference: sigma-rust/gf2_192/src/gf2_192.rs

const std = @import("std");
const assert = std.debug.assert;
const challenge_mod = @import("challenge.zig");
const Challenge = challenge_mod.Challenge;
const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;

// ============================================================================
// Constants
// ============================================================================

/// Irreducible polynomial: x^192 + x^7 + x^2 + x + 1
/// Only need the last word since leading words are 0
const IRRED_PENTANOMIAL: i64 = (1 << 7) | (1 << 2) | (1 << 1) | 1;

/// Pre-computed multiples of IRRED_PENTANOMIAL for fast reduction
const IRRED_MULS: [16]i64 = blk: {
    var muls: [16]i64 = undefined;
    muls[0] = 0;
    muls[1] = IRRED_PENTANOMIAL;
    muls[2] = IRRED_PENTANOMIAL << 1;
    muls[3] = (IRRED_PENTANOMIAL << 1) ^ IRRED_PENTANOMIAL;
    muls[4] = IRRED_PENTANOMIAL << 2;
    muls[5] = (IRRED_PENTANOMIAL << 2) ^ IRRED_PENTANOMIAL;
    muls[6] = (IRRED_PENTANOMIAL << 2) ^ (IRRED_PENTANOMIAL << 1);
    muls[7] = (IRRED_PENTANOMIAL << 2) ^ (IRRED_PENTANOMIAL << 1) ^ IRRED_PENTANOMIAL;
    muls[8] = IRRED_PENTANOMIAL << 3;
    muls[9] = (IRRED_PENTANOMIAL << 3) ^ IRRED_PENTANOMIAL;
    muls[10] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 1);
    muls[11] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 1) ^ IRRED_PENTANOMIAL;
    muls[12] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 2);
    muls[13] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 2) ^ IRRED_PENTANOMIAL;
    muls[14] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 2) ^ (IRRED_PENTANOMIAL << 1);
    muls[15] = (IRRED_PENTANOMIAL << 3) ^ (IRRED_PENTANOMIAL << 2) ^ (IRRED_PENTANOMIAL << 1) ^ IRRED_PENTANOMIAL;
    break :blk muls;
};

pub const MAX_POLY_DEGREE = 16;

// ============================================================================
// GF(2^192) Element
// ============================================================================

/// Element of GF(2^192)
/// Represented as 3 x 64-bit words (192 bits total)
pub const Gf2_192 = struct {
    word: [3]i64,

    /// Zero element
    pub const ZERO: Gf2_192 = .{ .word = .{ 0, 0, 0 } };

    /// One element
    pub const ONE: Gf2_192 = .{ .word = .{ 1, 0, 0 } };

    /// Create zero element
    pub fn zero() Gf2_192 {
        return ZERO;
    }

    /// Create one element
    pub fn one() Gf2_192 {
        return ONE;
    }

    /// Create from i32 value
    pub fn fromInt(v: i32) Gf2_192 {
        return .{ .word = .{ v, 0, 0 } };
    }

    /// Create from 24-byte array (big-endian)
    pub fn fromBytes(bytes: [24]u8) Gf2_192 {
        var result: Gf2_192 = undefined;
        // Bytes are big-endian: bytes[0..8] = word[2], bytes[8..16] = word[1], bytes[16..24] = word[0]
        result.word[2] = @bitCast(std.mem.readInt(u64, bytes[0..8], .big));
        result.word[1] = @bitCast(std.mem.readInt(u64, bytes[8..16], .big));
        result.word[0] = @bitCast(std.mem.readInt(u64, bytes[16..24], .big));
        return result;
    }

    /// Create from Challenge
    pub fn fromChallenge(ch: Challenge) Gf2_192 {
        return fromBytes(ch.bytes);
    }

    /// Convert to 24-byte array (big-endian)
    pub fn toBytes(self: Gf2_192) [24]u8 {
        var result: [24]u8 = undefined;
        std.mem.writeInt(u64, result[0..8], @bitCast(self.word[2]), .big);
        std.mem.writeInt(u64, result[8..16], @bitCast(self.word[1]), .big);
        std.mem.writeInt(u64, result[16..24], @bitCast(self.word[0]), .big);
        return result;
    }

    /// Convert to Challenge
    pub fn toChallenge(self: Gf2_192) Challenge {
        return Challenge{ .bytes = self.toBytes() };
    }

    /// Check if zero
    pub fn isZero(self: Gf2_192) bool {
        return self.word[0] == 0 and self.word[1] == 0 and self.word[2] == 0;
    }

    /// Check if one
    pub fn isOne(self: Gf2_192) bool {
        return self.word[0] == 1 and self.word[1] == 0 and self.word[2] == 0;
    }

    /// Check equality
    pub fn eql(self: Gf2_192, other: Gf2_192) bool {
        return self.word[0] == other.word[0] and
            self.word[1] == other.word[1] and
            self.word[2] == other.word[2];
    }

    /// Addition in GF(2^192) is XOR
    pub fn add(self: Gf2_192, other: Gf2_192) Gf2_192 {
        return .{
            .word = .{
                self.word[0] ^ other.word[0],
                self.word[1] ^ other.word[1],
                self.word[2] ^ other.word[2],
            },
        };
    }

    /// Multiplication in GF(2^192)
    /// Uses table lookups with x^4-and-add algorithm
    pub fn mul(self: Gf2_192, other: Gf2_192) Gf2_192 {
        const a = self;
        const b = other;

        // Build multiplication table for a * {0, 1, x, x+1, ..., x^3+x^2+x+1}
        var a0muls: [16]i64 = [_]i64{0} ** 16;
        var a1muls: [16]i64 = [_]i64{0} ** 16;
        var a2muls: [16]i64 = [_]i64{0} ** 16;

        a0muls[1] = a.word[0];
        a1muls[1] = a.word[1];
        a2muls[1] = a.word[2];

        // a*x, a*x^2, a*x^3
        inline for ([_]usize{ 2, 4, 8 }) |i| {
            const prev = i / 2;
            a0muls[i] = a0muls[prev] << 1;
            a1muls[i] = (a1muls[prev] << 1) | lrs(a0muls[prev], 63);
            a2muls[i] = (a2muls[prev] << 1) | lrs(a1muls[prev], 63);
            // mod reduce
            a0muls[i] ^= IRRED_MULS[@intCast(lrs(a2muls[prev], 63))];
        }

        // a*(x+1)
        a0muls[3] = a0muls[1] ^ a0muls[2];
        a1muls[3] = a1muls[1] ^ a1muls[2];
        a2muls[3] = a2muls[1] ^ a2muls[2];

        // a*(x^2+1), a*(x^2+x), a*(x^2+x+1)
        inline for (1..4) |i| {
            a0muls[4 | i] = a0muls[4] ^ a0muls[i];
            a1muls[4 | i] = a1muls[4] ^ a1muls[i];
            a2muls[4 | i] = a2muls[4] ^ a2muls[i];
        }

        // a*(x^3+...) combinations
        inline for (1..8) |i| {
            a0muls[8 | i] = a0muls[8] ^ a0muls[i];
            a1muls[8 | i] = a1muls[8] ^ a1muls[i];
            a2muls[8 | i] = a2muls[8] ^ a2muls[i];
        }

        var w0: i64 = 0;
        var w1: i64 = 0;
        var w2: i64 = 0;

        // Process each word of b
        var j: usize = 3;
        while (j > 0) {
            j -= 1;
            const multiplier = b.word[j];
            var i: i8 = 60;
            while (i >= 0) : (i -= 4) {
                // Multiply by x^4
                const mod_idx: usize = @intCast(lrs(w2, 60));
                w2 = (w2 << 4) | lrs(w1, 60);
                w1 = (w1 << 4) | lrs(w0, 60);
                w0 = (w0 << 4) ^ IRRED_MULS[mod_idx];

                // Add correct multiple of a
                const idx: usize = @intCast(lrs(multiplier, @intCast(i)) & 15);
                w0 ^= a0muls[idx];
                w1 ^= a1muls[idx];
                w2 ^= a2muls[idx];
            }
        }

        return .{ .word = .{ w0, w1, w2 } };
    }

    /// Multiply by i8 value (more efficient than full mul)
    pub fn mulByI8(self: Gf2_192, b: i8) Gf2_192 {
        const a = self;
        var w0: i64 = 0;
        var w1: i64 = 0;
        var w2: i64 = 0;

        var i: i4 = 7;
        while (i >= 0) : (i -= 1) {
            const w3 = lrs(w2, 63);
            w2 = (w2 << 1) | lrs(w1, 63);
            w1 = (w1 << 1) | lrs(w0, 63);
            w0 <<= 1;
            const t: i64 = @intCast(lrs8(b, @intCast(i)) & 1);
            w2 ^= a.word[2] *% t;
            w1 ^= a.word[1] *% t;
            w0 ^= (a.word[0] *% t) ^ (IRRED_PENTANOMIAL *% w3);
        }

        return .{ .word = .{ w0, w1, w2 } };
    }

    /// Multiplicative inverse using Fermat's little theorem
    /// z^{-1} = z^{2^192 - 2}
    pub fn invert(self: Gf2_192) Gf2_192 {
        // Compute z^{2^192-2} = z^{191 ones followed by zero in binary}
        var z_to_2_to_k1s = self;

        // Square to get exponent 10 in binary
        var res = self.mul(self);

        // z raised to power with 2^k ones followed by 2^k zeros
        var z_to_2_to_k1s_2_to_k0s = res;

        var k: u6 = 0;
        while (k < 6) {
            k += 1;
            // Fill zeros with ones
            z_to_2_to_k1s = z_to_2_to_k1s_2_to_k0s.mul(z_to_2_to_k1s);
            // Append 2^k zeros
            z_to_2_to_k1s_2_to_k0s = power2To2ToK(z_to_2_to_k1s, k);
            // Prepend 2^k ones to result
            res = res.mul(z_to_2_to_k1s_2_to_k0s);
        }
        z_to_2_to_k1s_2_to_k0s = power2To2ToK(z_to_2_to_k1s_2_to_k0s, k);
        return res.mul(z_to_2_to_k1s_2_to_k0s);
    }
};

/// Raise to power 2^{2^k}
fn power2To2ToK(z: Gf2_192, k: u6) Gf2_192 {
    var res = z;
    const iterations: u64 = @as(u64, 1) << k;
    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        res = res.mul(res);
    }
    return res;
}

/// Logical right shift for i64
fn lrs(x: i64, shift: u6) i64 {
    return @bitCast(@as(u64, @bitCast(x)) >> shift);
}

/// Logical right shift for i8
fn lrs8(x: i8, shift: u3) i8 {
    return @bitCast(@as(u8, @bitCast(x)) >> shift);
}

// ============================================================================
// GF(2^192) Polynomial
// ============================================================================

/// Polynomial over GF(2^192)
/// Used for THRESHOLD challenge distribution
pub const Gf2_192Poly = struct {
    /// Coefficients (index 0 is constant term)
    coefficients: [MAX_POLY_DEGREE + 1]Gf2_192,
    /// Degree of polynomial
    degree: u8,

    /// Create constant polynomial
    pub fn makeConstant(value: Gf2_192) Gf2_192Poly {
        var poly: Gf2_192Poly = undefined;
        poly.coefficients[0] = value;
        for (1..MAX_POLY_DEGREE + 1) |i| {
            poly.coefficients[i] = Gf2_192.ZERO;
        }
        poly.degree = 0;
        return poly;
    }

    /// Create from byte representation
    /// coeff0 is the degree-0 coefficient, more_coeffs contains higher-degree coefficients
    pub fn fromBytes(coeff0: [24]u8, more_coeffs: []const u8) !Gf2_192Poly {
        if (more_coeffs.len % 24 != 0) return error.InvalidLength;
        const degree = more_coeffs.len / 24;
        if (degree > MAX_POLY_DEGREE) return error.DegreeTooHigh;

        var poly: Gf2_192Poly = undefined;
        poly.coefficients[0] = Gf2_192.fromBytes(coeff0);
        poly.degree = @intCast(degree);

        for (0..degree) |i| {
            const start = i * 24;
            var bytes: [24]u8 = undefined;
            @memcpy(&bytes, more_coeffs[start .. start + 24]);
            poly.coefficients[i + 1] = Gf2_192.fromBytes(bytes);
        }

        // Zero remaining coefficients
        for (degree + 1..MAX_POLY_DEGREE + 1) |i| {
            poly.coefficients[i] = Gf2_192.ZERO;
        }

        return poly;
    }

    /// Serialize to bytes (excluding degree-0 coefficient)
    pub fn toBytes(self: *const Gf2_192Poly) [MAX_POLY_DEGREE * 24]u8 {
        var result: [MAX_POLY_DEGREE * 24]u8 = undefined;
        for (1..self.degree + 1) |i| {
            const bytes = self.coefficients[i].toBytes();
            const start = (i - 1) * 24;
            @memcpy(result[start .. start + 24], &bytes);
        }
        // Zero remaining
        for (self.degree..MAX_POLY_DEGREE) |i| {
            const start = i * 24;
            @memset(result[start .. start + 24], 0);
        }
        return result;
    }

    /// Evaluate polynomial at point x (where x is interpreted as i8)
    pub fn evaluate(self: *const Gf2_192Poly, x: u8) Gf2_192 {
        // Use Horner's method
        var res = self.coefficients[self.degree];
        if (self.degree > 0) {
            var d: usize = self.degree;
            while (d > 0) {
                d -= 1;
                res = res.mulByI8(@bitCast(x));
                res = res.add(self.coefficients[d]);
            }
        }
        return res;
    }

    /// Interpolate polynomial through given points
    /// Creates polynomial f such that:
    /// - f(0) = value_at_zero
    /// - f(points[i]) = values[i] for all i
    pub fn interpolate(
        points: []const u8,
        values: []const Gf2_192,
        value_at_zero: Gf2_192,
    ) !Gf2_192Poly {
        if (points.len != values.len) return error.LengthMismatch;
        if (points.len > MAX_POLY_DEGREE) return error.TooManyPoints;

        const result_degree = values.len;

        var result = makeConstantInt(result_degree, 0);
        var vanishing_poly = makeConstantInt(result_degree, 1);

        for (0..points.len) |i| {
            var t = result.evaluate(points[i]);
            var s = vanishing_poly.evaluate(points[i]);

            // Find r such that currentValue + r * valueOfVanishingPoly = values[i]
            t = t.add(values[i]);
            s = s.invert();
            t = t.mul(s);

            result.addMonicTimesConstant(&vanishing_poly, t);
            vanishing_poly.multiplyByLinearBinomial(@bitCast(points[i]));
        }

        // Last point at 0
        var t = result.coefficients[0];
        var s = vanishing_poly.coefficients[0];

        t = t.add(value_at_zero);
        s = s.invert();
        t = t.mul(s);
        result.addMonicTimesConstant(&vanishing_poly, t);

        return result;
    }

    /// Create constant polynomial with integer value
    fn makeConstantInt(max_degree: usize, value: i32) Gf2_192Poly {
        var poly: Gf2_192Poly = undefined;
        poly.coefficients[0] = Gf2_192.fromInt(value);
        for (1..MAX_POLY_DEGREE + 1) |i| {
            poly.coefficients[i] = Gf2_192.ZERO;
        }
        poly.degree = 0;
        _ = max_degree;
        return poly;
    }

    /// Add r*p to self, where p is monic
    fn addMonicTimesConstant(self: *Gf2_192Poly, p: *const Gf2_192Poly, r: Gf2_192) void {
        for (0..p.degree) |i| {
            const t = p.coefficients[i].mul(r);
            self.coefficients[i] = self.coefficients[i].add(t);
        }
        self.degree = p.degree;
        self.coefficients[self.degree] = r;
    }

    /// Multiply self by (x + r), assumes self is monic
    fn multiplyByLinearBinomial(self: *Gf2_192Poly, r: i8) void {
        self.degree += 1;
        self.coefficients[self.degree] = Gf2_192.ONE;
        var i: usize = self.degree;
        while (i > 1) {
            i -= 1;
            self.coefficients[i] = self.coefficients[i].mulByI8(r);
            self.coefficients[i] = self.coefficients[i].add(self.coefficients[i - 1]);
        }
        self.coefficients[0] = self.coefficients[0].mulByI8(r);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Gf2_192: zero and one" {
    const z = Gf2_192.zero();
    const o = Gf2_192.one();

    try std.testing.expect(z.isZero());
    try std.testing.expect(!z.isOne());
    try std.testing.expect(o.isOne());
    try std.testing.expect(!o.isZero());
}

test "Gf2_192: add is XOR" {
    const a = Gf2_192{ .word = .{ 0xABCD, 0x1234, 0x5678 } };
    const b = Gf2_192{ .word = .{ 0x1111, 0x2222, 0x3333 } };
    const c = a.add(b);

    try std.testing.expectEqual(@as(i64, 0xABCD ^ 0x1111), c.word[0]);
    try std.testing.expectEqual(@as(i64, 0x1234 ^ 0x2222), c.word[1]);
    try std.testing.expectEqual(@as(i64, 0x5678 ^ 0x3333), c.word[2]);
}

test "Gf2_192: add is self-inverse" {
    const a = Gf2_192{ .word = .{ 0x123456789ABCDEF0, 0x7EDCBA9876543210, 0x0011223344556677 } };
    const b = a.add(a);

    try std.testing.expect(b.isZero());
}

test "Gf2_192: mul by one is identity" {
    const a = Gf2_192{ .word = .{ 0x123456789ABCDEF0, 0x7EDCBA9876543210, 0x0011223344556677 } };
    const b = a.mul(Gf2_192.ONE);

    try std.testing.expect(a.eql(b));
}

test "Gf2_192: mul by zero is zero" {
    const a = Gf2_192{ .word = .{ 0x123456789ABCDEF0, 0x7EDCBA9876543210, 0x0011223344556677 } };
    const b = a.mul(Gf2_192.ZERO);

    try std.testing.expect(b.isZero());
}

test "Gf2_192: invert" {
    const a = Gf2_192{ .word = .{ 42, 0, 0 } };
    const a_inv = a.invert();
    const product = a.mul(a_inv);

    try std.testing.expect(product.isOne());
}

test "Gf2_192: bytes roundtrip" {
    const bytes = [_]u8{0x01} ++ [_]u8{0x02} ** 7 ++ [_]u8{0x03} ** 8 ++ [_]u8{0x04} ** 8;
    const elem = Gf2_192.fromBytes(bytes);
    const out = elem.toBytes();

    try std.testing.expectEqualSlices(u8, &bytes, &out);
}

test "Gf2_192Poly: constant polynomial" {
    const val = Gf2_192.fromInt(17);
    const poly = Gf2_192Poly.makeConstant(val);

    // Evaluates to 17 everywhere
    try std.testing.expect(poly.evaluate(0).eql(val));
    try std.testing.expect(poly.evaluate(5).eql(val));
    try std.testing.expect(poly.evaluate(255).eql(val));
}

test "Gf2_192Poly: interpolate constant" {
    const value = Gf2_192.fromInt(42);
    const poly = try Gf2_192Poly.interpolate(&[_]u8{}, &[_]Gf2_192{}, value);

    try std.testing.expect(poly.evaluate(0).eql(value));
    try std.testing.expect(poly.evaluate(1).eql(value));
}

test "Gf2_192Poly: interpolate linear" {
    // Create polynomial passing through (0, 10), (1, 20)
    const value_at_zero = Gf2_192.fromInt(10);
    const poly = try Gf2_192Poly.interpolate(
        &[_]u8{1},
        &[_]Gf2_192{Gf2_192.fromInt(20)},
        value_at_zero,
    );

    try std.testing.expect(poly.evaluate(0).eql(value_at_zero));
    // Due to GF(2) arithmetic, f(1) should equal value passed
    const at_one = poly.evaluate(1);
    try std.testing.expect(at_one.eql(Gf2_192.fromInt(20)));
}
