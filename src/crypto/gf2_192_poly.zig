//! GF(2^192) Polynomial Arithmetic
//!
//! Implements polynomials over GF(2^192) for THRESHOLD signature challenge distribution.
//! In k-of-n threshold signatures, challenges are distributed using polynomial interpolation:
//! - Root challenge is the constant term (coeff0)
//! - Additional n-k coefficients define the polynomial
//! - Child challenge i = P(i) where i ∈ {1, 2, ..., n}
//!
//! Polynomial format (from proof bytes):
//! - Constant term (24 bytes): the root challenge
//! - Coefficients 1 through n-k-1 (each 24 bytes): higher degree terms
//!
//! Reference: sigmastate/src/main/scala/sigmastate/crypto/GF2_192_Poly.scala

const std = @import("std");
const assert = std.debug.assert;
const GF2_192 = @import("gf2_192.zig").GF2_192;

// ============================================================================
// Polynomial over GF(2^192)
// ============================================================================

/// Polynomial over GF(2^192)
/// P(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... + coeffs[n-1]*x^(n-1)
/// Maximum degree is MAX_DEGREE (supports up to n-k polynomial for threshold)
pub const GF2_192_Poly = struct {
    /// Polynomial coefficients
    /// coeffs[0] = constant term
    /// coeffs[i] = coefficient of x^i
    coeffs: [MAX_COEFFS]GF2_192,
    /// Number of coefficients (degree + 1)
    len: u8,

    /// Maximum number of coefficients supported
    /// In threshold signatures, this is n-k+1 where n is the total signers
    /// For Ergo, n <= 255 (u8), so we support up to 256 coefficients
    pub const MAX_COEFFS = 256;

    // Compile-time assertion
    comptime {
        assert(MAX_COEFFS <= 256);
    }

    /// Zero polynomial
    pub const zero = GF2_192_Poly{
        .coeffs = [_]GF2_192{GF2_192.zero} ** MAX_COEFFS,
        .len = 0,
    };

    /// Constant polynomial equal to one
    pub fn one() GF2_192_Poly {
        var p = zero;
        p.coeffs[0] = GF2_192.one;
        p.len = 1;
        return p;
    }

    /// Create a constant polynomial from a field element
    pub fn constant(c: GF2_192) GF2_192_Poly {
        var p = zero;
        p.coeffs[0] = c;
        p.len = if (c.isZero()) 0 else 1;
        return p;
    }

    /// Create polynomial from coefficient bytes
    /// The first 24 bytes are the constant term, subsequent 24-byte chunks are higher coefficients
    ///
    /// Format: [coeff0 (24 bytes)][coeff1 (24 bytes)]...[coeffN (24 bytes)]
    ///
    /// For THRESHOLD signatures:
    /// - coeff0 is the root challenge (24 bytes)
    /// - coeffs 1..n-k are the additional polynomial coefficients
    pub fn fromBytes(bytes: []const u8) error{InvalidLength}!GF2_192_Poly {
        // PRECONDITION 1: length must be multiple of 24
        if (bytes.len % 24 != 0) return error.InvalidLength;

        const num_coeffs = bytes.len / 24;

        // PRECONDITION 2: must have at least one coefficient
        if (num_coeffs == 0) return error.InvalidLength;

        // PRECONDITION 3: cannot exceed maximum coefficients
        if (num_coeffs > MAX_COEFFS) return error.InvalidLength;

        var p = zero;
        p.len = @intCast(num_coeffs);

        for (0..num_coeffs) |i| {
            const start = i * 24;
            p.coeffs[i] = GF2_192.fromBytes(bytes[start..][0..24].*);
        }

        // POSTCONDITION: length matches input
        assert(p.len * 24 == bytes.len);
        return p;
    }

    /// Create polynomial from root challenge and additional coefficients
    /// This is the format used in THRESHOLD proofs:
    /// - root_challenge: the constant term (24 bytes)
    /// - more_coeffs: additional coefficient bytes (n-k-1 coefficients, each 24 bytes)
    pub fn fromRootAndMore(root_challenge: [24]u8, more_coeffs: []const u8) error{InvalidLength}!GF2_192_Poly {
        // PRECONDITION: more_coeffs must be multiple of 24
        if (more_coeffs.len % 24 != 0) return error.InvalidLength;

        const additional_count = more_coeffs.len / 24;

        // PRECONDITION: total coefficients within bounds
        if (1 + additional_count > MAX_COEFFS) return error.InvalidLength;

        var p = zero;
        p.coeffs[0] = GF2_192.fromBytes(root_challenge);
        p.len = @intCast(1 + additional_count);

        for (0..additional_count) |i| {
            const start = i * 24;
            p.coeffs[1 + i] = GF2_192.fromBytes(more_coeffs[start..][0..24].*);
        }

        return p;
    }

    /// Evaluate polynomial at a point using Horner's method
    /// P(x) = coeffs[0] + x*(coeffs[1] + x*(coeffs[2] + ... x*coeffs[n-1]))
    ///
    /// For THRESHOLD: evaluate at i ∈ {1, 2, ..., n} to get child challenges
    pub fn evaluate(self: GF2_192_Poly, x: GF2_192) GF2_192 {
        if (self.len == 0) return GF2_192.zero;

        // Horner's method from highest degree to lowest
        var result = self.coeffs[self.len - 1];

        var i: usize = self.len - 1;
        while (i > 0) {
            i -= 1;
            result = result.mul(x).add(self.coeffs[i]);
        }

        return result;
    }

    /// Evaluate polynomial at a byte value (convenience for THRESHOLD)
    /// Child indices are 1, 2, ..., n
    pub fn evaluateAt(self: GF2_192_Poly, index: u8) GF2_192 {
        // PRECONDITION: index should typically be non-zero for child challenges
        // But zero evaluation is mathematically valid (returns constant term)

        return self.evaluate(GF2_192.fromByte(index));
    }

    /// Get the degree of the polynomial
    /// Returns -1 for zero polynomial
    pub fn degree(self: GF2_192_Poly) i32 {
        if (self.len == 0) return -1;

        // Find highest non-zero coefficient
        var i: usize = self.len;
        while (i > 0) {
            i -= 1;
            if (!self.coeffs[i].isZero()) {
                return @intCast(i);
            }
        }
        return -1;
    }

    /// Add two polynomials
    pub fn add(self: GF2_192_Poly, other: GF2_192_Poly) GF2_192_Poly {
        var result = zero;
        result.len = @max(self.len, other.len);

        for (0..result.len) |i| {
            const a = if (i < self.len) self.coeffs[i] else GF2_192.zero;
            const b = if (i < other.len) other.coeffs[i] else GF2_192.zero;
            result.coeffs[i] = a.add(b);
        }

        // Normalize: reduce len if high coefficients are zero
        while (result.len > 0 and result.coeffs[result.len - 1].isZero()) {
            result.len -= 1;
        }

        return result;
    }

    /// Subtract two polynomials (same as add in GF(2))
    pub fn sub(self: GF2_192_Poly, other: GF2_192_Poly) GF2_192_Poly {
        return self.add(other);
    }

    /// Multiply polynomial by a scalar
    pub fn scalarMul(self: GF2_192_Poly, scalar: GF2_192) GF2_192_Poly {
        if (scalar.isZero()) return zero;

        var result = self;
        for (0..result.len) |i| {
            result.coeffs[i] = result.coeffs[i].mul(scalar);
        }

        // Normalize
        while (result.len > 0 and result.coeffs[result.len - 1].isZero()) {
            result.len -= 1;
        }

        return result;
    }

    /// Check if polynomials are equal
    pub fn eql(self: GF2_192_Poly, other: GF2_192_Poly) bool {
        if (self.len != other.len) return false;

        for (0..self.len) |i| {
            if (!self.coeffs[i].eql(other.coeffs[i])) return false;
        }
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "gf2_192_poly: zero polynomial" {
    const p = GF2_192_Poly.zero;
    try std.testing.expectEqual(@as(u8, 0), p.len);
    try std.testing.expectEqual(@as(i32, -1), p.degree());

    // Evaluation of zero polynomial is zero
    try std.testing.expect(p.evaluate(GF2_192.one).isZero());
}

test "gf2_192_poly: one polynomial" {
    const p = GF2_192_Poly.one();
    try std.testing.expectEqual(@as(u8, 1), p.len);
    try std.testing.expectEqual(@as(i32, 0), p.degree());

    // P(x) = 1 for all x
    try std.testing.expect(p.evaluate(GF2_192.zero).eql(GF2_192.one));
    try std.testing.expect(p.evaluate(GF2_192.one).eql(GF2_192.one));
    try std.testing.expect(p.evaluate(GF2_192.fromByte(42)).eql(GF2_192.one));
}

test "gf2_192_poly: constant polynomial" {
    const c = GF2_192.fromByte(0x42);
    const p = GF2_192_Poly.constant(c);

    try std.testing.expectEqual(@as(u8, 1), p.len);
    try std.testing.expect(p.evaluate(GF2_192.fromByte(1)).eql(c));
    try std.testing.expect(p.evaluate(GF2_192.fromByte(99)).eql(c));
}

test "gf2_192_poly: fromBytes basic" {
    // Single coefficient (constant polynomial)
    var bytes: [24]u8 = [_]u8{0} ** 24;
    bytes[23] = 0x05; // Little value in big-endian format

    const p = try GF2_192_Poly.fromBytes(&bytes);
    try std.testing.expectEqual(@as(u8, 1), p.len);
    try std.testing.expect(p.coeffs[0].eql(GF2_192.fromByte(0x05)));
}

test "gf2_192_poly: fromBytes multiple coefficients" {
    // Two coefficients: P(x) = a + b*x
    var bytes: [48]u8 = [_]u8{0} ** 48;
    bytes[23] = 0x03; // coeff[0] = 3
    bytes[47] = 0x02; // coeff[1] = 2

    const p = try GF2_192_Poly.fromBytes(&bytes);
    try std.testing.expectEqual(@as(u8, 2), p.len);
    try std.testing.expectEqual(@as(i32, 1), p.degree());

    // P(0) = 3
    try std.testing.expect(p.evaluateAt(0).eql(GF2_192.fromByte(0x03)));

    // P(1) = 3 + 2*1 = 3 XOR 2 = 1
    try std.testing.expect(p.evaluateAt(1).eql(GF2_192.fromByte(0x01)));
}

test "gf2_192_poly: fromBytes invalid length" {
    // Not a multiple of 24
    var bytes: [25]u8 = [_]u8{0} ** 25;
    try std.testing.expectError(error.InvalidLength, GF2_192_Poly.fromBytes(&bytes));

    // Empty
    var empty: [0]u8 = .{};
    try std.testing.expectError(error.InvalidLength, GF2_192_Poly.fromBytes(&empty));
}

test "gf2_192_poly: evaluate linear polynomial" {
    // P(x) = 1 + x (in GF(2))
    // coeff[0] = 1, coeff[1] = 1
    var p = GF2_192_Poly.zero;
    p.coeffs[0] = GF2_192.one;
    p.coeffs[1] = GF2_192.one;
    p.len = 2;

    // P(0) = 1 + 0 = 1
    try std.testing.expect(p.evaluateAt(0).eql(GF2_192.one));

    // P(1) = 1 + 1 = 0 (in GF(2), XOR)
    try std.testing.expect(p.evaluateAt(1).isZero());

    // P(2) = 1 + 2 = 3
    try std.testing.expect(p.evaluateAt(2).eql(GF2_192.fromByte(3)));
}

test "gf2_192_poly: evaluate quadratic polynomial" {
    // P(x) = 1 + x + x^2
    var p = GF2_192_Poly.zero;
    p.coeffs[0] = GF2_192.one; // 1
    p.coeffs[1] = GF2_192.one; // x
    p.coeffs[2] = GF2_192.one; // x^2
    p.len = 3;

    // P(0) = 1
    try std.testing.expect(p.evaluateAt(0).eql(GF2_192.one));

    // P(1) = 1 + 1 + 1 = 1 (in GF(2))
    try std.testing.expect(p.evaluateAt(1).eql(GF2_192.one));

    // P(2) = 1 + 2 + 4 = 7
    try std.testing.expect(p.evaluateAt(2).eql(GF2_192.fromByte(7)));
}

test "gf2_192_poly: addition" {
    // P1(x) = 1 + x
    var p1 = GF2_192_Poly.zero;
    p1.coeffs[0] = GF2_192.one;
    p1.coeffs[1] = GF2_192.one;
    p1.len = 2;

    // P2(x) = x + x^2
    var p2 = GF2_192_Poly.zero;
    p2.coeffs[1] = GF2_192.one;
    p2.coeffs[2] = GF2_192.one;
    p2.len = 3;

    // P1 + P2 = 1 + (1+1)x + x^2 = 1 + x^2 (x terms cancel)
    const sum = p1.add(p2);
    try std.testing.expectEqual(@as(i32, 2), sum.degree());
    try std.testing.expect(sum.coeffs[0].eql(GF2_192.one));
    try std.testing.expect(sum.coeffs[1].isZero());
    try std.testing.expect(sum.coeffs[2].eql(GF2_192.one));
}

test "gf2_192_poly: self-addition is zero" {
    var p = GF2_192_Poly.zero;
    p.coeffs[0] = GF2_192.fromByte(0x42);
    p.coeffs[1] = GF2_192.fromByte(0xFF);
    p.len = 2;

    const result = p.add(p);
    try std.testing.expectEqual(@as(i32, -1), result.degree());
}

test "gf2_192_poly: scalar multiplication" {
    // P(x) = 1 + x
    var p = GF2_192_Poly.zero;
    p.coeffs[0] = GF2_192.one;
    p.coeffs[1] = GF2_192.one;
    p.len = 2;

    // Multiply by 3
    const scalar = GF2_192.fromByte(3);
    const result = p.scalarMul(scalar);

    // Result = 3 + 3x
    try std.testing.expect(result.coeffs[0].eql(GF2_192.fromByte(3)));
    try std.testing.expect(result.coeffs[1].eql(GF2_192.fromByte(3)));
}

test "gf2_192_poly: fromRootAndMore" {
    // Root challenge = 0x42
    var root: [24]u8 = [_]u8{0} ** 24;
    root[23] = 0x42;

    // Additional coefficient = 0x07
    var more: [24]u8 = [_]u8{0} ** 24;
    more[23] = 0x07;

    const p = try GF2_192_Poly.fromRootAndMore(root, &more);
    try std.testing.expectEqual(@as(u8, 2), p.len);
    try std.testing.expect(p.coeffs[0].eql(GF2_192.fromByte(0x42)));
    try std.testing.expect(p.coeffs[1].eql(GF2_192.fromByte(0x07)));
}

test "gf2_192_poly: THRESHOLD challenge distribution" {
    // Simulates 2-of-3 threshold signature challenge distribution
    // Polynomial has k=2 coefficients (degree 1): P(x) = c0 + c1*x
    // Children get challenges: P(1), P(2), P(3)

    var root: [24]u8 = [_]u8{0} ** 24;
    root[23] = 0x0A; // Root challenge = 10

    var coeff1: [24]u8 = [_]u8{0} ** 24;
    coeff1[23] = 0x05; // Coefficient for x term = 5

    const p = try GF2_192_Poly.fromRootAndMore(root, &coeff1);

    // P(0) = 10 (root challenge)
    try std.testing.expect(p.evaluateAt(0).eql(GF2_192.fromByte(0x0A)));

    // P(1) = 10 + 5*1 = 10 XOR 5 = 15
    try std.testing.expect(p.evaluateAt(1).eql(GF2_192.fromByte(15)));

    // P(2) = 10 + 5*2 = 10 XOR 10 = 0
    try std.testing.expect(p.evaluateAt(2).isZero());

    // P(3) = 10 + 5*3 = 10 XOR 15 = 5
    try std.testing.expect(p.evaluateAt(3).eql(GF2_192.fromByte(5)));
}
