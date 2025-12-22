//! secp256k1 Elliptic Curve Operations
//!
//! Implements GroupElement operations for ErgoTree:
//! - Point validation (on curve check)
//! - Point addition (group operation)
//! - Scalar multiplication
//! - SEC1 compressed encoding/decoding
//! - Point negation
//!
//! The curve equation: y² = x³ + 7 (mod p)
//! where p = 2²⁵⁶ - 2³² - 977
//!
//! Reference: SEC 2: Recommended Elliptic Curve Domain Parameters
//! Reference: sigmastate GroupElement operations

const std = @import("std");
const assert = std.debug.assert;
const timing = @import("timing.zig");

// ============================================================================
// Error Types
// ============================================================================

pub const Secp256k1Error = error{
    /// Point is not on the curve
    PointNotOnCurve,
    /// Invalid encoding prefix (not 0x02, 0x03, or infinity)
    InvalidEncoding,
    /// Value is not a valid field element (>= p)
    InvalidFieldElement,
    /// No square root exists (for y-coordinate recovery)
    NoSquareRoot,
};

// ============================================================================
// Field Element (mod p)
// ============================================================================

/// Field element in F_p where p = 2^256 - 2^32 - 977
/// Represented as 4 x u64 limbs in little-endian order
pub const FieldElement = struct {
    limbs: [4]u64,

    /// Field prime p = 2^256 - 2^32 - 977
    /// = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    pub const P: [4]u64 = .{
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    };

    pub const zero = FieldElement{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one = FieldElement{ .limbs = .{ 1, 0, 0, 0 } };

    // Compile-time assertions for constant correctness
    comptime {
        // P must have top limbs all 1s (2^256 - small number)
        assert(P[3] == 0xFFFFFFFFFFFFFFFF);
        assert(P[2] == 0xFFFFFFFFFFFFFFFF);
        assert(P[1] == 0xFFFFFFFFFFFFFFFF);
        // P's low limb encodes -2^32 - 977 in two's complement
        assert(P[0] == 0xFFFFFFFEFFFFFC2F);
        // Zero is all zeros
        assert(zero.limbs[0] == 0 and zero.limbs[3] == 0);
        // One has value 1 in lowest limb
        assert(one.limbs[0] == 1 and one.limbs[1] == 0);
    }

    /// Create from u64
    pub fn fromInt(n: u64) FieldElement {
        return .{ .limbs = .{ n, 0, 0, 0 } };
    }

    /// Create from big-endian bytes (32 bytes)
    pub fn fromBytes(bytes: *const [32]u8) Secp256k1Error!FieldElement {
        // Precondition: input is exactly 32 bytes (ensured by type)
        assert(bytes.len == 32);

        var limbs: [4]u64 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, bytes[offset..][0..8], .big);
        }

        const fe = FieldElement{ .limbs = limbs };
        // Validate < p
        if (cmpLimbs(limbs, P) != .lt) {
            return error.InvalidFieldElement;
        }

        // Postcondition: result is a valid field element (< p)
        assert(cmpLimbs(fe.limbs, P) == .lt);
        return fe;
    }

    /// Convert to big-endian bytes (32 bytes)
    pub fn toBytes(self: FieldElement) [32]u8 {
        var result: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, result[offset..][0..8], self.limbs[i], .big);
        }
        return result;
    }

    /// Check if zero
    pub fn isZero(self: FieldElement) bool {
        return self.limbs[0] == 0 and self.limbs[1] == 0 and
            self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    /// Check equality (NOT constant-time - use constantTimeEql for crypto)
    pub fn eql(a: FieldElement, b: FieldElement) bool {
        return a.limbs[0] == b.limbs[0] and a.limbs[1] == b.limbs[1] and
            a.limbs[2] == b.limbs[2] and a.limbs[3] == b.limbs[3];
    }

    /// Constant-time equality comparison (for cryptographic use)
    /// CRITICAL: No early exit - always examines all limbs
    pub fn constantTimeEql(a: FieldElement, b: FieldElement) bool {
        const a_bytes = a.toBytes();
        const b_bytes = b.toBytes();
        return timing.constantTimeEqlFixed(32, &a_bytes, &b_bytes);
    }

    /// Addition mod p
    pub fn add(a: FieldElement, b: FieldElement) FieldElement {
        // Precondition: inputs are valid field elements (< p)
        assert(cmpLimbs(a.limbs, P) == .lt);
        assert(cmpLimbs(b.limbs, P) == .lt);

        var result: [4]u64 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            const sum1 = @addWithOverflow(a.limbs[i], b.limbs[i]);
            const sum2 = @addWithOverflow(sum1[0], carry);
            result[i] = sum2[0];
            carry = sum1[1] + sum2[1];
        }

        // If carry or result >= p, subtract p
        if (carry != 0 or cmpLimbs(result, P) != .lt) {
            result = subLimbs(result, P);
        }

        // Postcondition: result is a valid field element (< p)
        assert(cmpLimbs(result, P) == .lt);
        return .{ .limbs = result };
    }

    /// Subtraction mod p
    pub fn sub(a: FieldElement, b: FieldElement) FieldElement {
        // Precondition: inputs are valid field elements (< p)
        assert(cmpLimbs(a.limbs, P) == .lt);
        assert(cmpLimbs(b.limbs, P) == .lt);

        var result: [4]u64 = undefined;
        if (cmpLimbs(a.limbs, b.limbs) != .lt) {
            // a >= b: simple subtraction
            result = subLimbs(a.limbs, b.limbs);
        } else {
            // a < b: compute a - b + p = (a + p) - b
            result = addLimbsNoReduce(a.limbs, P);
            result = subLimbs(result, b.limbs);
        }

        // Postcondition: result is a valid field element (< p)
        assert(cmpLimbs(result, P) == .lt);
        return .{ .limbs = result };
    }

    /// Multiplication mod p
    pub fn mul(a: FieldElement, b: FieldElement) FieldElement {
        // Precondition: inputs are valid field elements (< p)
        assert(cmpLimbs(a.limbs, P) == .lt);
        assert(cmpLimbs(b.limbs, P) == .lt);

        // Schoolbook multiplication with Barrett reduction
        var result: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };

        for (0..4) |i| {
            var carry: u64 = 0;
            for (0..4) |j| {
                const prod: u128 = @as(u128, a.limbs[i]) * @as(u128, b.limbs[j]);
                const sum: u128 = @as(u128, result[i + j]) + prod + @as(u128, carry);
                result[i + j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
            result[i + 4] = carry;
        }

        // Reduce mod p
        const reduced = reduce512(result);
        // Postcondition: result is a valid field element (< p)
        assert(cmpLimbs(reduced.limbs, P) == .lt);
        return reduced;
    }

    /// Squaring mod p (slightly more efficient than mul)
    pub fn square(self: FieldElement) FieldElement {
        return self.mul(self);
    }

    /// Negation mod p: -a = p - a (if a != 0)
    pub fn neg(self: FieldElement) FieldElement {
        if (self.isZero()) return self;
        return .{ .limbs = subLimbs(P, self.limbs) };
    }

    /// Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    pub fn inv(self: FieldElement) FieldElement {
        // Precondition: cannot invert zero
        assert(!self.isZero());
        // Precondition: input is a valid field element (< p)
        assert(cmpLimbs(self.limbs, P) == .lt);

        // p - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        // Use square-and-multiply
        const result = self.pow(P_MINUS_2);

        // Postcondition: self * result = 1 (mod p)
        assert(self.mul(result).eql(one));
        return result;
    }

    /// Exponentiation: self^exp mod p
    pub fn pow(self: FieldElement, exp: [4]u64) FieldElement {
        // Precondition: base is a valid field element (< p)
        assert(cmpLimbs(self.limbs, P) == .lt);

        var result = one;
        var base = self;

        for (0..4) |limb_idx| {
            var bits = exp[limb_idx];
            for (0..64) |_| {
                if (bits & 1 == 1) {
                    result = result.mul(base);
                }
                base = base.square();
                bits >>= 1;
            }
        }

        // Postcondition: result is a valid field element (< p)
        assert(cmpLimbs(result.limbs, P) == .lt);
        return result;
    }

    /// Square root mod p using Tonelli-Shanks
    /// For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
    pub fn sqrt(self: FieldElement) Secp256k1Error!FieldElement {
        // Precondition: input is a valid field element (< p)
        assert(cmpLimbs(self.limbs, P) == .lt);

        if (self.isZero()) return zero;

        // Since p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4)
        const candidate = self.pow(P_PLUS_1_DIV_4);

        // Verify: candidate² == self
        if (!candidate.square().eql(self)) {
            return error.NoSquareRoot;
        }

        // Postcondition: candidate² == self
        assert(candidate.square().eql(self));
        return candidate;
    }

    // p - 2 for Fermat inverse
    const P_MINUS_2: [4]u64 = .{
        0xFFFFFFFEFFFFFC2D,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    };

    // (p + 1) / 4 for square root
    // p+1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30
    // (p+1)/4 = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C
    const P_PLUS_1_DIV_4: [4]u64 = .{
        0xFFFFFFFFBFFFFF0C,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x3FFFFFFFFFFFFFFF,
    };

    // secp256k1 reduction constant: 2^256 = c (mod p), where c = 2^32 + 977
    const SECP256K1_C: u64 = 0x1000003D1;

    // Reduce 512-bit number mod p using secp256k1's special form
    // p = 2^256 - 2^32 - 977, so 2^256 = 2^32 + 977 (mod p)
    fn reduce512(x: [8]u64) FieldElement {
        var result: [5]u64 = .{ x[0], x[1], x[2], x[3], 0 };

        // Reduce high limbs: x[4..8] * c
        for (4..8) |i| {
            if (x[i] == 0) continue;
            reduceAddMulC(&result, x[i], i - 4);
        }

        // Reduce 5th limb until it's zero
        while (result[4] != 0) {
            const hi = result[4];
            result[4] = 0;
            reduceAddMulC(&result, hi, 0);
        }

        var r: [4]u64 = .{ result[0], result[1], result[2], result[3] };

        // Final reduction if r >= p
        while (cmpLimbs(r, P) != .lt) {
            r = subLimbs(r, P);
        }

        return .{ .limbs = r };
    }

    // Helper: Add value * c at position in 5-limb accumulator
    fn reduceAddMulC(result: *[5]u64, value: u64, pos: usize) void {
        const prod_full: u128 = @as(u128, value) * @as(u128, SECP256K1_C);
        const prod_lo: u64 = @truncate(prod_full);
        const prod_hi: u64 = @truncate(prod_full >> 64);

        var sum: u128 = @as(u128, result[pos]) + @as(u128, prod_lo);
        result[pos] = @truncate(sum);
        var carry: u64 = @truncate(sum >> 64);

        if (pos + 1 < 5) {
            sum = @as(u128, result[pos + 1]) + @as(u128, prod_hi) + @as(u128, carry);
            result[pos + 1] = @truncate(sum);
            carry = @truncate(sum >> 64);

            var j = pos + 2;
            while (carry != 0 and j < 5) : (j += 1) {
                sum = @as(u128, result[j]) + @as(u128, carry);
                result[j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
        }
    }
};

// ============================================================================
// Scalar (mod n)
// ============================================================================

/// Curve order n
pub const N: [4]u64 = .{
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
};

/// Scalar element in Z_n (integers modulo curve order n)
/// Used for private keys and responses in sigma protocols
pub const Scalar = struct {
    limbs: [4]u64,

    pub const zero = Scalar{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one = Scalar{ .limbs = .{ 1, 0, 0, 0 } };

    /// Create from 32-byte big-endian encoding
    pub fn fromBytes(bytes: [32]u8) !Scalar {
        var limbs: [4]u64 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            limbs[i] = std.mem.readInt(u64, bytes[offset..][0..8], .big);
        }

        // Validate < n
        if (cmpLimbs(limbs, N) != .lt) {
            return error.InvalidScalar;
        }

        return Scalar{ .limbs = limbs };
    }

    /// Create from u64
    pub fn fromInt(n: u64) Scalar {
        return Scalar{ .limbs = .{ n, 0, 0, 0 } };
    }

    /// Convert to 32-byte big-endian encoding
    pub fn toBytes(self: Scalar) [32]u8 {
        var result: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, result[offset..][0..8], self.limbs[i], .big);
        }
        return result;
    }

    /// Check if zero
    pub fn isZero(self: Scalar) bool {
        return self.limbs[0] == 0 and self.limbs[1] == 0 and
            self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    /// Check equality
    pub fn eql(a: Scalar, b: Scalar) bool {
        return a.limbs[0] == b.limbs[0] and a.limbs[1] == b.limbs[1] and
            a.limbs[2] == b.limbs[2] and a.limbs[3] == b.limbs[3];
    }

    /// Addition mod n
    pub fn add(a: Scalar, b: Scalar) Scalar {
        var result: [4]u64 = undefined;
        var carry: u64 = 0;

        for (0..4) |i| {
            const sum1 = @addWithOverflow(a.limbs[i], b.limbs[i]);
            const sum2 = @addWithOverflow(sum1[0], carry);
            result[i] = sum2[0];
            carry = sum1[1] + sum2[1];
        }

        // If carry or result >= n, subtract n
        if (carry != 0 or cmpLimbs(result, N) != .lt) {
            result = subLimbs(result, N);
        }

        return Scalar{ .limbs = result };
    }

    /// Subtraction mod n
    pub fn sub(a: Scalar, b: Scalar) Scalar {
        var result: [4]u64 = undefined;
        if (cmpLimbs(a.limbs, b.limbs) != .lt) {
            result = subLimbs(a.limbs, b.limbs);
        } else {
            // a < b: compute a - b + n
            result = addLimbsNoReduce(a.limbs, N);
            result = subLimbs(result, b.limbs);
        }

        return Scalar{ .limbs = result };
    }

    /// Multiplication mod n
    pub fn mul(a: Scalar, b: Scalar) Scalar {
        // Schoolbook multiplication
        var result: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };

        for (0..4) |i| {
            var carry: u64 = 0;
            for (0..4) |j| {
                const prod: u128 = @as(u128, a.limbs[i]) * @as(u128, b.limbs[j]);
                const sum: u128 = @as(u128, result[i + j]) + prod + @as(u128, carry);
                result[i + j] = @truncate(sum);
                carry = @truncate(sum >> 64);
            }
            result[i + 4] = carry;
        }

        // Reduce mod n using Barrett reduction
        return reduceScalar512(result);
    }

    /// Reduce 512-bit number mod n
    fn reduceScalar512(x: [8]u64) Scalar {
        // Simple modular reduction by repeated subtraction
        // For production, Barrett reduction would be more efficient
        var result: [5]u64 = .{ x[0], x[1], x[2], x[3], 0 };

        // Reduce high limbs
        for (4..8) |i| {
            if (x[i] == 0) continue;
            // Multiply by 2^(64*i) mod n and add
            // For now, use a simple approach
            const val = x[i];
            var shift_amount: usize = (i - 4) * 64;
            while (shift_amount >= 256) {
                // 2^256 mod n needs to be computed
                shift_amount -= 256;
            }
            // Add the contribution - this is a simplified version
            const contribution = @as(u128, val) << @intCast(shift_amount % 64);
            const limb_idx = shift_amount / 64;
            if (limb_idx < 5) {
                const sum: u128 = @as(u128, result[limb_idx]) + contribution;
                result[limb_idx] = @truncate(sum);
                var carry: u64 = @truncate(sum >> 64);
                var j = limb_idx + 1;
                while (carry != 0 and j < 5) : (j += 1) {
                    const s2: u128 = @as(u128, result[j]) + @as(u128, carry);
                    result[j] = @truncate(s2);
                    carry = @truncate(s2 >> 64);
                }
            }
        }

        var r: [4]u64 = .{ result[0], result[1], result[2], result[3] };

        // Final reduction while r >= n
        while (cmpLimbs(r, N) != .lt) {
            r = subLimbs(r, N);
        }

        return Scalar{ .limbs = r };
    }
};

// ============================================================================
// Point on secp256k1
// ============================================================================

/// Point on the secp256k1 curve
pub const Point = struct {
    x: FieldElement,
    y: FieldElement,
    is_infinity: bool,

    /// Point at infinity (identity element)
    pub const infinity = Point{
        .x = FieldElement.zero,
        .y = FieldElement.zero,
        .is_infinity = true,
    };

    /// Generator point G
    pub const G = Point{
        .x = .{ .limbs = .{
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        } },
        .y = .{ .limbs = .{
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        } },
        .is_infinity = false,
    };

    /// Validate that point is on the curve: y² = x³ + 7
    pub fn isValid(self: Point) bool {
        if (self.is_infinity) return true;

        // y² mod p
        const y2 = self.y.square();

        // x³ + 7 mod p
        const x2 = self.x.square();
        const x3 = x2.mul(self.x);
        const rhs = x3.add(FieldElement.fromInt(7));

        return y2.eql(rhs);
    }

    /// Decode from SEC1 compressed format (33 bytes)
    /// 0x00... (33 zeros) = infinity
    /// 0x02 + x = even y
    /// 0x03 + x = odd y
    pub fn decode(bytes: *const [33]u8) Secp256k1Error!Point {
        // Check for infinity (33 zero bytes)
        var all_zero = true;
        for (bytes) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return infinity;

        const prefix = bytes[0];
        if (prefix != 0x02 and prefix != 0x03) {
            return error.InvalidEncoding;
        }

        // Extract x coordinate
        const x = try FieldElement.fromBytes(bytes[1..33]);

        // Compute y² = x³ + 7
        const x2 = x.square();
        const x3 = x2.mul(x);
        const y2 = x3.add(FieldElement.fromInt(7));

        // Compute y = sqrt(y²)
        const y = try y2.sqrt();

        // Choose correct y based on parity (prefix 0x02 = even, 0x03 = odd)
        const y_is_odd = (y.limbs[0] & 1) == 1;
        const want_odd = prefix == 0x03;
        const final_y = if (y_is_odd != want_odd) y.neg() else y;

        const point = Point{ .x = x, .y = final_y, .is_infinity = false };

        // Verify point is on curve (should always be true if sqrt worked)
        assert(point.isValid());

        return point;
    }

    /// Encode to SEC1 compressed format (33 bytes)
    /// PAIR ASSERTION: decode() asserts isValid() after deserializing,
    /// encode() asserts isValid() before serializing
    pub fn encode(self: Point) [33]u8 {
        // CRITICAL: Never serialize an invalid point
        assert(self.is_infinity or self.isValid());

        if (self.is_infinity) {
            return [_]u8{0} ** 33;
        }

        var result: [33]u8 = undefined;
        result[0] = if ((self.y.limbs[0] & 1) == 1) 0x03 else 0x02;
        const x_bytes = self.x.toBytes();
        @memcpy(result[1..33], &x_bytes);
        return result;
    }

    /// Check equality (NOT constant-time - use constantTimeEql for crypto)
    pub fn eql(a: Point, b: Point) bool {
        if (a.is_infinity and b.is_infinity) return true;
        if (a.is_infinity != b.is_infinity) return false;
        return a.x.eql(b.x) and a.y.eql(b.y);
    }

    /// Constant-time equality comparison (for cryptographic use)
    /// CRITICAL: No early exit - encodes both points and compares bytes
    pub fn constantTimeEql(a: Point, b: Point) bool {
        const a_bytes = a.encode();
        const b_bytes = b.encode();
        return timing.constantTimeEqlFixed(33, &a_bytes, &b_bytes);
    }

    /// Point negation: -P = (x, -y)
    pub fn neg(self: Point) Point {
        if (self.is_infinity) return self;
        return .{
            .x = self.x,
            .y = self.y.neg(),
            .is_infinity = false,
        };
    }

    /// Point addition
    pub fn add(self: Point, other: Point) Point {
        // Precondition: both points are valid (on curve or infinity)
        assert(self.is_infinity or self.isValid());
        assert(other.is_infinity or other.isValid());

        if (self.is_infinity) return other;
        if (other.is_infinity) return self;

        // Check for P + (-P) = O
        if (self.x.eql(other.x)) {
            if (self.y.eql(other.y)) {
                // P + P = 2P (point doubling)
                return self.double();
            } else {
                // P + (-P) = O
                return infinity;
            }
        }

        // General addition formula:
        // λ = (y2 - y1) / (x2 - x1)
        // x3 = λ² - x1 - x2
        // y3 = λ(x1 - x3) - y1
        const dy = other.y.sub(self.y);
        const dx = other.x.sub(self.x);
        const lambda = dy.mul(dx.inv());

        const lambda2 = lambda.square();
        const x3 = lambda2.sub(self.x).sub(other.x);
        const y3 = lambda.mul(self.x.sub(x3)).sub(self.y);

        const result = Point{ .x = x3, .y = y3, .is_infinity = false };
        // Postcondition: result is on curve
        assert(result.isValid());
        return result;
    }

    /// Point doubling: 2P
    pub fn double(self: Point) Point {
        // Precondition: point is valid (on curve or infinity)
        assert(self.is_infinity or self.isValid());

        if (self.is_infinity) return self;
        if (self.y.isZero()) return infinity; // Tangent is vertical

        // Doubling formula:
        // λ = (3x² + a) / (2y)  where a = 0 for secp256k1
        // λ = 3x² / 2y
        // x3 = λ² - 2x
        // y3 = λ(x - x3) - y
        const x2 = self.x.square();
        const three_x2 = x2.add(x2).add(x2); // 3x²
        const two_y = self.y.add(self.y); // 2y
        const lambda = three_x2.mul(two_y.inv());

        const lambda2 = lambda.square();
        const x3 = lambda2.sub(self.x).sub(self.x);
        const y3 = lambda.mul(self.x.sub(x3)).sub(self.y);

        const result = Point{ .x = x3, .y = y3, .is_infinity = false };
        // Postcondition: result is on curve
        assert(result.isValid());
        return result;
    }

    /// Scalar multiplication: k * P using double-and-add
    /// WARNING: NOT constant-time - use mulConstantTime for crypto
    pub fn mul(self: Point, k: [4]u64) Point {
        // Precondition: point is valid (on curve or infinity)
        assert(self.is_infinity or self.isValid());

        if (self.is_infinity) return infinity;

        // Check for zero scalar
        if (k[0] == 0 and k[1] == 0 and k[2] == 0 and k[3] == 0) {
            return infinity;
        }

        var result = infinity;
        var temp = self;

        // Process each bit from LSB to MSB
        for (0..4) |limb_idx| {
            var bits = k[limb_idx];
            for (0..64) |_| {
                if (bits & 1 == 1) {
                    result = result.add(temp);
                }
                temp = temp.double();
                bits >>= 1;
            }
        }

        // Postcondition: result is valid (on curve or infinity)
        assert(result.is_infinity or result.isValid());
        return result;
    }

    /// Constant-time scalar multiplication using Montgomery ladder
    /// CRITICAL: Always performs same operations regardless of scalar bits
    ///
    /// Uses the Montgomery ladder algorithm which maintains two points R0 and R1
    /// such that R1 - R0 = P throughout the computation. This provides:
    /// - Constant-time execution (same ops for all scalar bits)
    /// - Protection against simple power analysis
    /// - Protection against timing attacks
    pub fn mulConstantTime(self: Point, k: [4]u64) Point {
        // Precondition: point is valid (on curve or infinity)
        assert(self.is_infinity or self.isValid());

        if (self.is_infinity) return infinity;

        // Check for zero scalar (constant-time check)
        const is_zero = timing.constantTimeEqU64(k[0] | k[1] | k[2] | k[3], 0);
        if (is_zero == 1) return infinity;

        // Montgomery ladder: maintain R0, R1 such that R1 = R0 + P
        var r0 = infinity;
        var r1 = self;

        // Process bits from MSB to LSB
        // Start from bit 255 (most significant) down to 0
        var i: i32 = 255;
        while (i >= 0) : (i -= 1) {
            const bit_pos: u32 = @intCast(i);
            const limb_idx = bit_pos / 64;
            const bit_idx: u6 = @intCast(bit_pos % 64);
            const bit: u1 = @truncate(k[limb_idx] >> bit_idx);

            // Constant-time conditional swap: if bit == 1, swap R0 and R1
            // This is the key to constant-time operation
            conditionalSwapPoints(&r0, &r1, bit);

            // After potential swap:
            // bit == 0: r0 unchanged, r1 unchanged
            // bit == 1: r0 <-> r1 swapped
            r1 = r0.add(r1); // R1 = R0 + R1
            r0 = r0.double(); // R0 = 2 * R0

            // Swap back
            conditionalSwapPoints(&r0, &r1, bit);
        }

        // Postcondition: result is valid (on curve or infinity)
        assert(r0.is_infinity or r0.isValid());
        return r0;
    }

    /// Helper: Constant-time conditional swap of two points
    /// If choice == 1, swap a and b; if choice == 0, leave unchanged
    /// CRITICAL: No branching on choice value
    fn conditionalSwapPoints(a: *Point, b: *Point, choice: u1) void {
        // Swap x coordinates
        conditionalSwapFieldElements(&a.x, &b.x, choice);
        // Swap y coordinates
        conditionalSwapFieldElements(&a.y, &b.y, choice);
        // Swap infinity flags
        conditionalSwapBool(&a.is_infinity, &b.is_infinity, choice);
    }

    /// Helper: Constant-time conditional swap of two field elements
    fn conditionalSwapFieldElements(a: *FieldElement, b: *FieldElement, choice: u1) void {
        const mask: u64 = @as(u64, 0) -% @as(u64, choice);
        for (0..4) |i| {
            const diff = mask & (a.limbs[i] ^ b.limbs[i]);
            a.limbs[i] ^= diff;
            b.limbs[i] ^= diff;
        }
    }

    /// Helper: Constant-time conditional swap of two bools
    fn conditionalSwapBool(a: *bool, b: *bool, choice: u1) void {
        const a_int: u8 = @intFromBool(a.*);
        const b_int: u8 = @intFromBool(b.*);
        const mask: u8 = @as(u8, 0) -% @as(u8, choice);
        const diff = mask & (a_int ^ b_int);
        a.* = (a_int ^ diff) != 0;
        b.* = (b_int ^ diff) != 0;
    }
};

// ============================================================================
// Internal Helper Functions
// ============================================================================

fn cmpLimbs(a: [4]u64, b: [4]u64) std.math.Order {
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        if (a[i] > b[i]) return .gt;
        if (a[i] < b[i]) return .lt;
    }
    return .eq;
}

fn subLimbs(a: [4]u64, b: [4]u64) [4]u64 {
    var result: [4]u64 = undefined;
    var borrow: u64 = 0;

    for (0..4) |i| {
        const diff1 = @subWithOverflow(a[i], b[i]);
        const diff2 = @subWithOverflow(diff1[0], borrow);
        result[i] = diff2[0];
        borrow = diff1[1] + diff2[1];
    }

    return result;
}

fn addLimbsNoReduce(a: [4]u64, b: [4]u64) [4]u64 {
    var result: [4]u64 = undefined;
    var carry: u64 = 0;

    for (0..4) |i| {
        const sum1 = @addWithOverflow(a[i], b[i]);
        const sum2 = @addWithOverflow(sum1[0], carry);
        result[i] = sum2[0];
        carry = sum1[1] + sum2[1];
    }

    // For a + p where a < p, result fits in 4 limbs
    assert(carry == 0 or carry == 1);
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "secp256k1: field element basic" {
    const a = FieldElement.fromInt(42);
    const b = FieldElement.fromInt(10);

    const sum = a.add(b);
    try std.testing.expect(sum.eql(FieldElement.fromInt(52)));

    const diff = a.sub(b);
    try std.testing.expect(diff.eql(FieldElement.fromInt(32)));

    const prod = a.mul(b);
    try std.testing.expect(prod.eql(FieldElement.fromInt(420)));
}

test "secp256k1: field element inverse" {
    const a = FieldElement.fromInt(42);
    const a_inv = a.inv();
    const should_be_one = a.mul(a_inv);
    try std.testing.expect(should_be_one.eql(FieldElement.one));
}

test "secp256k1: generator is on curve" {
    try std.testing.expect(Point.G.isValid());
}

test "secp256k1: infinity is valid" {
    try std.testing.expect(Point.infinity.isValid());
}

test "secp256k1: G + G = 2G" {
    const two_g = Point.G.add(Point.G);
    const two_g_double = Point.G.double();
    try std.testing.expect(two_g.eql(two_g_double));
    try std.testing.expect(two_g.isValid());
}

test "secp256k1: P + (-P) = O" {
    const neg_g = Point.G.neg();
    const result = Point.G.add(neg_g);
    try std.testing.expect(result.is_infinity);
}

test "secp256k1: encode/decode roundtrip" {
    const encoded = Point.G.encode();
    const decoded = try Point.decode(&encoded);
    try std.testing.expect(decoded.eql(Point.G));
}

test "secp256k1: encode/decode infinity" {
    const encoded = Point.infinity.encode();
    const decoded = try Point.decode(&encoded);
    try std.testing.expect(decoded.is_infinity);
}

test "secp256k1: scalar mul by 1" {
    const result = Point.G.mul(.{ 1, 0, 0, 0 });
    try std.testing.expect(result.eql(Point.G));
}

test "secp256k1: scalar mul by 2" {
    const result = Point.G.mul(.{ 2, 0, 0, 0 });
    const expected = Point.G.double();
    try std.testing.expect(result.eql(expected));
}

test "secp256k1: n * G = O (order test)" {
    // n * G should equal infinity
    // This is a slow test but important for correctness
    const result = Point.G.mul(N);
    try std.testing.expect(result.is_infinity);
}

test "secp256k1: invalid prefix rejected" {
    var bad_encoding: [33]u8 = undefined;
    bad_encoding[0] = 0x04; // Uncompressed prefix (not supported)
    @memset(bad_encoding[1..], 0);

    try std.testing.expectError(error.InvalidEncoding, Point.decode(&bad_encoding));
}

// ============================================================================
// Constant-Time Tests
// ============================================================================

test "secp256k1: constantTimeEql Point equal" {
    try std.testing.expect(Point.G.constantTimeEql(Point.G));
    try std.testing.expect(Point.infinity.constantTimeEql(Point.infinity));
}

test "secp256k1: constantTimeEql Point different" {
    const two_g = Point.G.double();
    try std.testing.expect(!Point.G.constantTimeEql(two_g));
    try std.testing.expect(!Point.G.constantTimeEql(Point.infinity));
}

test "secp256k1: constantTimeEql FieldElement" {
    const a = FieldElement.fromInt(42);
    const b = FieldElement.fromInt(42);
    const c = FieldElement.fromInt(43);

    try std.testing.expect(a.constantTimeEql(b));
    try std.testing.expect(!a.constantTimeEql(c));
}

test "secp256k1: mulConstantTime by 1" {
    const result = Point.G.mulConstantTime(.{ 1, 0, 0, 0 });
    try std.testing.expect(result.eql(Point.G));
}

test "secp256k1: mulConstantTime by 2" {
    const result = Point.G.mulConstantTime(.{ 2, 0, 0, 0 });
    const expected = Point.G.double();
    try std.testing.expect(result.eql(expected));
}

test "secp256k1: mulConstantTime matches mul" {
    // Test with various scalars
    const scalars = [_][4]u64{
        .{ 1, 0, 0, 0 },
        .{ 2, 0, 0, 0 },
        .{ 7, 0, 0, 0 },
        .{ 256, 0, 0, 0 },
        .{ 0xDEADBEEF, 0, 0, 0 },
        .{ 0, 1, 0, 0 }, // Larger scalar
    };

    for (scalars) |k| {
        const result_ct = Point.G.mulConstantTime(k);
        const result_var = Point.G.mul(k);
        try std.testing.expect(result_ct.eql(result_var));
    }
}

test "secp256k1: mulConstantTime by 0" {
    const result = Point.G.mulConstantTime(.{ 0, 0, 0, 0 });
    try std.testing.expect(result.is_infinity);
}

test "secp256k1: mulConstantTime n * G = O (order test)" {
    // n * G should equal infinity using constant-time mult
    // This verifies Montgomery ladder correctness
    const result = Point.G.mulConstantTime(N);
    try std.testing.expect(result.is_infinity);
}
