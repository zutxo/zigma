//! GF(2^192) Galois Field Arithmetic
//!
//! Implements arithmetic in GF(2^192) for THRESHOLD signature polynomial interpolation.
//! This field is used to distribute challenges in k-of-n threshold signatures.
//!
//! Field operations:
//! - Addition: XOR (no carry, characteristic 2)
//! - Multiplication: polynomial multiplication with reduction
//! - The irreducible polynomial is x^192 + x^7 + x^2 + x + 1
//!
//! Elements are represented as 24 bytes (192 bits) in little-endian order.
//!
//! Reference: sigmastate/src/main/scala/sigmastate/crypto/GF2_192.scala

const std = @import("std");
const assert = std.debug.assert;
const timing = @import("timing.zig");

// ============================================================================
// GF(2^192) Element
// ============================================================================

/// Element of GF(2^192)
/// Represented as 3 x u64 limbs in little-endian order
/// Total: 192 bits = 24 bytes
pub const GF2_192 = struct {
    /// Three 64-bit limbs, little-endian
    /// limbs[0] contains bits 0-63
    /// limbs[1] contains bits 64-127
    /// limbs[2] contains bits 128-191
    limbs: [3]u64,

    /// Zero element (additive identity)
    pub const zero = GF2_192{ .limbs = .{ 0, 0, 0 } };

    /// One element (multiplicative identity)
    pub const one = GF2_192{ .limbs = .{ 1, 0, 0 } };

    // Compile-time assertions
    comptime {
        // Zero is all zeros
        assert(zero.limbs[0] == 0 and zero.limbs[1] == 0 and zero.limbs[2] == 0);
        // One has value 1 in lowest limb
        assert(one.limbs[0] == 1 and one.limbs[1] == 0 and one.limbs[2] == 0);
    }

    /// Create from a single u8 value (for point evaluation)
    pub fn fromByte(x: u8) GF2_192 {
        return GF2_192{ .limbs = .{ @as(u64, x), 0, 0 } };
    }

    /// Create from 24 bytes (big-endian, as used in Ergo)
    pub fn fromBytes(bytes: [24]u8) GF2_192 {
        var limbs: [3]u64 = undefined;

        // Big-endian to little-endian limbs
        // bytes[0..8] -> limbs[2] (most significant)
        // bytes[8..16] -> limbs[1]
        // bytes[16..24] -> limbs[0] (least significant)
        limbs[2] = std.mem.readInt(u64, bytes[0..8], .big);
        limbs[1] = std.mem.readInt(u64, bytes[8..16], .big);
        limbs[0] = std.mem.readInt(u64, bytes[16..24], .big);

        return GF2_192{ .limbs = limbs };
    }

    /// Convert to 24 bytes (big-endian)
    pub fn toBytes(self: GF2_192) [24]u8 {
        var result: [24]u8 = undefined;

        // Little-endian limbs to big-endian bytes
        std.mem.writeInt(u64, result[0..8], self.limbs[2], .big);
        std.mem.writeInt(u64, result[8..16], self.limbs[1], .big);
        std.mem.writeInt(u64, result[16..24], self.limbs[0], .big);

        return result;
    }

    /// Check if zero
    pub fn isZero(self: GF2_192) bool {
        return self.limbs[0] == 0 and self.limbs[1] == 0 and self.limbs[2] == 0;
    }

    /// Check equality
    pub fn eql(a: GF2_192, b: GF2_192) bool {
        return a.limbs[0] == b.limbs[0] and
            a.limbs[1] == b.limbs[1] and
            a.limbs[2] == b.limbs[2];
    }

    /// Constant-time equality
    pub fn constantTimeEql(a: GF2_192, b: GF2_192) bool {
        const a_bytes = a.toBytes();
        const b_bytes = b.toBytes();
        return timing.constantTimeEqlFixed(24, &a_bytes, &b_bytes);
    }

    /// Addition in GF(2^192) is XOR
    /// This is because the field has characteristic 2
    pub fn add(a: GF2_192, b: GF2_192) GF2_192 {
        return GF2_192{
            .limbs = .{
                a.limbs[0] ^ b.limbs[0],
                a.limbs[1] ^ b.limbs[1],
                a.limbs[2] ^ b.limbs[2],
            },
        };
    }

    /// Subtraction in GF(2^192) is also XOR (same as addition)
    pub fn sub(a: GF2_192, b: GF2_192) GF2_192 {
        return add(a, b);
    }

    /// Multiplication in GF(2^192)
    /// Uses schoolbook multiplication followed by reduction modulo the irreducible polynomial
    /// Irreducible polynomial: x^192 + x^7 + x^2 + x + 1
    pub fn mul(a: GF2_192, b: GF2_192) GF2_192 {
        // Result of multiplication before reduction: up to 384 bits
        var product: [6]u64 = .{ 0, 0, 0, 0, 0, 0 };

        // Schoolbook multiplication in GF(2) (carry-less)
        // Each limb-pair multiplication uses XOR for accumulation
        for (0..3) |i| {
            for (0..3) |j| {
                const prod = clmul64(a.limbs[i], b.limbs[j]);
                product[i + j] ^= prod[0];
                product[i + j + 1] ^= prod[1];
            }
        }

        // Reduce modulo x^192 + x^7 + x^2 + x + 1
        return reduce384(product);
    }

    /// Square in GF(2^192)
    pub fn square(self: GF2_192) GF2_192 {
        return self.mul(self);
    }

    /// Multiplicative inverse using Fermat's Little Theorem
    /// Returns a^(-1) such that a * a^(-1) = 1
    ///
    /// In GF(2^192): a^(2^192) = a (Frobenius)
    /// Therefore: a^(-1) = a^(2^192 - 2)
    ///
    /// The exponent 2^192 - 2 in binary is 191 ones followed by a zero.
    pub fn inv(self: GF2_192) GF2_192 {
        // PRECONDITION: cannot invert zero
        assert(!self.isZero());

        var result = one;

        // Process the 191 one bits (bits 191 through 1)
        // Using left-to-right binary exponentiation
        for (0..191) |_| {
            result = result.square();
            result = result.mul(self);
        }

        // Process the final zero bit (bit 0) - just square, no multiply
        result = result.square();

        // POSTCONDITION: self * result = 1
        assert(self.mul(result).eql(one));
        return result;
    }

    /// Power function: self^exp
    pub fn pow(self: GF2_192, exp: u64) GF2_192 {
        if (exp == 0) return one;

        var result = one;
        var base = self;
        var e = exp;

        while (e > 0) {
            if (e & 1 == 1) {
                result = result.mul(base);
            }
            base = base.square();
            e >>= 1;
        }

        return result;
    }

    // ========================================================================
    // Internal Helper Functions
    // ========================================================================

    /// The irreducible polynomial x^192 + x^7 + x^2 + x + 1
    /// Represented as the low 192 bits (without the x^192 term)
    /// = x^7 + x^2 + x + 1 = 0b10000111 = 0x87
    const REDUCTION_POLY: u64 = 0x87;

    /// Reduce a 384-bit product modulo the irreducible polynomial
    fn reduce384(product: [6]u64) GF2_192 {
        var result: [3]u64 = .{ product[0], product[1], product[2] };

        // Reduce high bits (192-383) back into low bits
        // For each bit in position 192+i, we add REDUCTION_POLY shifted by i
        //
        // Since REDUCTION_POLY = x^7 + x^2 + x + 1 = 0x87:
        // x^192 ≡ x^7 + x^2 + x + 1 (mod irreducible)
        // x^(192+i) ≡ x^(7+i) + x^(2+i) + x^(1+i) + x^i

        // Process limbs 3, 4, 5 (high 192 bits)
        for (3..6) |i| {
            const high = product[i];
            if (high == 0) continue;

            const limb_offset = i - 3;

            // For each bit position in high limb:
            // bit at position 192 + 64*limb_offset + bit_pos
            // reduces to positions: 7+..., 2+..., 1+..., 0+... (relative to bit_pos)

            // We can process the whole limb at once using shifts
            // high * x^(192 - 192 + 64*limb_offset) mod P
            // = high * (x^7 + x^2 + x + 1) shifted appropriately

            const r = clmul64(high, REDUCTION_POLY);
            result[limb_offset] ^= r[0];
            if (limb_offset + 1 < 3) {
                result[limb_offset + 1] ^= r[1];
            } else {
                // Need further reduction if carry into position >= 192
                if (r[1] != 0) {
                    result[0] ^= clmul64(r[1], REDUCTION_POLY)[0];
                }
            }
        }

        return GF2_192{ .limbs = result };
    }

    /// Carry-less multiplication of two 64-bit values
    /// Returns 128-bit result as [low, high]
    fn clmul64(a: u64, b: u64) [2]u64 {
        // Software carry-less multiplication (polynomial multiplication over GF(2))
        var result_lo: u64 = 0;
        var result_hi: u64 = 0;

        var temp_b = b;

        // Process each bit of b
        for (0..64) |i| {
            if (temp_b & 1 == 1) {
                // Add a * x^i to result
                if (i == 0) {
                    result_lo ^= a;
                } else if (i < 64) {
                    result_lo ^= a << @intCast(i);
                    result_hi ^= a >> @intCast(64 - i);
                }
            }
            temp_b >>= 1;
            if (temp_b == 0) break;
        }

        return .{ result_lo, result_hi };
    }

    /// Compute degree of polynomial (position of highest set bit)
    fn degreeOf(a: GF2_192) i32 {
        if (a.limbs[2] != 0) {
            return 128 + @as(i32, 63 - @as(i32, @clz(a.limbs[2])));
        }
        if (a.limbs[1] != 0) {
            return 64 + @as(i32, 63 - @as(i32, @clz(a.limbs[1])));
        }
        if (a.limbs[0] != 0) {
            return @as(i32, 63 - @as(i32, @clz(a.limbs[0])));
        }
        return -1; // Zero polynomial has degree -1
    }

    /// Shift left by n bits (multiply by x^n)
    fn shiftLeft(a: GF2_192, n: u32) GF2_192 {
        if (n == 0) return a;
        if (n >= 192) return zero;

        var result: [3]u64 = .{ 0, 0, 0 };
        const limb_shift = n / 64;
        const bit_shift: u6 = @intCast(n % 64);

        if (bit_shift == 0) {
            // Pure limb shift
            for (0..3) |i| {
                if (i + limb_shift < 3) {
                    result[i + limb_shift] = a.limbs[i];
                }
            }
        } else {
            // Combined limb and bit shift
            // Note: bit_shift is 1-63 here, so right_shift is also 1-63
            const right_shift: u6 = @intCast(64 - @as(u7, bit_shift));
            for (0..3) |i| {
                if (i + limb_shift < 3) {
                    result[i + limb_shift] |= a.limbs[i] << bit_shift;
                }
                if (i + limb_shift + 1 < 3) {
                    result[i + limb_shift + 1] |= a.limbs[i] >> right_shift;
                }
            }
        }

        return GF2_192{ .limbs = result };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "gf2_192: zero and one" {
    try std.testing.expect(GF2_192.zero.isZero());
    try std.testing.expect(!GF2_192.one.isZero());
    try std.testing.expect(GF2_192.zero.eql(GF2_192.zero));
    try std.testing.expect(GF2_192.one.eql(GF2_192.one));
}

test "gf2_192: fromByte" {
    const x = GF2_192.fromByte(0x42);
    try std.testing.expectEqual(@as(u64, 0x42), x.limbs[0]);
    try std.testing.expectEqual(@as(u64, 0), x.limbs[1]);
    try std.testing.expectEqual(@as(u64, 0), x.limbs[2]);
}

test "gf2_192: fromBytes roundtrip" {
    var bytes: [24]u8 = undefined;
    for (0..24) |i| {
        bytes[i] = @intCast(i + 1);
    }

    const x = GF2_192.fromBytes(bytes);
    const result = x.toBytes();

    try std.testing.expectEqualSlices(u8, &bytes, &result);
}

test "gf2_192: addition is XOR" {
    const a = GF2_192{ .limbs = .{ 0xFF00FF00, 0xAA55AA55, 0x12345678 } };
    const b = GF2_192{ .limbs = .{ 0x0F0F0F0F, 0x55AA55AA, 0x87654321 } };

    const sum = a.add(b);

    try std.testing.expectEqual(@as(u64, 0xFF00FF00 ^ 0x0F0F0F0F), sum.limbs[0]);
    try std.testing.expectEqual(@as(u64, 0xAA55AA55 ^ 0x55AA55AA), sum.limbs[1]);
    try std.testing.expectEqual(@as(u64, 0x12345678 ^ 0x87654321), sum.limbs[2]);
}

test "gf2_192: addition is self-inverse" {
    const a = GF2_192{ .limbs = .{ 0xDEADBEEF, 0xCAFEBABE, 0x12345678 } };
    const result = a.add(a);

    try std.testing.expect(result.isZero());
}

test "gf2_192: subtraction equals addition" {
    const a = GF2_192{ .limbs = .{ 0xFF, 0xAA, 0x55 } };
    const b = GF2_192{ .limbs = .{ 0x0F, 0x55, 0xAA } };

    try std.testing.expect(a.sub(b).eql(a.add(b)));
}

test "gf2_192: multiplication by zero" {
    const a = GF2_192{ .limbs = .{ 0xDEADBEEF, 0xCAFEBABE, 0x12345678 } };
    const result = a.mul(GF2_192.zero);

    try std.testing.expect(result.isZero());
}

test "gf2_192: multiplication by one" {
    const a = GF2_192{ .limbs = .{ 0xDEADBEEF, 0xCAFEBABE, 0x12345678 } };
    const result = a.mul(GF2_192.one);

    try std.testing.expect(result.eql(a));
}

test "gf2_192: multiplication is commutative" {
    const a = GF2_192.fromByte(0x03);
    const b = GF2_192.fromByte(0x05);

    const ab = a.mul(b);
    const ba = b.mul(a);

    try std.testing.expect(ab.eql(ba));
}

test "gf2_192: small multiplication" {
    // In GF(2)[x]: (x+1) * (x+1) = x^2 + 1
    // 0x03 * 0x03 = 0x05 (no reduction needed for small values)
    const a = GF2_192.fromByte(0x03); // x + 1
    const result = a.mul(a); // (x+1)^2 = x^2 + 2x + 1 = x^2 + 1 (in GF(2))

    // x^2 + 1 = 0b101 = 5
    try std.testing.expectEqual(@as(u64, 5), result.limbs[0]);
    try std.testing.expectEqual(@as(u64, 0), result.limbs[1]);
    try std.testing.expectEqual(@as(u64, 0), result.limbs[2]);
}

test "gf2_192: inverse" {
    const a = GF2_192.fromByte(0x03);
    const a_inv = a.inv();
    const product = a.mul(a_inv);

    try std.testing.expect(product.eql(GF2_192.one));
}

test "gf2_192: pow 0 is one" {
    const a = GF2_192.fromByte(0x42);
    const result = a.pow(0);

    try std.testing.expect(result.eql(GF2_192.one));
}

test "gf2_192: pow 1 is self" {
    const a = GF2_192.fromByte(0x42);
    const result = a.pow(1);

    try std.testing.expect(result.eql(a));
}

test "gf2_192: pow 2 is square" {
    const a = GF2_192.fromByte(0x03);
    const pow2 = a.pow(2);
    const square = a.square();

    try std.testing.expect(pow2.eql(square));
}

test "gf2_192: degreeOf" {
    const zero_deg = GF2_192.degreeOf(GF2_192.zero);
    try std.testing.expectEqual(@as(i32, -1), zero_deg);

    const one_deg = GF2_192.degreeOf(GF2_192.one);
    try std.testing.expectEqual(@as(i32, 0), one_deg);

    const x_deg = GF2_192.degreeOf(GF2_192{ .limbs = .{ 2, 0, 0 } }); // x = 0b10
    try std.testing.expectEqual(@as(i32, 1), x_deg);

    const high_deg = GF2_192.degreeOf(GF2_192{ .limbs = .{ 0, 0, 1 } }); // x^128
    try std.testing.expectEqual(@as(i32, 128), high_deg);
}
