

## Phase 5: Cryptographic Primitives

### Prompt 5.1: BigInt Implementation

```
TASK: Implement 256-bit signed integer arithmetic

CONTEXT (From Cryptography Engineers):
"BigInt in Ergo is used for:
1. Cryptographic scalars (elliptic curve exponents)
2. Large monetary calculations
3. Proof verification

Requirements:
- Signed 256-bit (two's complement)
- Arbitrary precision up to 256 bits
- Overflow detection
- Constant-time for crypto operations (where used with secrets)

You can use Zig's built-in arbitrary precision or implement manually."

PREREQUISITE KNOWLEDGE:
- 256 bits = 32 bytes
- Serialized as big-endian, signed (two's complement)
- Must support: add, sub, mul, div, mod, negate, compare
- GroupElement.exp takes BigInt exponent

CREATE FILE: src/crypto/bigint.zig

OPTIONS:
1. Use std.math.big.int (Zig standard library)
2. Implement fixed 256-bit arithmetic manually
3. Bind to GMP or similar library

RECOMMEND: Option 2 for determinism and no dependencies

IMPLEMENTATION:
```zig
/// 256-bit signed integer
pub const BigInt256 = struct {
    /// Little-endian limbs (for efficient arithmetic)
    limbs: [4]u64,
    /// Sign: false = positive/zero, true = negative
    negative: bool,
    
    pub const zero = BigInt256{ .limbs = .{0, 0, 0, 0}, .negative = false };
    pub const one = BigInt256{ .limbs = .{1, 0, 0, 0}, .negative = false };
    pub const max_value = BigInt256{ .limbs = .{
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        std.math.maxInt(u64) >> 1,  // 255 bits positive
    }, .negative = false };
    pub const min_value = BigInt256{ .limbs = .{
        0,
        0,
        0,
        1 << 63,  // -2^255
    }, .negative = true };
    
    /// Create from bytes (big-endian, two's complement)
    pub fn fromBytes(bytes: []const u8) !BigInt256 {
        if (bytes.len > 32) return error.ValueTooLarge;
        
        // Determine sign from MSB
        const negative = bytes.len > 0 and (bytes[0] & 0x80) != 0;
        
        // Convert to limbs
        var result = BigInt256{ .limbs = .{0, 0, 0, 0}, .negative = negative };
        
        // Copy bytes, sign-extend if necessary
        var padded: [32]u8 = if (negative) .{0xFF} ** 32 else .{0} ** 32;
        @memcpy(padded[32 - bytes.len..], bytes);
        
        // Convert big-endian bytes to little-endian limbs
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            result.limbs[i] = std.mem.readInt(u64, padded[offset..][0..8], .big);
        }
        
        // If negative, convert from two's complement
        if (negative) {
            result = result.negate() catch unreachable;
            result.negative = true;
        }
        
        return result;
    }
    
    /// Convert to bytes (big-endian, two's complement)
    pub fn toBytes(self: BigInt256, buffer: []u8) []u8 {
        // Convert to two's complement if negative
        var value = if (self.negative) self.negate() catch self else self;
        
        // Convert limbs to big-endian bytes
        var full: [32]u8 = undefined;
        for (0..4) |i| {
            const offset = 32 - (i + 1) * 8;
            std.mem.writeInt(u64, full[offset..][0..8], value.limbs[i], .big);
        }
        
        // Find minimal representation
        var start: usize = 0;
        while (start < 31 and full[start] == (if (self.negative) 0xFF else 0)) {
            start += 1;
        }
        
        // Ensure sign bit is correct
        if (!self.negative and (full[start] & 0x80) != 0) {
            start -|= 1;
        }
        if (self.negative and (full[start] & 0x80) == 0) {
            start -|= 1;
        }
        
        const len = 32 - start;
        @memcpy(buffer[0..len], full[start..]);
        return buffer[0..len];
    }
    
    /// Addition
    pub fn add(a: BigInt256, b: BigInt256) !BigInt256 {
        if (a.negative == b.negative) {
            // Same sign: add magnitudes
            const result_limbs = addLimbs(a.limbs, b.limbs);
            if (result_limbs[1]) return error.Overflow;  // Carry out
            return BigInt256{ .limbs = result_limbs[0], .negative = a.negative };
        } else {
            // Different signs: subtract magnitudes
            const cmp = compareMagnitude(a.limbs, b.limbs);
            if (cmp == .eq) return zero;
            if (cmp == .gt) {
                return BigInt256{
                    .limbs = subLimbs(a.limbs, b.limbs),
                    .negative = a.negative,
                };
            } else {
                return BigInt256{
                    .limbs = subLimbs(b.limbs, a.limbs),
                    .negative = b.negative,
                };
            }
        }
    }
    
    // ... more operations
};
```

TESTS:
[ ] Create from bytes
[ ] Convert to bytes
[ ] Add positive numbers
[ ] Add negative numbers
[ ] Subtract across zero
[ ] Multiply
[ ] Divide
[ ] Modulo
[ ] Overflow detection
[ ] Roundtrip serialization
```

### Prompt 5.2: secp256k1 Curve Operations

```
TASK: Implement elliptic curve operations on secp256k1

CONTEXT (From Cryptography Engineers):
"GroupElement in Ergo is a point on the secp256k1 curve (same as Bitcoin).
Operations needed:
1. Point validation (is on curve)
2. Point addition (group operation)
3. Scalar multiplication (exponentiation)
4. Point encoding/decoding (SEC1 compressed)
5. Point negation (additive inverse)

CRITICAL: Every deserialized point MUST be validated.
Invalid points can break security assumptions."

PREREQUISITE KNOWLEDGE:
- secp256k1 is y² = x³ + 7 over Fp where p = 2²⁵⁶ - 2³² - 977
- Generator G is specified in SEC 2
- Order n is a 256-bit prime (number of points in group)
- Compressed encoding: 0x02/0x03 prefix + 32-byte x-coordinate
- Point at infinity: encoded as 33 zero bytes in Ergo

OPTIONS:
1. Bind to libsecp256k1 (recommended for production)
2. Pure Zig implementation (for determinism/simplicity)
3. Use zig-crypto if it supports secp256k1

CREATE FILE: src/crypto/secp256k1.zig

PURE ZIG IMPLEMENTATION (simplified):
```zig
/// Field prime: 2^256 - 2^32 - 977
pub const P = BigInt256.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

/// Curve order
pub const N = BigInt256.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

/// Generator x-coordinate
pub const Gx = BigInt256.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

/// Generator y-coordinate  
pub const Gy = BigInt256.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

/// Point on secp256k1 curve
pub const Point = struct {
    x: BigInt256,
    y: BigInt256,
    is_infinity: bool,
    
    pub const infinity = Point{
        .x = BigInt256.zero,
        .y = BigInt256.zero,
        .is_infinity = true,
    };
    
    pub const generator = Point{
        .x = Gx,
        .y = Gy,
        .is_infinity = false,
    };
    
    /// Validate point is on curve
    pub fn isValid(self: Point) bool {
        if (self.is_infinity) return true;
        
        // Check y² = x³ + 7 (mod p)
        const y2 = self.y.mulMod(self.y, P);
        const x3 = self.x.mulMod(self.x, P).mulMod(self.x, P);
        const rhs = x3.addMod(BigInt256.fromInt(7), P);
        
        return y2.equals(rhs);
    }
    
    /// Decode from SEC1 compressed format (33 bytes)
    pub fn decode(bytes: *const [33]u8) !Point {
        // Check for infinity (all zeros)
        if (std.mem.allEqual(u8, bytes, 0)) {
            return infinity;
        }
        
        // Check prefix
        const prefix = bytes[0];
        if (prefix != 0x02 and prefix != 0x03) {
            return error.InvalidPointEncoding;
        }
        
        // Extract x-coordinate
        const x = try BigInt256.fromBytes(bytes[1..33]);
        
        // Compute y from x: y = sqrt(x³ + 7)
        const x3 = x.mulMod(x, P).mulMod(x, P);
        const rhs = x3.addMod(BigInt256.fromInt(7), P);
        const y = try sqrtMod(rhs, P);
        
        // Choose correct y based on prefix (even/odd)
        const y_is_odd = y.limbs[0] & 1 == 1;
        const want_odd = prefix == 0x03;
        const final_y = if (y_is_odd != want_odd) P.sub(y) else y;
        
        const point = Point{ .x = x, .y = final_y, .is_infinity = false };
        
        // CRITICAL: Validate point is on curve
        if (!point.isValid()) {
            return error.PointNotOnCurve;
        }
        
        return point;
    }
    
    /// Encode to SEC1 compressed format
    pub fn encode(self: Point) [33]u8 {
        if (self.is_infinity) {
            return [_]u8{0} ** 33;
        }
        
        var result: [33]u8 = undefined;
        result[0] = if (self.y.limbs[0] & 1 == 1) 0x03 else 0x02;
        _ = self.x.toBytes(result[1..]);
        return result;
    }
    
    /// Point addition (group operation)
    pub fn add(self: Point, other: Point) Point {
        if (self.is_infinity) return other;
        if (other.is_infinity) return self;
        
        // Check for point doubling
        if (self.x.equals(other.x)) {
            if (self.y.equals(other.y)) {
                return self.double();
            } else {
                // P + (-P) = O (point at infinity)
                return infinity;
            }
        }
        
        // Standard addition formula
        // λ = (y2 - y1) / (x2 - x1)
        // x3 = λ² - x1 - x2
        // y3 = λ(x1 - x3) - y1
        const dy = other.y.subMod(self.y, P);
        const dx = other.x.subMod(self.x, P);
        const lambda = dy.mulMod(dx.invMod(P), P);
        
        const x3 = lambda.mulMod(lambda, P).subMod(self.x, P).subMod(other.x, P);
        const y3 = lambda.mulMod(self.x.subMod(x3, P), P).subMod(self.y, P);
        
        return Point{ .x = x3, .y = y3, .is_infinity = false };
    }
    
    /// Scalar multiplication: self * k
    pub fn multiply(self: Point, k: BigInt256) Point {
        if (self.is_infinity or k.isZero()) {
            return infinity;
        }
        
        // Double-and-add algorithm
        var result = infinity;
        var temp = self;
        var scalar = k;
        
        while (!scalar.isZero()) {
            if (scalar.limbs[0] & 1 == 1) {
                result = result.add(temp);
            }
            temp = temp.double();
            scalar = scalar.shiftRight(1);
        }
        
        return result;
    }
    
    /// Point negation (additive inverse)
    pub fn negate(self: Point) Point {
        if (self.is_infinity) return self;
        return Point{
            .x = self.x,
            .y = P.sub(self.y),
            .is_infinity = false,
        };
    }
};
```

TESTS:
[ ] Decode valid compressed point
[ ] Reject invalid prefix
[ ] Reject point not on curve
[ ] Generator is valid
[ ] Addition: G + G = 2G
[ ] Scalar multiplication: n * G = O (infinity)
[ ] Encode/decode roundtrip
[ ] Point negation: P + (-P) = O
```

### Prompt 5.3: Hash Functions

```
TASK: Implement Blake2b256 and SHA256 hash functions

CONTEXT (From Cryptography Engineers):
"Ergo uses:
- Blake2b256 for box IDs, transaction IDs, general hashing
- SHA256 for compatibility with Bitcoin-style proofs

Both must be deterministic across platforms. Use well-tested
implementations. Zig standard library has both."

CREATE FILE: src/crypto/hash.zig

IMPLEMENTATION:
```zig
const std = @import("std");
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Blake2b-256 hash (32 bytes output)
pub fn blake2b256(data: []const u8) [32]u8 {
    var hasher = Blake2b256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// SHA-256 hash (32 bytes output)
pub fn sha256(data: []const u8) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// Streaming Blake2b256 for large data
pub const Blake2b256Hasher = struct {
    state: Blake2b256,
    
    pub fn init() Blake2b256Hasher {
        return .{ .state = Blake2b256.init(.{}) };
    }
    
    pub fn update(self: *Blake2b256Hasher, data: []const u8) void {
        self.state.update(data);
    }
    
    pub fn finalize(self: *Blake2b256Hasher) [32]u8 {
        return self.state.finalResult();
    }
};
```

TESTS:
[ ] Blake2b256 known test vectors
[ ] SHA256 known test vectors (NIST)
[ ] Empty input
[ ] Large input (>1MB)
[ ] Incremental hashing matches single-shot
```

---
